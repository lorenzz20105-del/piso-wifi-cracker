#!/usr/bin/env python3
"""Mock captive portal for testing wificrack.py. Run on port 8080."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import json

VALID_USER = "admin"
VALID_PASS = "nbn2025!"

LOGIN_HTML = """<!DOCTYPE html><html><head><title>WiFi Login</title></head><body>
<h1>Captive Portal</h1>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username"><br>
<input type="password" name="password" placeholder="Password"><br>
<button type="submit">Connect</button>
</form>
</body></html>"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(LOGIN_HTML.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        
        if self.path == "/api/auth":
            try: data = json.loads(body)
            except: data = {}
            user = data.get("u", "")
            pwd  = data.get("p", "")
        else:
            params = parse_qs(body)
            user = params.get("username", [""])[0]
            pwd  = params.get("password", [""])[0]

        if user == VALID_USER and pwd == VALID_PASS:
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.end_headers()
            self.wfile.write(b"<html>Welcome! You are authenticated.</html>")
        else:
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>Error: Invalid username or password. Please try again.</html>")

    def log_message(self, fmt, *args):
        pass  # quiet

if __name__ == "__main__":
    print("[*] Mock portal listening on http://0.0.0.0:8080")
    print(f"[*] Valid creds -> {VALID_USER}:{VALID_PASS}")
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
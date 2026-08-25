"""JWT authentication training lab.

Run only on your own machine for coursework. The server is intentionally
bound to 127.0.0.1. It implements a minimal JWT (HS256) encoder/decoder
from scratch -- no third-party JWT library -- so that both a vulnerable
and a safe verification path can be shown side by side:

  /vulnerable-login, /vulnerable-profile -- signs with a weak, guessable
      secret and accepts an unsigned "alg": "none" token outright.
  /safe-login, /safe-profile -- signs with a strong random secret,
      enforces the expected algorithm, verifies the signature in constant
      time, and checks token expiry.

Only alice's credentials are known ahead of time. The admin account's
password is a random secret generated at startup and never displayed or
used anywhere in this app -- any admin access in the vulnerable path can
only happen through JWT forgery, not through logging in as admin.
"""
import base64
import hashlib
import hmac
import json
import time
import secrets
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST, PORT = "127.0.0.1", 8084

USERS = {
    "alice": {"password": "orchid-47", "role": "student"},
    "admin": {"password": secrets.token_hex(16), "role": "admin"},
}

WEAK_SECRET = "secret"                  # deliberately weak / a common default
STRONG_SECRET = secrets.token_hex(32)   # generated once at startup; never exposed


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign(header: dict, payload: dict, secret: str) -> str:
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url_encode(sig)}"


def issue_vulnerable_token(username, role):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"username": username, "role": role, "iat": int(time.time())}
    return sign(header, payload, WEAK_SECRET)


def issue_safe_token(username, role, ttl_seconds):
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"username": username, "role": role, "iat": now, "exp": now + ttl_seconds}
    return sign(header, payload, STRONG_SECRET)


def split_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        return None
    return header, payload, header_b64, payload_b64, sig_b64


def decode_vulnerable(token):
    parsed = split_token(token)
    if parsed is None:
        return None, "malformed token"
    header, payload, header_b64, payload_b64, sig_b64 = parsed

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        # BUG: an unsigned token is accepted outright, no signature checked at all.
        return payload, None

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(WEAK_SECRET.encode(), signing_input, hashlib.sha256).digest()
    try:
        actual_sig = b64url_decode(sig_b64)
    except Exception:
        return None, "malformed signature"
    # BUG: weak, guessable signing secret; also a non-constant-time compare.
    if actual_sig == expected_sig:
        return payload, None
    return None, "invalid signature"


def decode_safe(token):
    parsed = split_token(token)
    if parsed is None:
        return None, "malformed token"
    header, payload, header_b64, payload_b64, sig_b64 = parsed

    if header.get("alg") != "HS256":
        return None, f"algorithm '{header.get('alg')}' is not permitted; only HS256 is accepted"

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(STRONG_SECRET.encode(), signing_input, hashlib.sha256).digest()
    try:
        actual_sig = b64url_decode(sig_b64)
    except Exception:
        return None, "malformed signature"
    if not hmac.compare_digest(actual_sig, expected_sig):
        return None, "invalid signature"

    if "exp" not in payload or int(time.time()) >= payload["exp"]:
        return None, "token expired"
    return payload, None


def page(title, body):
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
    <meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>{escape(title)}</title><style>
    body{{font-family:system-ui;max-width:820px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
    nav a{{margin-right:1rem}} input{{padding:.45rem;margin:.2rem;width:16rem}} button{{padding:.45rem .7rem}}
    code,pre{{background:#f2f2f2;padding:.2rem .35rem}} pre{{overflow:auto;padding:1rem;word-break:break-all;white-space:pre-wrap}}
    .warning{{background:#fff3cd;padding:1rem;border-left:4px solid #d39e00}}
    .ok{{background:#e6f6e6;padding:1rem;border-left:4px solid #2e7d32}}
    .bad{{background:#fdecea;padding:1rem;border-left:4px solid #c62828}}
    </style></head><body><h1>{escape(title)}</h1>
    <nav><a href='/'>Home</a><a href='/vulnerable-login'>Vulnerable login</a><a href='/safe-login'>Safe login</a></nav>{body}</body></html>"""


class JwtLabHandler(BaseHTTPRequestHandler):
    def send_html(self, content, status=200):
        data = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_form_body(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        return parse_qs(body)

    def token_from_request(self, params):
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return params.get("token", [""])[0]

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/":
            self.home()
        elif parsed.path == "/vulnerable-login":
            self.send_html(self.login_page(vulnerable=True))
        elif parsed.path == "/safe-login":
            self.send_html(self.login_page(vulnerable=False))
        elif parsed.path == "/vulnerable-profile":
            self.profile(vulnerable=True, params=params)
        elif parsed.path == "/safe-profile":
            self.profile(vulnerable=False, params=params)
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    def do_POST(self):
        if self.path == "/vulnerable-login":
            self.handle_login(vulnerable=True)
        elif self.path == "/safe-login":
            self.handle_login(vulnerable=False)
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    def home(self):
        self.send_html(page("JWT authentication training lab", """
          <p class='warning'><strong>Local training only.</strong> This application is intentionally insecure in one of its two login flows and binds to <code>127.0.0.1</code>. Do not deploy it.</p>
          <p>Both flows issue a JWT on login and require it to view a protected profile page. Compare a flow that trusts a weak secret and an unsigned <code>"alg":"none"</code> token against one that pins the algorithm, uses a strong random secret, and checks expiry.</p>
          <p>Only <code>alice / orchid-47</code> is a known credential (role: student). The <code>admin</code> account's password is a random secret generated at startup and never used anywhere in this app — any admin access must come from forging a token, not from logging in.</p>
          <ul><li><a href='/vulnerable-login'>Weak-secret / alg:none exercise</a></li><li><a href='/safe-login'>Strong-secret + validation comparison</a></li></ul>"""))

    def login_page(self, vulnerable):
        action = "/vulnerable-login" if vulnerable else "/safe-login"
        title = "Vulnerable login" if vulnerable else "Safe login"
        note = ("<p class='warning'>Deliberately vulnerable: tokens are signed with the weak secret <code>\"secret\"</code>, "
                "and the profile endpoint accepts any token whose header says <code>\"alg\":\"none\"</code> without checking a signature at all.</p>"
                if vulnerable else
                "<p class='ok'>Validated: tokens are signed with a strong random secret generated at startup, only <code>HS256</code> is accepted, "
                "the signature is checked with a constant-time comparison, and expiry is enforced.</p>")
        ttl_field = "" if vulnerable else "<label>Token lifetime (seconds) <input name='ttl' value='300'></label>"
        form = f"""<form method='post' action='{action}'>
        <label>Username <input name='username' value='alice'></label>
        <label>Password <input name='password' type='password' value='orchid-47'></label>
        {ttl_field}
        <button>Log in</button></form>"""
        return page(title, note + form)

    def handle_login(self, vulnerable):
        fields = self.read_form_body()
        username = fields.get("username", [""])[0]
        password = fields.get("password", [""])[0]
        user = USERS.get(username)
        title = "Vulnerable login" if vulnerable else "Safe login"

        if not user or user["password"] != password:
            self.send_html(self.login_page(vulnerable) + "<p class='bad'>Invalid username or password.</p>", 401)
            return

        if vulnerable:
            token = issue_vulnerable_token(username, user["role"])
            profile_url = f"/vulnerable-profile?token={token}"
        else:
            ttl = int(fields.get("ttl", ["300"])[0] or 300)
            token = issue_safe_token(username, user["role"], ttl)
            profile_url = f"/safe-profile?token={token}"

        result = (f"<div class='ok'><p>Logged in as <strong>{escape(username)}</strong> (role: {escape(user['role'])}).</p>"
                   f"<p>Issued JWT:</p><pre>{escape(token)}</pre>"
                   f"<p><a href='{escape(profile_url)}'>View protected profile with this token</a></p></div>")
        self.send_html(page(title, result))

    def profile(self, vulnerable, params):
        token = self.token_from_request(params)
        title = "Vulnerable profile" if vulnerable else "Safe profile"
        if not token:
            self.send_html(page(title, "<p class='bad'>No token supplied. Pass it as <code>?token=...</code> or an <code>Authorization: Bearer ...</code> header.</p>"), 401)
            return

        payload, error = (decode_vulnerable(token) if vulnerable else decode_safe(token))
        if error:
            self.send_html(page(title, f"<p class='bad'>Rejected: {escape(error)}</p><p>Token:</p><pre>{escape(token)}</pre>"), 401)
            return

        role = payload.get("role", "?")
        badge = "<p class='bad'><strong>Elevated to admin.</strong></p>" if role == "admin" else ""
        result = (f"<div class='ok'><p>Authenticated as <strong>{escape(str(payload.get('username')))}</strong> "
                   f"(role: <strong>{escape(str(role))}</strong>).</p>{badge}"
                   f"<p>Decoded payload:</p><pre>{escape(json.dumps(payload, indent=2))}</pre></div>")
        self.send_html(page(title, result))

    def log_message(self, format, *args):
        return  # keep the training output tidy


if __name__ == "__main__":
    print(f"JWT lab: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), JwtLabHandler).serve_forever()

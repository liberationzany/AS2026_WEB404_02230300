"""CSRF training lab.

Run only on your own machine for coursework.  The server is intentionally
bound to 127.0.0.1.  It simulates a tiny "account settings" page (change
your email address) in two versions:

  /vulnerable-settings -- accepts the change-email POST from anywhere,
                           relying only on the session cookie.
  /safe-settings        -- requires a per-session CSRF token to be present
                            and correct on the same POST.

A third page, /attacker-page, plays the role of a malicious site hosted on
a different origin: it auto-submits a hidden form to whichever settings
endpoint you point it at, exactly as an attacker-controlled page would.
"""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse
import secrets

HOST, PORT = "127.0.0.1", 8083

# session_id -> {"email": str, "csrf_token": str}
SESSIONS = {}


def new_session():
    session_id = secrets.token_hex(16)
    SESSIONS[session_id] = {"email": "student@example.com", "csrf_token": secrets.token_hex(16)}
    return session_id


def page(title, body):
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
    <meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>{escape(title)}</title><style>
    body{{font-family:system-ui;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
    nav a{{margin-right:1rem}} input{{padding:.45rem;margin:.2rem;width:20rem}} button{{padding:.45rem .7rem}}
    code,pre{{background:#f2f2f2;padding:.2rem .35rem}} pre{{overflow:auto;padding:1rem}}
    .warning{{background:#fff3cd;padding:1rem;border-left:4px solid #d39e00}}
    .ok{{background:#e6f6e6;padding:1rem;border-left:4px solid #2e7d32}}
    .bad{{background:#fdecea;padding:1rem;border-left:4px solid #c62828}}
    </style></head><body><h1>{escape(title)}</h1>
    <nav><a href='/'>Home</a><a href='/vulnerable-settings'>Vulnerable settings</a><a href='/safe-settings'>Safe settings</a><a href='/attacker-page'>Attacker page</a></nav>{body}</body></html>"""


class CsrfLabHandler(BaseHTTPRequestHandler):
    def send_html(self, content, status=200, cookies=None):
        data = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if cookies:
            for name, value in cookies.items():
                self.send_header("Set-Cookie", f"{name}={value}; Path=/; SameSite=None")
        self.end_headers()
        self.wfile.write(data)

    def get_session(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        session_id = cookie["session_id"].value if "session_id" in cookie else None
        if session_id and session_id in SESSIONS:
            return session_id, None
        session_id = new_session()
        return session_id, {"session_id": session_id}

    def read_form_body(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        return parse_qs(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/":
            self.home()
        elif parsed.path == "/vulnerable-settings":
            self.settings_page(vulnerable=True)
        elif parsed.path == "/safe-settings":
            self.settings_page(vulnerable=False)
        elif parsed.path == "/attacker-page":
            self.attacker_page(params)
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    def do_POST(self):
        if self.path == "/vulnerable-settings":
            self.handle_settings(vulnerable=True)
        elif self.path == "/safe-settings":
            self.handle_settings(vulnerable=False)
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    def home(self):
        session_id, new_cookie = self.get_session()
        self.send_html(page("CSRF training lab", """
          <p class='warning'><strong>Local training only.</strong> This application is intentionally insecure in one of its two settings pages and binds to <code>127.0.0.1</code>. Do not deploy it.</p>
          <p>Both pages let you change the account's email address, mimicking a common account-settings form. Compare a version protected only by a session cookie against one that also requires a CSRF token. The attacker page simulates a malicious site that auto-submits a forged request.</p>
          <ul><li><a href='/vulnerable-settings'>Cookie-only settings exercise</a></li><li><a href='/safe-settings'>CSRF-token-protected comparison</a></li><li><a href='/attacker-page'>Simulated attacker page</a></li></ul>"""), cookies=new_cookie)

    def settings_page(self, vulnerable):
        session_id, new_cookie = self.get_session()
        session = SESSIONS[session_id]
        if vulnerable:
            note = "<p class='warning'>Deliberately vulnerable: the form is protected only by the session cookie. Any site the browser sends this cookie to can trigger this POST.</p>"
            token_field = ""
            action = "/vulnerable-settings"
            title = "Vulnerable settings"
        else:
            note = "<p class='ok'>Protected: the form embeds a per-session CSRF token that must be echoed back exactly on submission.</p>"
            token_field = f"<input type='hidden' name='csrf_token' value='{escape(session['csrf_token'])}'>"
            action = "/safe-settings"
            title = "Safe settings"
        form = f"""<p>Current email: <strong>{escape(session['email'])}</strong></p>
        <form method='post' action='{action}'>{token_field}
        <label>New email <input name='email' type='email' value=''></label><button>Update email</button></form>"""
        self.send_html(page(title, note + form), cookies=new_cookie)

    def handle_settings(self, vulnerable):
        session_id, new_cookie = self.get_session()
        session = SESSIONS[session_id]
        fields = self.read_form_body()
        new_email = fields.get("email", [""])[0]
        submitted_token = fields.get("csrf_token", [""])[0]

        if vulnerable:
            session["email"] = new_email or session["email"]
            result = f"<div class='ok'><p>Email updated to <strong>{escape(session['email'])}</strong>.</p><p>No CSRF token was required or checked.</p></div>"
        else:
            if not submitted_token or not secrets.compare_digest(submitted_token, session["csrf_token"]):
                result = f"<div class='bad'><p>Rejected: missing or incorrect CSRF token.</p><p>Submitted token: <code>{escape(submitted_token or '(none)')}</code></p><p>Email was <strong>not</strong> changed; it remains <strong>{escape(session['email'])}</strong>.</p></div>"
                self.send_html(page("Safe settings", result + f"<p><a href='/safe-settings'>Back to safe settings</a></p>"), status=403, cookies=new_cookie)
                return
            session["email"] = new_email or session["email"]
            result = f"<div class='ok'><p>Email updated to <strong>{escape(session['email'])}</strong>.</p><p>The submitted CSRF token matched the session's token.</p></div>"

        title = "Vulnerable settings" if vulnerable else "Safe settings"
        self.send_html(page(title, result + f"<p><a href='/{'vulnerable-settings' if vulnerable else 'safe-settings'}'>Back</a></p>"), cookies=new_cookie)

    def attacker_page(self, params):
        target = params.get("target", ["/vulnerable-settings"])[0]
        if target not in ("/vulnerable-settings", "/safe-settings"):
            target = "/vulnerable-settings"
        body = f"""<p class='bad'>This page simulates a malicious third-party site. Its hidden form auto-submits itself to
        <code>http://{HOST}:{PORT}{escape(target)}</code> as soon as the page loads, using whatever session cookie your browser already holds for this lab
        (the browser attaches cookies for a domain automatically, regardless of which site the request came from). No click is required in a real attack;
        the button below exists only so this lab's screenshot can show the forged form before and after it fires.</p>
        <p>Forged request targets: <code>{escape(target)}</code> —
        <a href='/attacker-page?target=/vulnerable-settings'>target vulnerable</a> |
        <a href='/attacker-page?target=/safe-settings'>target safe</a></p>
        <form method='post' action='{escape(target)}'>
          <input type='hidden' name='email' value='attacker@evil.example'>
          <button type='submit'>Simulate visiting the malicious page (submits the forged form)</button>
        </form>"""
        self.send_html(page("Simulated attacker page", body))

    def log_message(self, format, *args):
        return  # keep the training output tidy


if __name__ == "__main__":
    print(f"CSRF lab: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), CsrfLabHandler).serve_forever()

"""OS command injection training lab.

Run only on your own machine for coursework.  The server is intentionally
bound to 127.0.0.1.  It hosts a small "network diagnostics" CLI-in-a-browser
feature in two versions:

  /vulnerable-ping  -- builds a shell command by concatenating raw user
                       input, then runs it with shell=True.
  /safe-ping        -- validates the input against a strict allow-list
                       pattern and calls the ping binary directly as an
                       argument list, with shell=True never used at all.
"""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import platform
import re
import subprocess

HOST, PORT = "127.0.0.1", 8082

# Only dotted IPv4 addresses or simple hostnames are ever legitimate input
# for a ping tool. Anything else is rejected outright by the safe endpoint.
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,63})[A-Za-z0-9]$|^[A-Za-z0-9]$")

COUNT_FLAG = "-n" if platform.system() == "Windows" else "-c"


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
    <nav><a href='/'>Home</a><a href='/vulnerable-ping'>Vulnerable ping</a><a href='/safe-ping'>Safe ping</a></nav>{body}</body></html>"""


class CommandLabHandler(BaseHTTPRequestHandler):
    def send_html(self, content, status=200):
        data = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/":
            self.home()
        elif parsed.path == "/vulnerable-ping":
            self.vulnerable_ping(params)
        elif parsed.path == "/safe-ping":
            self.safe_ping(params)
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    def home(self):
        self.send_html(page("Command injection training lab", """
          <p class='warning'><strong>Local training only.</strong> This application is intentionally insecure in one of its two ping features and binds to <code>127.0.0.1</code>. Do not deploy it.</p>
          <p>Both pages offer a "ping this host" diagnostic, mimicking a common CLI-in-a-web-app pattern. Compare a version that builds a shell command from raw input against one that validates input and never invokes a shell.</p>
          <ul><li><a href='/vulnerable-ping'>Unsafe shell concatenation exercise</a></li><li><a href='/safe-ping'>Allow-list + argument-list comparison</a></li></ul>"""))

    def vulnerable_ping(self, params):
        host = params.get("host", [""])[0]
        result = ""
        if "host" in params:
            command = f"ping {COUNT_FLAG} 1 {host}"
            try:
                completed = subprocess.run(
                    command, shell=True, capture_output=True, text=True, timeout=8
                )
                output = completed.stdout + completed.stderr
            except subprocess.TimeoutExpired:
                output = "(command timed out)"
            result = (f"<p>Executed shell command:</p><pre>{escape(command)}</pre>"
                      f"<p>Output:</p><pre>{escape(output)}</pre>")
        form = """<p class='warning'>Deliberately vulnerable: the host field is concatenated straight into a shell command string run with <code>shell=True</code>. Try <code>127.0.0.1 &amp;&amp; whoami</code> or <code>127.0.0.1 &amp;&amp; dir</code>.</p>
        <form><label>Host to ping <input name='host' value='{h}'></label><button>Ping</button></form>""".format(h=escape(host))
        self.send_html(page("Vulnerable ping", form + result))

    def safe_ping(self, params):
        host = params.get("host", [""])[0]
        result = ""
        if "host" in params:
            if not HOSTNAME_PATTERN.match(host):
                result = f"<p class='bad'>Rejected: <code>{escape(host)}</code> is not a valid hostname or IPv4 address (allow-list: letters, digits, dots, hyphens only).</p>"
            else:
                command = ["ping", COUNT_FLAG, "1", host]
                try:
                    completed = subprocess.run(
                        command, shell=False, capture_output=True, text=True, timeout=8
                    )
                    output = completed.stdout + completed.stderr
                except (subprocess.TimeoutExpired, OSError) as error:
                    output = f"(error: {error})"
                result = (f"<p class='ok'>Executed as an argument list (no shell involved):</p><pre>{escape(repr(command))}</pre>"
                          f"<p>Output:</p><pre>{escape(output)}</pre>")
        note = "<p class='ok'>Validated: the host must match a strict hostname/IPv4 pattern before it is used, and the ping binary is invoked directly as an argument list with <code>shell=False</code> — there is no shell to inject into.</p>"
        form = "<form><label>Host to ping <input name='host' value='{h}'></label><button>Ping</button></form>".format(h=escape(host))
        self.send_html(page("Safe ping", note + form + result))

    def log_message(self, format, *args):
        return  # keep the training output tidy


if __name__ == "__main__":
    print(f"Command injection lab: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), CommandLabHandler).serve_forever()

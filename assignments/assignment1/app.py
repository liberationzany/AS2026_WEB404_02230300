"""Deliberately vulnerable SQL injection training lab.

Run only on your own machine for coursework.  The server is intentionally
bound to 127.0.0.1 and uses a disposable SQLite database.
"""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import sqlite3

HOST, PORT = "127.0.0.1", 8080
DATABASE = Path(__file__).with_name("training_lab.db")


def reset_database():
    """Create a small fictional data set each time the app starts."""
    with sqlite3.connect(DATABASE) as connection:
        connection.executescript("""
            DROP TABLE IF EXISTS users;
            CREATE TABLE users (
              id INTEGER PRIMARY KEY,
              username TEXT NOT NULL UNIQUE,
              password TEXT NOT NULL,
              role TEXT NOT NULL
            );
            INSERT INTO users (username, password, role) VALUES
              ('alice', 'orchid-47', 'student'),
              ('bob', 'maple-92', 'student'),
              ('instructor', 'demo-only-secret', 'instructor');
        """)


def page(title, body):
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
    <meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>{escape(title)}</title><style>
    body{{font-family:system-ui;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
    nav a{{margin-right:1rem}} input{{padding:.45rem;margin:.2rem}} button{{padding:.45rem .7rem}}
    code,pre{{background:#f2f2f2;padding:.2rem .35rem}} pre{{overflow:auto;padding:1rem}}
    .warning{{background:#fff3cd;padding:1rem;border-left:4px solid #d39e00}}
    </style></head><body><h1>{escape(title)}</h1>
    <nav><a href='/'>Home</a><a href='/login'>Vulnerable login</a><a href='/search'>Vulnerable search</a><a href='/blind-check'>Blind check</a><a href='/safe-search'>Safe search</a></nav>{body}</body></html>"""


class LabHandler(BaseHTTPRequestHandler):
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
            self.send_html(page("SQL injection training lab", """
              <p class='warning'><strong>Local training only.</strong> This application is intentionally insecure and binds to <code>127.0.0.1</code>. Do not deploy it.</p>
              <p>Use the vulnerable pages to observe unsafe string-concatenated SQL, then compare the safe search page.</p>
              <ul><li><a href='/login'>Authentication-bypass exercise</a></li><li><a href='/search'>Search / UNION exercise</a></li><li><a href='/blind-check'>Boolean-blind exercise</a></li><li><a href='/safe-search'>Parameterized comparison</a></li></ul>"""))
        elif parsed.path == "/login":
            self.login(params)
        elif parsed.path == "/search":
            self.search(params, safe=False)
        elif parsed.path == "/blind-check":
            self.blind_check(params)
        elif parsed.path == "/safe-search":
            self.search(params, safe=True)
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    def login(self, params):
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        result = ""
        if "username" in params:
            query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                with sqlite3.connect(DATABASE) as connection:
                    row = connection.execute(query).fetchone()
                result = f"<p>{'Logged in as <strong>' + escape(row[1]) + '</strong> (' + escape(row[2]) + ')' if row else 'Login failed.'}</p>"
            except sqlite3.Error as error:
                result = f"<p>Database error: <code>{escape(str(error))}</code></p>"
            result += f"<p>Executed query:</p><pre>{escape(query)}</pre>"
        form = """<p class='warning'>Deliberately vulnerable: user input is concatenated into SQL.</p>
        <form><label>Username <input name='username' value='{u}'></label><br>
        <label>Password <input name='password' type='text' value='{p}'></label><br><button>Log in</button></form>""".format(u=escape(username), p=escape(password))
        self.send_html(page("Vulnerable login", form + result))

    def blind_check(self, params):
        username = params.get("username", [""])[0]
        result = ""
        if "username" in params:
            query = f"SELECT 1 FROM users WHERE username = '{username}'"
            try:
                with sqlite3.connect(DATABASE) as connection:
                    found = connection.execute(query).fetchone() is not None
                # Intentionally limited feedback: no records or database errors are shown.
                result = "<p><strong>Account exists.</strong></p>" if found else "<p><strong>No matching account.</strong></p>"
            except sqlite3.Error:
                result = "<p><strong>No matching account.</strong></p>"
        form = """<p class='warning'>Deliberately vulnerable Boolean-blind check: it only reveals whether the query produced a result.</p>
        <form><label>Username <input name='username' value='{u}'></label><button>Check</button></form>""".format(u=escape(username))
        self.send_html(page("Vulnerable blind check", form + result))

    def search(self, params, safe):
        term = params.get("q", [""])[0]
        result = ""
        if "q" in params:
            try:
                with sqlite3.connect(DATABASE) as connection:
                    if safe:
                        query = "SELECT id, username, role FROM users WHERE username LIKE ?"
                        rows = connection.execute(query, (f"%{term}%",)).fetchall()
                        display_query = query + "\nparameters: " + repr((f"%{term}%",))
                    else:
                        query = f"SELECT id, username, role FROM users WHERE username LIKE '%{term}%'"
                        rows = connection.execute(query).fetchall()
                        display_query = query
                items = "".join(f"<li>{row[0]} — {escape(row[1])} — {escape(row[2])}</li>" for row in rows) or "<li>No results</li>"
                result = f"<p>Results:</p><ul>{items}</ul><p>Executed query:</p><pre>{escape(display_query)}</pre>"
            except sqlite3.Error as error:
                result = f"<p>Database error: <code>{escape(str(error))}</code></p><pre>{escape(query)}</pre>"
        title = "Safe search" if safe else "Vulnerable search"
        note = "This version uses a parameterized query." if safe else "Deliberately vulnerable: the search term is concatenated into SQL."
        form = f"<p class='warning'>{note}</p><form><label>Username contains <input name='q' value='{escape(term)}'></label><button>Search</button></form>"
        self.send_html(page(title, form + result))

    def log_message(self, format, *args):
        return  # keep the training output tidy


if __name__ == "__main__":
    reset_database()
    print(f"Training lab: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop. Database resets on each start.")
    ThreadingHTTPServer((HOST, PORT), LabHandler).serve_forever()

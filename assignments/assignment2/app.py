"""File upload security training lab.

Run only on your own machine for coursework.  The server is intentionally
bound to 127.0.0.1.  It hosts two comparable upload features:

  /vulnerable-upload  -- accepts any file, any content, original filename.
  /safe-upload        -- extension allow-list, magic-byte content sniffing,
                          size limit, random storage filenames, and safe
                          response headers.

A "sandbox guard" (clearly labelled below) stops the vulnerable endpoint
from ever writing outside its own uploads/vulnerable folder.  That guard is
an environment safety net for this lab machine -- it is NOT part of the
vulnerable feature's own logic, and the page still tells you when it fired
so the underlying path-traversal weakness is visible.
"""
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote
import mimetypes
import re
import secrets

HOST, PORT = "127.0.0.1", 8081
ROOT = Path(__file__).parent
VULN_DIR = (ROOT / "uploads" / "vulnerable").resolve()
SAFE_DIR = (ROOT / "uploads" / "safe").resolve()
VULN_DIR.mkdir(parents=True, exist_ok=True)
SAFE_DIR.mkdir(parents=True, exist_ok=True)

HARD_CAP = 15 * 1024 * 1024       # lab-machine safety net for both endpoints
SAFE_UPLOAD_LIMIT = 2 * 1024 * 1024  # the /safe-upload feature's own rule

# extension -> (mime type, magic bytes to require, how to serve it)
ALLOWED_TYPES = {
    ".png": ("image/png", (b"\x89PNG\r\n\x1a\n",), "inline"),
    ".jpg": ("image/jpeg", (b"\xff\xd8\xff",), "inline"),
    ".jpeg": ("image/jpeg", (b"\xff\xd8\xff",), "inline"),
    ".gif": ("image/gif", (b"GIF87a", b"GIF89a"), "inline"),
    ".pdf": ("application/pdf", (b"%PDF-",), "attachment"),
    ".txt": ("text/plain; charset=utf-8", None, "attachment"),
}
SCRIPT_MARKERS = ("<script", "<?php", "<%", "javascript:")
BINARY_SIGNATURES = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"%PDF-", b"MZ")


def page(title, body):
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
    <meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>{escape(title)}</title><style>
    body{{font-family:system-ui;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.5}}
    nav a{{margin-right:1rem}} input{{padding:.45rem;margin:.2rem}} button{{padding:.45rem .7rem}}
    code,pre{{background:#f2f2f2;padding:.2rem .35rem}} pre{{overflow:auto;padding:1rem}}
    .warning{{background:#fff3cd;padding:1rem;border-left:4px solid #d39e00}}
    .ok{{background:#e6f6e6;padding:1rem;border-left:4px solid #2e7d32}}
    .bad{{background:#fdecea;padding:1rem;border-left:4px solid #c62828}}
    ul.files li{{margin:.25rem 0}}
    </style></head><body><h1>{escape(title)}</h1>
    <nav><a href='/'>Home</a><a href='/vulnerable-upload'>Vulnerable upload</a><a href='/safe-upload'>Safe upload</a></nav>{body}</body></html>"""


def list_files(directory, url_prefix):
    names = sorted(p.relative_to(directory).as_posix() for p in directory.rglob("*") if p.is_file())
    if not names:
        return "<p><em>No files uploaded yet.</em></p>"
    items = "".join(
        f"<li><a href='{url_prefix}/{quote(name)}'>{escape(name)}</a></li>" for name in names
    )
    return f"<ul class='files'>{items}</ul>"


def parse_multipart(body: bytes, boundary: bytes):
    """Minimal multipart/form-data parser: returns list of (headers, content)."""
    marker = b"--" + boundary
    raw_parts = body.split(marker)
    parts = []
    for raw in raw_parts[1:-1]:
        if raw.startswith(b"\r\n"):
            raw = raw[2:]
        elif raw.startswith(b"\n"):
            raw = raw[1:]
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        header_blob, sep, content = raw.partition(b"\r\n\r\n")
        if not sep:
            continue
        headers = {}
        for line in header_blob.split(b"\r\n"):
            if b":" in line:
                key, value = line.split(b":", 1)
                headers[key.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
        parts.append((headers, content))
    return parts


def field(parts, name):
    for headers, content in parts:
        disp = headers.get("content-disposition", "")
        if re.search(rf'name="{re.escape(name)}"', disp):
            filename_match = re.search(r'filename="([^"]*)"', disp)
            filename = filename_match.group(1) if filename_match else None
            return filename, content
    return None, None


class UploadLabHandler(BaseHTTPRequestHandler):
    def send_html(self, content, status=200):
        data = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, path: Path, mime: str, disposition: str, name: str, extra_headers=None):
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'{disposition}; filename="{name}"')
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    # ---- routing -----------------------------------------------------
    def do_GET(self):
        if self.path == "/":
            self.home()
        elif self.path == "/vulnerable-upload":
            self.send_html(self.upload_page(vulnerable=True))
        elif self.path == "/safe-upload":
            self.send_html(self.upload_page(vulnerable=False))
        elif self.path.startswith("/uploads-vulnerable/"):
            self.serve_vulnerable(self.path[len("/uploads-vulnerable/"):])
        elif self.path.startswith("/uploads-safe/"):
            self.serve_safe(self.path[len("/uploads-safe/"):])
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    def do_POST(self):
        if self.path == "/vulnerable-upload":
            self.handle_vulnerable_upload()
        elif self.path == "/safe-upload":
            self.handle_safe_upload()
        else:
            self.send_html(page("Not found", "<p>That page does not exist.</p>"), 404)

    # ---- pages ---------------------------------------------------------
    def home(self):
        self.send_html(page("File upload security lab", """
          <p class='warning'><strong>Local training only.</strong> This application is intentionally insecure in one of its two upload features and binds to <code>127.0.0.1</code>. Do not deploy it.</p>
          <p>Compare an upload feature with no validation against one that enforces an extension allow-list, magic-byte content sniffing, a size limit, and random storage filenames.</p>
          <ul><li><a href='/vulnerable-upload'>Unrestricted upload exercise</a></li><li><a href='/safe-upload'>Validated upload comparison</a></li></ul>"""))

    def upload_page(self, vulnerable):
        if vulnerable:
            note = "<p class='warning'>Deliberately vulnerable: no extension check, no content check, no size limit, and the file is stored under its original name. A lab-only sandbox guard (not a security feature) stops writes from leaving this folder so testing stays safe.</p>"
            listing = list_files(VULN_DIR, "/uploads-vulnerable")
            action = "/vulnerable-upload"
            title = "Vulnerable upload"
        else:
            note = (f"<p class='ok'>Validated: only {', '.join(sorted(ALLOWED_TYPES))} are accepted, file content must match its extension's "
                    f"magic bytes, files must be {SAFE_UPLOAD_LIMIT // (1024*1024)} MB or smaller, and stored files get a random name.</p>")
            listing = list_files(SAFE_DIR, "/uploads-safe")
            action = "/safe-upload"
            title = "Safe upload"
        form = f"""<form method='post' action='{action}' enctype='multipart/form-data'>
        <input type='file' name='file'><button>Upload</button></form>"""
        return page(title, note + form + "<h2>Uploaded files</h2>" + listing)

    # ---- upload handling -------------------------------------------------
    def read_multipart_body(self):
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            return None, "Expected a multipart/form-data upload."
        match = re.search(r"boundary=(.+)$", ctype)
        if not match:
            return None, "Missing multipart boundary."
        boundary = match.group(1).strip('"').encode()
        length = int(self.headers.get("Content-Length", 0))
        if length > HARD_CAP:
            self.rfile.read(0)  # do not attempt to read an oversized body
            return None, "TOO_LARGE"
        body = self.rfile.read(length)
        return parse_multipart(body, boundary), None

    def handle_vulnerable_upload(self):
        parts, error = self.read_multipart_body()
        if error == "TOO_LARGE":
            self.send_html(page("Vulnerable upload", "<p class='bad'>Rejected by the lab-machine hard cap (15 MB) -- unrelated to the vulnerable feature's own logic, which has no size limit at all.</p>"), 413)
            return
        if error:
            self.send_html(page("Vulnerable upload", f"<p class='bad'>{escape(error)}</p>"), 400)
            return
        original_name, content = field(parts, "file")
        if not original_name:
            self.send_html(self.upload_page(vulnerable=True) + "<p class='bad'>No file selected.</p>")
            return

        candidate = (VULN_DIR / Path(original_name)).resolve()
        sandbox_root = VULN_DIR
        if candidate != sandbox_root and sandbox_root not in candidate.parents:
            result = (f"<div class='bad'><p><strong>Blocked by the lab safety net</strong>, not by the vulnerable feature itself.</p>"
                      f"<p>Filename <code>{escape(original_name)}</code> resolved to <code>{escape(str(candidate))}</code>, "
                      f"outside <code>{escape(str(sandbox_root))}</code>.</p>"
                      f"<p>Without this outer guard, that path would have been written directly -- a directory traversal vulnerability caused by using an unvalidated filename to build a filesystem path.</p></div>")
        else:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_bytes(content)
            rel = candidate.relative_to(VULN_DIR).as_posix()
            result = (f"<div class='ok'><p>Stored as <code>{escape(rel)}</code> with no validation of type or content.</p>"
                      f"<p><a href='/uploads-vulnerable/{quote(rel)}'>View the uploaded file</a> (served with the browser-guessed content type -- an uploaded <code>.html</code> file will execute as a page).</p></div>")
        self.send_html(self.upload_page(vulnerable=True) + result)

    def handle_safe_upload(self):
        parts, error = self.read_multipart_body()
        if error == "TOO_LARGE":
            self.send_html(page("Safe upload", "<p class='bad'>Rejected: request exceeded the lab-machine hard cap.</p>"), 413)
            return
        if error:
            self.send_html(page("Safe upload", f"<p class='bad'>{escape(error)}</p>"), 400)
            return
        original_name, content = field(parts, "file")
        if not original_name:
            self.send_html(self.upload_page(vulnerable=False) + "<p class='bad'>No file selected.</p>")
            return

        ok, message = self.validate_safe_upload(original_name, content)
        if not ok:
            self.send_html(self.upload_page(vulnerable=False) + f"<p class='bad'>Rejected: {escape(message)}</p>", 400)
            return

        ext = Path(original_name).suffix.lower()
        safe_name = secrets.token_hex(8) + ext
        (SAFE_DIR / safe_name).write_bytes(content)
        result = (f"<div class='ok'><p>Accepted. Original name <code>{escape(original_name)}</code> was discarded; "
                  f"stored as <code>{escape(safe_name)}</code>.</p>"
                  f"<p><a href='/uploads-safe/{quote(safe_name)}'>View the uploaded file</a> (served with a validated content type, "
                  f"<code>X-Content-Type-Options: nosniff</code>, and a forced-download disposition for non-image types).</p></div>")
        self.send_html(self.upload_page(vulnerable=False) + result)

    def validate_safe_upload(self, original_name, content):
        ext = Path(original_name).suffix.lower()
        if ext not in ALLOWED_TYPES:
            return False, f"file type '{ext or '(none)'}' is not on the allow-list."
        if len(content) > SAFE_UPLOAD_LIMIT:
            return False, f"file exceeds the {SAFE_UPLOAD_LIMIT // (1024*1024)} MB limit."
        if len(content) == 0:
            return False, "file is empty."
        mime, magic_options, _ = ALLOWED_TYPES[ext]
        if magic_options and not any(content.startswith(sig) for sig in magic_options):
            return False, "file content does not match its extension (possible spoofed file type)."
        if ext == ".txt":
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                return False, "text file is not valid UTF-8."
            if any(sig in content[:16] for sig in BINARY_SIGNATURES):
                return False, "text file content matches a binary file signature."
            lowered = text.lower()
            if any(marker in lowered for marker in SCRIPT_MARKERS):
                return False, "text file contains disallowed script markers."
        return True, ""

    # ---- serving stored files -------------------------------------------
    def serve_vulnerable(self, encoded_name):
        name = unquote(encoded_name)
        candidate = (VULN_DIR / Path(name)).resolve()
        if candidate != VULN_DIR and VULN_DIR not in candidate.parents:
            self.send_html(page("Blocked", "<p class='bad'>Blocked by the lab safety net (outside the sandbox).</p>"), 403)
            return
        if not candidate.is_file():
            self.send_html(page("Not found", "<p>No such file.</p>"), 404)
            return
        ext = candidate.suffix.lower()
        if ext in (".html", ".htm"):
            mime = "text/html"
        elif ext == ".svg":
            mime = "image/svg+xml"
        else:
            mime = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_file(candidate, mime, "inline", candidate.name)

    def serve_safe(self, encoded_name):
        name = unquote(encoded_name)
        if "/" in name or "\\" in name:
            self.send_html(page("Not found", "<p>No such file.</p>"), 404)
            return
        candidate = SAFE_DIR / name
        if not candidate.is_file():
            self.send_html(page("Not found", "<p>No such file.</p>"), 404)
            return
        ext = candidate.suffix.lower()
        mime, _, disposition = ALLOWED_TYPES.get(ext, ("application/octet-stream", None, "attachment"))
        self.send_file(candidate, mime, disposition, candidate.name, extra_headers={"X-Content-Type-Options": "nosniff"})

    def log_message(self, format, *args):
        return  # keep the training output tidy


if __name__ == "__main__":
    print(f"Upload lab: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    ThreadingHTTPServer((HOST, PORT), UploadLabHandler).serve_forever()

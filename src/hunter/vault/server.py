"""PracticeVault — a deliberately vulnerable local practice target.

Stdlib-only (``http.server``), in-memory state, deterministic responses, and
EXACTLY nine planted, documented vulnerabilities (see ``answer_key.json`` in
this package). It exists so the harness has something to find on day one and
so demos work without ever touching a real target.

NEVER bind this server to a public interface — it is vulnerable by design.
``start_server(host="127.0.0.1", port=0)`` keeps it on loopback by default.

Planted vulnerabilities (dedupe keys):
1. missing-headers|GET|/|-            every response lacks CSP/XFO/XCTO
2. dir-listing|GET|/static/|-         HTML directory listing with <a href> links
3. reflected-xss|GET|/search|q        q echoed RAW into HTML (no escaping)
4. sql-error|POST|/login|username     username containing ' -> 500 + SQLite syntax error
5. path-traversal|GET|/download|file  file=../../secret.txt -> fake passwd content
6. open-redirect|GET|/goto|url        302 with Location == url param (external allowed)
7. unauth-action|POST|/transfer|-     POST returns "Transfer complete" with no auth
8. auth-bypass|GET|/admin|cookie.role 403 bare; 200 with plaintext Cookie: role=admin
9. sensitive-file|GET|/backup/users.sql|-  200 text with username,md5hash rows
"""

from __future__ import annotations

import posixpath
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ADMIN_USER = "admin"
ADMIN_PASSWORD = "admin123"

# In-memory "filesystem" -----------------------------------------------------

FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "vault:x:1000:1000:PracticeVault:/home/vault:/bin/sh\n"
)

DOWNLOADS = {
    "readme.txt": "PracticeVault download area.\nNothing sensitive in this file.\n",
    "changelog.txt": "v1.0 - initial release.\n",
}

# Files "outside" the downloads root; only reachable via path traversal.
SECRET_FILES = {
    "secret.txt": FAKE_PASSWD,
}

STATIC_FILES = {
    "style.css": "body { font-family: sans-serif; margin: 2rem; }\n",
    "app.js": "console.log('PracticeVault');\n",
}

USERS_SQL = (
    "username,md5hash\n"
    "admin,21232f297a57a5a743894a0e4a801fc3\n"
    "alice,6384e2b2184bcbf58eccf10ca7a6563c\n"
    "bob,9f9d51bc70ef21ca5c14f307980a29d8\n"
)

# Static page bodies ----------------------------------------------------------

HOME_HTML = """<!DOCTYPE html>
<html>
<head><title>PracticeVault</title></head>
<body>
<h1>PracticeVault</h1>
<p>A deliberately vulnerable practice target. Your mission: find the planted issues.</p>
<ul>
<li><a href="/search?q=hunter">Search products</a></li>
<li><a href="/login">Login</a></li>
<li><a href="/download?file=readme.txt">Downloads</a></li>
<li><a href="/goto">Redirect service</a></li>
<li><a href="/transfer">Transfer funds</a></li>
<li><a href="/admin">Admin panel</a></li>
<li><a href="/static/">Static assets</a></li>
<li><a href="/backup/users.sql">User export (backup)</a></li>
</ul>
</body>
</html>
"""

LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html>
<head><title>PracticeVault - Login</title></head>
<body>
<h1>Login</h1>
<form method="post" action="/login">
<label>Username <input type="text" name="username"></label>
<label>Password <input type="password" name="password"></label>
<button type="submit">Sign in</button>
</form>
</body>
</html>
"""

TRANSFER_PAGE_HTML = """<!DOCTYPE html>
<html>
<head><title>PracticeVault - Transfer</title></head>
<body>
<h1>Transfer funds</h1>
<form method="post" action="/transfer">
<label>From account <input type="text" name="from"></label>
<label>To account <input type="text" name="to"></label>
<label>Amount <input type="text" name="amount"></label>
<button type="submit">Send</button>
</form>
</body>
</html>
"""

ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html>
<head><title>PracticeVault - Admin</title></head>
<body>
<h1>Admin panel</h1>
<p>Logged in via plaintext cookie: role=admin</p>
<table>
<tr><th>username</th><th>role</th></tr>
<tr><td>admin</td><td>admin</td></tr>
<tr><td>alice</td><td>user</td></tr>
<tr><td>bob</td><td>user</td></tr>
</table>
</body>
</html>
"""


def _render_dir_listing(path: str, names: list[str]) -> str:
    items = "".join(f'<li><a href="{name}">{name}</a></li>' for name in sorted(names))
    return (
        "<!DOCTYPE html>\n"
        f"<html>\n<head><title>Directory listing for {path}</title></head>\n"
        f"<body>\n<h1>Directory listing for {path}</h1>\n<hr>\n<ul>\n{items}\n</ul>\n"
        "<hr>\n</body>\n</html>\n"
    )


class _VaultHandler(BaseHTTPRequestHandler):
    """Request handler with the nine planted vulnerabilities.

    Deliberately HTTP/1.0 (one connection per request): keep-alive plus
    ThreadingHTTPServer has an idle-connection race that can surface as a
    transient client error, and this vault's contract is deterministic
    responses.
    """

    server_version = "PracticeVault/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        pass  # keep test output clean; the vault never logs

    # -- plumbing ---------------------------------------------------------------

    def _send(
        self,
        status: int,
        body: str,
        content_type: str = "text/html; charset=utf-8",
        extra: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _cookie(self, name: str) -> str | None:
        header = self.headers.get("Cookie", "")
        for part in header.split(";"):
            key, sep, value = part.strip().partition("=")
            if sep and key == name:
                return value
        return None

    # -- GET routes ---------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            self._send(200, HOME_HTML)
        elif path == "/search":
            query = (qs.get("q") or [""])[0]
            if query:
                # RAW echo, no HTML escaping — planted reflected XSS.
                self._send(200, f"<h1>Search results</h1><p>Results for: {query}</p>")
            else:
                self._send(200, "<h1>Search</h1><p>Provide a query: /search?q=term</p>")
        elif path == "/login":
            self._send(200, LOGIN_PAGE_HTML)
        elif path == "/download":
            self._download(qs)
        elif path == "/goto":
            target = (qs.get("url") or [""])[0]
            if target:
                # Planted open redirect: Location echoes the url param verbatim.
                self._send(302, "", extra={"Location": target})
            else:
                self._send(200, "<h1>Redirect service</h1><p>Usage: /goto?url=https://example.com</p>")
        elif path == "/transfer":
            self._send(200, TRANSFER_PAGE_HTML)
        elif path == "/admin":
            if self._cookie("role") == "admin":
                self._send(200, ADMIN_PANEL_HTML)
            else:
                self._send(403, "<h1>403 Forbidden</h1><p>Admin access required.</p>")
        elif path in ("/static", "/static/"):
            self._send(200, _render_dir_listing("/static/", list(STATIC_FILES)))
        elif path.startswith("/static/"):
            name = path[len("/static/"):]
            content = STATIC_FILES.get(name)
            if content is None:
                self._send(404, "<h1>404 Not Found</h1>")
            else:
                mime = (
                    "text/css; charset=utf-8" if name.endswith(".css") else "text/javascript; charset=utf-8"
                )
                self._send(200, content, content_type=mime)
        elif path == "/backup/users.sql":
            self._send(200, USERS_SQL, content_type="text/plain; charset=utf-8")
        else:
            self._send(404, "<h1>404 Not Found</h1>")

    def _download(self, qs: dict[str, list[str]]) -> None:
        """Naive join simulation: normpath the requested name against the
        downloads root. Anything that climbs out with ``..`` falls through to
        the "outside" in-memory files (planted path traversal)."""
        requested = (qs.get("file") or [""])[0]
        if not requested:
            items = "".join(
                f'<li><a href="/download?file={name}">{name}</a></li>' for name in sorted(DOWNLOADS)
            )
            self._send(200, f"<h1>Downloads</h1><ul>{items}</ul>")
            return
        resolved = posixpath.normpath(requested)
        if resolved.startswith(".."):
            content = SECRET_FILES.get(posixpath.basename(resolved))
            if content is None:
                self._send(404, "<h1>404 Not Found</h1>")
            else:
                self._send(200, content, content_type="text/plain; charset=utf-8")
        elif resolved in DOWNLOADS:
            self._send(200, DOWNLOADS[resolved], content_type="text/plain; charset=utf-8")
        else:
            self._send(404, "<h1>404 Not Found</h1>")

    # -- POST routes ---------------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        form = parse_qs(raw)

        if parsed.path == "/login":
            username = (form.get("username") or [""])[0]
            password = (form.get("password") or [""])[0]
            if "'" in username:
                # Planted SQL error disclosure: raw SQLite exception text.
                body = (
                    "<h1>500 - SQLite error</h1>"
                    f"<pre>sqlite3.OperationalError: near \"{username}\": syntax error</pre>"
                )
                self._send(500, body)
            elif username == ADMIN_USER and password == ADMIN_PASSWORD:
                # Session cookie is plaintext and lacks HttpOnly/Secure on purpose.
                self._send(
                    200,
                    "<h1>Login successful</h1><p>Welcome, admin.</p>",
                    extra={"Set-Cookie": "role=user; Path=/"},
                )
            else:
                self._send(401, "<h1>401 Unauthorized</h1><p>Invalid credentials.</p>")
        elif parsed.path == "/transfer":
            # Planted missing authorization: no session/role check at all.
            source = (form.get("from") or ["?"])[0]
            destination = (form.get("to") or ["?"])[0]
            amount = (form.get("amount") or ["?"])[0]
            self._send(
                200,
                f"<h1>Transfer complete</h1><p>Sent {amount} from account "
                f"{source} to account {destination}.</p>",
            )
        else:
            self._send(404, "<h1>404 Not Found</h1>")


class _VaultHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        pass  # client disconnects during shutdown are routine; stay quiet


class VaultServer:
    """Handle for a running PracticeVault instance."""

    def __init__(self, server: _VaultHTTPServer, thread: threading.Thread) -> None:
        self._server = server
        self._thread = thread

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def shutdown(self) -> None:
        """Stop the server and release the port. Safe to call once."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def start_server(host: str = "127.0.0.1", port: int = 0) -> tuple[VaultServer, int]:
    """Start PracticeVault on loopback. ``port=0`` picks an ephemeral port.

    Returns ``(VaultServer, port)``. Always call ``handle.shutdown()``
    (tests: use try/finally or a fixture).
    """
    server = _VaultHTTPServer((host, port), _VaultHandler)
    thread = threading.Thread(target=server.serve_forever, name="practicevault", daemon=True)
    thread.start()
    handle = VaultServer(server, thread)
    # Readiness wait: serve_forever balik langsung, di runner sibuk request
    # pertama bisa refused sebelum socket listen. Poll sampai connectable.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((handle.host, handle.port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.02)
    return handle, handle.port

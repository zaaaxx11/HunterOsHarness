"""MITM traffic recorder — captures HTTP requests/responses as sha256 evidence."""
import json, hashlib, threading, time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

__all__ = ["TrafficRecorder"]


class TrafficRecorder:
    """Captures HTTP traffic via proxy — stores as sha256-chained evidence."""

    def __init__(self, ledger: Any, run_id: str, max_body: int = 262144):
        self.ledger = ledger
        self.run_id = run_id
        self.max_body = max_body
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._count = 0

    def start(self, host: str = "127.0.0.1", port: int = 8788) -> str:
        import httpx
        recorder = self

        class _Handler(BaseHTTPRequestHandler):
            def _proxy(self, method):
                target = self.path
                body = b""
                cl = int(self.headers.get("Content-Length", 0))
                if 0 < cl < recorder.max_body:
                    body = self.rfile.read(cl)

                status, rbody, rheaders, err, t0 = 502, b"", {}, None, time.time()
                try:
                    hdrs = {k: v for k, v in self.headers.items()
                            if k.lower() not in ("host", "proxy-connection", "transfer-encoding")}
                    if body:
                        hdrs["Content-Length"] = str(len(body))
                    client = httpx.Client(timeout=30, follow_redirects=False,
                                          headers={"User-Agent": "HunterOsHarness-MITM/0.1"},
                                          trust_env=False)
                    r = client.request(method, target, content=body or None, headers=hdrs)
                    status = r.status_code
                    rbody = r.content[:recorder.max_body]
                    rheaders = dict(r.headers)
                except Exception as e:
                    err = str(e)[:500]
                elapsed = (time.time() - t0) * 1000

                ev = {
                    "method": method, "url": target, "status": status,
                    "request_headers": dict(self.headers),
                    "request_body": body.decode("utf-8", "replace")[:recorder.max_body] if body else "",
                    "response_headers": rheaders,
                    "response_body": rbody.decode("utf-8", "replace")[:recorder.max_body],
                    "elapsed_ms": round(elapsed, 2), "error": err,
                }
                evh = hashlib.sha256(json.dumps(ev, sort_keys=True).encode()).hexdigest()
                try:
                    recorder.ledger.add_evidence(
                        recorder.run_id, "http_exchange",
                        {"sha256": evh, "body": json.dumps(ev)},
                    )
                except Exception:
                    pass
                recorder._count += 1

                self.send_response(status)
                for k, v in rheaders.items():
                    if k.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(rbody)

            do_GET = lambda s: s._proxy("GET")
            do_POST = lambda s: s._proxy("POST")
            do_PUT = lambda s: s._proxy("PUT")
            do_DELETE = lambda s: s._proxy("DELETE")
            do_PATCH = lambda s: s._proxy("PATCH")
            do_HEAD = lambda s: s._proxy("HEAD")

            def log_message(self, format, *args):
                pass

        self._server = HTTPServer((host, port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://{host}:{port}"

    def stop(self) -> int:
        if self._server:
            self._server.shutdown()
        if self._thread:
            self._thread.join(timeout=5)
        return self._count

    @property
    def count(self) -> int:
        return self._count
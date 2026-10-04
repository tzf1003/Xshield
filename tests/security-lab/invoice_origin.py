"""Intentionally vulnerable invoice origin for a second, isolated site.

The detail endpoint authenticates a user but deliberately omits owner checking.
Run only on loopback through the security-lab Compose project.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from urllib.parse import urlsplit

INVOICES = {
    "invoice-100": {"ref": "invoice-100", "owner": "alice", "cents": 1299},
    "invoice-200": {"ref": "invoice-200", "owner": "bob", "cents": 2999},
}
COUNTS = {}
LOCK = Lock()


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = urlsplit(self.path).path
        user = self.headers.get("X-Lab-User", "")
        if path != "/session" or user not in ("alice", "bob"):
            return self.reply(401, {"error": "lab_identity_required"})
        return self.reply(200, {
            "identity": {"id": f"principal_{user}", "authorization_context": f"billing:{user}"},
            "access_token": f"invoice-token-{user}",
        })

    def do_GET(self):
        path = urlsplit(self.path).path
        with LOCK:
            key = f"GET {path}"
            COUNTS[key] = COUNTS.get(key, 0) + 1
        if path == "/health":
            return self.reply(200, {"ok": True})
        if path == "/__lab/metrics":
            with LOCK:
                return self.reply(200, dict(COUNTS))
        bearer = self.headers.get("Authorization", "")
        user = bearer.removeprefix("Bearer invoice-token-") if bearer.startswith("Bearer invoice-token-") else ""
        if user not in ("alice", "bob"):
            return self.reply(401, {"error": "lab_identity_required"})
        if path == "/invoices":
            return self.reply(200, {"invoices": [item for item in INVOICES.values() if item["owner"] == user]})
        if path.startswith("/invoices/"):
            invoice = INVOICES.get(path.removeprefix("/invoices/"))
            return self.reply(200, invoice) if invoice else self.reply(404, {"error": "not_found"})
        return self.reply(404, {"error": "not_found"})

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

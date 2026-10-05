"""Small orders app for the real-browser provenance loop (local tests only).

The page script knows nothing about Xshield: it logs in, keeps the bearer token
in sessionStorage, lists the user's orders and opens one on click, always with
its own ``Authorization`` header. The detail API is deliberately vulnerable
(it never checks ownership), so only the edge's UI-action provenance stands
between a user and another user's order. ``/__lab/metrics`` counts every
request that actually reached this origin; tests read it directly, never
through the edge.
"""

import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import unquote, urlsplit

HERE = Path(__file__).resolve().parent
LOGIN_PAGE = (HERE / "login.html").read_bytes()
APP_PAGE = (HERE / "app.html").read_bytes()
ORDERS = {
    "ord-alice-1": {"id": "ord-alice-1", "owner": "alice", "title": "Alice order one"},
    "ord-alice-2": {"id": "ord-alice-2", "owner": "alice", "title": "Alice order two"},
    "ord-bob-1": {"id": "ord-bob-1", "owner": "bob", "title": "Bob order one"},
}
USERS = {"alice", "bob"}
TOKENS = {}
COUNTS = {}
LOCK = Lock()


def count(method, path):
    with LOCK:
        key = f"{method} {path}"
        COUNTS[key] = COUNTS.get(key, 0) + 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def user(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        with LOCK:
            return TOKENS.get(header.removeprefix("Bearer "))

    def reply(self, status, body, content_type="application/json"):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/__lab/metrics":
            with LOCK:
                return self.reply(200, dict(COUNTS))
        count("GET", path)
        if path == "/":
            return self.reply(200, LOGIN_PAGE, "text/html; charset=utf-8")
        if path == "/app":
            return self.reply(200, APP_PAGE, "text/html; charset=utf-8")
        user = self.user()
        if user is None:
            return self.reply(401, {"error": "login_required"})
        if path == "/orders":
            mine = [
                {"id": order["id"], "title": order["title"]}
                for order in ORDERS.values()
                if order["owner"] == user
            ]
            return self.reply(200, {"orders": mine})
        if path.startswith("/orders/"):
            order = ORDERS.get(unquote(path.removeprefix("/orders/")))
            if order is None:
                return self.reply(404, {"error": "not_found"})
            # Deliberately vulnerable: any logged-in user may read any order.
            return self.reply(200, order)
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        count("POST", path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = json.loads(self.rfile.read(min(length, 4096)) or b"{}") if length else {}
        if path == "/api/login":
            user = body.get("user")
            if user not in USERS:
                return self.reply(401, {"error": "invalid_credentials"})
            token = secrets.token_urlsafe(24)
            with LOCK:
                TOKENS[token] = user
            return self.reply(200, {
                "access_token": token,
                "identity": {"id": f"principal_{user}", "authorization_context": "orders:customer"},
            })
        if path == "/api/logout":
            header = self.headers.get("Authorization", "")
            with LOCK:
                found = TOKENS.pop(header.removeprefix("Bearer "), None)
            return self.reply(200 if found else 401, {"logged_out": found is not None})
        return self.reply(404, {"error": "not_found"})

    def log_message(self, *_arguments):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("APP_ORIGIN_PORT", "0"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()

"""The EMR origin behind the v4 acceptance lab (docs/04 section 4.3).

It has no object-level authorization on purpose: any logged-in doctor can read,
delete or share any patient by ID, so every refusal the lab expects must come
from the edge. The origin runs in-process inside scripts/test_idor_lab.py and
must never be deployed.
"""

from __future__ import annotations

import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from urllib.parse import parse_qs, urlsplit

# Shared by every lab account. The lab checks that this string never reaches Jev.
PASSWORD = "LAB-PASSWORD-7f3e9d"
# Login name -> doctor ID. doctor_c is the share recipient and owns no patients.
DOCTORS = {"doctor_a": "DR-A", "doctor_b": "DR-B", "doctor_c": "DR-C"}
# Administrator logins. Their sessions hold the role "admin", which the home page names; only they
# get the administrator's search (docs/07 section 7.4.7).
ADMINS = {"admin_root": "DR-ROOT"}
PATIENTS = {
    "PT-7001": {"id": "PT-7001", "name": "患者 A", "doctor": "DR-A"},
    "PT-7002": {"id": "PT-7002", "name": "患者 B", "doctor": "DR-A"},
    "PT-7003": {"id": "PT-7003", "name": "患者 C", "doctor": "DR-A"},
    "PT-7004": {"id": "PT-7004", "name": "患者 D", "doctor": "DR-B"},
}


class EmrOrigin:
    """An origin on a loopback port. `served` lists every request it handled."""

    def __init__(self) -> None:
        self.lock = Lock()
        self.patients = {key: dict(value) for key, value in PATIENTS.items()}
        self.sessions: dict[str, str] = {}  # SID cookie value -> doctor ID
        self.roles: dict[str, str] = {}  # SID cookie value -> role, for administrators only
        self.shares: dict[str, str] = {}  # share code -> patient ID
        self.next_patient = 7005
        # (method, request target, X-Xshield-Request-Id as received or None)
        self.served: list[tuple[str, str, str | None]] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.origin = self
        self.port: int = self.server.server_address[1]

    def start(self) -> None:
        Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    @property
    def origin(self) -> EmrOrigin:
        return self.server.origin  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        request_id = self.headers.get("X-Xshield-Request-Id")
        with self.origin.lock:
            self.origin.served.append((method, self.path, request_id))
            status, payload, extra = self._route(method, body)
        self._send(status, payload, extra)

    def _sid(self) -> str | None:
        """The SID cookie's value, when the request carries one."""
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "SID":
                return value
        return None

    def _caller(self) -> str | None:
        """The doctor behind the SID cookie, or None when the session is unknown."""
        token = self._sid()
        return None if token is None else self.origin.sessions.get(token)

    def _role(self) -> str | None:
        """The role behind the SID cookie, when it is an administrator's."""
        token = self._sid()
        return None if token is None else self.origin.roles.get(token)

    def _route(self, method: str, body: bytes) -> tuple[int, object, dict[str, str]]:
        origin = self.origin
        url = urlsplit(self.path)
        parts = [part for part in url.path.split("/") if part]
        query = parse_qs(url.query)
        if method == "POST" and url.path == "/login":
            credentials = _json(body)
            user = credentials.get("username")
            accounts = {**DOCTORS, **ADMINS}
            if user not in accounts or credentials.get("password") != PASSWORD:
                return 401, {"error": "invalid_credentials"}, {}
            token = secrets.token_urlsafe(18)
            origin.sessions[token] = accounts[user]
            if user in ADMINS:
                origin.roles[token] = "admin"
            return 302, None, {"Location": "/api/home", "Set-Cookie": f"SID={token}; Path=/; HttpOnly"}
        doctor = self._caller()
        if doctor is None:
            return 401, {"error": "login_required"}, {}
        if method == "GET" and url.path == "/api/home":
            # An administrator's home page names the role; a doctor's home page does not.
            home: dict[str, object] = {"doctor": {"id": doctor}}
            if self._role() == "admin":
                home["role"] = "admin"
            return 200, home, {}
        if method == "GET" and url.path == "/api/patients":
            # Deliberately trusts the doctor parameter: "my patients" is whoever is named.
            owner = query.get("doctor", [doctor])[0]
            return 200, {"patients": [p for p in origin.patients.values() if p["doctor"] == owner]}, {}
        if method == "POST" and url.path == "/api/patients":
            # Numeric ids: the object map's path templates replace numeric and UUID segments
            # only (docs/07), so a patient created in the lab has positions in the map.
            patient = {"id": str(origin.next_patient), "name": _json(body).get("name", ""), "doctor": doctor}
            origin.next_patient += 1
            origin.patients[patient["id"]] = patient
            return 201, patient, {}
        if len(parts) == 3 and parts[:2] == ["api", "patients"]:
            # Deliberately vulnerable: the patient named in the path is never checked.
            patient = origin.patients.get(parts[2])
            if method == "GET" and patient is not None:
                return 200, patient, {}
            if method == "DELETE" and patient is not None:
                del origin.patients[parts[2]]
                return 200, {"deleted": parts[2]}, {}
            return 404, {"error": "not_found"}, {}
        if len(parts) == 4 and parts[:2] == ["api", "patients"] and parts[3] == "share" and method == "POST":
            if parts[2] not in origin.patients:
                return 404, {"error": "not_found"}, {}
            code = "SHR-" + secrets.token_hex(4).upper()
            origin.shares[code] = parts[2]
            return 201, {"code": code}, {}
        if len(parts) == 4 and parts[:2] == ["api", "patients"] and parts[3] == "notes" and method == "POST":
            # Deliberately vulnerable as well: a note is written on any patient named in the path.
            if parts[2] not in origin.patients:
                return 404, {"error": "not_found"}, {}
            return 201, {"saved": True, "patient": parts[2]}, {}
        if len(parts) == 2 and parts[0] == "share" and method == "POST":
            patient_id = origin.shares.get(parts[1])
            if patient_id is None:
                return 404, {"error": "unknown_share_code"}, {}
            return 200, {"patient": origin.patients[patient_id]}, {}
        if method == "GET" and url.path == "/api/admin/search":
            # The administrator's search: every patient, to administrator sessions only.
            if self._role() != "admin":
                return 403, {"error": "forbidden"}, {}
            text = query.get("q", [""])[0]
            return 200, {"results": [p for p in origin.patients.values() if text in p["name"]]}, {}
        if method == "GET" and url.path == "/api/search":
            text = query.get("q", [""])[0]
            return 200, {"results": [p for p in origin.patients.values() if text in p["name"]]}, {}
        if method == "POST" and url.path == "/api/notes":
            return 201, {"saved": True}, {}
        return 404, {"error": "not_found"}, {}

    def _send(self, status: int, payload: object, extra: dict[str, str]) -> None:
        data = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        for name, value in extra.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def _json(body: bytes) -> dict:
    try:
        value = json.loads(body) if body else {}
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}

"""The clinic origin: a lab EMR that knows the truth the effectiveness lab scores against (plan 4.1).

Like idor_origin.py it has no object-level authorization on purpose: any logged-in doctor can read,
change or delete any patient, so every refusal the lab expects must come from the edge. Unlike that
origin it keeps the ground truth: which account owns each object, which object each response showed
to which session in an identity field, which responses echoed a value the session had only sent, and
where each object position sits with its tier. The data comes from a seed, so one seed always gives
the same data. The origin runs in-process and must never be deployed.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import secrets
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Any
from urllib.parse import parse_qs, urlsplit

DEFAULT_SEED = 20261113
QUICK_DOCTORS = 12  # plan 5.2: quick mode; the full mode uses 48
PASSWORD = "CLINIC-LAB-PASSWORD-5d1c"  # shared by every lab account; synthetic
DEPARTMENTS = ("内科", "外科", "儿科", "妇产科", "骨科", "皮肤科")
ORGANIZATIONS = ("ORG-1", "ORG-2")
UNASSIGNED = "未分科"
ADMIN_ROLE = "admin"
ADMINS = {"admin_1": "ADM-1", "admin_2": "ADM-2"}  # login name -> administrator id
LIST_LIMIT = 7  # every list answers at most this many items (docs/07 section 7.9.16)
SURNAMES = ("王", "李", "张", "刘", "陈", "杨", "黄", "赵", "周", "吴", "徐", "孙")
GIVEN_NAMES = ("伟", "芳", "敏", "静", "丽", "强", "磊", "军", "洋", "娜", "秀英", "桂兰")
ENTRIES = ("/login", "/api/token", "/api/home", "/api/patients", "/share/*")
BYPASS = ("/static/*",)
CORS_HEADERS = (
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"),
    ("Access-Control-Allow-Headers", "Content-Type, Authorization"),
)
CLASSES = (
    ("patient", "患者"), ("visit", "就诊"), ("prescription", "处方"), ("report", "报告"),
    ("doctor", "医生"), ("org", "机构"), ("staff", "员工"),
)

# The request positions of the object map, as the edge writes them (docs/07 section 7.4.7). An
# accepts_public of True means normal traffic may act on a value the public search showed.
REQUEST_POSITIONS: tuple[dict[str, Any], ...] = (
    {"key": "GET /api/patients/{id} path[2]", "class": "patient", "accepts_public": False, "learnable": True},
    {"key": "PUT /api/patients/{id} path[2]", "class": "patient", "accepts_public": False, "learnable": True},
    {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "accepts_public": False, "learnable": True},
    {"key": "POST /api/patients/{id}/notes path[2]", "class": "patient", "accepts_public": True, "learnable": True},
    {"key": "POST /api/patients/{id}/share path[2]", "class": "patient", "accepts_public": False, "learnable": True},
    {"key": "GET /api/visits/{id} path[2]", "class": "visit", "accepts_public": False, "learnable": True},
    {"key": "GET /api/prescriptions/{id} path[2]", "class": "prescription", "accepts_public": False,
     "learnable": True},
    {"key": "GET /api/reports/{id} path[2]", "class": "report", "accepts_public": False, "learnable": False,
     "why": "慢速 id（RP-2026-0001）不化为 {id}，没有声明就没有位置"},
    {"key": "GET /api/patients/{id}/comments path[2]", "class": "patient", "accepts_public": False,
     "learnable": False, "why": "良性旅程不读评论；评论只在属性越权告警（W6）里出现"},
    {"key": "POST /api/patients/{id}/attachments path[2]", "class": "patient", "accepts_public": False,
     "learnable": False, "why": "上传超过 48 KiB 不经判定，由 P0-1 用例覆盖；良性旅程不上传"},
)

# The response positions, as fingerprints are keyed (docs/07 section 7.4.3). A tier of None means the
# position carries no tier; learnable False marks a position the edge cannot place by rule.
RESPONSE_POSITIONS: tuple[dict[str, Any], ...] = (
    {"key": "GET /api/patients patients[].id", "class": "patient", "tier": "self", "learnable": True},
    {"key": "GET /api/patients/{id} id", "class": "patient", "tier": "self", "learnable": True},
    {"key": "GET /api/patients/{id} visits[].id", "class": "visit", "tier": "self", "learnable": True},
    {"key": "GET /api/patients/{id} prescriptions[].id", "class": "prescription", "tier": "self",
     "learnable": True},
    {"key": "GET /api/visits/{id} id", "class": "visit", "tier": "self", "learnable": True},
    {"key": "GET /api/visits/{id} patient_id", "class": "patient", "tier": "self", "learnable": True},
    {"key": "GET /api/prescriptions/{id} id", "class": "prescription", "tier": "self", "learnable": True},
    {"key": "GET /api/prescriptions/{id} patient_id", "class": "patient", "tier": "self", "learnable": True},
    {"key": "GET /api/reports/{id} patient_id", "class": "patient", "tier": "self", "learnable": False,
     "why": "慢速 id，路由不化为 {id}"},
    {"key": "POST /api/patients id", "class": "patient", "tier": "self", "learnable": True},
    {"key": "GET /api/search results[].id", "class": "patient", "tier": "public", "learnable": True},
    {"key": "GET /api/directory doctors[].id", "class": "doctor", "tier": "public", "learnable": True},
    {"key": "GET /api/directory doctors[].org", "class": "org", "tier": "public", "learnable": True},
    {"key": "GET /api/admin/search results[].id", "class": "patient", "tier": "admin", "learnable": True},
    {"key": "GET /api/admin/export patients[].id", "class": "patient", "tier": "admin", "learnable": True},
    {"key": "GET /share/{code} patient.id", "class": "patient", "tier": None, "learnable": False,
     "why": "分享码不化为模板，键随码变；兑换响应没有固定档位，授权来自分享码"},
    {"key": "GET /api/patients/{id}/comments comments[].author.id", "class": "doctor", "tier": None,
     "learnable": False, "why": "评论作者不按档位划分（属性越权告警 W6 的对象）"},
    {"key": "POST /api/token patients[].id", "class": "patient", "tier": "self", "learnable": False,
     "why": "JSON 凭证站点的登录接口，Cookie 站点不走它"},
)

# Identity positions (docs/07 section 7.9.15). The token login names its user as well, but only the JSON
# credential site declares it.
# The function table of the truth site (docs/07 7.9.18): one entry per route the origin answers, except GET /metrics,
# which is left out on purpose, so the gateway asks Jev about it (objects.ask_unknown_functions). The two
# administrator routes are the administrator tier, at reliability high.
FUNCTIONS: tuple[dict[str, Any], ...] = (
    {"key": "GET /static/app.js", "source": "admin"},
    {"key": "POST /login", "source": "admin"},
    {"key": "POST /api/token", "source": "admin"},
    {"key": "GET /api/home", "source": "admin"},
    {"key": "POST /api/session/refresh", "source": "admin"},
    {"key": "GET /api/patients", "source": "admin"},
    {"key": "POST /api/patients", "source": "admin"},
    {"key": "GET /api/patients/{id}", "source": "admin"},
    {"key": "PUT /api/patients/{id}", "source": "admin"},
    {"key": "DELETE /api/patients/{id}", "source": "admin"},
    {"key": "GET /api/patients/{id}/comments", "source": "admin"},
    {"key": "POST /api/patients/{id}/notes", "source": "admin"},
    {"key": "POST /api/patients/{id}/share", "source": "admin"},
    {"key": "POST /api/patients/{id}/attachments", "source": "admin"},
    {"key": "GET /share/{id}", "source": "admin"},
    {"key": "GET /api/visits/{id}", "source": "admin"},
    {"key": "GET /api/prescriptions/{id}", "source": "admin"},
    {"key": "GET /api/reports/{id}", "source": "admin"},
    {"key": "GET /api/search", "source": "admin"},
    {"key": "GET /api/directory", "source": "admin"},
    {"key": "GET /api/admin/search", "source": "admin", "tier": "admin", "reliability": "high"},
    {"key": "GET /api/admin/export", "source": "admin", "tier": "admin", "reliability": "high"},
    {"key": "POST /api/profile", "source": "admin"},
    {"key": "POST /api/forms/intake", "source": "admin"},
)

IDENTITY: tuple[dict[str, Any], ...] = (
    {"key": "GET /api/home doctor.id", "class": "doctor", "identity": "user"},
    {"key": "GET /api/home doctor.org", "class": "org", "identity": "org"},
    {"key": "GET /api/home role", "class": "staff", "identity": "role"},
)

# Request and response fields that carry no object, spelled as the edge records them (plan 9.3): a body or
# query field as `body.<name>` or `query.<name>`, a response field by its path. --check requires every key
# here to appear in the decision records. Not listed: the share redemption fields (the edge spells them per
# share code, so no template matches) and the JSON credential route POST /api/token (the cookie site never
# calls it, so no record can show its spelling).
NON_OBJECTS = (
    "POST /login body.username",
    "POST /login body.password",
    "GET /api/search query.q",
    "GET /api/admin/search query.q",
    "POST /api/patients body.name",
    "PUT /api/patients/{id} body.name",
    "POST /api/patients/{id}/notes body.text",
    "GET /api/patients patients[].name",
    "GET /api/patients patients[].age",
    "GET /api/patients patients[].dept",
    "GET /api/patients/{id} name",
    "GET /api/patients/{id} age",
    "GET /api/patients/{id} prescriptions[].days",
    "GET /api/visits/{id} date",
    "GET /api/visits/{id} note",
    "GET /api/prescriptions/{id} drug",
    "GET /api/prescriptions/{id} days",
    "GET /api/search query",
    "GET /api/search page",
    "GET /api/search results[].name",
    "GET /api/search results[].age",
    "GET /api/search results[].dept",
    "GET /api/admin/search results[].name",
    "GET /api/admin/search results[].age",
    "GET /api/admin/search results[].dept",
    "GET /api/admin/export patients[].name",
    "GET /api/admin/export patients[].age",
    "GET /api/admin/export patients[].dept",
    "GET /api/directory doctors[].name",
    "GET /api/directory doctors[].dept",
    "POST /api/patients/{id}/share code",
)


@dataclass
class Result:
    """What the origin answers for one request, and what the response teaches the session."""

    status: int
    payload: object = None
    headers: tuple[tuple[str, str], ...] = ()
    shown: tuple[tuple[str, str], ...] = ()  # (class, value) placed in an identity field
    echoed: tuple[str, ...] = ()  # values of the request the response repeats
    session: str | None = None  # the credential that learns these, when it is a new one
    raw: bytes | None = None
    content_type: str = "application/json; charset=utf-8"


@dataclass(frozen=True)
class Served:
    """One request the origin handled, in the order it handled them."""

    index: int
    method: str
    target: str
    request_id: str | None
    status: int
    credential: str | None


class ClinicOrigin:
    """The clinic origin on a loopback port. `served` lists every request it handled."""

    def __init__(self, seed: int = DEFAULT_SEED, doctors: int = QUICK_DOCTORS) -> None:
        if doctors < 1:
            raise ValueError("the clinic needs at least one doctor")
        self.seed = seed
        self.doctor_count = doctors
        self.lock = Lock()
        self.index = 0
        self.served: list[Served] = []
        self.sessions: dict[str, str] = {}  # credential -> account id (a doctor or an administrator)
        self.roles: dict[str, str] = {}  # credential -> role; only the administrators' role is ADMIN_ROLE
        self.shown: dict[str, dict[tuple[str, str], int]] = {}  # credential -> (class, value) -> request index
        self.echoes: dict[str, set[str]] = {}  # credential -> values the origin repeated back to it
        self.shares: dict[str, str] = {}  # share code -> patient id
        self.doctors: dict[str, dict[str, Any]] = {}
        self.admins: dict[str, dict[str, Any]] = {}
        self.accounts: dict[str, str] = {}  # login name -> account id
        self.patients: dict[str, dict[str, Any]] = {}  # every patient ever made, deleted ones marked
        self.visits: dict[str, dict[str, Any]] = {}
        self.prescriptions: dict[int, dict[str, Any]] = {}
        self.reports: dict[str, dict[str, Any]] = {}
        self.comments: dict[str, list[dict[str, Any]]] = {}
        self.rng = random.Random(f"{seed}:runtime")  # share codes and new attributes, in request order
        self._generate()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.origin = self  # type: ignore[attr-defined]
        self.port: int = self.server.server_address[1]

    def start(self) -> None:
        Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # Data ----------------------------------------------------------------------------------------

    def _generate(self) -> None:
        rng = random.Random(f"{self.seed}:data")
        for index in range(self.doctor_count):
            doctor_id = str(101 + index)
            self.doctors[doctor_id] = {
                "id": doctor_id, "name": _person(rng), "dept": DEPARTMENTS[index % len(DEPARTMENTS)],
                "org": ORGANIZATIONS[index % len(ORGANIZATIONS)], "phone": _phone(rng),
                "email": f"dr{doctor_id}@clinic.example",
            }
            self.accounts[f"doctor_{doctor_id}"] = doctor_id
        for username, admin_id in ADMINS.items():
            self.admins[admin_id] = {"id": admin_id, "name": _person(rng)}
            self.accounts[username] = admin_id
        patient_number, prescription_number, report_number = 10001, 1, 1
        for doctor in self.doctors.values():
            for _ in range(rng.randint(4, 6)):
                pid = str(patient_number)
                patient_number += 1
                patient: dict[str, Any] = {
                    "id": pid, "name": _person(rng), "age": rng.randint(18, 90), "owner": doctor["id"],
                    "dept": doctor["dept"], "deleted": False, "visits": [], "prescriptions": [],
                }
                self.patients[pid] = patient
                for _ in range(rng.randint(1, 2)):
                    visit_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
                    self.visits[visit_id] = {"id": visit_id, "patient": pid, "date": _date(rng), "note": "复诊"}
                    patient["visits"].append(visit_id)
                for _ in range(rng.randint(1, 2)):
                    self.prescriptions[prescription_number] = {
                        "id": prescription_number, "patient": pid, "drug": f"药品{prescription_number}",
                        "days": rng.randint(3, 14),
                    }
                    patient["prescriptions"].append(prescription_number)
                    prescription_number += 1
                report_id = f"RP-2026-{report_number:04d}"
                report_number += 1
                self.reports[report_id] = {"id": report_id, "patient": pid, "summary": "检查正常"}
        self.next_patient = patient_number
        self.next_prescription = prescription_number
        doctor_ids = list(self.doctors)
        for position, pid in enumerate(self.patients):
            owner = self.patients[pid]["owner"]
            if position % 3 == 0 and len(doctor_ids) > 1:
                author = doctor_ids[(position + 1) % len(doctor_ids)]
                if author == owner:
                    author = doctor_ids[(position + 2) % len(doctor_ids)]
                self.comments[pid] = [{"id": f"CM-{pid}", "body": "请复查。", "author": author}]

    def owner_of(self, object_class: str, value: str) -> str | None:
        """The account that owns an object, from the ground truth. Deleted objects keep their owner."""
        with self.lock:
            return self._owner(object_class, value)

    def _owner(self, object_class: str, value: str) -> str | None:
        if object_class == "doctor":
            return value if value in self.doctors else None
        if object_class == "patient":
            patient = self.patients.get(value)
        elif object_class == "visit":
            visit = self.visits.get(value)
            patient = self.patients.get(visit["patient"]) if visit else None
        elif object_class == "prescription":
            prescription = self.prescriptions.get(_number(value))
            patient = self.patients.get(prescription["patient"]) if prescription else None
        elif object_class == "report":
            report = self.reports.get(value)
            patient = self.patients.get(report["patient"]) if report else None
        else:
            return None
        return patient["owner"] if patient else None

    def snapshot(self) -> dict[str, Any]:
        """The generated data as plain values, for tests and for comparing two seeds."""
        with self.lock:
            return {
                "doctors": self.doctors, "admins": self.admins, "patients": self.patients,
                "visits": self.visits, "prescriptions": {str(k): v for k, v in self.prescriptions.items()},
                "reports": self.reports, "comments": self.comments,
            }

    # Truth ---------------------------------------------------------------------------------------

    def truth(self) -> dict[str, Any]:
        """The position truth of the origin, in the format of plan section 9.3."""
        return {
            "site": "clinic", "seed": self.seed,
            "classes": [name for name, _ in CLASSES],
            "identity": [dict(item) for item in IDENTITY],
            "request_positions": [dict(item) for item in REQUEST_POSITIONS],
            "response_positions": [dict(item) for item in RESPONSE_POSITIONS],
            "non_objects": list(NON_OBJECTS),
            "functions": [{"key": item["key"], "tier": item.get("tier")} for item in FUNCTIONS],
        }

    def reference_state(self, credential: str | None, object_class: str, value: str) -> dict[str, bool]:
        """Whether the origin has shown this value to the credential, or only echoed it back.

        A value the origin showed in an identity field is shown (plan 3.1). A value the credential
        sent and the origin repeated without showing it is an echo.
        """
        with self.lock:
            if not credential:
                return {"shown": False, "echoed": False}
            shown = (object_class, value) in self.shown.get(credential, {})
            echoed = not shown and value in self.echoes.get(credential, set())
            return {"shown": shown, "echoed": echoed}

    def shown_of(self, credential: str) -> dict[tuple[str, str], int]:
        with self.lock:
            return dict(self.shown.get(credential, {}))

    def served_request_ids(self) -> set[str]:
        with self.lock:
            return {entry.request_id for entry in self.served if entry.request_id}

    def was_served(self, request_id: str) -> bool:
        with self.lock:
            return any(entry.request_id == request_id for entry in self.served)

    # HTTP ----------------------------------------------------------------------------------------

    def respond(self, method: str, target: str, headers: Any, body: bytes, request_id: str | None) -> Result:
        with self.lock:
            self.index += 1
            credential = _credential(headers)
            result = self._dispatch(method, target, headers, body, credential)
            if 200 <= result.status < 300:
                learner = result.session or credential
                if learner and (result.shown or result.echoed):
                    self._learn(learner, result.shown, result.echoed)
            self.served.append(Served(self.index, method, target, request_id, result.status, credential))
            return result

    def _learn(self, credential: str, shown: tuple[tuple[str, str], ...], echoed: tuple[str, ...]) -> None:
        seen = self.shown.setdefault(credential, {})
        for item in shown:
            seen.setdefault(item, self.index)
        if echoed:
            self.echoes.setdefault(credential, set()).update(echoed)

    def _open(self, account: str) -> str:
        token = secrets.token_urlsafe(24)
        self.sessions[token] = account
        if account in self.admins:
            self.roles[token] = ADMIN_ROLE
        self.shown.setdefault(token, {})
        self.echoes.setdefault(token, set())
        return token

    def _dispatch(self, method: str, target: str, headers: Any, body: bytes, credential: str | None) -> Result:
        url = urlsplit(target)
        path = url.path
        query = {key: values[0] for key, values in parse_qs(url.query, keep_blank_values=True).items()}
        if method == "OPTIONS":
            return Result(204, headers=CORS_HEADERS)
        if method == "GET" and path == "/metrics":
            return Result(200, raw=b"xshield_clinic_origin_up 1\n", content_type="text/plain; charset=utf-8")
        if method == "GET" and path == "/static/app.js":
            return Result(200, raw=b"/* clinic lab app */\n", content_type="application/javascript; charset=utf-8")
        if method == "POST" and path == "/login":
            return self._login(_fields(headers, body))
        if method == "POST" and path == "/api/token":
            return self._token(_fields(headers, body))
        account = self.sessions.get(credential) if credential else None
        if account is None:
            return Result(401, {"error": "login_required"})
        return self._authorized(method, path, query, headers, body, credential, account)

    def _login(self, fields: dict[str, str]) -> Result:
        account = self.accounts.get(str(fields.get("username", "")))
        if account is None or fields.get("password") != PASSWORD:
            return Result(401, {"error": "invalid_credentials"})
        token = self._open(account)
        cookie = f"SID={token}; Path=/; HttpOnly"
        return Result(302, headers=(("Location", "/api/home"), ("Set-Cookie", cookie)), session=token)

    def _token(self, fields: dict[str, str]) -> Result:
        account = self.accounts.get(str(fields.get("username", "")))
        if account is None or fields.get("password") != PASSWORD:
            return Result(401, {"error": "invalid_credentials"})
        token = self._open(account)
        owned = self._owned(account)
        payload = {"token": token, "user": {"id": account},
                   "patients": [_summary(patient) for patient in owned]}
        return Result(200, payload, shown=(("doctor", account),) + _shown_patients(owned), session=token)

    def _authorized(self, method: str, path: str, query: dict[str, str], headers: Any, body: bytes,
                    credential: str, account: str) -> Result:
        role = self.roles.get(credential)
        parts = [part for part in path.split("/") if part]
        if method == "GET" and path == "/api/home":
            org = self.doctors[account]["org"] if account in self.doctors else ORGANIZATIONS[0]
            payload: dict[str, Any] = {"doctor": {"id": account, "org": org}}
            if role == ADMIN_ROLE:
                payload["role"] = ADMIN_ROLE
            return Result(200, payload, shown=(("doctor", account), ("org", org)))
        if method == "POST" and path == "/api/session/refresh":
            return self._refresh(credential, account)
        if method == "GET" and path == "/api/patients":
            return self._patient_list(query, headers, account, credential)
        if method == "POST" and path == "/api/patients":
            return self._create_patient(_fields(headers, body), account)
        if len(parts) == 3 and parts[:2] == ["api", "patients"] and _is_number(parts[2]):
            return self._patient(method, parts[2], _fields(headers, body))
        if len(parts) == 4 and parts[:2] == ["api", "patients"] and _is_number(parts[2]):
            if method == "GET" and parts[3] == "comments":
                return self._comments(parts[2])
            return self._patient_action(method, parts[2], parts[3], body, headers)
        if method == "GET" and len(parts) == 2 and parts[0] == "share":
            return self._redeem(parts[1])
        if method == "GET" and len(parts) == 3 and parts[:2] == ["api", "visits"]:
            return self._visit(parts[2])
        if method == "GET" and len(parts) == 3 and parts[:2] == ["api", "prescriptions"]:
            return self._prescription(parts[2])
        if method == "GET" and len(parts) == 3 and parts[:2] == ["api", "reports"]:
            return self._report(parts[2])
        if method == "GET" and path == "/api/search":
            return self._search(query.get("q", ""), credential)
        if method == "GET" and path == "/api/directory":
            return self._directory(query.get("dept", ""))
        if method == "GET" and path == "/api/admin/search":
            if role != ADMIN_ROLE:
                return Result(403, {"error": "forbidden"})
            return self._admin_search(query.get("q", ""))
        if method == "GET" and path == "/api/admin/export":
            if role != ADMIN_ROLE:
                return Result(403, {"error": "forbidden"})
            found = self._all_patients()[:LIST_LIMIT]
            return Result(200, {"patients": [_summary(patient) for patient in found]},
                          shown=_shown_patients(found))
        if method == "POST" and path == "/api/profile":
            fields = _fields(headers, body)
            if "role" in fields:
                self.roles[credential] = str(fields["role"])
            return Result(200, {"saved": True, "role": self.roles.get(credential, "doctor")})
        if method == "POST" and path == "/api/forms/intake":
            return Result(200, {"received": len(_fields(headers, body))})
        return Result(404, {"error": "not_found"})

    def _refresh(self, credential: str, account: str) -> Result:
        token = secrets.token_urlsafe(24)
        self.sessions[token] = self.sessions.pop(credential)
        if credential in self.roles:
            self.roles[token] = self.roles.pop(credential)
        self.shown[token] = self.shown.pop(credential, {})
        self.echoes[token] = self.echoes.pop(credential, set())
        cookie = f"SID={token}; Path=/; HttpOnly"
        return Result(200, {"refreshed": True}, headers=(("Set-Cookie", cookie),), session=token)

    def _patient_list(self, query: dict[str, str], headers: Any, account: str, credential: str) -> Result:
        # Deliberately trusts the doctor parameter: "my patients" is whoever is named.
        owned = self._owned(query.get("doctor", account))[:LIST_LIMIT]
        payload = {"patients": [_summary(patient) for patient in owned]}
        raw = json.dumps(payload, ensure_ascii=False).encode()
        etag = '"' + hashlib.sha256(raw).hexdigest()[:24] + '"'
        if headers.get("If-None-Match") == etag:
            return Result(304, headers=(("ETag", etag),))
        return Result(200, payload, headers=(("ETag", etag),), shown=_shown_patients(owned))

    def _create_patient(self, fields: dict[str, str], account: str) -> Result:
        pid = str(self.next_patient)
        self.next_patient += 1
        dept = self.doctors[account]["dept"] if account in self.doctors else UNASSIGNED
        self.patients[pid] = {
            "id": pid, "name": str(fields.get("name", "")), "age": self.rng.randint(18, 90), "owner": account,
            "dept": dept, "deleted": False, "visits": [], "prescriptions": [],
        }
        return Result(201, {"id": pid}, shown=(("patient", pid),))

    def _patient(self, method: str, pid: str, fields: dict[str, str]) -> Result:
        # No object-level check: the patient named in the path is returned or changed for anyone.
        patient = self.patients.get(pid)
        if patient is None or patient["deleted"]:
            return Result(404, {"error": "not_found"})
        if method == "GET":
            detail = {
                "id": pid, "name": patient["name"], "age": patient["age"],
                "visits": [{"id": visit} for visit in patient["visits"]],
                "prescriptions": [{"id": number, "days": self.prescriptions[number]["days"]}
                                  for number in patient["prescriptions"]],
            }
            shown = (("patient", pid),) + tuple(("visit", visit) for visit in patient["visits"]) + tuple(
                ("prescription", str(number)) for number in patient["prescriptions"])
            return Result(200, detail, shown=shown)
        if method == "PUT":
            patient["name"] = str(fields.get("name", patient["name"]))
            return Result(200, {"saved": True})
        if method == "DELETE":
            patient["deleted"] = True
            return Result(200, {"deleted": True})
        return Result(405, {"error": "method_not_allowed"})

    def _patient_action(self, method: str, pid: str, action: str, body: bytes, headers: Any) -> Result:
        if pid not in self.patients or self.patients[pid]["deleted"]:
            return Result(404, {"error": "not_found"})
        if method == "POST" and action == "notes":
            return Result(201, {"saved": True})
        if method == "POST" and action == "share":
            code = "SHR-" + f"{self.rng.getrandbits(32):08X}"
            self.shares[code] = pid
            return Result(201, {"code": code})
        if method == "POST" and action == "attachments":
            return Result(201, {"stored": True, "bytes": len(body)})
        return Result(404, {"error": "not_found"})

    def _comments(self, pid: str) -> Result:
        if pid not in self.patients or self.patients[pid]["deleted"]:
            return Result(404, {"error": "not_found"})
        items = []
        shown: list[tuple[str, str]] = []
        for comment in self.comments.get(pid, [])[:LIST_LIMIT]:
            author = self.doctors[comment["author"]]
            items.append({"id": comment["id"], "body": comment["body"], "author": {
                "id": author["id"], "name": author["name"], "phone": author["phone"], "email": author["email"]}})
            shown.append(("doctor", author["id"]))
        return Result(200, {"comments": items}, shown=tuple(shown))

    def _redeem(self, code: str) -> Result:
        pid = self.shares.get(code)
        if pid is None:
            return Result(404, {"error": "unknown_share_code"})
        patient = self.patients[pid]
        if patient["deleted"]:
            return Result(404, {"error": "not_found"})
        return Result(200, {"patient": _summary(patient)}, shown=(("patient", pid),))

    def _visit(self, visit_id: str) -> Result:
        visit = self.visits.get(visit_id)
        if visit is None:
            return Result(404, {"error": "not_found"})
        payload = {"id": visit_id, "patient_id": visit["patient"], "date": visit["date"], "note": visit["note"]}
        return Result(200, payload, shown=(("visit", visit_id), ("patient", visit["patient"])))

    def _prescription(self, text: str) -> Result:
        if not _is_number(text) or int(text) not in self.prescriptions:
            return Result(404, {"error": "not_found"})
        number = int(text)
        item = self.prescriptions[number]
        payload = {"id": number, "patient_id": item["patient"], "drug": item["drug"], "days": item["days"]}
        return Result(200, payload, shown=(("prescription", str(number)), ("patient", item["patient"])))

    def _report(self, report_id: str) -> Result:
        report = self.reports.get(report_id)
        if report is None:
            return Result(404, {"error": "not_found"})
        payload = {"id": report_id, "patient_id": report["patient"], "summary": report["summary"]}
        return Result(200, payload, shown=(("report", report_id), ("patient", report["patient"])))

    def _search(self, text: str, credential: str) -> Result:
        # Public: any logged-in doctor gets the same first results for a name or a department.
        found = [patient for patient in self._all_patients() if _matches(patient, text, with_id=False)]
        found = found[:LIST_LIMIT]
        payload = {"query": text, "page": 1, "results": [_summary(patient) for patient in found]}
        return Result(200, payload, shown=_shown_patients(found), echoed=(text,) if text else ())

    def _directory(self, dept: str) -> Result:
        doctors = [doctor for doctor in self.doctors.values() if not dept or doctor["dept"] == dept]
        doctors = doctors[:LIST_LIMIT]
        payload = {"doctors": [{"id": d["id"], "name": d["name"], "dept": d["dept"], "org": d["org"]}
                               for d in doctors]}
        shown = tuple(("doctor", d["id"]) for d in doctors) + tuple(("org", d["org"]) for d in doctors)
        return Result(200, payload, shown=shown)

    def _admin_search(self, text: str) -> Result:
        found = [patient for patient in self._all_patients() if _matches(patient, text, with_id=True)]
        found = found[:LIST_LIMIT]
        return Result(200, {"results": [_summary(patient) for patient in found]}, shown=_shown_patients(found))

    def _owned(self, account: str) -> list[dict[str, Any]]:
        return [patient for patient in self.patients.values()
                if patient["owner"] == account and not patient["deleted"]][:LIST_LIMIT]

    def _all_patients(self) -> list[dict[str, Any]]:
        return [patient for patient in self.patients.values() if not patient["deleted"]]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_OPTIONS(self) -> None:
        self._handle("OPTIONS")

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        origin: ClinicOrigin = self.server.origin  # type: ignore[attr-defined]
        result = origin.respond(method, self.path, self.headers, body, self.headers.get("X-Xshield-Request-Id"))
        self._send(result)

    def _send(self, result: Result) -> None:
        if result.raw is not None:
            data = result.raw
        elif result.payload is None:
            data = b""
        else:
            data = json.dumps(result.payload, ensure_ascii=False).encode()
        self.send_response(result.status)
        for name, value in result.headers:
            self.send_header(name, value)
        self.send_header("Content-Type", result.content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def site_spec(config: str, origin_port: int, mode: str = "enforce") -> dict[str, Any]:
    """The lab site for one object-map configuration (plan 3.3).

    `none` declares only the identity positions: no object map, so the edge judges as a site without
    one. `truth` declares every learnable position from the origin's truth, each at reliability high, and the
    origin's function table with ask_unknown_functions (every route but GET /metrics is in the table).
    """
    if config not in ("none", "truth"):
        raise ValueError(f"unknown configuration {config!r}")
    name = f"clinic-{config}"
    slots: list[dict[str, Any]] = [
        {"key": item["key"], "class": item["class"], "source": "admin", "identity": item["identity"]}
        for item in IDENTITY
    ]
    classes = {item["class"] for item in IDENTITY}
    if config == "truth":
        for item in REQUEST_POSITIONS:
            if item["learnable"]:
                slots.append({"key": item["key"], "class": item["class"], "source": "admin",
                              "accepts_public": item["accepts_public"], "reliability": "high"})
                classes.add(item["class"])
        for item in RESPONSE_POSITIONS:
            if item["learnable"] and item["tier"] is not None:
                slots.append({"key": item["key"], "class": item["class"], "source": "admin",
                              "tier": item["tier"], "reliability": "high"})
                classes.add(item["class"])
    class_names = dict(CLASSES)
    objects: dict[str, Any] = {
        "classes": [{"id": cls, "name": class_names[cls]} for cls, _ in CLASSES if cls in classes],
        "slots": slots,
    }
    if config == "truth":
        objects["functions"] = [dict(item) for item in FUNCTIONS]
        objects["ask_unknown_functions"] = True
    return {
        "name": name, "hosts": [f"{name}.lab"], "origin": f"http://127.0.0.1:{origin_port}",
        "session": {"cookie": "SID"}, "entries": list(ENTRIES), "bypass": list(BYPASS),
        "mode": mode, "on_jev_unavailable": "deny",
        "advanced": {"address_calls_per_minute": 600},
        "objects": objects,
    }


def _credential(headers: Any) -> str | None:
    """The session credential: the SID cookie, or a bearer token in Authorization."""
    for part in (headers.get("Cookie") or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "SID" and value:
            return value
    authorization = (headers.get("Authorization") or "").strip()
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return None


def _fields(headers: Any, body: bytes) -> dict[str, Any]:
    """The fields of a JSON or form body; anything else has none."""
    kind = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if kind == "application/json":
        try:
            value = json.loads(body) if body else {}
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}
    if kind in ("", "application/x-www-form-urlencoded"):
        return {key: values[0] for key, values in
                parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()}
    return {}


def _summary(patient: dict[str, Any]) -> dict[str, Any]:
    return {"id": patient["id"], "name": patient["name"], "age": patient["age"], "dept": patient["dept"]}


def _shown_patients(patients: list[dict[str, Any]]) -> tuple[tuple[str, str], ...]:
    return tuple(("patient", patient["id"]) for patient in patients)


def _matches(patient: dict[str, Any], text: str, *, with_id: bool) -> bool:
    if text == "":
        return True
    return text in patient["name"] or text == patient["dept"] or (with_id and text == patient["id"])


def _is_number(text: str) -> bool:
    return re.fullmatch(r"\d{1,9}", text) is not None


def _number(text: str) -> int:
    return int(text) if _is_number(text) else -1


def _person(rng: random.Random) -> str:
    return rng.choice(SURNAMES) + rng.choice(GIVEN_NAMES)


def _phone(rng: random.Random) -> str:
    return f"1{rng.choice('3456789')}{rng.randrange(10 ** 9):09d}"


def _date(rng: random.Random) -> str:
    return f"2026-{rng.randint(1, 10):02d}-{rng.randint(1, 28):02d}"

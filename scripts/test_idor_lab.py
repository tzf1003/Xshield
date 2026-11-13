#!/usr/bin/env python3
"""Runs the docs/04 section 4.3 acceptance scenarios against the real xshield-edge.

The lab runs in this process and a child edge process, with no Docker and no
database, and never calls a model:
- tests/security-lab/idor_origin.py: an EMR origin with no object authorization;
- tests/security-lab/fake_jev.py: a scripted Jev endpoint with fixed answers;
- xshield-edge, configured from a sites file written here (XSHIELD_EDGE_SITES_FILE).

Each check compares the status the client received, whether the origin served
the request, and the decision record the edge wrote for that request ID. Where
a scenario expects a refusal, the origin is also asked directly to show that the
refused object really is reachable, so the refusal is the edge's doing.

Usage: python3 scripts/test_idor_lab.py [--only A2,C4]
Exit status is 1 when any check fails. CARGO_TARGET_DIR moves the build output.
"""

from __future__ import annotations

import argparse
import http.client
import json
import secrets
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests/security-lab"))

from fake_jev import FakeJev  # noqa: E402
from idor_origin import PASSWORD, EmrOrigin, new_long_token  # noqa: E402
from labkit import Edge, Sent, build_edge, exchange, free_port  # noqa: E402

ENTRIES = ["/login", "/api/home", "/api/patients", "/share/*"]
# The EMR's object map (docs/01 section 1.4). The search shows every doctor's patients to any
# logged-in doctor (tier public), so a sighting there proves no right to delete a patient, while a
# note on a patient takes such a sighting (accepts_public). Positions take numeric ids only.
EMR_OBJECTS = {
    "classes": [{"id": "patient", "name": "患者"}],
    "slots": [
        {"key": "GET /api/search results[].id", "class": "patient", "source": "admin",
         "tier": "public", "reliability": "high"},
        {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "admin",
         "accepts_public": False, "reliability": "high"},
        {"key": "POST /api/patients/{id}/notes path[2]", "class": "patient", "source": "admin",
         "accepts_public": True, "reliability": "high"},
    ],
}

# The largest address budget the configuration accepts (docs/07 section 7.4.8).
ADDRESS_BUDGET_MAX = 600

# The identity site declares the doctor id of GET /api/home as the session's user (docs/07 7.9.15).
# The other sites declare nothing, so their decision records carry no identity.
IDENTITY_OBJECTS = {
    "classes": [{"id": "doctor", "name": "医生"}],
    "slots": [
        {"key": "GET /api/home doctor.id", "class": "doctor", "source": "admin", "identity": "user"},
        {"key": "GET /api/comments comments[].author.id", "class": "doctor", "source": "admin"},
    ],
}

# The administrator site (docs/07 section 7.4.7). The administrator's search (tier admin) shows the
# patients to administrator sessions only, so it proves a right to delete for them and no one else.
# The public search still proves nothing for a delete, whoever runs it. The home page names the role.
ADMIN_OBJECTS = {
    "classes": [{"id": "patient", "name": "患者"}, {"id": "staff", "name": "员工"}],
    "slots": [
        {"key": "GET /api/search results[].id", "class": "patient", "source": "admin",
         "tier": "public", "reliability": "high"},
        {"key": "GET /api/admin/search results[].id", "class": "patient", "source": "admin",
         "tier": "admin", "reliability": "high"},
        {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "admin",
         "accepts_public": False, "reliability": "high"},
        {"key": "POST /api/patients/{id}/notes path[2]", "class": "patient", "source": "admin",
         "accepts_public": True, "reliability": "high"},
        {"key": "GET /api/home role", "class": "staff", "source": "admin", "identity": "role"},
    ],
}

# The doctor's own patients (docs/07 section 7.4.7). The listing of "my patients" is tier self, so a
# session's own listing proves each patient in it, as an untiered response would, while the public
# search still proves no delete. The DELETE position takes no public source, as in EMR_OBJECTS.
SELF_OBJECTS = {
    "classes": [{"id": "patient", "name": "患者"}],
    "slots": [
        {"key": "GET /api/search results[].id", "class": "patient", "source": "admin",
         "tier": "public", "reliability": "high"},
        {"key": "GET /api/patients patients[].id", "class": "patient", "source": "admin",
         "tier": "self", "reliability": "high"},
        {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "admin",
         "accepts_public": False, "reliability": "high"},
    ],
}
# The function table of the functions site (docs/07 section 7.9.18): three administrator-only
# functions. The medium one tightens nothing (F8).
ADMIN_FUNCTIONS = [
    {"key": "POST /api/admin/export", "source": "admin", "tier": "admin", "reliability": "high"},
    {"key": "DELETE /api/patients/{id}", "source": "admin", "tier": "admin", "reliability": "high"},
    {"key": "GET /api/admin/search", "source": "admin", "tier": "admin", "reliability": "medium"},
]
# Functions every session may use, declared without a tier. The baseline site asks Jev about any
# function it does not list (docs/07 section 7.9.18).
BASELINE_FUNCTIONS = [
    {"key": "POST /login", "source": "admin"},
    {"key": "GET /api/home", "source": "admin"},
    {"key": "GET /api/patients", "source": "admin"},
    {"key": "POST /api/patients", "source": "admin"},
    {"key": "GET /api/patients/{id}", "source": "admin"},
    {"key": "GET /api/search", "source": "admin"},
]
FUNCTIONS_OBJECTS = {**ADMIN_OBJECTS, "functions": ADMIN_FUNCTIONS}
BASELINE_OBJECTS = {**ADMIN_OBJECTS, "functions": BASELINE_FUNCTIONS, "ask_unknown_functions": True}
# The observation site holds both tables and asks about unknown functions (F13).
FOBSERVE_OBJECTS = {
    **ADMIN_OBJECTS,
    "functions": ADMIN_FUNCTIONS + BASELINE_FUNCTIONS,
    "ask_unknown_functions": True,
}


@dataclass(frozen=True)
class Expect:
    """What one request must produce."""

    status: int
    path: str  # decision_path, docs/07 section 7.4
    outcome: str  # allowed, blocked, would_block or unjudged
    origin: bool  # whether the origin served the request
    failure: str | None = None  # jev.failure code, when one is expected


def login_form(user: str) -> dict:
    """A login body. The csrf field is a fresh token, as a real login form sends,
    so identical logins are judged each time instead of served from the allow cache."""
    return {"username": user, "password": PASSWORD, "csrf": secrets.token_hex(8)}


def site_specs(origin_port: int) -> list[dict]:
    """The lab sites. Each variant of docs/04 section 4.3 gets its own host."""
    base = {"origin": f"http://127.0.0.1:{origin_port}", "session": {"cookie": "SID"},
            "entries": ENTRIES, "mode": "enforce"}

    def site(name: str, host: str, **changes: object) -> dict:
        return {"name": name, "hosts": [host], **base, **changes}

    fast_timeout = {"jev_timeout_ms": 100}
    specs = [
        site("emr", "emr.lab", objects=EMR_OBJECTS),
        site("plain", "plain.lab"),
        site("observe", "observe.lab", mode="observe"),
        site("deny-when-down", "deny.lab", advanced=fast_timeout),
        site("allow-when-down", "allow.lab", on_jev_unavailable="allow", advanced=fast_timeout),
        site("limited", "limit.lab", advanced={"session_calls_per_minute": 2}),
        site("identity", "identity.lab", objects=IDENTITY_OBJECTS),
        site("admin", "admin.lab", objects=ADMIN_OBJECTS),
        site("self", "self.lab", objects=SELF_OBJECTS),
        site("functions", "functions.lab", objects=FUNCTIONS_OBJECTS),
        site("baseline", "baseline.lab", objects=BASELINE_OBJECTS),
        site("fobserve", "fobserve.lab", mode="observe", objects=FOBSERVE_OBJECTS),
        # A JSON credential site: the token login returns a long session token in its body, and the
        # session carries it as a bearer token in the Authorization header (docs/01 section 1.7).
        site("token", "token.lab", session={"header": "Authorization"},
             entries=[*ENTRIES, "/api/token-login"]),
    ]
    # Every lab login comes from the same loopback address, and the address budget counts all of
    # them, so a long run would exhaust it and turn later logins into JEV_CALL_LIMIT. The lab tests
    # the session limit (limit.lab), not the address one, so every site takes the largest budget.
    return [{**spec, "advanced": {"address_calls_per_minute": ADDRESS_BUDGET_MAX,
                                  **spec.get("advanced", {})}} for spec in specs]


class Lab:
    """Sends requests through the edge and records every check's result."""

    def __init__(self, origin: EmrOrigin, jev: FakeJev, edge: Edge) -> None:
        self.origin = origin
        self.jev = jev
        self.edge = edge
        self.results: list[tuple[str, str, bool, str]] = []  # (scenario, check, ok, detail)
        self.scenario = ""

    def send(self, host: str, method: str, target: str, *, cookie: str | None = None,
             form: dict[str, str] | None = None, json_body: dict | None = None, body: bytes | None = None,
             headers: dict[str, str] | None = None, authorization: str | None = None,
             source: str | None = None) -> Sent:
        """One request through the edge, from the loopback address `source` when one is given."""
        if authorization:
            headers = {**(headers or {}), "Authorization": authorization}
        return exchange(self.edge, self.origin_was_served, host, method, target, source=source,
                        cookie=cookie, form=form, json_body=json_body, body=body, headers=headers)

    def origin_was_served(self, request_id: str) -> bool:
        return any(served_id == request_id for _, _, served_id in self.origin_served())

    def origin_served(self) -> list[tuple[str, str, str | None]]:
        with self.origin.lock:
            return list(self.origin.served)

    def origin_direct(self, check: str, method: str, target: str, cookie: str = "",
                      authorization: str = "") -> None:
        """Asks the origin without the edge, to show the object is reachable there."""
        headers = {"Content-Length": "0"}
        if cookie:
            headers["Cookie"] = cookie
        if authorization:
            headers["Authorization"] = authorization
        connection = http.client.HTTPConnection("127.0.0.1", self.origin.port, timeout=10)
        try:
            connection.request(method, target, headers=headers)
            status = connection.getresponse().status
        finally:
            connection.close()
        self.check(f"{check}: origin serves it without the edge", status == 200,
                   f"origin answered {status}")

    def login(self, host: str, user: str, check: str = "", source: str | None = None) -> str:
        """Logs `user` in through the edge and returns the SID cookie for later requests."""
        sent = self.send(host, "POST", "/login", json_body=login_form(user), source=source)
        cookie = ""
        for name, value in sent.reply.headers:
            if name.lower() == "set-cookie" and value.startswith("SID="):
                cookie = value.split(";", 1)[0]
        self.expect(check or f"login {user} on {host}", sent,
                    Expect(302, "jev_allow", "allowed", True))
        return cookie

    def expect(self, check: str, sent: Sent, want: Expect) -> Sent:
        problems = []
        record = sent.record or {}
        if sent.reply.status != want.status:
            problems.append(f"status {sent.reply.status}, want {want.status}")
        if record.get("decision_path") != want.path:
            problems.append(f"decision_path {record.get('decision_path')}, want {want.path}")
        if record.get("outcome") != want.outcome:
            problems.append(f"outcome {record.get('outcome')}, want {want.outcome}")
        if sent.served != want.origin:
            problems.append(f"origin served {sent.served}, want {want.origin}")
        if want.failure is not None:
            failure = (record.get("jev") or {}).get("failure")
            if failure != want.failure:
                problems.append(f"jev.failure {failure}, want {want.failure}")
        self.check(check, not problems, "; ".join(problems) or "ok")
        return sent

    def check(self, label: str, ok: bool, detail: str = "ok") -> None:
        self.results.append((self.scenario, label, ok, detail))


def judged_request(lab: Lab, method: str, path: str) -> dict | None:
    """The request Jev was last shown for this method and path (the state's request)."""
    with lab.jev.lock:
        shown = [document["state"]["request"] for document in lab.jev.bodies]
    matching = [request for request in shown if request["method"] == method and request["path"] == path]
    return matching[-1] if matching else None


def judged_value(request: dict | None, value: str) -> dict:
    """The state's entry for one value of a judged request, or {} when Jev was not shown it."""
    return next((item for item in (request or {}).get("values", []) if item.get("value") == value), {})


def traced_value(record: dict | None, value: str) -> dict:
    """The decision record's trace entry for one request value, or {} when it has none."""
    values = ((record or {}).get("trace") or {}).get("values", [])
    return next((item for item in values if item.get("value") == value), {})


SCENARIOS: list[tuple[str, str, Callable[[Lab], None]]] = []


def scenario(code: str, title: str) -> Callable[[Callable[[Lab], None]], Callable[[Lab], None]]:
    def register(function: Callable[[Lab], None]) -> Callable[[Lab], None]:
        SCENARIOS.append((code, title, function))
        return function

    return register


@scenario("A1", "医生 A 浏览我的患者列表后打开患者 B：放行")
def a1(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    lab.expect("list my patients", lab.send("emr.lab", "GET", "/api/patients", cookie=cookie),
               Expect(200, "fast_allow", "allowed", True))
    lab.expect("open patient B", lab.send("emr.lab", "GET", "/api/patients/PT-7002", cookie=cookie),
               Expect(200, "fast_allow", "allowed", True))


@scenario("A2", "医生 A 把地址改成患者 D：拦截")
def a2(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    lab.expect("list my patients", lab.send("emr.lab", "GET", "/api/patients", cookie=cookie),
               Expect(200, "fast_allow", "allowed", True))
    lab.expect("open patient D from the same session", lab.send(
        "emr.lab", "GET", "/api/patients/PT-7004", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    lab.origin_direct("A2 patient D", "GET", "/api/patients/PT-7004", cookie)


@scenario("A3", "医生 A 新开会话，直接打开患者 B：拦截")
def a3(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a", "A3 new session logs in")
    lab.expect("open patient B in the new session", lab.send(
        "emr.lab", "GET", "/api/patients/PT-7002", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    lab.origin_direct("A3 patient B", "GET", "/api/patients/PT-7002", cookie)


@scenario("A4", "医生 A 删除患者 D：拦截")
def a4(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    lab.expect("list my patients", lab.send("emr.lab", "GET", "/api/patients", cookie=cookie),
               Expect(200, "fast_allow", "allowed", True))
    lab.expect("delete patient D", lab.send("emr.lab", "DELETE", "/api/patients/PT-7004", cookie=cookie),
               Expect(403, "jev_deny", "blocked", False))
    # The refused DELETE never reached the origin, so patient D is still there.
    lab.origin_direct("A4 patient D still exists", "GET", "/api/patients/PT-7004", cookie)


@scenario("A5", "医生 A 在“我的患者”接口上加别的医生参数：拦截")
def a5(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    lab.expect("list my patients", lab.send("emr.lab", "GET", "/api/patients", cookie=cookie),
               Expect(200, "fast_allow", "allowed", True))
    lab.expect("list with doctor B's parameter", lab.send(
        "emr.lab", "GET", "/api/patients?doctor=DR-B", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    lab.origin_direct("A5 doctor B's list", "GET", "/api/patients?doctor=DR-B", cookie)


@scenario("A6", "接收者兑换患者 A 的分享码后打开患者 A：放行")
def a6(lab: Lab) -> None:
    owner = lab.login("emr.lab", "doctor_a")
    lab.expect("list my patients", lab.send("emr.lab", "GET", "/api/patients", cookie=owner),
               Expect(200, "fast_allow", "allowed", True))
    shared = lab.expect("owner shares patient A", lab.send(
        "emr.lab", "POST", "/api/patients/PT-7001/share", cookie=owner),
        Expect(201, "fast_allow", "allowed", True))
    code = shared.reply.json().get("code", "MISSING")
    receiver = lab.login("emr.lab", "doctor_c", "A6 receiver logs in")
    lab.expect("receiver redeems the share code", lab.send(
        "emr.lab", "POST", f"/share/{code}", cookie=receiver),
        Expect(200, "jev_allow", "allowed", True))
    lab.expect("receiver opens patient A", lab.send(
        "emr.lab", "GET", "/api/patients/PT-7001", cookie=receiver),
        Expect(200, "fast_allow", "allowed", True))


@scenario("A7", "接收者未兑换分享码，直接打开患者 A：拦截")
def a7(lab: Lab) -> None:
    receiver = lab.login("emr.lab", "doctor_c", "A7 receiver logs in without redeeming")
    lab.expect("receiver opens patient A without the code", lab.send(
        "emr.lab", "GET", "/api/patients/PT-7001", cookie=receiver),
        Expect(403, "jev_deny", "blocked", False))
    lab.origin_direct("A7 patient A", "GET", "/api/patients/PT-7001", receiver)


@scenario("A8", "医生 A 新建患者后打开新患者详情：放行")
def a8(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    created = lab.expect("create a patient", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "林小雨"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    lab.expect("open the new patient", lab.send(
        "emr.lab", "GET", f"/api/patients/{new_id}", cookie=cookie),
        Expect(200, "fast_allow", "allowed", True))
    # The name typed into the new record is input, not an object reference (docs/01 section 1.5).
    with lab.jev.lock:
        judged = [doc["state"]["request"] for doc in lab.jev.bodies]
    create = [request for request in judged
              if request["method"] == "POST" and request["path"] == "/api/patients"][-1]
    kinds = [value["kind"] for value in create["values"] if value["at"] == "body.name"]
    lab.check("Jev was shown the new patient's name as input", kinds == ["input"], f"kinds {kinds}")


@scenario("A9", "医生 A 搜到医生 B 的患者后删除：拦截（越权尝试）；没被搜到的患者仍拦截")
def a9(lab: Lab) -> None:
    # Doctor B owns two patients. Only the first one carries the name doctor A searches for, so the
    # only difference between the two DELETEs is whether the origin showed the patient to doctor A.
    cookie_b = lab.login("emr.lab", "doctor_b", "A9 doctor B logs in")
    shown_id = lab.expect("doctor B creates a patient the search will find", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "搜索靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    hidden_id = lab.expect("doctor B creates a patient the search will not find", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "隐藏靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_a = lab.login("emr.lab", "doctor_a", "A9 doctor A logs in")
    query = "/api/search?q=" + urllib.parse.quote("搜索靶患者", safe="")
    found = lab.expect("doctor A searches by name", lab.send(
        "emr.lab", "GET", query, cookie=cookie_a), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the search shows doctor B's patient to doctor A", shown_id in shown, f"ids {shown}")
    # The search is public: it shows every doctor's patients to any logged-in doctor. The map says
    # so (tier public), and the DELETE position takes no public sighting, so the edge sends the
    # DELETE to Jev as an attempt and Jev denies it (docs/01 section 1.4).
    denied = lab.expect("doctor A deletes the patient the search showed", lab.send(
        "emr.lab", "DELETE", f"/api/patients/{shown_id}", cookie=cookie_a),
        Expect(403, "jev_deny", "blocked", False))
    traced = traced_value(denied.record, shown_id)
    lab.check("the trace names the attempt, the position's access and the search's tier",
              traced.get("attempt") == "over_privilege"
              and traced.get("public_access") == {"accepts": False, "reliability": "high"}
              and (traced.get("sources") or [{}])[0].get("tier") == "public",
              f"trace value {traced}")
    asked = judged_value(judged_request(lab, "DELETE", f"/api/patients/{shown_id}"), shown_id)
    lab.check("Jev was shown the value as an attempt, with the search's tier",
              asked.get("attempt") == "over_privilege"
              and any("(tier public, reliability high)" in seen for seen in asked.get("seen_as", [])),
              f"Jev value {asked}")
    lab.expect("doctor A deletes the patient the search did not show", lab.send(
        "emr.lab", "DELETE", f"/api/patients/{hidden_id}", cookie=cookie_a),
        Expect(403, "jev_deny", "blocked", False))
    with lab.origin.lock:
        kept_shown = shown_id in lab.origin.patients
        kept = hidden_id in lab.origin.patients
    lab.check("the origin kept the patient the search showed", kept_shown, f"{shown_id} is gone")
    lab.check("the origin kept the patient the search did not show", kept, f"{hidden_id} missing")
    lab.origin_direct("A9 the patient the search showed", "GET", f"/api/patients/{shown_id}", cookie_a)


@scenario("A10", "医生 A 搜到医生 B 的患者后写备注：放行（备注位置接受公开来源）")
def a10(lab: Lab) -> None:
    cookie_b = lab.login("emr.lab", "doctor_b", "A10 doctor B logs in")
    shown_id = lab.expect("doctor B creates a patient the search will find", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "备注靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_a = lab.login("emr.lab", "doctor_a", "A10 doctor A logs in")
    query = "/api/search?q=" + urllib.parse.quote("备注靶患者", safe="")
    found = lab.expect("doctor A searches by name", lab.send(
        "emr.lab", "GET", query, cookie=cookie_a), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the search shows the patient to doctor A", shown_id in shown, f"ids {shown}")
    # A note's position takes a public sighting as proof (accepts_public), so the sighting verifies
    # the id: the note is allowed without Jev, and it is no attempt.
    noted = lab.expect("doctor A writes a note on the patient the search showed", lab.send(
        "emr.lab", "POST", f"/api/patients/{shown_id}/notes", cookie=cookie_a),
        Expect(201, "fast_allow", "allowed", True))
    traced = traced_value(noted.record, shown_id)
    lab.check("the note's id is verified by the public sighting and is no attempt",
              traced.get("verified") is True and "attempt" not in traced, f"trace value {traced}")


@scenario("A11", "没有标注层级的站点：同样的搜后删除仍按标注前的判定（Jev 判放行）")
def a11(lab: Lab) -> None:
    # A site whose map gives no tiers judges the search and the delete as it did before tiers existed.
    cookie_b = lab.login("plain.lab", "doctor_b", "A11 doctor B logs in on the plain site")
    shown_id = lab.expect("doctor B creates a patient the search will find", lab.send(
        "plain.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "普通站靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_a = lab.login("plain.lab", "doctor_a", "A11 doctor A logs in on the plain site")
    query = "/api/search?q=" + urllib.parse.quote("普通站靶患者", safe="")
    lab.expect("doctor A searches by name", lab.send(
        "plain.lab", "GET", query, cookie=cookie_a), Expect(200, "jev_allow", "allowed", True))
    lab.expect("doctor A deletes the patient the search showed", lab.send(
        "plain.lab", "DELETE", f"/api/patients/{shown_id}", cookie=cookie_a),
        Expect(200, "jev_allow", "allowed", True))
    asked = judged_value(judged_request(lab, "DELETE", f"/api/patients/{shown_id}"), shown_id)
    lab.check("Jev was shown no tier, no public access and no attempt",
              "attempt" not in asked and "public_access" not in asked
              and not any("tier" in seen for seen in asked.get("seen_as", [])),
              f"Jev value {asked}")
    with lab.origin.lock:
        gone = shown_id not in lab.origin.patients
    lab.check("the origin lost the patient", gone, f"{shown_id} still there")


@scenario("A12", "医生 A 搜到医生 B 的患者 D（慢速 id PT-7004）后删除：拦截（越权尝试，按声明的 {id} 位置判定）")
def a12(lab: Lab) -> None:
    # Patient D has a slug id, so the DELETE of it names no numeric id. The declared {id} position of
    # DELETE is what places it: before that position covered slug ids, the DELETE was taken for an
    # undeclared, open route, and the search's sighting of patient D verified it.
    cookie_a = lab.login("emr.lab", "doctor_a", "A12 doctor A logs in")
    query = "/api/search?q=" + urllib.parse.quote("患者 D", safe="")
    found = lab.expect("doctor A searches for patient D by name", lab.send(
        "emr.lab", "GET", query, cookie=cookie_a), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the search shows doctor B's patient D by its slug id", "PT-7004" in shown, f"ids {shown}")
    # The search is public, so the sighting proves nothing for a delete of a position that takes no
    # public source. The slug id is judged as that position, so Jev sees an attempt and denies it.
    denied = lab.expect("doctor A deletes patient D by the slug id the search showed", lab.send(
        "emr.lab", "DELETE", "/api/patients/PT-7004", cookie=cookie_a),
        Expect(403, "jev_deny", "blocked", False))
    traced = traced_value(denied.record, "PT-7004")
    lab.check("the trace places the slug id at the declared position and names the attempt",
              traced.get("attempt") == "over_privilege"
              and traced.get("slot") == "DELETE /api/patients/{id} path[2]"
              and traced.get("public_access") == {"accepts": False, "reliability": "high"}
              and (traced.get("sources") or [{}])[0].get("tier") == "public",
              f"trace value {traced}")
    asked = judged_value(judged_request(lab, "DELETE", "/api/patients/PT-7004"), "PT-7004")
    lab.check("Jev was shown the slug id as an attempt, with the search's tier",
              asked.get("attempt") == "over_privilege"
              and any("(tier public, reliability high)" in seen for seen in asked.get("seen_as", [])),
              f"Jev value {asked}")
    with lab.origin.lock:
        kept = "PT-7004" in lab.origin.patients
    lab.check("the origin kept patient D", kept, "PT-7004 is gone")
    lab.origin_direct("A12 patient D", "GET", "/api/patients/PT-7004", cookie_a)


@scenario("B1", "搜索框、表单里输入正常中文和英文文本：放行")
def b1(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    query = "/api/search?q=" + urllib.parse.quote("张伟 hello world", safe="")
    lab.expect("search with Chinese and English text", lab.send("emr.lab", "GET", query, cookie=cookie),
               Expect(200, "jev_allow", "allowed", True))
    lab.expect("the same search again is served from the allow cache", lab.send(
        "emr.lab", "GET", query, cookie=cookie),
        Expect(200, "cached_allow", "allowed", True))
    lab.expect("form note with Chinese and English text", lab.send(
        "emr.lab", "POST", "/api/notes", cookie=cookie,
        form={"note": "今天复诊，血压平稳 BP stable"}),
        Expect(201, "jev_allow", "allowed", True))


@scenario("B2", "参数里带注入、命令执行、路径穿越类内容：拦截")
def b2(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    lab.expect("SQL injection in a query", lab.send(
        "emr.lab", "GET", "/api/search?q=" + urllib.parse.quote("' OR 1=1 --", safe=""), cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    lab.expect("path traversal in a query", lab.send(
        "emr.lab", "GET", "/api/search?q=" + urllib.parse.quote("../../etc/passwd", safe=""), cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    lab.expect("command execution in a form", lab.send(
        "emr.lab", "POST", "/api/notes", cookie=cookie, form={"note": "x; cat /etc/passwd"}),
        Expect(403, "jev_deny", "blocked", False))


def long_note_form() -> dict:
    """A note of 24 fields of 420 characters and one of 1,500: its state is cut into two batches or more
    (docs/02 section 2.4), and the request names a patient id in its path."""
    fields = {f"field{index:02d}": "正常的文字" * 84 for index in range(24)}
    fields["remark"] = "正常的文字" * 300
    return fields


@scenario("B3", "医生 A 在搜到的自己新建患者上提交两批以上的长备注：放行，每一批都带着路径里的编号")
def b3(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    patient = lab.expect("doctor A creates a patient", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "分批备注靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    query = "/api/search?q=" + urllib.parse.quote("分批备注靶患者", safe="")
    found = lab.expect("doctor A searches the patient by name", lab.send(
        "emr.lab", "GET", query, cookie=cookie), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the search shows the patient to doctor A", patient in shown, f"ids {shown}")
    noted = lab.expect("doctor A sends the long note on the patient", lab.send(
        "emr.lab", "POST", f"/api/patients/{patient}/notes", cookie=cookie, json_body=long_note_form()),
        Expect(201, "jev_allow", "allowed", True))
    batches = ((noted.record or {}).get("jev") or {}).get("batches") or 0
    lab.check("the note was judged in at least two batches", batches >= 2, f"batches {batches}")


@scenario("B4", "同样的长备注发给医生 B 的患者，医生 A 没见过这个编号：拦截")
def b4(lab: Lab) -> None:
    cookie_b = lab.login("emr.lab", "doctor_b")
    other = lab.expect("doctor B creates a patient", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "他人分批靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_a = lab.login("emr.lab", "doctor_a")
    lab.expect("doctor A sends the same long note on doctor B's patient", lab.send(
        "emr.lab", "POST", f"/api/patients/{other}/notes", cookie=cookie_a, json_body=long_note_form()),
        Expect(403, "jev_deny", "blocked", False))
    lab.origin_direct("B4 patient of doctor B", "GET", f"/api/patients/{other}", cookie_a)


@scenario("B10", "查询串里垫 200 个惰性参数，后面是别的医生的患者编号：拦截")
def b10(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    padding = "&".join(f"pad{index}=x" for index in range(200))
    lab.expect("a patient number of another doctor behind 200 inert parameters", lab.send(
        "emr.lab", "GET", f"/api/search?{padding}&patient_id=PT-7004", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    asked = judged_value(judged_request(lab, "GET", "/api/search"), "PT-7004")
    lab.check("Jev was shown the number as a reference behind the padding",
              asked.get("kind") == "reference" and asked.get("at") == "query.patient_id", f"asked {asked}")


@scenario("B11", "multipart 表单的字段引用别的医生的患者编号：拦截")
def b11(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    boundary = "xshieldlab"
    fields = (("patient_id", "PT-7004"), ("note", "今天复诊，血压平稳"))
    text = "".join(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
                   for name, value in fields) + f"--{boundary}--\r\n"
    lab.expect("multipart form naming another doctor's patient", lab.send(
        "emr.lab", "POST", "/api/notes", cookie=cookie, body=text.encode("utf-8"),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}),
        Expect(403, "jev_deny", "blocked", False))
    asked = judged_value(judged_request(lab, "POST", "/api/notes"), "PT-7004")
    lab.check("Jev was shown the field as a reference",
              asked.get("kind") == "reference" and asked.get("at") == "body.patient_id", f"asked {asked}")


@scenario("B12", "一个值里 600 个字符的填充之后是注入串：拦截")
def b12(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    value = "a" * 600 + "' OR 1=1 --"
    lab.expect("an injection after 600 characters of one value", lab.send(
        "emr.lab", "GET", "/api/search?q=" + urllib.parse.quote(value, safe=""), cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))


@scenario("B13", "120 个字段的正常表单：放行到源站")
def b13(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    fields = {f"field{index:03d}": "正常的值" for index in range(120)}
    lab.expect("a normal form with 120 fields", lab.send(
        "emr.lab", "POST", "/api/notes", cookie=cookie, form=fields),
        Expect(201, "jev_allow", "allowed", True))


@scenario("B14", "没有 Content-Type 的表单，字段引用别的医生的患者编号：拦截")
def b14(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    lab.expect("a form with no content type naming another doctor's patient", lab.send(
        "emr.lab", "POST", "/api/notes", cookie=cookie, body=b"note=routine&patient_id=PT-7004"),
        Expect(403, "jev_deny", "blocked", False))
    asked = judged_value(judged_request(lab, "POST", "/api/notes"), "PT-7004")
    lab.check("Jev was shown the field as a reference",
              asked.get("kind") == "reference" and asked.get("at") == "body.patient_id", f"asked {asked}")


@scenario("B15", "表单类型的请求体同时是能解析的 JSON，表单字段引用别的医生的患者编号：拦截")
def b15(lab: Lab) -> None:
    cookie = lab.login("emr.lab", "doctor_a")
    # The body is JSON and also a form. The origin reads it as a form, so `patient_id` is a field of it.
    lab.expect("a form-typed body that is also JSON names another doctor's patient", lab.send(
        "emr.lab", "POST", "/api/notes", cookie=cookie,
        body=b'{"a":"&note=x&patient_id=PT-7004&b="}',
        headers={"Content-Type": "application/x-www-form-urlencoded"}),
        Expect(403, "jev_deny", "blocked", False))
    asked = judged_value(judged_request(lab, "POST", "/api/notes"), "PT-7004")
    lab.check("Jev was shown the field as a reference",
              asked.get("kind") == "reference" and asked.get("at") == "body.patient_id", f"asked {asked}")


@scenario("C1", "Jev 超时或不可用，on_jev_unavailable=deny：拦截并注明原因")
def c1(lab: Lab) -> None:
    cookie = lab.login("deny.lab", "doctor_a")
    lab.expect("Jev answers 503", lab.send(
        "deny.lab", "GET", "/api/search?q=JEVDOWN", cookie=cookie),
        Expect(403, "jev_unavailable", "blocked", False, failure="JEV_HTTP_ERROR"))
    lab.expect("Jev times out", lab.send(
        "deny.lab", "GET", "/api/search?q=JEVSLOW", cookie=cookie),
        Expect(403, "jev_unavailable", "blocked", False, failure="JEV_TIMEOUT"))


@scenario("C2", "同上，on_jev_unavailable=allow：放行并注明未经判定")
def c2(lab: Lab) -> None:
    cookie = lab.login("allow.lab", "doctor_a")
    lab.expect("Jev answers 503", lab.send(
        "allow.lab", "GET", "/api/search?q=JEVDOWN", cookie=cookie),
        Expect(200, "jev_unavailable", "unjudged", True, failure="JEV_HTTP_ERROR"))
    lab.expect("Jev times out", lab.send(
        "allow.lab", "GET", "/api/search?q=JEVSLOW", cookie=cookie),
        Expect(200, "jev_unavailable", "unjudged", True, failure="JEV_TIMEOUT"))


@scenario("C3", "观察模式下的 A2：转发，日志记“本应拦截”")
def c3(lab: Lab) -> None:
    cookie = lab.login("observe.lab", "doctor_a")
    lab.expect("list my patients", lab.send("observe.lab", "GET", "/api/patients", cookie=cookie),
               Expect(200, "fast_allow", "allowed", True))
    lab.expect("open patient D in observe mode", lab.send(
        "observe.lab", "GET", "/api/patients/PT-7004", cookie=cookie),
        Expect(200, "jev_deny", "would_block", True))


@scenario("C4", "登录请求的口令字段不出现在发给 Jev 的内容里")
def c4(lab: Lab) -> None:
    before = len(lab.jev.bodies)
    sent = lab.send("emr.lab", "POST", "/login", json_body=login_form("doctor_a"))
    lab.expect("login is judged and forwarded", sent, Expect(302, "jev_allow", "allowed", True))
    with lab.jev.lock:
        shown = json.dumps(lab.jev.bodies[before:], ensure_ascii=False)
    logged = json.dumps((sent.record or {}).get("jev") or {}, ensure_ascii=False)
    lab.check("Jev was shown the login with the password redacted",
              "<redacted>" in shown and PASSWORD not in shown,
              "password reached Jev" if PASSWORD in shown else "no redaction marker")
    lab.check("the decision log does not keep the password either",
              PASSWORD not in logged, "password in the decision record")


# The sessions of one address share a total of ten times the session limit (docs/02 section 2.5),
# and every lab request comes from loopback, so the scenarios on limit.lab each use an address of
# their own: the calls of the sessions of the other sites would otherwise count in their total.
@scenario("C5", "同一会话一分钟内超过调用上限：超出部分拒绝并回 429")
def c5(lab: Lab) -> None:
    source = "127.0.0.2"
    cookie = lab.login("limit.lab", "doctor_a", source=source)
    lab.expect("first judged call", lab.send(
        "limit.lab", "POST", "/api/notes", cookie=cookie, form={"note": "第一条"}, source=source),
        Expect(201, "jev_allow", "allowed", True))
    lab.expect("second judged call", lab.send(
        "limit.lab", "POST", "/api/notes", cookie=cookie, form={"note": "第二条"}, source=source),
        Expect(201, "jev_allow", "allowed", True))
    refused = lab.send("limit.lab", "POST", "/api/notes", cookie=cookie, form={"note": "第三条"},
                       source=source)
    lab.expect("third call is over the session limit", refused,
               Expect(429, "jev_unavailable", "blocked", False, failure="JEV_CALL_LIMIT"))
    lab.check("the refusal says rate_limited whatever on_jev_unavailable is",
              refused.reply.json().get("error") == "rate_limited",
              refused.reply.body[:200].decode("utf-8", "replace"))


@scenario("C9", "同一来源地址的会话合计超过单会话上限的 10 倍：超出部分拒绝并回 429，别的地址不受影响")
def c9(lab: Lab) -> None:
    # limit.lab allows 2 calls a minute per session, so 20 for all the sessions of one address.
    source = "127.0.0.3"
    cookies = [lab.login("limit.lab", "doctor_a", f"C9 session {index} logs in", source=source)
               for index in range(11)]
    for index, cookie in enumerate(cookies[:10]):
        for call in range(2):
            lab.expect(f"C9 session {index} call {call + 1}, inside both limits", lab.send(
                "limit.lab", "POST", "/api/notes", cookie=cookie,
                form={"note": f"第{index}个会话的第{call}条"}, source=source),
                Expect(201, "jev_allow", "allowed", True))
    before = len(lab.jev.bodies)
    refused = lab.send("limit.lab", "POST", "/api/notes", cookie=cookies[10],
                       form={"note": "第十一个会话"}, source=source)
    lab.expect("C9 the eleventh session has used no call and is refused for the address total",
               refused, Expect(429, "jev_unavailable", "blocked", False, failure="JEV_CALL_LIMIT"))
    lab.check("C9 the refusal says rate_limited and no call reached Jev",
              refused.reply.json().get("error") == "rate_limited" and len(lab.jev.bodies) == before,
              refused.reply.body[:200].decode("utf-8", "replace"))
    other = lab.login("limit.lab", "doctor_a", "C9 a session of another address logs in",
                      source="127.0.0.4")
    lab.expect("C9 a session of another address is not affected", lab.send(
        "limit.lab", "POST", "/api/notes", cookie=other, form={"note": "另一个地址的笔记"},
        source="127.0.0.4"), Expect(201, "jev_allow", "allowed", True))


@scenario("G1", "JSON 凭证站点：登录响应里的长令牌绑定会话，入口放行；登录响应和列表都没给过的病人交 Jev 拦截")
def g1(lab: Lab) -> None:
    login = lab.expect("token login is judged and forwarded", lab.send(
        "token.lab", "POST", "/api/token-login", json_body=login_form("doctor_a")),
        Expect(200, "jev_allow", "allowed", True))
    token = login.reply.json().get("authentication", {}).get("token", "")
    lab.check("the token is longer than a value is kept", len(token) > 700, f"length {len(token)}")
    bearer = f"Bearer {token}"
    listed = lab.expect("list my patients with the token", lab.send(
        "token.lab", "GET", "/api/patients", authorization=bearer),
        Expect(200, "fast_allow", "allowed", True))
    session = ((listed.record or {}).get("trace") or {}).get("session") or {}
    lab.check("the session is bound to that login", session.get("login_request_id") == login.reply.request_id,
              f"login_request_id {session.get('login_request_id')}, want {login.reply.request_id}")
    lab.check("the binding left no reason for being unbound", session.get("login_unbound") is None,
              f"login_unbound {session.get('login_unbound')}")
    lab.expect("open patient D, which neither the login nor the list showed", lab.send(
        "token.lab", "GET", "/api/patients/PT-7004", authorization=bearer),
        Expect(403, "jev_deny", "blocked", False))
    lab.origin_direct("G1 patient D", "GET", "/api/patients/PT-7004", authorization=bearer)


@scenario("G2", "JSON 凭证站点：源站没发过的长令牌访问入口，判定记录写 login_unmatched")
def g2(lab: Lab) -> None:
    unknown = new_long_token()
    sent = lab.expect("an entry with a token the origin never issued", lab.send(
        "token.lab", "GET", "/api/patients", authorization=f"Bearer {unknown}"),
        Expect(401, "fast_allow", "allowed", True))
    session = ((sent.record or {}).get("trace") or {}).get("session") or {}
    lab.check("no held login carries it, and the record says so",
              session.get("login_unbound") == "login_unmatched",
              f"login_unbound {session.get('login_unbound')}")
    lab.check("no login is bound to the session", session.get("login_request_id") is None,
              f"login_request_id {session.get('login_request_id')}")


@scenario("W1", "声明了身份位置的站点：判定记录带会话的用户标签；换账号标签不同；未声明的站点不写身份")
def w1(lab: Lab) -> None:
    def identity_of(sent: Sent) -> dict:
        session = ((sent.record or {}).get("trace") or {}).get("session") or {}
        return session.get("identity") or {}

    # The first identity response sets the session's user; the next judged request carries it.
    cookie_a = lab.login("identity.lab", "doctor_a", "W1 doctor A logs in on the identity site")
    lab.expect("W1 doctor A opens the home page", lab.send(
        "identity.lab", "GET", "/api/home", cookie=cookie_a), Expect(200, "fast_allow", "allowed", True))
    listed_a = lab.expect("W1 doctor A lists patients", lab.send(
        "identity.lab", "GET", "/api/patients", cookie=cookie_a), Expect(200, "fast_allow", "allowed", True))
    user_a = identity_of(listed_a).get("user", "")
    lab.check("the decision record carries doctor A's user as a 16-digit keyed label",
              len(user_a) == 16 and all(char in "0123456789abcdef" for char in user_a),
              f"identity {identity_of(listed_a)}")
    lab.check("the decision record keeps no doctor id",
              "DR-A" not in json.dumps(listed_a.record, ensure_ascii=False), "DR-A is in the record")

    cookie_b = lab.login("identity.lab", "doctor_b", "W1 doctor B logs in on the identity site")
    lab.expect("W1 doctor B opens the home page", lab.send(
        "identity.lab", "GET", "/api/home", cookie=cookie_b), Expect(200, "fast_allow", "allowed", True))
    listed_b = lab.expect("W1 doctor B lists patients", lab.send(
        "identity.lab", "GET", "/api/patients", cookie=cookie_b), Expect(200, "fast_allow", "allowed", True))
    user_b = identity_of(listed_b).get("user", "")
    lab.check("another account carries another user label", user_b != "" and user_b != user_a,
              f"both {user_a!r} and {user_b!r}")

    cookie_again = lab.login("identity.lab", "doctor_a", "W1 doctor A logs in again")
    lab.expect("W1 doctor A opens the home page again", lab.send(
        "identity.lab", "GET", "/api/home", cookie=cookie_again), Expect(200, "fast_allow", "allowed", True))
    relisted = lab.expect("W1 doctor A lists patients again", lab.send(
        "identity.lab", "GET", "/api/patients", cookie=cookie_again), Expect(200, "fast_allow", "allowed", True))
    lab.check("the same account carries the same user label", identity_of(relisted).get("user") == user_a,
              f"identity {identity_of(relisted)}")

    plain = lab.login("emr.lab", "doctor_a", "W1 doctor A logs in on a site without identity")
    unset = lab.expect("W1 the same list on a site without identity", lab.send(
        "emr.lab", "GET", "/api/patients", cookie=plain), Expect(200, "fast_allow", "allowed", True))
    lab.check("a site without identity positions writes no identity", not identity_of(unset),
              f"identity {identity_of(unset)}")


@scenario("W4a", "管理员在管理档搜索里搜到医生 B 的患者后删除：放行（管理档对管理员会话算正证）")
def w4a(lab: Lab) -> None:
    cookie_b = lab.login("emr.lab", "doctor_b", "W4a doctor B logs in")
    shown_id = lab.expect("doctor B creates a patient the administrator will find", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "管理靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_admin = lab.login("admin.lab", "admin_root", "W4a the administrator logs in")
    lab.expect("W4a the administrator opens the home page", lab.send(
        "admin.lab", "GET", "/api/home", cookie=cookie_admin), Expect(200, "fast_allow", "allowed", True))
    query = "/api/admin/search?q=" + urllib.parse.quote("管理靶患者", safe="")
    found = lab.expect("the administrator searches the administrator listing", lab.send(
        "admin.lab", "GET", query, cookie=cookie_admin), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the administrator listing shows doctor B's patient", shown_id in shown, f"ids {shown}")
    deleted = lab.expect("the administrator deletes the patient the listing showed", lab.send(
        "admin.lab", "DELETE", f"/api/patients/{shown_id}", cookie=cookie_admin),
        Expect(200, "fast_allow", "allowed", True))
    traced = traced_value(deleted.record, shown_id)
    lab.check("the id is verified by the administrator tier and is no attempt",
              traced.get("verified") is True and "attempt" not in traced, f"trace value {traced}")
    with lab.origin.lock:
        gone = shown_id not in lab.origin.patients
    lab.check("the origin deleted the patient", gone, f"{shown_id} is still there")


@scenario("W4b", "管理员没在管理档搜索里见过的患者，直接删除：拦截（角色不是放行理由）")
def w4b(lab: Lab) -> None:
    cookie_b = lab.login("emr.lab", "doctor_b", "W4b doctor B logs in")
    hidden_id = lab.expect("doctor B creates a patient the administrator will not find", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "未搜靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_admin = lab.login("admin.lab", "admin_root", "W4b the administrator logs in")
    lab.expect("W4b the administrator opens the home page", lab.send(
        "admin.lab", "GET", "/api/home", cookie=cookie_admin), Expect(200, "fast_allow", "allowed", True))
    lab.expect("W4b the administrator deletes the patient nobody showed", lab.send(
        "admin.lab", "DELETE", f"/api/patients/{hidden_id}", cookie=cookie_admin),
        Expect(403, "jev_deny", "blocked", False))
    with lab.origin.lock:
        kept = hidden_id in lab.origin.patients
    lab.check("the origin kept the patient nobody showed", kept, f"{hidden_id} is gone")


@scenario("W4c", "管理员在公共搜索里搜到医生 B 的患者后删除：拦截（公共档的见过不证明删除）")
def w4c(lab: Lab) -> None:
    cookie_b = lab.login("emr.lab", "doctor_b", "W4c doctor B logs in")
    shown_id = lab.expect("doctor B creates a patient the public search will find", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "公搜靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_admin = lab.login("admin.lab", "admin_root", "W4c the administrator logs in")
    lab.expect("W4c the administrator opens the home page", lab.send(
        "admin.lab", "GET", "/api/home", cookie=cookie_admin), Expect(200, "fast_allow", "allowed", True))
    query = "/api/search?q=" + urllib.parse.quote("公搜靶患者", safe="")
    found = lab.expect("the administrator searches publicly", lab.send(
        "admin.lab", "GET", query, cookie=cookie_admin), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the public search shows the patient to the administrator", shown_id in shown,
              f"ids {shown}")
    denied = lab.expect("the administrator deletes the patient the public search showed", lab.send(
        "admin.lab", "DELETE", f"/api/patients/{shown_id}", cookie=cookie_admin),
        Expect(403, "jev_deny", "blocked", False))
    traced = traced_value(denied.record, shown_id)
    lab.check("the public sighting is an attempt for the administrator too",
              traced.get("attempt") == "over_privilege", f"trace value {traced}")


@scenario("W4d", "管理员在管理档搜索里搜到患者后写备注（POST 子路径）：放行（备注位置接受公开来源）")
def w4d(lab: Lab) -> None:
    cookie_b = lab.login("emr.lab", "doctor_b", "W4d doctor B logs in")
    shown_id = lab.expect("doctor B creates a patient the administrator will find", lab.send(
        "emr.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "管理备注靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_admin = lab.login("admin.lab", "admin_root", "W4d the administrator logs in")
    # The home page names the administrator's role, which the administrator listing needs.
    lab.expect("W4d the administrator opens the home page", lab.send(
        "admin.lab", "GET", "/api/home", cookie=cookie_admin), Expect(200, "fast_allow", "allowed", True))
    query = "/api/admin/search?q=" + urllib.parse.quote("管理备注靶患者", safe="")
    found = lab.expect("the administrator searches the administrator listing", lab.send(
        "admin.lab", "GET", query, cookie=cookie_admin), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the administrator listing shows the patient", shown_id in shown, f"ids {shown}")
    noted = lab.expect("the administrator writes a note on the patient the listing showed", lab.send(
        "admin.lab", "POST", f"/api/patients/{shown_id}/notes", cookie=cookie_admin),
        Expect(201, "fast_allow", "allowed", True))
    traced = traced_value(noted.record, shown_id)
    lab.check("the note's id is verified by the administrator tier and is no attempt",
              traced.get("verified") is True and "attempt" not in traced, f"trace value {traced}")


@scenario("W4e", "本人档：声明“我的患者”为 self 的站点上，医生 A 打开和删除自己的患者：放行（本人档的展示证明会话见过对象）")
def w4e(lab: Lab) -> None:
    # Doctor A creates a patient in one session; a new session then lists her patients. The listing
    # is tier self, so it proves each patient in it, and opening or deleting one needs no Jev call.
    cookie_first = lab.login("self.lab", "doctor_a", "W4e doctor A logs in on the self site")
    own_id = lab.expect("W4e doctor A creates a patient", lab.send(
        "self.lab", "POST", "/api/patients", cookie=cookie_first, json_body={"name": "本人档自己靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie = lab.login("self.lab", "doctor_a", "W4e doctor A logs in again, with nothing shown yet")
    listed = lab.expect("W4e doctor A lists her patients", lab.send(
        "self.lab", "GET", "/api/patients", cookie=cookie), Expect(200, "fast_allow", "allowed", True))
    listed_ids = [item.get("id") for item in listed.reply.json().get("patients", [])]
    lab.check("the own listing shows the new patient", own_id in listed_ids, f"ids {listed_ids}")
    lab.expect("W4e doctor A opens the patient her listing showed", lab.send(
        "self.lab", "GET", f"/api/patients/{own_id}", cookie=cookie),
        Expect(200, "fast_allow", "allowed", True))
    lab.expect("W4e doctor A deletes the patient her listing showed", lab.send(
        "self.lab", "DELETE", f"/api/patients/{own_id}", cookie=cookie),
        Expect(200, "fast_allow", "allowed", True))
    with lab.origin.lock:
        gone = own_id not in lab.origin.patients
    lab.check("the origin deleted the patient", gone, f"{own_id} is still there")


@scenario("W4f", "本人档：同一站点上，医生 A 搜到医生 B 的患者后删除：拦截（越权尝试，本人档不放行别人的患者）")
def w4f(lab: Lab) -> None:
    cookie_b = lab.login("self.lab", "doctor_b", "W4f doctor B logs in on the self site")
    shown_id = lab.expect("W4f doctor B creates a patient the search will find", lab.send(
        "self.lab", "POST", "/api/patients", cookie=cookie_b, json_body={"name": "本人档他人靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    cookie_a = lab.login("self.lab", "doctor_a", "W4f doctor A logs in on the self site")
    query = "/api/search?q=" + urllib.parse.quote("本人档他人靶患者", safe="")
    found = lab.expect("W4f doctor A searches by name", lab.send(
        "self.lab", "GET", query, cookie=cookie_a), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the search shows doctor B's patient to doctor A", shown_id in shown, f"ids {shown}")
    denied = lab.expect("W4f doctor A deletes the patient the search showed", lab.send(
        "self.lab", "DELETE", f"/api/patients/{shown_id}", cookie=cookie_a),
        Expect(403, "jev_deny", "blocked", False))
    traced = traced_value(denied.record, shown_id)
    lab.check("the trace names the attempt and the search's tier",
              traced.get("attempt") == "over_privilege"
              and (traced.get("sources") or [{}])[0].get("tier") == "public",
              f"trace value {traced}")
    asked = judged_value(judged_request(lab, "DELETE", f"/api/patients/{shown_id}"), shown_id)
    lab.check("Jev was shown the value as an attempt, with the search's tier",
              asked.get("attempt") == "over_privilege"
              and any("(tier public, reliability high)" in seen for seen in asked.get("seen_as", [])),
              f"Jev value {asked}")
    with lab.origin.lock:
        kept = shown_id in lab.origin.patients
    lab.check("the origin kept doctor B's patient", kept, f"{shown_id} is gone")


@scenario("W4g", "本人档：医生 A 先在搜索里搜到自己的患者（删除被拦），它出现在“我的患者”里之后再删除：放行")
def w4g(lab: Lab) -> None:
    cookie_first = lab.login("self.lab", "doctor_a", "W4g doctor A logs in on the self site")
    own_id = lab.expect("W4g doctor A creates a patient of her own", lab.send(
        "self.lab", "POST", "/api/patients", cookie=cookie_first, json_body={"name": "本人档先搜后列表靶患者"}),
        Expect(201, "jev_allow", "allowed", True)).reply.json().get("id", "MISSING")
    # A new session has seen nothing yet: the search is the only response that shows the patient.
    cookie = lab.login("self.lab", "doctor_a", "W4g doctor A logs in again, with nothing shown yet")
    query = "/api/search?q=" + urllib.parse.quote("本人档先搜后列表靶患者", safe="")
    found = lab.expect("W4g doctor A searches for her patient", lab.send(
        "self.lab", "GET", query, cookie=cookie), Expect(200, "jev_allow", "allowed", True))
    shown = [item.get("id") for item in found.reply.json().get("results", [])]
    lab.check("the search shows the patient", own_id in shown, f"ids {shown}")
    lab.expect("W4g the delete before her listing showed it is an attempt", lab.send(
        "self.lab", "DELETE", f"/api/patients/{own_id}", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    listed = lab.expect("W4g doctor A lists her patients", lab.send(
        "self.lab", "GET", "/api/patients", cookie=cookie), Expect(200, "fast_allow", "allowed", True))
    listed_ids = [item.get("id") for item in listed.reply.json().get("patients", [])]
    lab.check("the own listing shows the patient", own_id in listed_ids, f"ids {listed_ids}")
    deleted = lab.expect("W4g doctor A deletes the patient after her listing showed it", lab.send(
        "self.lab", "DELETE", f"/api/patients/{own_id}", cookie=cookie),
        Expect(200, "fast_allow", "allowed", True))
    traced = traced_value(deleted.record, own_id)
    lab.check("the own listing verifies the id, and it is no attempt any more",
              traced.get("verified") is True and "attempt" not in traced, f"trace value {traced}")
    with lab.origin.lock:
        gone = own_id not in lab.origin.patients
    lab.check("the origin deleted the patient", gone, f"{own_id} is still there")


@scenario("W6", "评论作者是另一位医生且资料带手机号、邮箱：记一条属性越权告警，请求照常放行；自己的资料和未声明身份的站点不告警")
def w6(lab: Lab) -> None:
    def response_of(sent: Sent) -> dict:
        return ((sent.record or {}).get("trace") or {}).get("response") or {}

    def exposure_of(sent: Sent) -> dict | None:
        return response_of(sent).get("exposure")

    cookie = lab.login("identity.lab", "doctor_a", "W6 doctor A logs in on the identity site")
    lab.expect("W6 doctor A opens the home page", lab.send(
        "identity.lab", "GET", "/api/home", cookie=cookie), Expect(200, "fast_allow", "allowed", True))
    lab.expect("W6 doctor A lists her patients", lab.send(
        "identity.lab", "GET", "/api/patients", cookie=cookie), Expect(200, "fast_allow", "allowed", True))
    shown = lab.expect("W6 doctor A reads the comments on her patient PT-7001", lab.send(
        "identity.lab", "GET", "/api/comments?patient=PT-7001", cookie=cookie),
        Expect(200, "fast_allow", "allowed", True))
    exposure = exposure_of(shown) or {}
    lab.check("the alert names the author position of the other doctor",
              exposure.get("users") == ["GET /api/comments comments[].author.id"], f"exposure {exposure}")
    lab.check("the alert names the phone and the email by their field names",
              sorted((item["kind"], item["by"], item["slot"]) for item in exposure.get("attributes", [])) == [
                  ("email", "name", "GET /api/comments comments[].author.email"),
                  ("phone", "name", "GET /api/comments comments[].author.phone")],
              f"exposure {exposure}")
    lab.check("the decision record keeps no contact detail",
              not any(value in json.dumps(shown.record, ensure_ascii=False)
                      for value in ("13800000002", "dr-b@emr.example")), "a contact detail is in the record")

    own = lab.expect("W6 doctor A reads the comments on her patient PT-7002", lab.send(
        "identity.lab", "GET", "/api/comments?patient=PT-7002", cookie=cookie),
        Expect(200, "fast_allow", "allowed", True))
    lab.check("her own contact details in a comment raise no alert", "exposure" not in response_of(own),
              f"exposure {exposure_of(own)}")

    plain = lab.login("emr.lab", "doctor_a", "W6 doctor A logs in on a site without identity")
    lab.expect("W6 the same patients on a site without identity", lab.send(
        "emr.lab", "GET", "/api/patients", cookie=plain), Expect(200, "fast_allow", "allowed", True))
    unset = lab.expect("W6 the same comments on a site without identity", lab.send(
        "emr.lab", "GET", "/api/comments?patient=PT-7001", cookie=plain),
        Expect(200, "fast_allow", "allowed", True))
    lab.check("a site without identity positions writes no exposure key", "exposure" not in response_of(unset),
              f"exposure {exposure_of(unset)}")

def jev_calls(lab: Lab) -> int:
    """How many judgements Jev has been asked so far."""
    with lab.jev.lock:
        return len(lab.jev.bodies)


def function_of(record: dict | None) -> dict | None:
    """The trace's function of one decision record (docs/07 section 7.4.3), or None when it has none."""
    return ((record or {}).get("trace") or {}).get("function")


def judged_state(lab: Lab, method: str, path: str) -> dict:
    """The state Jev was last shown for this method and path, or {} when Jev was not asked about it."""
    with lab.jev.lock:
        states = [document["state"] for document in lab.jev.bodies]
    matching = [state for state in states
                if state["request"]["method"] == method and state["request"]["path"] == path]
    return matching[-1] if matching else {}


@scenario("F5", "医生 POST /api/admin/export（管理档功能，非管理员）：交 Jev 判为越权尝试，拦截，源站没收到")
def f5(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F5 doctor A logs in")
    denied = lab.expect("F5 doctor A exports", lab.send(
        "functions.lab", "POST", "/api/admin/export", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    shown = (judged_state(lab, "POST", "/api/admin/export").get("request") or {})
    lab.check("F5 Jev is shown the function as an over-privilege attempt",
              shown.get("function") == {"tier": "admin", "attempt": "over_privilege"},
              f"function {shown.get('function')}")
    traced = function_of(denied.record) or {}
    lab.check("F5 the trace names the function, its tier and the attempt",
              traced.get("key") == "POST /api/admin/export" and traced.get("entry") == "POST /api/admin/export"
              and traced.get("tier") == "admin" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F5b", "医生 POST 并带 X-HTTP-Method-Override: DELETE：按更严的 DELETE 判为越权尝试，拦截")
def f5b(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F5b doctor A logs in")
    created = lab.expect("F5b doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "覆盖靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    overridden = lab.expect("F5b the request overrides its method to DELETE", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie,
        headers={"X-HTTP-Method-Override": "DELETE"}), Expect(403, "jev_deny", "blocked", False))
    traced = function_of(overridden.record) or {}
    lab.check("F5b the trace keys the request by POST and names the DELETE function",
              traced.get("key") == "POST /api/patients/{id}" and traced.get("entry") == "DELETE /api/patients/{id}"
              and traced.get("attempt") == "over_privilege", f"trace function {traced}")


@scenario("F6", "管理员 admin_root 访问管理功能：放行，不交 Jev，记录带档位但没有尝试")
def f6(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "admin_root", "F6 the administrator logs in")
    lab.expect("F6 the administrator opens the home page", lab.send(
        "functions.lab", "GET", "/api/home", cookie=cookie), Expect(200, "fast_allow", "allowed", True))
    before = jev_calls(lab)
    exported = lab.expect("F6 the administrator exports", lab.send(
        "functions.lab", "POST", "/api/admin/export", cookie=cookie), Expect(200, "fast_allow", "allowed", True))
    lab.check("F6 Jev is not asked about the administrator's export", jev_calls(lab) == before,
              f"{jev_calls(lab) - before} new calls")
    traced = function_of(exported.record) or {}
    lab.check("F6 the trace names the administrator tier and no attempt",
              traced.get("tier") == "admin" and "attempt" not in traced, f"trace function {traced}")


@scenario("F7", "医生新建患者后 DELETE 它：值已核验，仍因管理档功能拦截（越权尝试不快速放行）")
def f7(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F7 doctor A logs in")
    created = lab.expect("F7 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "删除靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    lab.expect("F7 doctor A deletes the patient she created", lab.send(
        "functions.lab", "DELETE", f"/api/patients/{new_id}", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    shown = (judged_state(lab, "DELETE", f"/api/patients/{new_id}").get("request") or {})
    values = [value for value in shown.get("values", []) if value.get("value") == new_id]
    lab.check("F7 the id is verified and Jev is shown the attempt",
              len(values) == 1 and values[0].get("verified") is True
              and shown.get("function") == {"tier": "admin", "attempt": "over_privilege"},
              f"values {values} function {shown.get('function')}")


@scenario("F8", "医生 GET /api/admin/search（管理档可靠性为 medium）：不收紧，与没有条目时相同")
def f8(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F8 doctor A logs in")
    searched = lab.expect("F8 doctor A opens the administrator search", lab.send(
        "functions.lab", "GET", "/api/admin/search?q=x", cookie=cookie),
        Expect(403, "fast_allow", "allowed", True))
    lab.check("F8 the trace has no function", function_of(searched.record) is None,
              f"trace function {function_of(searched.record)}")


@scenario("F9", "医生 GET /metrics（基线外的功能，站点要求交 Jev）：交 Jev 判为运维，拦截")
def f9(lab: Lab) -> None:
    cookie = lab.login("baseline.lab", "doctor_a", "F9 doctor A logs in on the baseline site")
    denied = lab.expect("F9 doctor A reads the metrics", lab.send(
        "baseline.lab", "GET", "/metrics", cookie=cookie), Expect(403, "jev_deny", "blocked", False))
    shown = (judged_state(lab, "GET", "/metrics").get("request") or {})
    lab.check("F9 Jev is shown the function as unknown", shown.get("function") == {"known": False},
              f"function {shown.get('function')}")
    traced = function_of(denied.record) or {}
    lab.check("F9 the trace names the function as unknown and no entry",
              traced.get("key") == "GET /metrics" and traced.get("known") is False and "entry" not in traced,
              f"trace function {traced}")


@scenario("F10", "医生 GET /api/comments（基线外）两次：第一次交 Jev 放行，第二次走放行缓存")
def f10(lab: Lab) -> None:
    cookie = lab.login("baseline.lab", "doctor_a", "F10 doctor A logs in on the baseline site")
    lab.expect("F10 doctor A reads the comments", lab.send(
        "baseline.lab", "GET", "/api/comments", cookie=cookie), Expect(200, "jev_allow", "allowed", True))
    shown = (judged_state(lab, "GET", "/api/comments").get("request") or {})
    lab.check("F10 Jev is shown the function as unknown", shown.get("function") == {"known": False},
              f"function {shown.get('function')}")
    before = jev_calls(lab)
    lab.expect("F10 doctor A reads the comments again", lab.send(
        "baseline.lab", "GET", "/api/comments", cookie=cookie), Expect(200, "cached_allow", "allowed", True))
    lab.check("F10 the second read asks Jev nothing", jev_calls(lab) == before,
              f"{jev_calls(lab) - before} new calls")


@scenario("F11", "不带凭证访问入口路径 DELETE /api/patients（基线里没有这个方法）：交 Jev，放行后源站答 401")
def f11(lab: Lab) -> None:
    lab.expect("F11 an anonymous delete on an entry path", lab.send(
        "baseline.lab", "DELETE", "/api/patients"), Expect(401, "jev_allow", "allowed", True))
    state = judged_state(lab, "DELETE", "/api/patients")
    lab.check("F11 Jev is shown an entry request whose function is unknown",
              state.get("entry") == {"matched": True}
              and (state.get("request") or {}).get("function") == {"known": False},
              f"state {state}")


@scenario("F12", "没有功能表的站点：医生 POST /api/admin/export 与 GET /metrics 照旧快速放行（对照 F5、F9）")
def f12(lab: Lab) -> None:
    cookie = lab.login("admin.lab", "doctor_a", "F12 doctor A logs in on the administrator site")
    before = jev_calls(lab)
    exported = lab.expect("F12 doctor A exports on a site without a table", lab.send(
        "admin.lab", "POST", "/api/admin/export", cookie=cookie), Expect(200, "fast_allow", "allowed", True))
    metrics = lab.expect("F12 doctor A reads the metrics on a site without a table", lab.send(
        "admin.lab", "GET", "/metrics", cookie=cookie), Expect(404, "fast_allow", "allowed", True))
    lab.check("F12 Jev is not asked", jev_calls(lab) == before, f"{jev_calls(lab) - before} new calls")
    lab.check("F12 the records carry no function",
              function_of(exported.record) is None and function_of(metrics.record) is None,
              f"trace functions {function_of(exported.record)} {function_of(metrics.record)}")


# The query of F16: 230 values, so that the `_method` field comes after the 200th value of the request.
LATE_METHOD_QUERY = "&".join(f"k{i}=v{i}" for i in range(230)) + "&_method=DELETE"


@scenario("F16", "医生 POST /api/patients/{新编号}，_method=DELETE 排在 200 个值之后：按更严的 DELETE 判为越权尝试，拦截")
def f16(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F16 doctor A logs in")
    created = lab.expect("F16 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "后置方法靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    late = lab.expect("F16 doctor A posts with a late _method field", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}?{LATE_METHOD_QUERY}", cookie=cookie),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(late.record) or {}
    lab.check("F16 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F17", "医生 POST multipart/form-data，_method 是一个文本字段，值 DELETE：读到的字段按更严的 DELETE 判为越权尝试，拦截")
def f17(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F17 doctor A logs in")
    created = lab.expect("F17 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "表单方法靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    body = (b'--lab\r\nContent-Disposition: form-data; name="note"\r\n\r\nx\r\n'
            b'--lab\r\nContent-Disposition: form-data; name="_method"\r\n\r\nDELETE\r\n--lab--\r\n')
    part = lab.expect("F17 doctor A posts a multipart form with a _method field", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie, body=body,
        headers={"Content-Type": "multipart/form-data; boundary=lab"}),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(part.record) or {}
    lab.check("F17 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F18", "医生 POST 不带 Content-Type，请求体 note=hello world&_method=DELETE：带空格，网关按字段读到 _method，按 DELETE 判为越权尝试，拦截")
def f18(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F18 doctor A logs in")
    created = lab.expect("F18 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "无类型靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    untyped = lab.expect("F18 doctor A posts a spaced body with no content type that names _method", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie, body=b"note=hello world&_method=DELETE"),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(untyped.record) or {}
    lab.check("F18 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F19", "医生 POST 不带 Content-Type，请求体 note=x&_method=DELETE 像表单：读成字段，按 DELETE 判为越权尝试，拦截")
def f19(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F19 doctor A logs in")
    created = lab.expect("F19 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "表单无类型靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    form = lab.expect("F19 doctor A posts a form-shaped body with no content type that names _method", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie, body=b"note=x&_method=DELETE"),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(form.record) or {}
    lab.check("F19 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F20", "医生 POST 表单类型，请求体能解析成 JSON（含 &_method=DELETE&）：源站可能按表单读到 _method，按更严的 DELETE 判为越权尝试，拦截")
def f20(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F20 doctor A logs in")
    created = lab.expect("F20 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "JSON 形状靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    shaped = lab.expect("F20 doctor A posts a JSON-shaped body typed as a form that names _method", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, body=b'{"a":"&_method=DELETE&b="}'),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(shaped.record) or {}
    lab.check("F20 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F21", "医生 POST 不带 Content-Type，请求体 note=x;%5Fm%65thod=DELETE：带分号不像表单，按文字读，_method 的一个字母做了百分号编码，解码一遍后按 DELETE 判为越权尝试，拦截")
def f21(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F21 doctor A logs in")
    created = lab.expect("F21 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "编码无类型靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    spelled = lab.expect("F21 doctor A posts a body with no content type that spells _method with an escape after a semicolon", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie, body=b"note=x;%5Fm%65thod=DELETE"),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(spelled.record) or {}
    lab.check("F21 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F22", "医生 POST 不带 Content-Type，请求体 note=x;_method=DELETE 带分号：不像表单，按文字读，按更严的 DELETE 判为越权尝试，拦截")
def f22(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F22 doctor A logs in")
    created = lab.expect("F22 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "分号无类型靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    semicolon = lab.expect("F22 doctor A posts a body with no content type that names _method after a semicolon", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie, body=b"note=x;_method=DELETE"),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(semicolon.record) or {}
    lab.check("F22 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F23", "医生 POST 不带 Content-Type，请求体 note=hello world&%5Fm%65thod=DELETE：带空格，网关按字段读到解码后的 _method，按 DELETE 判为越权尝试，拦截")
def f23(lab: Lab) -> None:
    cookie = lab.login("functions.lab", "doctor_a", "F23 doctor A logs in")
    created = lab.expect("F23 doctor A creates a patient", lab.send(
        "functions.lab", "POST", "/api/patients", cookie=cookie, json_body={"name": "编码空格无类型靶患者"}),
        Expect(201, "jev_allow", "allowed", True))
    new_id = created.reply.json().get("id", "MISSING")
    escaped = lab.expect("F23 doctor A posts a spaced body with no content type that spells _method with an escape", lab.send(
        "functions.lab", "POST", f"/api/patients/{new_id}", cookie=cookie, body=b"note=hello world&%5Fm%65thod=DELETE"),
        Expect(403, "jev_deny", "blocked", False))
    traced = function_of(escaped.record) or {}
    lab.check("F23 the trace names DELETE /api/patients/{id} as the over-privilege attempt",
              traced.get("entry") == "DELETE /api/patients/{id}" and traced.get("attempt") == "over_privilege",
              f"trace function {traced}")


@scenario("F13", "观察模式的功能表站点：医生 POST /api/admin/export 与 GET /metrics 都转发，记为本应拦截")
def f13(lab: Lab) -> None:
    cookie = lab.login("fobserve.lab", "doctor_a", "F13 doctor A logs in on the observation site")
    lab.expect("F13 the export would be blocked", lab.send(
        "fobserve.lab", "POST", "/api/admin/export", cookie=cookie), Expect(200, "jev_deny", "would_block", True))
    lab.expect("F13 the metrics read would be blocked", lab.send(
        "fobserve.lab", "GET", "/metrics", cookie=cookie), Expect(404, "jev_deny", "would_block", True))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--only", default="", help="comma separated scenario codes, e.g. A2,C4")
    arguments = parser.parse_args()
    wanted = {code.strip().upper() for code in arguments.only.split(",") if code.strip()}
    selected = [item for item in SCENARIOS if not wanted or item[0].upper() in wanted]
    if not selected:
        print(f"no scenario matches {arguments.only!r}", file=sys.stderr)
        return 2

    build_edge()
    origin = EmrOrigin()
    jev = FakeJev()
    origin.start()
    jev.start()
    edge = None
    with tempfile.TemporaryDirectory(prefix="xshield-lab-") as directory:
        sites = Path(directory) / "sites.json"
        sites.write_text(json.dumps(site_specs(origin.port), ensure_ascii=False), encoding="utf-8")
        try:
            edge = Edge(sites, jev.url, free_port())
            lab = Lab(origin, jev, edge)
            for code, title, function in selected:
                lab.scenario = code
                print(f"{code} {title}")
                try:
                    function(lab)
                except Exception as error:  # a crashed scenario is a failed one
                    lab.check(f"{code} ran to the end", False, f"{type(error).__name__}: {error}")
            failed = [row for row in lab.results if not row[2]]
            for scenario_code, label, ok, detail in lab.results:
                marker = "ok  " if ok else "FAIL"
                print(f"  [{marker}] {label}" + ("" if ok else f" -- {detail}"))
            print(f"{len(lab.results) - len(failed)}/{len(lab.results)} checks passed")
            if failed:
                print("edge stderr (last lines):", file=sys.stderr)
                print("\n".join(edge.stderr_tail()), file=sys.stderr)
                return 1
            return 0
        finally:
            if edge is not None:
                edge.stop()
            origin.stop()
            jev.stop()


if __name__ == "__main__":
    sys.exit(main())

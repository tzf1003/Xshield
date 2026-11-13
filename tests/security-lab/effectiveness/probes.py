"""Probes of the protection segment (plan 4.3): object-level attacks, injection points and benign text.

A probe is one conversation with one site of the gateway. Its setup requests are sent but not scored; each
scored request becomes one observation row in the format of plan 9.1. Every probe logs in on its own and sends
from an address of the pool, so neither the gateway's allow cache nor a per-address budget can carry a result
from one probe into the next (plan 4.3). The objects a probe names come from the origin's own data, so another
seed changes the ids and keeps the case.

Stdlib only. The lab's transport is labkit; the origin is clinic_origin.ClinicOrigin.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import labkit
from clinic_origin import PASSWORD, ClinicOrigin
from fake_jev import FakeJev

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
DOCTOR_A, DOCTOR_B, DOCTOR_C = "101", "102", "103"  # A and B are in different departments (clinic_origin)
ADMIN = "admin_1"
# The injection points of plan 4.3. The path point is one segment of the entry /share/, which needs no session.
ATTACK_POINTS = ("search", "json", "form", "path")
# A benign text that holds one of these is not sent to the path point: it would change the route (plan 4.3).
PATH_SEPARATORS = ("/", "\\")
# Probes send from 127.0.1.20 to 127.0.1.99. The training journeys use 127.0.1.1 to 127.0.1.12 and .101, .102.
POOL_FIRST, POOL_SIZE = 20, 80


class ProbeError(RuntimeError):
    """The origin's data or the gateway's answer does not give the probe what it needs. The lab stops."""


# Corpus -------------------------------------------------------------------------------------------------

def corpus(name: str) -> list[dict[str, Any]]:
    text = (CORPUS / name).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def quick_attacks() -> list[dict[str, Any]]:
    return [row for row in corpus("attacks.jsonl") if row["quick"]]


def quick_benign() -> list[dict[str, Any]]:
    return [row for row in corpus("benign.jsonl") if row["quick"]]


def attack_texts() -> tuple[str, ...]:
    """The whole attack corpus: the ideal model of plan 6 knows every attack text, quick or not."""
    return tuple(row["text"] for row in corpus("attacks.jsonl"))


def first_attack(cls: str = "sqli", *, ascii_only: bool = False) -> str:
    """The first quick attack of a class. ascii_only picks one a header value can carry."""
    for row in quick_attacks():
        text = row["text"]
        if row["class"] == cls and (not ascii_only or (text.isascii() and "\n" not in text and "\r" not in text)):
            return text
    raise ProbeError(f"the quick corpus has no {cls} attack for this probe")


# Sites, sessions and the probe context ------------------------------------------------------------------

@dataclass(frozen=True)
class Site:
    """One site of the gateway, and the origin behind it. Every site has an origin of its own (see lab.py)."""

    name: str  # the site name in the sites file, for example clinic-truth
    config: str  # none or truth: the object map the site declares (plan 3.3)
    mode: str  # enforce or observe
    origin: ClinicOrigin

    @property
    def host(self) -> str:
        return f"{self.name}.lab"


@dataclass
class Score:
    """The case a scored request belongs to: the observation fields that describe the expectation."""

    case: str
    group: str  # attack, benign or regression
    category: str
    expect: str  # block or allow
    reason: str | None = None  # access, attack, no_session or limit, for a block
    status: str = "must"  # must or known_gap (regressions only)
    ref: str | None = None
    requires: tuple[str, ...] = ()
    note: str = ""


@dataclass
class Session:
    source: str | None
    token: str | None = None


class Pool:
    """Source addresses handed out in turn, one per session (see POOL_FIRST)."""

    def __init__(self) -> None:
        self.count = 0

    def next(self) -> str | None:
        index = POOL_FIRST + self.count % POOL_SIZE
        self.count += 1
        return labkit.loopback_source(index)


class Prober:
    """Sends the requests of the probes to one site and keeps the observation rows they score."""

    def __init__(self, edge: labkit.Edge, site: Site, pool: Pool, *, jev: FakeJev | None = None,
                 run: int = 1, only: frozenset[str] = frozenset()) -> None:
        self.edge = edge
        self.site = site
        self.pool = pool
        self.jev = jev  # the ideal model, whose states answer "did the payload reach Jev"; None when live
        self.run = run
        self.only = only
        self.rows: list[dict[str, Any]] = []
        self.setup: list[str] = []
        self.meta: Score | None = None
        # Payloads that were not sent at the path point, by group, because they do not fit one segment.
        self.unsent: dict[str, int] = {"attack": 0, "benign": 0}

    def begin(self, meta: Score) -> None:
        """Starts one probe. Its setup requests are the ones sent after this call and before a scored one."""
        self.meta = meta
        self.setup = []

    def wants(self, meta: Score) -> bool:
        """Whether a case is selected by --only (a case name, its category or its family)."""
        if not self.only:
            return True
        return bool({meta.case, meta.category, meta.case.split("/", 1)[0]} & self.only)

    def login(self, account: str) -> Session:
        session = Session(source=self.pool.next())
        sent = self.request(session, "POST", "/login", form={"username": account, "password": PASSWORD})
        session.token = _session_cookie(sent)
        return session

    def renew(self, session: Session, sent: labkit.Sent) -> None:
        """Takes the credential a response names: the refresh answer replaces the session's SID."""
        token = _session_cookie(sent)
        if token:
            session.token = token

    def request(self, session: Session | None, method: str, target: str, *, scored: bool = False,
                refs: Iterable[tuple[str, str]] = (), carry: str | None = None, cookie: str | None = None,
                **options: Any) -> labkit.Sent:
        """One request to the site. `refs` are the (class, value) pairs the scorer checks (S1, S2) and `carry`
        is the text whose arrival at Jev is recorded as `delivered`."""
        if session is None:
            session = Session(source=self.pool.next())
        if cookie is None and session.token:
            cookie = f"SID={session.token}"
        if cookie is not None:
            options["cookie"] = cookie
        # What the origin had shown this credential before the request is sent (plan 3.1).
        states = [(cls, value, self.site.origin.reference_state(session.token, cls, value)) for cls, value in refs]
        before = len(self.jev.states) if self.jev is not None else 0
        sent = labkit.exchange(self.edge, self.site.origin.was_served, self.site.host, method, target,
                               source=session.source, **options)
        if scored:
            self._score(sent, states, before, carry)
        elif sent.reply.request_id:
            self.setup.append(sent.reply.request_id)
        return sent

    def _score(self, sent: labkit.Sent, states: list[tuple[str, str, dict[str, bool]]], before: int,
               carry: str | None) -> None:
        meta = self.meta
        if meta is None:
            raise ProbeError("a scored request was sent before begin()")
        if not self.wants(meta):
            return
        delivered = None
        if carry is not None and carry.strip() and self.jev is not None:
            try:
                delivered = self.jev.carries(carry, since=before)
            except ValueError:  # the text normalises to nothing, so no judgement can show it
                delivered = None
        self.rows.append({
            "case": meta.case, "group": meta.group, "category": meta.category,
            "expect": meta.expect, "reason": meta.reason if meta.expect == "block" else None,
            "status": meta.status, "ref": meta.ref,
            "config": self.site.config, "site": self.site.name, "mode": self.site.mode, "run": self.run,
            "request_id": sent.reply.request_id or "", "setup_request_ids": list(self.setup),
            "client_status": sent.reply.status, "origin_served": sent.served,
            "refs": [{"value": value, "class": cls, "shown": state["shown"], "echoed": state["echoed"]}
                     for cls, value, state in states],
            "requires": list(meta.requires), "note": meta.note, "delivered": delivered,
        })


def _session_cookie(sent: labkit.Sent) -> str | None:
    for name, value in sent.reply.headers:
        if name.lower() == "set-cookie" and value.startswith("SID="):
            return value[len("SID="):].split(";", 1)[0] or None
    return None


def _payload(sent: labkit.Sent) -> dict[str, Any]:
    try:
        value = sent.reply.json()
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _header(sent: labkit.Sent, name: str) -> str | None:
    for key, value in sent.reply.headers:
        if key.lower() == name.lower():
            return value
    return None


# Origin data the probes name ----------------------------------------------------------------------------

def account(doctor: str) -> str:
    return f"doctor_{doctor}"


def patients_of(origin: ClinicOrigin, owner: str) -> list[str]:
    """The patients of an account that are not deleted, in the order the origin made them."""
    return [pid for pid, patient in origin.patients.items() if patient["owner"] == owner and not patient["deleted"]]


def first_patient(origin: ClinicOrigin, owner: str) -> str:
    found = patients_of(origin, owner)
    if not found:
        raise ProbeError(f"the origin has no patient of {owner}")
    return found[0]


def report_of(origin: ClinicOrigin, pid: str) -> str:
    for report_id, report in origin.reports.items():
        if report["patient"] == pid:
            return report_id
    raise ProbeError(f"patient {pid} has no report")


def public_patient(p: Prober, session: Session, dept: str, viewer: str | None) -> str:
    """A public search for a department (setup), then the first result that another account owns."""
    results = _payload(p.request(session, "GET", f"/api/search?q={quote(dept, safe='')}")).get("results", [])
    for item in results:
        owner = p.site.origin.owner_of("patient", item["id"])
        if owner is not None and owner != viewer:
            return str(item["id"])
    raise ProbeError(f"the public search for {dept} showed no patient of another account")


def dept_of(p: Prober, doctor: str) -> str:
    return str(p.site.origin.doctors[doctor]["dept"])


# Object-level families (plan 4.3) -----------------------------------------------------------------------

def idor_read(p: Prober) -> None:
    """Doctor A browses its own list, then reads one of B's patient, visit, prescription and report."""
    origin = p.site.origin
    b_patient = first_patient(origin, DOCTOR_B)
    visit = origin.patients[b_patient]["visits"][0]
    prescription = origin.patients[b_patient]["prescriptions"][0]
    report = report_of(origin, b_patient)
    targets = (
        ("idor_read/patient", "patient", b_patient, f"/api/patients/{b_patient}"),
        ("idor_read/visit", "visit", visit, f"/api/visits/{visit}"),
        ("idor_read/prescription", "prescription", str(prescription), f"/api/prescriptions/{prescription}"),
        ("idor_read/report", "report", report, f"/api/reports/{report}"),
    )
    for case, cls, value, target in targets:
        p.begin(Score(case, "attack", "idor_read", "block", "access", note=cls))
        session = p.login(account(DOCTOR_A))
        p.request(session, "GET", "/api/patients")
        p.request(session, "GET", target, scored=True, refs=[(cls, value)])


def idor_write(p: Prober) -> None:
    """Doctor A, after browsing its own list, changes or deletes one of B's patients."""
    b_patient = first_patient(p.site.origin, DOCTOR_B)
    for case, method, body in (("idor_write/update", "PUT", {"name": "改名"}), ("idor_write/delete", "DELETE", None)):
        p.begin(Score(case, "attack", "idor_write", "block", "access"))
        session = p.login(account(DOCTOR_A))
        p.request(session, "GET", "/api/patients")
        options: dict[str, Any] = {"json_body": body} if body is not None else {}
        p.request(session, method, f"/api/patients/{b_patient}", scored=True, refs=[("patient", b_patient)],
                  **options)


def idor_fresh_session(p: Prober) -> None:
    """A new session opens its own patient directly, without going through the list."""
    own = first_patient(p.site.origin, DOCTOR_A)
    p.begin(Score("idor_fresh_session", "attack", "idor_fresh_session", "block", "access"))
    session = p.login(account(DOCTOR_A))
    p.request(session, "GET", f"/api/patients/{own}", scored=True, refs=[("patient", own)])


def idor_param(p: Prober) -> None:
    """The doctor's own list, with the doctor parameter naming B."""
    p.begin(Score("idor_param", "attack", "idor_param", "block", "access"))
    session = p.login(account(DOCTOR_A))
    p.request(session, "GET", "/api/patients")
    p.request(session, "GET", f"/api/patients?doctor={DOCTOR_B}", scored=True, refs=[("doctor", DOCTOR_B)])


def idor_public_source(p: Prober) -> None:
    """A public search shows B's patient to A; A then deletes or changes it. Needs the tier declarations."""
    for case, method, body in (("idor_public_source/delete", "DELETE", None),
                               ("idor_public_source/update", "PUT", {"name": "改名"})):
        p.begin(Score(case, "attack", "idor_public_source", "block", "access", requires=("tiers",)))
        session = p.login(account(DOCTOR_A))
        seen = public_patient(p, session, dept_of(p, DOCTOR_B), DOCTOR_A)
        options: dict[str, Any] = {"json_body": body} if body is not None else {}
        p.request(session, method, f"/api/patients/{seen}", scored=True, refs=[("patient", seen)], **options)


def idor_cross_class(p: Prober) -> None:
    """A prescription number used as a patient id, and (live Jev only) a page number used as a prescription number."""
    origin = p.site.origin
    own = first_patient(origin, DOCTOR_A)
    number = origin.patients[own]["prescriptions"][0]
    # Both positions declare their class, so the probe needs an object map to compare them: "none" has none.
    p.begin(Score("idor_cross_class/prescription-as-patient", "attack", "idor_cross_class", "block", "access",
                  requires=("classes",)))
    session = p.login(account(DOCTOR_A))
    p.request(session, "GET", "/api/patients")
    p.request(session, "GET", f"/api/patients/{own}")  # shows the prescriptions of the patient
    p.request(session, "GET", f"/api/patients/{number}", scored=True, refs=[("patient", str(number))])
    # The page probe goes to the live Jev only. The page's position declares no class, so the ideal model has
    # nothing to compare it with, and a rule that guessed from field names would be the model's answer, not ours.
    if p.jev is not None:
        return
    # The page probe is B's: prescription 1 is one of A's own, and A reading it would be a legitimate read.
    if origin.owner_of("prescription", "1") == DOCTOR_B:
        raise ProbeError("prescription 1 belongs to the probe's doctor, so the page probe would not be an attack")
    p.begin(Score("idor_cross_class/page-as-prescription", "attack", "idor_cross_class", "block", "access"))
    session = p.login(account(DOCTOR_B))
    p.request(session, "GET", f"/api/search?q={quote(dept_of(p, DOCTOR_B), safe='')}")  # the answer's page is 1
    p.request(session, "GET", "/api/prescriptions/1", scored=True, refs=[("prescription", "1")])


def idor_share(p: Prober) -> None:
    """B shares its patient; A opens it without redeeming the code."""
    origin = p.site.origin
    b_patient = first_patient(origin, DOCTOR_B)
    p.begin(Score("idor_share", "attack", "idor_share", "block", "access"))
    owner = p.login(account(DOCTOR_B))
    p.request(owner, "GET", "/api/patients")
    p.request(owner, "POST", f"/api/patients/{b_patient}/share")
    session = p.login(account(DOCTOR_A))
    p.request(session, "GET", "/api/patients")
    p.request(session, "GET", f"/api/patients/{b_patient}", scored=True, refs=[("patient", b_patient)])


def admin_tier(p: Prober) -> None:
    """The administrator deletes a patient it has not seen in the administrator search, and then one it has
    seen only in the public search (which needs the tier declarations)."""
    origin = p.site.origin
    p.begin(Score("admin_tier/unseen", "attack", "admin_tier", "block", "access"))
    session = p.login(ADMIN)
    unseen = first_patient(origin, DOCTOR_C)
    p.request(session, "DELETE", f"/api/patients/{unseen}", scored=True, refs=[("patient", unseen)])
    p.begin(Score("admin_tier/public-source", "attack", "admin_tier", "block", "access", requires=("tiers",)))
    session = p.login(ADMIN)
    seen = public_patient(p, session, dept_of(p, DOCTOR_B), None)
    p.request(session, "DELETE", f"/api/patients/{seen}", scored=True, refs=[("patient", seen)])


def no_session(p: Prober) -> None:
    """Requests to non-entry paths without a credential."""
    own = first_patient(p.site.origin, DOCTOR_A)
    p.begin(Score("no_session/patient", "attack", "no_session", "block", "no_session"))
    p.request(None, "GET", f"/api/patients/{own}", scored=True, refs=[("patient", own)])
    p.begin(Score("no_session/search", "attack", "no_session", "block", "no_session"))
    p.request(None, "GET", f"/api/search?q={quote(dept_of(p, DOCTOR_A), safe='')}", scored=True)


# Injection points and benign text (plan 4.3, 4.4) --------------------------------------------------------

def send_at_point(p: Prober, point: str, text: str, meta: Score) -> None:
    """One scored request that carries `text` at one injection point, from a session of its own."""
    p.begin(meta)
    if not p.wants(meta):  # --only: the probe is not selected, so it is not sent either
        return
    if point == "path":
        p.request(None, "GET", f"/share/{quote(text, safe='')}", scored=True, carry=text)
        return
    session = p.login(account(DOCTOR_A))
    if point == "search":
        p.request(session, "GET", f"/api/search?q={quote(text, safe='')}", scored=True, carry=text)
    elif point == "json":
        p.request(session, "POST", "/api/patients", json_body={"name": text}, scored=True, carry=text)
    elif point == "form":
        p.request(session, "POST", "/api/forms/intake", form={"note": text}, scored=True, carry=text)
    else:
        raise ProbeError(f"unknown injection point {point!r}")


def splits_path(text: str) -> bool:
    """Whether a text cannot be one path segment: a separator would change the route it sits in (plan 4.3)."""
    return any(separator in text for separator in PATH_SEPARATORS)


def injection(p: Prober, row: dict[str, Any]) -> None:
    for point in ATTACK_POINTS:
        if point == "path" and splits_path(row["text"]):
            p.unsent["attack"] += 1  # the gateway would answer no_session for the route, not judge the payload
            continue
        meta = Score(case=f"injection_{row['class']}/{point}/{row['id']}", group="attack",
                     category=f"injection_{row['class']}", expect="block", reason="attack", note=row["note"])
        send_at_point(p, point, row["text"], meta)


def benign_text(p: Prober, row: dict[str, Any]) -> None:
    for point in ATTACK_POINTS:
        if point == "path" and splits_path(row["text"]):
            p.unsent["benign"] += 1  # the same rule as for attacks: a value with a separator is not sent there
            continue
        meta = Score(case=f"benign_text/{point}/{row['id']}", group="benign", category="benign_text",
                     expect="allow", note=row["class"])
        send_at_point(p, point, row["text"], meta)


FAMILIES: tuple[Callable[[Prober], None], ...] = (
    idor_read, idor_write, idor_fresh_session, idor_param, idor_public_source, idor_cross_class, idor_share,
    admin_tier, no_session,
)


def run_site(p: Prober, attacks: Sequence[dict[str, Any]], benign: Sequence[dict[str, Any]]) -> None:
    """Every probe family of plan 4.3 except the regression cases, against one site."""
    for family in FAMILIES:
        family(p)
    for row in attacks:
        injection(p, row)
    for row in benign:
        benign_text(p, row)


def new_prober(edge: labkit.Edge, site: Site, pool: Pool, *, jev: FakeJev | None, run: int,
               only: frozenset[str]) -> Prober:
    return Prober(edge, site, pool, jev=jev, run=run, only=only)


__all__ = [
    "ADMIN", "ATTACK_POINTS", "DOCTOR_A", "DOCTOR_B", "DOCTOR_C", "Pool", "Prober", "ProbeError", "Score",
    "Session", "Site", "account", "attack_texts", "benign_text", "first_attack", "first_patient", "injection",
    "new_prober", "patients_of", "public_patient", "quick_attacks", "quick_benign", "report_of", "run_site",
    "send_at_point", "_header", "_payload", "field",
]

"""Benign training traffic for the clinic lab (plan 4.2), and the truth self-check (plan 10, batch 2).

run_training() plays one journey for each login of each doctor, then one session per administrator.
Every step is a normal path: a login, the home page, my patients and their details, visits and
prescriptions, searches by department, a note on a patient another doctor found, an update, a new
patient, a share that a colleague redeems, the directory, and the deletion of one of the doctor's own
patients. The journeys are fixed by the seed, so one seed always sends the same requests in the same
order. The rows it returns are observations in the format of plan 9.1 with group "train".

`python3 tests/security-lab/clinic_traffic.py --check` runs the training through the edge with the truth
configuration and checks the result against the decision records. Every learnable position and every
non_objects key of the origin's truth must appear, no benign request may be blocked, would-blocked or left
unjudged, and the four pieces of evidence in plan 4.2 must reach the counts the learning rules need for `high`.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import labkit
from clinic_origin import ADMINS, DEFAULT_SEED, DEPARTMENTS, PASSWORD, QUICK_DOCTORS, ClinicOrigin, site_spec
from fake_jev import FakeJev

Send = Callable[..., labkit.Sent]

BUDGET_SECONDS = 30  # plan 10, batch 2: 12 users with 4 logins each, in 30 seconds
# The learning defaults (crates/xshield-core/src/context/learning.rs). A `high` verdict needs twice the
# minimum number of units or votes, and 980 per mille agreement; the public rule needs 900 per mille.
SESSIONS_MIN = 5
VOTES_MIN = 20
HIGH_AGREEMENT_PER_MILLE = 980
UNJUDGED_OUTCOMES = ("blocked", "would_block", "unjudged")
# The training runs in observation mode (plan 9.1): the edge forwards and logs what it would block.
TRAINING_MODE = "observe"

# Free text comes from the corpus of plan 4.4: its quick subset, or all of it in the full mode (plan 5.2).
CORPUS = Path(__file__).resolve().parent / "corpus"


def _corpus_rows(name: str) -> list[dict[str, Any]]:
    lines = (CORPUS / name).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _attack_texts() -> tuple[str, ...]:
    return tuple(row["text"] for row in _corpus_rows("attacks.jsonl"))


BENIGN_TEXTS = tuple(row["text"] for row in _corpus_rows("benign.jsonl") if row["quick"])
BENIGN_NAMES = tuple(row["text"] for row in _corpus_rows("benign.jsonl") if row["quick"] and row["class"] == "name")
FULL_BENIGN_TEXTS = tuple(row["text"] for row in _corpus_rows("benign.jsonl"))
FULL_BENIGN_NAMES = tuple(row["text"] for row in _corpus_rows("benign.jsonl") if row["class"] == "name")
# Attack sessions (plan 3.2, L5) log in as doctors from addresses of their own: ATTACKER_SOURCE plus their number,
# on the loopback net 127.0.1.x (see _source), so the most of them the last octet allows is 254 - ATTACKER_SOURCE.
ATTACKER_SOURCE = 150
ATTACKERS_MAX = 254 - ATTACKER_SOURCE
ATTACKER_WALKS = 6  # patients of other doctors that one attack session asks for by id


@dataclass
class Evidence:
    """What the training traffic gave the origin, counted the way the learning rules count it (plan 4.2)."""

    search_units: set[str] = field(default_factory=set)  # doctors whose public search answered 2xx
    public_views: dict[str, set[str]] = field(default_factory=dict)  # patient id -> doctors that saw it in a search
    refused_units: set[str] = field(default_factory=set)  # doctors the administrator search refused with 403
    deleted_sessions: set[str] = field(default_factory=set)  # sessions that deleted one of their own patients
    noted_sessions: set[str] = field(default_factory=set)  # sessions that noted another doctor's patient


@dataclass
class _Session:
    label: str
    source: str | None
    token: str | None = None
    login_request: str | None = None


def run_training(send: Send, origin: ClinicOrigin, seed: int, users: int, logins: int, *,
                 config: str = "truth", mode: str = TRAINING_MODE,
                 evidence: Evidence | None = None, full: bool = False,
                 attackers: int = 0, natural_order: bool = False) -> list[dict[str, Any]]:
    """The training observations of `logins` logins for each of the first `users` doctors.

    `full` takes the whole free-text corpus. `attackers` mixes that many attack sessions (plan 3.2, L5) into the
    benign ones, at places the seed chooses; with none, the traffic is the same as before. `natural_order` runs each
    doctor's own deletions between the other doctors' sessions instead of after all of them (plan 10, batch 7: the
    full mode's report-only variant, see full.py).

    `send(host, method, target, **options)` returns a labkit.Sent: the edge's answer in the lab, or the
    origin's own answer in the unit tests. The same seed sends the same requests in the same order.
    """
    if seed != origin.seed:
        raise ValueError(f"the traffic seed {seed} must be the origin's seed {origin.seed}")
    if not 1 <= users <= origin.doctor_count:
        raise ValueError(f"users must be between 1 and the origin's {origin.doctor_count} doctors")
    if logins < 1:
        raise ValueError("every doctor logs in at least once")
    if mode not in ("observe", "enforce"):
        raise ValueError(f"unknown mode {mode!r}")
    if not 0 <= attackers <= ATTACKERS_MAX:
        raise ValueError(f"attackers must be between 0 and {ATTACKERS_MAX}")
    driver = _Driver(send, origin, config, mode, evidence if evidence is not None else Evidence(), full=full,
                     natural_order=natural_order)
    driver.run(users, logins, attackers)
    return driver.rows


class _Driver:
    def __init__(self, send: Send, origin: ClinicOrigin, config: str, mode: str, evidence: Evidence,
                 *, full: bool = False, natural_order: bool = False) -> None:
        self.send = send
        self.origin = origin
        self.config = config
        self.mode = mode
        self.host = f"clinic-{config}.lab"
        self.evidence = evidence
        self.texts = FULL_BENIGN_TEXTS if full else BENIGN_TEXTS
        self.names = FULL_BENIGN_NAMES if full else BENIGN_NAMES
        self.natural_order = natural_order
        self.doctor_ids: list[str] = []
        self.origins: dict[str, list[str]] = {}  # doctor -> the patients it had at its first login
        self.pending_deletes: list[tuple[_Session, str, str]] = []  # (session, label, patient) for later
        self.rows: list[dict[str, Any]] = []

    def run(self, users: int, logins: int, attackers: int = 0) -> None:
        self.doctor_ids = list(self.origin.doctors)[:users]
        benign = [(index, doctor_id, login_no)
                  for index, doctor_id in enumerate(self.doctor_ids) for login_no in range(logins)]
        # The attack sessions take seeded places among the benign ones. With none, the order is the one of old.
        total = len(benign) + attackers
        places = set(random.Random(f"{self.origin.seed}:attack-places").sample(range(total), attackers))
        benign_order = iter(benign)
        attacker_number = 0
        for position in range(total):
            if position in places:
                self.attacker_session(attacker_number)
                attacker_number += 1
            else:
                if self.natural_order:
                    self.flush_deletes()  # the natural-order variant: a delete lands between two other sessions
                self.doctor_session(*next(benign_order))
        self.flush_deletes()
        for offset, (username, admin_id) in enumerate(ADMINS.items()):
            self.administrator_session(offset + 100, username, admin_id)

    def flush_deletes(self) -> None:
        """Runs the deletions the doctors' sessions queued, in the order they were queued, and empties the queue."""
        for session, label, pid in self.pending_deletes:
            deleted = self.step(session, "delete-own", "DELETE", f"/api/patients/{pid}", refs=(("patient", pid),))
            if deleted.reply.status == 200:
                self.evidence.deleted_sessions.add(label)
        self.pending_deletes.clear()

    def login(self, label: str, account: str, source_index: int) -> _Session:
        session = _Session(label=label, source=_source(source_index))
        sent = self.step(session, "login", "POST", "/login", expect=(302,),
                         form={"username": account, "password": PASSWORD})
        session.token = _session_cookie(sent)
        session.login_request = sent.reply.request_id
        return session

    def step(self, session: _Session, name: str, method: str, target: str, *, expect: tuple[int, ...] = (200,),
             refs: tuple[tuple[str, str], ...] = (), form: dict[str, str] | None = None,
             json_body: dict[str, Any] | None = None, category: str | None = None, verdict: str = "allow",
             reason: str | None = None, requires: tuple[str, ...] = ()) -> labkit.Sent:
        # verdict, reason, category and requires say what the row expects (plan 9.1). The defaults make an
        # allowed request of the benign group; a row that expects a block names the capability it needs.
        # The state is read before the request is sent: what the origin had shown this session by then.
        states = [(cls, value, self.origin.reference_state(session.token, cls, value)) for cls, value in refs]
        options: dict[str, Any] = {}
        if session.token:
            options["cookie"] = f"SID={session.token}"
        if form is not None:
            options["form"] = form
        if json_body is not None:
            options["json_body"] = json_body
        sent = self.send(self.host, method, target, source=session.source, **options)
        self.rows.append({
            "case": f"train/{session.label}/{name}", "group": "train" if verdict == "allow" else "attack",
            "category": category or f"train_{name.replace('-', '_')}",
            "expect": verdict, "reason": reason if verdict == "block" else None, "status": "must", "ref": None,
            "config": self.config, "site": f"clinic-{self.config}", "mode": self.mode, "run": 1,
            "request_id": sent.reply.request_id or "",
            "setup_request_ids": [session.login_request] if session.login_request else [],
            "client_status": sent.reply.status, "expected_status": list(expect),
            "origin_served": sent.served,
            "refs": [{"value": value, "class": cls, "shown": state["shown"], "echoed": state["echoed"]}
                     for cls, value, state in states],
            "requires": list(requires), "note": name, "session": session.label, "request": f"{method} {target}",
        })
        return sent

    def doctor_session(self, index: int, doctor_id: str, login_no: int) -> None:
        rng = random.Random(f"{self.origin.seed}:journey:{doctor_id}:{login_no}")
        label = f"{doctor_id}/{login_no}"
        session = self.login(label, f"doctor_{doctor_id}", index)
        self.step(session, "home", "GET", "/api/home")
        listing = _payload(self.step(session, "my-patients", "GET", "/api/patients"))
        mine = [item["id"] for item in listing.get("patients", [])]
        if login_no == 0:
            self.origins[doctor_id] = list(mine)
        for pid in mine:
            detail = _payload(self.step(session, "patient-detail", "GET", f"/api/patients/{pid}",
                                        refs=(("patient", pid),)))
            for visit in detail.get("visits", []):
                self.step(session, "visit", "GET", f"/api/visits/{visit['id']}", refs=(("visit", visit["id"]),))
            for item in detail.get("prescriptions", []):
                number = str(item["id"])
                self.step(session, "prescription", "GET", f"/api/prescriptions/{number}",
                          refs=(("prescription", number),))
        # The doctor's own department and two others. With the quick mode's two doctors per department, each
        # result list is seen by both doctors of that department, which is the public evidence of plan 4.2.
        own_dept = self.origin.doctors[doctor_id]["dept"]
        chosen = [own_dept, *rng.sample([dept for dept in DEPARTMENTS if dept != own_dept], 2)]
        found: list[str] = []
        for dept in chosen:
            answer = self.step(session, "search", "GET", f"/api/search?q={quote(dept, safe='')}")
            if answer.reply.status == 200:
                self.evidence.search_units.add(doctor_id)
                for item in _payload(answer).get("results", []):
                    self.evidence.public_views.setdefault(item["id"], set()).add(doctor_id)
                    found.append(item["id"])
        others = [pid for pid in dict.fromkeys(found) if self.origin.owner_of("patient", pid) != doctor_id]
        if login_no == 0:
            # Each ordinary doctor asks the administrator search once; the origin refuses every one. The doctor
            # is an over-privilege attempt, so the row expects a block, which only a function table gives (plan
            # 4.5, the functions item). Only a 403 the origin itself answered is evidence of a refusal.
            refused = self.step(session, "admin-search-refused", "GET",
                                f"/api/admin/search?q={quote(chosen[0], safe='')}", expect=(403,),
                                category="function_level", verdict="block", reason="access",
                                requires=("functions",))
            if refused.served and refused.reply.status == 403:
                self.evidence.refused_units.add(doctor_id)
        if others:
            target = rng.choice(others)
            noted = self.step(session, "note-other", "POST", f"/api/patients/{target}/notes", expect=(201,),
                              refs=(("patient", target),), json_body={"text": rng.choice(self.texts)})
            if noted.reply.status == 201:
                self.evidence.noted_sessions.add(label)
        self.step(session, "directory", "GET", "/api/directory")
        if mine:
            first = mine[0]
            self.step(session, "update-own", "PUT", f"/api/patients/{first}", refs=(("patient", first),),
                      json_body={"name": rng.choice(self.names)})
            created = _payload(self.step(session, "create", "POST", "/api/patients", expect=(201,),
                                         json_body={"name": rng.choice(self.names)}))
            if "id" in created:
                self.step(session, "open-created", "GET", f"/api/patients/{created['id']}",
                          refs=(("patient", created["id"]),))
            shared = _payload(self.step(session, "share", "POST", f"/api/patients/{first}/share",
                                        expect=(201,), refs=(("patient", first),)))
            if "code" in shared:
                self.colleague(index, label, first, shared["code"])
        # Session k of a doctor deletes the k-th of the patients the doctor had at the first login, counting
        # from the end. The deletions run after every doctor has searched (see run), so that each search
        # result is seen by the same doctors and the public evidence of plan 4.2 is not cut short by them.
        # The natural-order variant (full mode) runs them in the order of the day instead (see run).
        originals = self.origins.get(doctor_id, [])
        if login_no < len(originals):
            self.pending_deletes.append((session, label, originals[-1 - login_no]))

    def colleague(self, index: int, label: str, pid: str, code: str) -> None:
        colleague_index = (index + 1) % len(self.doctor_ids)
        account = f"doctor_{self.doctor_ids[colleague_index]}"
        session = self.login(f"{label}/colleague", account, colleague_index)
        self.step(session, "redeem-share", "GET", f"/share/{code}")
        self.step(session, "colleague-open", "GET", f"/api/patients/{pid}", refs=(("patient", pid),))

    def administrator_session(self, source_index: int, username: str, admin_id: str) -> None:
        rng = random.Random(f"{self.origin.seed}:journey:{admin_id}")
        session = self.login(f"{admin_id}/1", username, source_index)
        self.step(session, "home", "GET", "/api/home")
        dept = rng.choice(DEPARTMENTS)
        results = _payload(self.step(session, "admin-search", "GET",
                                     f"/api/admin/search?q={quote(dept, safe='')}"))
        self.step(session, "admin-export", "GET", "/api/admin/export")
        found = [item["id"] for item in results.get("results", [])]
        if found:
            self.step(session, "admin-delete", "DELETE", f"/api/patients/{found[0]}",
                      refs=(("patient", found[0]),))

    def attacker_session(self, number: int) -> None:
        """An attack session of the polluted training traffic (plan 3.2, L5). It is a doctor's real login, which asks
        by id for patients of other doctors it has never been shown, then searches a department and deletes one of the
        patients the search showed that belong to another doctor. Its rows are attack rows; the learning must not learn
        from them. Who it asks for and what it searches comes from the seed."""
        rng = random.Random(f"{self.origin.seed}:attacker:{number}")
        doctor_id = self.doctor_ids[number % len(self.doctor_ids)]
        others = [pid for pid, patient in self.origin.patients.items()
                  if not patient["deleted"] and patient["owner"] != doctor_id]
        session = self.login(f"attacker/{number}", f"doctor_{doctor_id}", ATTACKER_SOURCE + number)
        for pid in rng.sample(others, min(ATTACKER_WALKS, len(others))):
            self.step(session, "walk-id", "GET", f"/api/patients/{pid}", expect=(200, 403, 404),
                      refs=(("patient", pid),), verdict="block", reason="access", category="pollution_walk")
        dept = rng.choice(DEPARTMENTS)
        results = _payload(self.step(session, "search", "GET", f"/api/search?q={quote(dept, safe='')}"))
        victims = [item["id"] for item in results.get("results", [])
                   if self.origin.owner_of("patient", item["id"]) != doctor_id]
        if victims:
            self.step(session, "search-then-delete", "DELETE", f"/api/patients/{victims[0]}",
                      expect=(200, 403, 404), refs=(("patient", victims[0]),), verdict="block", reason="access",
                      category="pollution_delete")


def _source(index: int) -> str | None:
    return labkit.loopback_source(index + 1)


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


def verify(origin: ClinicOrigin, rows: list[dict[str, Any]], records: list[dict[str, Any]],
           evidence: Evidence, elapsed: float) -> tuple[list[str], list[str]]:
    """The report lines and the problems of one training run through the edge."""
    report = [f"  traffic: {len(rows)} requests in {elapsed:.1f} s (budget {BUDGET_SECONDS} s)"]
    problems: list[str] = []
    if elapsed > BUDGET_SECONDS:
        problems.append(f"the training traffic took {elapsed:.1f} s, over the {BUDGET_SECONDS} s budget")

    answered = {record.get("request_id") for record in records}
    unanswered = [row["case"] for row in rows if row["request_id"] not in answered]
    if unanswered:
        problems.append(f"{len(unanswered)} requests have no decision record, first: {unanswered[:3]}")

    flagged = [record for record in records if record.get("outcome") in UNJUDGED_OUTCOMES
               or (record.get("jev") or {}).get("failure")]
    report.append(f"  decision records: {len(records)}, blocked, would-block, unjudged or Jev failures: {len(flagged)}")
    for record in flagged[:5]:
        problems.append(f"{record.get('request_id')}: outcome {record.get('outcome')}, "
                        f"Jev failure {(record.get('jev') or {}).get('failure')}")

    unexpected = [row for row in rows if row["client_status"] not in row["expected_status"]]
    report.append(f"  answers as the journey expects: {len(rows) - len(unexpected)} of {len(rows)}")
    for row in unexpected[:5]:
        problems.append(f"{row['case']} answered {row['client_status']}, expected {row['expected_status']}: "
                        f"{row['request']}")

    truth = origin.truth()
    slots: set[str] = set()
    fingerprint_keys: set[str] = set()
    for record in records:
        trace = record.get("trace") or {}
        slots.update(value["slot"] for value in trace.get("values") or [] if value.get("slot"))
        fingerprint_keys.update(((trace.get("response") or {}).get("fingerprints") or {}).keys())
    request_keys = [item["key"] for item in truth["request_positions"] if item["learnable"]]
    response_keys = [item["key"] for item in truth["response_positions"] if item["learnable"]]
    missing = [key for key in request_keys if key not in slots] + \
              [key for key in response_keys if key not in fingerprint_keys]
    report.append(f"  learnable request positions seen: {len(request_keys) - sum(k not in slots for k in request_keys)}"
                  f" of {len(request_keys)}")
    report.append(f"  learnable response positions seen: "
                  f"{len(response_keys) - sum(k not in fingerprint_keys for k in response_keys)} of {len(response_keys)}")
    for key in missing:
        problems.append(f"learnable position never appears in a decision record: {key}")
    seen_non_objects = [key for key in truth["non_objects"] if key in slots or key in fingerprint_keys]
    report.append(f"  non_objects seen in records: {len(seen_non_objects)} of {len(truth['non_objects'])}")
    for key in truth["non_objects"]:
        if key not in slots and key not in fingerprint_keys:
            problems.append(f"non_objects key never appears in a decision record: {key}")

    units = len(evidence.search_units)
    values = len(evidence.public_views)
    shared = sum(1 for viewers in evidence.public_views.values() if len(viewers) >= 2)
    shared_per_mille = shared * 1000 // values if values else 0
    refused = len(evidence.refused_units)
    deleted = len(evidence.deleted_sessions)
    noted = len(evidence.noted_sessions)
    rules = [
        ("public: doctors that searched", units, 2 * SESSIONS_MIN),
        ("public: values seen in search", values, VOTES_MIN),
        ("public: values seen by two doctors or more, per mille", shared_per_mille, HIGH_AGREEMENT_PER_MILLE),
        ("admin: doctors refused by the administrator search", refused, 2 * SESSIONS_MIN),
        ("accepts_public false: sessions deleting an own patient", deleted, 2 * VOTES_MIN),
        ("accepts_public true: sessions noting another doctor's patient", noted, 2 * VOTES_MIN),
    ]
    for label, measured, required in rules:
        report.append(f"  evidence {label}: {measured} (high needs {required})")
        if measured < required:
            problems.append(f"evidence short of high: {label} is {measured}, needs {required}")
    return report, problems


def check(seed: int = DEFAULT_SEED, users: int = QUICK_DOCTORS, logins: int = 4) -> int:
    origin = ClinicOrigin(seed=seed, doctors=users)
    origin.start()
    # The ideal model (plan 6): an attack is a full attack text from the corpus, so benign text is never one.
    jev = FakeJev(attack_texts=_attack_texts())
    jev.start()
    edge: labkit.Edge | None = None
    try:
        labkit.build_edge()
        with tempfile.TemporaryDirectory() as scratch:
            sites = Path(scratch) / "sites.json"
            sites.write_text(json.dumps([site_spec("truth", origin.port, mode=TRAINING_MODE)], ensure_ascii=False),
                             encoding="utf-8")
            edge = labkit.Edge(sites, jev.url, labkit.free_port(), Path(scratch) / "decisions.jsonl")
            running = edge

            def through_edge(host: str, method: str, target: str, **options: Any) -> labkit.Sent:
                return labkit.exchange(running, origin.was_served, host, method, target, **options)

            evidence = Evidence()
            started = time.monotonic()
            rows = run_training(through_edge, origin, seed, users, logins, config="truth", mode=TRAINING_MODE,
                                evidence=evidence)
            elapsed = time.monotonic() - started
            with running.lock:
                records = list(running.records)
    finally:
        if edge is not None:
            edge.stop()
        jev.stop()
        origin.stop()
    report, problems = verify(origin, rows, records, evidence, elapsed)
    print(f"clinic truth self-check: seed {seed}, {users} doctors x {logins} logins")
    print("\n".join(report))
    if problems:
        print("FAIL")
        print("\n".join(f"  - {problem}" for problem in problems))
        return 1
    print("PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Clinic lab benign traffic and its truth self-check.")
    parser.add_argument("--check", action="store_true",
                        help="run the training through the edge and check the truth against the decisions")
    arguments = parser.parse_args(argv)
    if not arguments.check:
        parser.print_help()
        return 2
    return check()


if __name__ == "__main__":
    sys.exit(main())

"""Hand-written inputs for the scorer and report tests.

Each builder returns the fields the contracts (contracts.py) require, so score() can run on the
result directly. Nothing here reads a file: the fixtures directory holds the larger set that the
command-line tests use.
"""

from __future__ import annotations

import json
from typing import Any

ACCESS_OPTIONS = ("ALLOW", "DENY", "UNKNOWN")
ATTACK_OPTIONS = ("BENIGN", "ATTACK", "UNKNOWN")


def observation(case: str, *, request_id: str = "r1", group: str = "attack",
                category: str = "idor_direct", expect: str = "block", reason: str | None = "access",
                status: str = "must", ref: str | None = None, config: str = "truth",
                origin_served: bool | None = False, refs: list[dict[str, Any]] | None = None,
                requires: tuple[str, ...] = (), note: str = "") -> dict[str, Any]:
    """One scored request. A block carries its reason (default access); an allow carries none."""
    if expect == "allow":
        reason = None
    elif reason is None:
        reason = "access"
    return {
        "case": case, "group": group, "category": category, "expect": expect, "reason": reason,
        "status": status, "ref": ref, "config": config, "site": f"clinic-{config}", "mode": "enforce",
        "run": 1, "request_id": request_id, "setup_request_ids": [],
        "client_status": 403 if expect == "block" else 200, "origin_served": origin_served,
        "refs": refs or [], "requires": list(requires), "note": note,
    }


def reference(value: str, *, shown: bool = False, echoed: bool = False) -> dict[str, Any]:
    """A value the request carries that the scorer checks (S1, S2): shown by the origin, or echoed."""
    return {"value": value, "class": "patient", "shown": shown, "echoed": echoed}


def source(request_id: str, *, field: str = "id", request: str = "GET /api/search") -> dict[str, Any]:
    return {"field": field, "request": request, "request_id": request_id, "at_millis": 1}


def entry(value: str, *, verified: bool = False, sources: list[dict[str, Any]] | None = None,
          slot: str | None = None, attempt: str | None = None) -> dict[str, Any]:
    """One value in a decision record's trace. Only the fields the scorer reads are meaningful."""
    item: dict[str, Any] = {"at": "path[2]", "key": None, "value": value, "kind": "reference",
                            "inert": False, "seen": True, "verified": verified, "sources": sources or []}
    if slot:
        item.update({"slot": slot, "object": "patient", "object_from": "map"})
    if attempt:
        item["attempt"] = attempt
    return item


def _spread(options: tuple[str, ...], choice: str) -> dict[str, float]:
    return {option: 0.9 if option == choice else 0.05 for option in options}


def jev(access: str = "DENY", attack: str = "BENIGN") -> dict[str, Any]:
    """A Jev object as the gateway records it: the answer JSON and the probabilities of each answer."""
    answers = {"access": {"type": "choice", "choice": access},
               "attack": {"type": "choice", "choice": attack}}
    return {"state": "{}", "failure": None, "response": json.dumps({"answers": answers}),
            "access": _spread(ACCESS_OPTIONS, access), "attack": _spread(ATTACK_OPTIONS, attack),
            "conclusion": None, "millis": 3}


def jev_failed(code: str) -> dict[str, Any]:
    return {"state": "{}", "failure": code, "response": None, "access": {}, "attack": {},
            "conclusion": None, "millis": 0}


def decision(request_id: str, *, path: str = "jev_deny", outcome: str = "blocked", session: str = "s1",
             values: list[dict[str, Any]] | None = None, jev_record: dict[str, Any] | None = None,
             method: str = "GET", route: str = "/api/patients/1", judge_ms: int = 2) -> dict[str, Any]:
    """One decision record in the console export shape (docs/07 7.4), with the fields the scorer reads."""
    return {
        "at_millis": 1, "request_id": request_id, "site": "clinic-truth", "site_version": 3,
        "edge": "edge-1", "host": "clinic.lab", "client": "127.0.0.1", "session": session,
        "context": "session", "method": method, "path": route, "logical_path": route, "api": None,
        "request_headers": ["host"], "query": None, "status": 403 if outcome == "blocked" else 200,
        "decision_path": path, "outcome": outcome,
        "trace": {"v": 1, "values_truncated": False, "values": values or [],
                  "timing": {"total_ms": judge_ms + 1, "judge_ms": judge_ms, "origin_ms": 1}},
        "jev": jev_record,
    }


def truth_doc(request: list[tuple[str, str, bool]], response: list[tuple[str, str, str]],
              non_objects: tuple[str, ...] = ()) -> dict[str, Any]:
    """A truth file. Request positions are (key, class, accepts_public), response ones (key, class, tier)."""
    return {
        "site": "clinic", "seed": 1, "classes": ["patient", "doctor"], "identity": [],
        "request_positions": [{"key": key, "class": cls, "accepts_public": accepts, "learnable": True}
                              for key, cls, accepts in request],
        "response_positions": [{"key": key, "class": cls, "tier": tier, "learnable": True}
                              for key, cls, tier in response],
        "non_objects": list(non_objects),
    }


def candidate(key: str, side: str, cls: str) -> dict[str, Any]:
    return {"key": key, "side": side, "class": cls, "uses": 10, "sessions": 10}


def position(key: str, *, cls: str | None = None, accepts: bool | None = None, tier: str | None = None,
             reliability: str | None = "high", state: str = "confirmed") -> dict[str, Any]:
    return {"key": key, "state": state, "class": cls, "source": "rule", "tier": tier,
            "accepts_public": accepts, "reliability": reliability}


def judgement(key: str, tier: str, reliability: str = "high") -> dict[str, Any]:
    return {"key": key, "tier": tier, "reliability": reliability}


def learning_round(number: int, positions: list[dict[str, Any]],
                   judgements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"round": number, "run": {"started_millis": 0, "finished_millis": 1, "error": None},
            "positions": positions, "judgements": judgements}


def learned_doc(rounds: list[dict[str, Any]], bootstrap: list[dict[str, Any]]) -> dict[str, Any]:
    return {"bootstrap": bootstrap, "rounds": rounds, "final_spec": {"objects": {"slots": []}}}


def suspicious_probe() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """A probe for an object that the same session was shown earlier (plan 4.6, check 1)."""
    origin = decision("o1", path="fast_allow", outcome="allowed", session="s1")
    probe = decision("p1", session="s1", values=[entry("205", verified=True, sources=[source("o1")])],
                     jev_record=jev())
    return [observation("probe", request_id="p1", refs=[reference("205")])], [origin, probe]

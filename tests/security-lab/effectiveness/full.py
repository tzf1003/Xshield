"""The full mode of the effectiveness measurement (plan 5.2 and 10, batch 7), beyond what the quick mode measures.

- L4, the convergence cost (plan 3.2): the learning over 3, 6, 12 and 24 users, and over the full run's 48. For each
  layer, the first number of users at which the layer is at its top: it proposes nothing wrong, and its right positions
  carry the reliabilities that the largest user count learned. The top is that count's own learning, not the truth, and
  known-gap entries are not left out of it.
- L5, the anti-pollution (plan 3.2): the learning over the same training traffic with attack sessions mixed in, ten in
  a hundred of all the sessions. Its wrong proposals are findings to report, not a gate. A position the clean run learned
  right and the polluted run did not learn, or learned with a lower reliability, is lost (report only). The attack
  requests are counted by category: how many the observation run would have blocked, and how many it let through.
- The natural-order variant (plan 10, batch 7): the public agreement and the learned tier of the search result under the
  two orders of the deletions, reported beside each other (no gate).
- P6, the observation against the enforcement (plan 3.3): computed by score.py from the consistency rows; here it becomes
  a gate of the full mode, which must find no difference and must compare at least one request.
- The two-pass check: the whole full run is made twice in one command, and the deterministic part of the two reports
  must be equal. Timings and request IDs differ between runs, so they are left out.

The functions here are pure. They take what score.learning_metrics returns and never read a file or the clock; the
drivers that run the segments are in lab.py.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

FULL_DOCTORS = 48  # plan 5.2: the full mode's doctors (the quick mode has 12)
CONVERGENCE_USERS = (3, 6, 12, 24)  # plan 3.2 L4; the full run's own 48 users are the last point
POLLUTION_SHARE = 0.10  # plan 3.2 L5: attack sessions are this share of all the training sessions
LAYERS = ("L0", "L1", "L2", "L3")
RELIABILITY_LAYERS = ("L2", "L3")  # the layers whose right proposals carry a reliability (plan 3.2)
LAYER_TITLES = {
    "L0": "冷启动候选",
    "L1": "请求位置类别",
    "L2": "响应位置档位",
    "L3": "请求位置接受公共来源",
}
RELIABILITY_RANK = {"high": 2, "medium": 1, "low": 0}
TWO_PASS_GATE = "两遍核对（指标逐位相同）"
CONSISTENCY_GATE = "观察与拦截一致性（P6，必须为 0）"
# The natural-order variant (plan 10, batch 2 note, batch 7): the public search result that a deletion before other
# doctors' searches can cut short, and the agreement a public source needs to be reliability high.
NATURAL_ORDER_KEY = "GET /api/search results[].id"
HIGH_AGREEMENT_PER_MILLE = 980
ATTACK_OUTCOMES = ("would_block", "allowed")  # the other outcomes of an attack request are counted as "other"
ATTACKER_SESSION_PREFIX = "attacker/"  # the session label of an attack session (clinic_traffic.py)


def attacker_count(benign_sessions: int) -> int:
    """The attack sessions that make up POLLUTION_SHARE of all sessions when mixed into `benign_sessions` benign ones."""
    return round(benign_sessions * POLLUTION_SHARE / (1 - POLLUTION_SHARE))


def right_reliabilities(keys: Mapping[str, Any]) -> dict[str, str | None]:
    """Each right proposal of a layer with the reliability it carries (None for a layer whose proposals carry none)."""
    reliability = keys.get("reliability", {})
    return {key: reliability.get(key) for key in keys["right"]}


def at_top(keys: Mapping[str, Any], top: Mapping[str, str | None]) -> bool:
    """A layer is at its top when it proposes nothing wrong, known-gap entries included, and its right positions with
    their reliabilities are the ones the largest user count learned (`top`, from right_reliabilities)."""
    return not keys["wrong"] and right_reliabilities(keys) == dict(top)


def layer_summary(keys: Mapping[str, Any], metrics: Mapping[str, Any], layer: str) -> dict[str, Any]:
    """One layer of one learning run, from the keys it got right or wrong and its learning metrics. A layer with
    reliabilities also counts its right learnable positions that are high."""
    learnable = set(keys["learnable"])
    right = learnable & set(keys["right"])
    summary: dict[str, Any] = {
        "wrong": len(keys["wrong"]),
        "right": len(right),
        "learnable": len(learnable),
        "accuracy": metrics["accuracy"]["value"],
    }
    if layer in RELIABILITY_LAYERS:
        summary["high"] = sum(1 for key in right if keys["reliability"].get(key) == "high")
    return summary


def convergence(points: Sequence[tuple[int, Mapping[str, Any]]]) -> dict[str, Any]:
    """`points` are (users, learning metrics) in increasing order of users, and the last one is the top: the largest user
    count. Each point gets its layer summaries and whether each layer is at its top there; `first_top` names, per layer,
    the first number of users at which it is (None when no point is)."""
    if not points:
        raise ValueError("the convergence needs at least one point")
    _, top_found = points[-1]
    top = {layer: right_reliabilities(top_found["keys"][layer]) for layer in LAYERS}
    rows: list[dict[str, Any]] = []
    first: dict[str, int | None] = {layer: None for layer in LAYERS}
    for users, found in points:
        layers: dict[str, Any] = {}
        for layer in LAYERS:
            keys = found["keys"][layer]
            layers[layer] = layer_summary(keys, found["metrics"][layer], layer)
            layers[layer]["at_top"] = at_top(keys, top[layer])
        rows.append({"users": users, "layers": layers})
        for layer in LAYERS:
            if first[layer] is None and layers[layer]["at_top"]:
                first[layer] = users
    return {"points": rows, "first_top": first}


def _weaker(now: str | None, before: str | None) -> bool:
    """Whether a reliability is lower than the one it is compared with. Layers without reliabilities never are."""
    return now in RELIABILITY_RANK and before in RELIABILITY_RANK and RELIABILITY_RANK[now] < RELIABILITY_RANK[before]


def attack_summary(requests: Sequence[tuple[str, str]]) -> dict[str, dict[str, int]]:
    """The attack sessions' requests by category, from (category, outcome) pairs of the polluted run. `would_block` is a
    request that should be blocked and the observation run would have blocked it; `allowed` is one it let through, so its
    response was learned (plan 3.2, L5)."""
    table: dict[str, dict[str, int]] = {}
    for category, outcome in requests:
        item = table.setdefault(category, {"requests": 0, "would_block": 0, "allowed": 0, "other": 0})
        item["requests"] += 1
        item[outcome if outcome in ATTACK_OUTCOMES else "other"] += 1
    return table


def attack_requests(rows: Sequence[Mapping[str, Any]], outcomes: Mapping[str, str]) -> list[tuple[str, str]]:
    """The (category, outcome) of each request of an attack session in the polluted run's rows (plan 3.2, L5). The other
    attack rows, such as the function-level attempts of the doctors' and administrators' sessions, are not attack sessions
    and are left out. A request with no outcome in `outcomes` is unjudged."""
    return [(row["category"], outcomes.get(row["request_id"], "unjudged")) for row in rows
            if row["group"] == "attack" and str(row.get("session", "")).startswith(ATTACKER_SESSION_PREFIX)]


def pollution(clean: Mapping[str, Any], polluted: Mapping[str, Any], *, attackers: int, benign_sessions: int,
              attack_requests: Sequence[tuple[str, str]] = ()) -> dict[str, Any]:
    """L5 from the learning metrics of a clean and a polluted run over the same benign sessions. `false_learns` is the
    number of wrong proposals of the polluted run (a finding, not a gate). Per layer, `lost` lists the positions the clean
    run learned right and the polluted run did not learn, or learned with a lower reliability (`weaker`); report only."""
    layers: dict[str, Any] = {}
    for layer in LAYERS:
        clean_keys, polluted_keys = clean["keys"][layer], polluted["keys"][layer]
        clean_reliability, polluted_reliability = right_reliabilities(clean_keys), right_reliabilities(polluted_keys)
        right_clean = set(clean_keys["learnable"]) & set(clean_keys["right"])
        missing = right_clean - set(polluted_keys["right"])
        weaker = {key for key in right_clean & set(polluted_keys["right"])
                  if _weaker(polluted_reliability.get(key), clean_reliability.get(key))}
        layers[layer] = {
            "wrong_clean": len(clean_keys["wrong"]),
            "wrong_polluted": len(polluted_keys["wrong"]),
            "lost": sorted(missing | weaker),
            "weaker": sorted(weaker),
        }
    total = attackers + benign_sessions
    return {
        "attackers": attackers,
        "benign_sessions": benign_sessions,
        "share": attackers / total if total else None,
        "layers": layers,
        "false_learns": sum(item["wrong_polluted"] for item in layers.values()),
        "lost": sum(len(item["lost"]) for item in layers.values()),
        "weaker": sum(len(item["weaker"]) for item in layers.values()),
        "attack_requests": attack_summary(attack_requests),
    }


def public_agreement(learned: Mapping[str, Any] | None, key: str = NATURAL_ORDER_KEY) -> int | None:
    """The agreement per mille that the control counted behind the last judgement of `key` that has one, or None when no
    round of the learned file has it. The rounds are read in order, so the last one wins."""
    value: int | None = None
    for rnd in (learned or {}).get("rounds", []):
        for judgement in rnd.get("judgements", []):
            if judgement.get("key") == key and "agreement_per_mille" in judgement:
                value = judgement["agreement_per_mille"]
    return value


def _order_side(learned: Mapping[str, Any] | None, metrics: Mapping[str, Any] | None) -> dict[str, Any]:
    conclusion = ((metrics or {}).get("conclusions") or {}).get(NATURAL_ORDER_KEY) or {}
    return {"agreement": public_agreement(learned), "tier": conclusion.get("tier"),
            "reliability": conclusion.get("tier_reliability")}


def natural_order(ordered: Mapping[str, Any] | None, natural: Mapping[str, Any] | None, *,
                  ordered_metrics: Mapping[str, Any] | None = None,
                  natural_metrics: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The report-only comparison of the two orders of the deletions (no gate): for the search result, the public agreement
    the control counted, and the tier and reliability it learned, under the ordered run and under the natural-order run."""
    return {"key": NATURAL_ORDER_KEY, "threshold": HIGH_AGREEMENT_PER_MILLE,
            "ordered": _order_side(ordered, ordered_metrics), "natural": _order_side(natural, natural_metrics)}


def consistency_gate(p6: Mapping[str, Any] | None) -> dict[str, Any]:
    """P6 as a gate of the full mode (plan 3.3): the two modes must agree on every compared request, and at least one
    request must have been compared, since an empty comparison proves nothing."""
    compared = (p6 or {}).get("den") or 0
    differing = (p6 or {}).get("num")
    return {"name": CONSISTENCY_GATE, "value": differing, "limit": "== 0，且至少比较一个请求",
            "ok": compared > 0 and differing == 0}


def comparable(result: Mapping[str, Any]) -> dict[str, Any]:
    """The parts of a run's report that must be equal in a second run of the same command. Timings, request IDs and
    Jev probabilities are not in it, because they are not the same from one run to the next."""
    return {
        "metrics": result["metrics"],
        "gates": [(gate["name"], gate["value"], gate["ok"]) for gate in result["gates"]],
        "counts": result["counts"],
        "convergence": result.get("convergence"),
        "pollution": result.get("pollution"),
        "natural_order": result.get("natural_order"),
        "failures": sorted((item["case"], item["config"], item["got"]) for item in result["failures"]),
        "known_gaps": sorted((item["case"], item["unexpected_pass"]) for item in result["known_gaps"]),
        "learning": [(item["key"], item["ok"], item["why"]) for item in result["learning"]],
    }


def differences(first: Mapping[str, Any], second: Mapping[str, Any]) -> list[str]:
    """The names of the parts of two `comparable` documents that are not equal. Empty when the runs agree."""
    names = sorted(set(first) | set(second))
    return [name for name in names if _canonical(first.get(name)) != _canonical(second.get(name))]


def two_pass_gate(differing: Sequence[str]) -> dict[str, Any]:
    return {"name": TWO_PASS_GATE, "value": len(differing), "limit": "== 0", "ok": not differing}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=list)

"""The full mode of the effectiveness measurement (plan 5.2 and 10, batch 7), beyond what the quick mode measures.

- L4, the convergence cost (plan 3.2): the learning over 3, 6, 12 and 24 users, and over the full run's 48. For each
  layer, the first number of users at which the layer is fully correct.
- L5, the anti-pollution (plan 3.2): the learning over the same training traffic with attack sessions mixed in, ten in
  a hundred of all the sessions. Its wrong proposals are findings to report, not a gate. The positions the clean run
  learned right and the polluted run did not are counted as lost, report only.
- P6, the observation against the enforcement (plan 3.3): computed by score.py from the consistency rows.
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
LAYER_TITLES = {
    "L0": "冷启动候选",
    "L1": "请求位置类别",
    "L2": "响应位置档位",
    "L3": "请求位置接受公共来源",
}
TWO_PASS_GATE = "两遍核对（指标逐位相同）"
# The natural-order variant (plan 10, batch 2 note, batch 7): the public search result that a deletion before other
# doctors' searches can cut short, and the agreement a public source needs to be reliability high.
NATURAL_ORDER_KEY = "GET /api/search results[].id"
HIGH_AGREEMENT_PER_MILLE = 980


def attacker_count(benign_sessions: int) -> int:
    """The attack sessions that make up POLLUTION_SHARE of all sessions when mixed into `benign_sessions` benign ones."""
    return round(benign_sessions * POLLUTION_SHARE / (1 - POLLUTION_SHARE))


def fully_correct(keys: Mapping[str, Any]) -> bool:
    """A layer is fully correct when it proposes nothing wrong and every learnable position of the truth is right."""
    return not keys["wrong"] and set(keys["learnable"]) <= set(keys["right"])


def layer_summary(keys: Mapping[str, Any], metrics: Mapping[str, Any]) -> dict[str, Any]:
    """One layer of one learning run, from the keys it got right or wrong and its learning metrics."""
    learnable = set(keys["learnable"])
    return {
        "wrong": len(keys["wrong"]),
        "right": len(learnable & set(keys["right"])),
        "learnable": len(learnable),
        "accuracy": metrics["accuracy"]["value"],
        "fully_correct": fully_correct(keys),
    }


def convergence(points: Sequence[tuple[int, Mapping[str, Any]]]) -> dict[str, Any]:
    """`points` are (users, learning metrics) in increasing order of users. Each point gets its layer summaries, and
    `first_fully_correct` names, per layer, the first number of users at which the layer is fully correct (None when
    no point is)."""
    rows: list[dict[str, Any]] = []
    first: dict[str, int | None] = {layer: None for layer in LAYERS}
    for users, found in points:
        layers = {layer: layer_summary(found["keys"][layer], found["metrics"][layer]) for layer in LAYERS}
        rows.append({"users": users, "layers": layers})
        for layer in LAYERS:
            if first[layer] is None and layers[layer]["fully_correct"]:
                first[layer] = users
    return {"points": rows, "first_fully_correct": first}


def pollution(clean: Mapping[str, Any], polluted: Mapping[str, Any], *, attackers: int,
              benign_sessions: int) -> dict[str, Any]:
    """L5 from the learning metrics of a clean and a polluted run over the same benign sessions. `false_learns` is the
    number of wrong proposals of the polluted run (a finding, not a gate); `lost` per layer lists the positions the
    clean run learned right and the polluted run did not (report only)."""
    layers: dict[str, Any] = {}
    for layer in LAYERS:
        clean_keys, polluted_keys = clean["keys"][layer], polluted["keys"][layer]
        learnable = set(clean_keys["learnable"])
        lost = sorted((learnable & set(clean_keys["right"])) - set(polluted_keys["right"]))
        layers[layer] = {
            "wrong_clean": len(clean_keys["wrong"]),
            "wrong_polluted": len(polluted_keys["wrong"]),
            "lost": lost,
        }
    total = attackers + benign_sessions
    return {
        "attackers": attackers,
        "benign_sessions": benign_sessions,
        "share": attackers / total if total else None,
        "layers": layers,
        "false_learns": sum(item["wrong_polluted"] for item in layers.values()),
        "lost": sum(len(item["lost"]) for item in layers.values()),
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


def natural_order(ordered: Mapping[str, Any] | None, natural: Mapping[str, Any] | None) -> dict[str, Any]:
    """The report-only comparison of the two orders of the deletions (no gate): the public agreement of the search result
    that the ordered run and the natural-order run learned."""
    return {"key": NATURAL_ORDER_KEY, "threshold": HIGH_AGREEMENT_PER_MILLE,
            "ordered": public_agreement(ordered), "natural": public_agreement(natural)}


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

"""Metrics of the effectiveness measurement (plan section 3), computed from the input files.

`score` takes the parsed inputs and returns the report content: the section 9.5 keys
plus costs, counts and label checks. It reads no file, clock or environment, so the
same inputs give the same numbers. A denominator of zero gives None, which the report
shows as "—".

Population rules, applied throughout:

- A regression case with status known_gap is measured only by P7. Once a fix flips it
  to must, it counts in every metric.
- An observation without a decision record is "记录缺失". It is left out of every metric
  and fails the missing-record gate.
- A case whose requires names a capability its configuration lacks (tiers: "需要档位";
  functions: "需要功能表") is left out of P1 to P3 and P7 and counted per configuration and
  capability. A known gap that lacks one is still listed, so the gap does not vanish.
- S1, S3 and S4 measure the benign requests: rows whose expectation is allow.
- The label checks of section 4.6 move a probe out of P1 to P3 only when the caller asks
  (exclude_suspicious). The site runner does; the lab keeps every probe.
- A probe is a case with expect "block". Degradation cases (reason "limit", or a category
  starting with "degrade") are left out of P4 only.
"""

from __future__ import annotations

import json
import math
import statistics
from collections import Counter
from typing import Any, NamedTuple

BENIGN_GROUPS = frozenset({"train", "benign"})
FAST_PATHS = frozenset({"fast_allow", "cached_allow"})
# The benign requests that the gateway decided (plan 3.1). A bypass, an unknown site or a request without
# a session never reached a decision; jev_unavailable is unjudged and counts in P4 instead.
JUDGED_PATHS = frozenset({"fast_allow", "cached_allow", "jev_allow", "jev_deny"})
HIT_OUTCOMES = frozenset({"blocked", "would_block"})
# Positions whose proposals count for learning: a retired, suspended or ambiguous position is not one.
ACTIVE_STATES = frozenset({"proposed", "confirmed"})
LOWER_IS_BETTER = frozenset({"P2", "P4", "P5"})
CONFIG_ORDER = ("none", "learned", "truth")
CALL_LIMIT = "JEV_CALL_LIMIT"
TOLERANCE = 1e-9
REASON_TEXT = {
    "access": "越权（access=DENY）",
    "attack": "注入（attack=ATTACK）",
    "no_session": "无会话（no_session）",
    "limit": "限额（JEV_CALL_LIMIT）",
}
LEARNING_GATE_NAMES = (
    "L0 误学数",
    "L1 误学数",
    "L2 误学数",
    "L3 误学数",
    "学习稳定性（不加数据再跑一轮，提议集合不变）",
)
LEARNING_METRIC_NAMES = ("L0", "L1", "L2", "L3", "stability")


class Pair(NamedTuple):
    """One observation with its decision record and the two label checks of section 4.6."""

    row: dict[str, Any]
    rec: dict[str, Any]
    suspicious: bool  # check 1: an access probe whose target this session had been shown
    bypass: bool  # check 2: a probe that took the bypass path


def score(
    observations: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    truth: dict[str, Any] | None = None,
    learned: dict[str, Any] | None = None,
    *,
    exclude_suspicious: bool = False,
    baseline: dict[str, Any] | None = None,
    probe_values_from_record: bool = False,
) -> dict[str, Any]:
    records = {record["request_id"]: record for record in decisions}
    pairs: list[Pair] = []
    missing: list[dict[str, Any]] = []
    for row in observations:
        record = records.get(row["request_id"])
        if record is None:
            missing.append(row)
            continue
        suspicious, bypass = _label_flags(row, record, records, probe_values_from_record)
        pairs.append(Pair(row, record, suspicious, bypass))

    active = [pair for pair in pairs if not _known_gap(pair.row)]
    caps = _capabilities(truth, learned)
    defend = [pair for pair in active if _defends(pair, caps, exclude_suspicious)]

    metrics: dict[str, Any] = {}
    metrics.update(_session_metrics(active))
    metrics.update(_defense_metrics(defend, active, pairs, caps))
    learning, skip_reason = _learning(truth, learned, decisions)
    if learning is None:
        metrics.update({name: None for name in LEARNING_METRIC_NAMES})
        learning_gates = [_gate(name, None, None, None) for name in LEARNING_GATE_NAMES]
        learning_rows: list[dict[str, Any]] = []
    else:
        metrics.update(learning["metrics"])
        learning_gates = learning["gates"]
        learning_rows = learning["rows"]

    failures, known_gaps = _failures(pairs, missing, caps, exclude_suspicious)
    p4, p5, p7 = metrics["P4"], metrics["P5"], metrics["P7"]
    s2 = metrics["S2"]
    gates = [
        _gate("记录缺失数", len(missing), "== 0", (not missing) if observations else None),
        _gate("S2 误核验数", s2["value"], "== 0", s2["value"] == 0),
        _gate("P4 未判定请求数（理想模型下必须为 0）", p4["num"], "== 0",
              (p4["num"] == 0) if p4["den"] else None),
        _gate("P5 被拦请求到达源站数", p5["value"], "== 0",
              (p5["value"] == 0) if p5["value"] is not None else None),
        _gate("P7 must 用例通过率", p7["value"], "== 100%",
              (p7["value"] == 1) if p7["value"] is not None else None),
        _gate("P7 意外通过数", p7["unexpected_pass"], "== 0", p7["unexpected_pass"] == 0),
        *learning_gates,
    ]
    baseline_result = compare_baseline(_flatten(metrics), baseline)
    compared = baseline_result["compared"]
    gates.append(_gate(
        "基线比较（只进不退）",
        len(baseline_result["regressions"]) if compared else None,
        "== 0",
        (not baseline_result["regressions"]) if compared else None,
    ))

    skipped: list[dict[str, str]] = []
    if skip_reason is not None:
        skipped.append({"section": "学习段", "why": skip_reason})
    skipped.append({"section": "P6、L4、L5", "why": "完整模式专用，score 子命令不计算"})

    return {
        "metrics": metrics,
        "gates": gates,
        "baseline": baseline_result,
        "failures": failures,
        "known_gaps": known_gaps,
        "learning": learning_rows,
        "label_checks": _label_summary(pairs, exclude_suspicious),
        "costs": _costs(decisions),
        "counts": {
            "observations": len(observations),
            "decisions": len(decisions),
            "scored": len(active),
            "missing": len(missing),
            "known_gap_cases": sum(_known_gap(pair.row) for pair in pairs),
        },
        "needs": _needs(pairs, caps),
        "skipped": skipped,
        "passed": all(gate["ok"] is not False for gate in gates),
    }


# ---------------------------------------------------------------- shared helpers


def _metric(num: int, den: int) -> dict[str, Any]:
    return {"value": num / den if den else None, "num": num, "den": den}


def _gate(name: str, value: Any, limit: str, ok: bool | None) -> dict[str, Any]:
    return {"name": name, "value": value, "limit": limit, "ok": ok}


def _known_gap(row: dict[str, Any]) -> bool:
    return row["group"] == "regression" and row["status"] == "known_gap"


def _degraded(row: dict[str, Any]) -> bool:
    return row["reason"] == "limit" or row["category"].startswith("degrade")


def _missing(row: dict[str, Any], caps: dict[str, dict[str, bool]]) -> list[str]:
    """The capabilities the row requires and its configuration lacks. A row with none of them is scored."""
    have = caps.get(row["config"], {})
    return [name for name in row["requires"] if not have.get(name, False)]


def _label_excluded(pair: Pair, exclude_suspicious: bool) -> bool:
    return exclude_suspicious and pair.row["group"] != "regression" and (pair.suspicious or pair.bypass)


def _defends(pair: Pair, caps: dict[str, dict[str, bool]], exclude_suspicious: bool) -> bool:
    return not _missing(pair.row, caps) and not _label_excluded(pair, exclude_suspicious)


def _capabilities(truth: dict[str, Any] | None, learned: dict[str, Any] | None) -> dict[str, dict[str, bool]]:
    """What each configuration declares (plan 9.3): tiers, a function table, and the classes of its object map.
    "none" declares none of them: its map holds only the identity positions, and no class to compare with."""
    caps = {"none": {"tiers": False, "functions": False, "classes": False}}
    if truth is not None:
        caps["truth"] = {
            "tiers": any(bool(position.get("tier")) for position in truth["response_positions"]),
            "functions": bool(truth.get("functions")),
            "classes": bool(truth.get("classes")),
        }
    if learned is not None:
        objects = (learned.get("final_spec") or {}).get("objects") or {}
        # The learned configuration declares tiers when its slots, or its active positions, carry one.
        slots = objects.get("slots") or []
        rounds = learned.get("rounds") or []
        positions = rounds[-1]["positions"] if rounds else []
        # The identity positions name the classes every site has; a class listed beyond them was learned.
        identity = {slot.get("class") for slot in slots if slot.get("identity")}
        caps["learned"] = {
            "tiers": any(bool(slot.get("tier")) for slot in slots) or any(
                bool(position.get("tier")) and position["state"] in ACTIVE_STATES for position in positions),
            "functions": bool(objects.get("functions")),
            "classes": any(entry.get("id") not in identity for entry in objects.get("classes") or []),
        }
    return caps


def _entries(rec: dict[str, Any], value: str) -> list[dict[str, Any]]:
    values = (rec.get("trace") or {}).get("values") or []
    return [entry for entry in values if entry.get("value") == value]


def _verified(rec: dict[str, Any], value: str) -> bool:
    return any(bool(entry.get("verified")) for entry in _entries(rec, value))


def _same_session(rec: dict[str, Any], source: dict[str, Any], records: dict[str, dict[str, Any]]) -> bool:
    origin = records.get(source.get("request_id"))
    return origin is not None and bool(rec.get("session")) and origin.get("session") == rec.get("session")


def _label_flags(row: dict[str, Any], rec: dict[str, Any], records: dict[str, dict[str, Any]],
                 from_record: bool = False) -> tuple[bool, bool]:
    """Section 4.6 checks for a probe. Only expected blocks are probes. The values checked are the probe's
    references, or with from_record every value its decision record carries: a real site has no origin
    truth to name the references by. With from_record the probe is suspicious only when every one of those
    values was verified and came from this session, so one unverified value keeps the probe in the rate."""
    if row["expect"] != "block":
        return False, False
    if from_record:
        values = _record_values(rec)
        suspicious = row["reason"] == "access" and bool(values) and all(
            any(_proven_here(rec, entry, records) for entry in _entries(rec, value)) for value in values)
    else:
        suspicious = row["reason"] == "access" and any(
            _proven_here(rec, entry, records) for ref in row["refs"] for entry in _entries(rec, ref["value"]))
    return suspicious, rec["decision_path"] == "bypass"


def _proven_here(rec: dict[str, Any], entry: dict[str, Any], records: dict[str, dict[str, Any]]) -> bool:
    """The value was verified, and one of the sources it came from was in this session."""
    return bool(entry.get("verified")) and any(
        _same_session(rec, source, records) for source in entry.get("sources") or [])


def _record_values(rec: dict[str, Any]) -> list[str]:
    values = (rec.get("trace") or {}).get("values") or []
    return sorted({entry["value"] for entry in values if isinstance(entry.get("value"), str)})


def _jev_calls(rec: dict[str, Any]) -> int:
    jev = rec.get("jev")
    if not jev:
        return 0
    # A record carries a jev object when Jev was called or the call was skipped by the limit. A state cut into
    # batches is one call per batch (docs/07 7.5.1), and the record shows only one of them.
    if jev.get("failure") == CALL_LIMIT:
        return 0
    return int(jev.get("batches") or 1)


def _jev_choice(rec: dict[str, Any], kind: str) -> str | None:
    jev = rec.get("jev") or {}
    response = jev.get("response")
    if isinstance(response, str):
        try:
            answer = json.loads(response)["answers"][kind]["choice"]
        except (ValueError, KeyError, TypeError):
            answer = None
        if isinstance(answer, str):
            return answer
    probabilities = jev.get(kind)
    if isinstance(probabilities, dict) and probabilities:
        return max(probabilities, key=probabilities.get)
    return None


def _jev_summary(rec: dict[str, Any]) -> str:
    jev = rec.get("jev")
    if not jev:
        return "未调用 Jev"
    if jev.get("failure"):
        return f"Jev 失败：{jev['failure']}"
    parts = []
    for kind in ("access", "attack"):
        choice = _jev_choice(rec, kind)
        if choice is None:
            continue
        probability = (jev.get(kind) or {}).get(choice)
        shown = f"{probability:.2f}" if isinstance(probability, (int, float)) else "—"
        parts.append(f"{kind}={choice}（概率 {shown}）")
    return "，".join(parts) or "Jev 没有答案"


def _reason_matches(row: dict[str, Any], rec: dict[str, Any]) -> bool:
    """Whether a block came for the reason the case expects (P3). Timeouts and limits do not count
    as an access or attack judgement."""
    reason = row["reason"]
    if reason is None:
        return True
    path = rec["decision_path"]
    failure = (rec.get("jev") or {}).get("failure")
    if reason == "limit":
        return failure == CALL_LIMIT
    if reason == "no_session":
        return path == "no_session"
    if reason == "access":
        return path == "jev_deny" and _jev_choice(rec, "access") == "DENY"
    if reason == "attack":
        return path == "jev_deny" and _jev_choice(rec, "attack") == "ATTACK"
    return False


def _problems(row: dict[str, Any], rec: dict[str, Any]) -> list[str]:
    """Why a scored request does not meet its expectation; an empty list means it passes."""
    outcome = rec["outcome"]
    if outcome == "unjudged":
        return ["未判定"]
    problems = []
    if row["expect"] == "block":
        if outcome not in HIT_OUTCOMES:
            problems.append("应拦截，实际放行")
        elif not _reason_matches(row, rec):
            problems.append(f"拦截原因不符，应为 {REASON_TEXT[row['reason']]}")
    elif outcome in HIT_OUTCOMES:
        problems.append("应放行，实际拦截")
    if outcome == "blocked" and row.get("origin_served") is True:
        problems.append("被拦请求已到达源站")
    return problems


class _Tally:
    """Hits over a denominator: overall, by configuration, and by category and configuration."""

    def __init__(self) -> None:
        self.num = 0
        self.den = 0
        self.by_config: dict[str, list[int]] = {}
        self.by_category: dict[str, dict[str, list[int]]] = {}

    def add(self, category: str, config: str, hit: bool) -> None:
        self.den += 1
        self.num += int(hit)
        for cell in (self.by_config.setdefault(config, [0, 0]),
                     self.by_category.setdefault(category, {}).setdefault(config, [0, 0])):
            cell[0] += int(hit)
            cell[1] += 1

    def render(self) -> dict[str, Any]:
        return {
            **_metric(self.num, self.den),
            "by_config": {config: _metric(*cell) for config, cell in _sorted_configs(self.by_config).items()},
            "by_category": {
                category: {config: _metric(*cell) for config, cell in _sorted_configs(cells).items()}
                for category, cells in sorted(self.by_category.items())
            },
        }


def _sorted_configs(cells: dict[str, Any]) -> dict[str, Any]:
    def order(config: str) -> tuple[int, str]:
        position = CONFIG_ORDER.index(config) if config in CONFIG_ORDER else len(CONFIG_ORDER)
        return position, config

    return {config: cells[config] for config in sorted(cells, key=order)}


# ---------------------------------------------------------------- session values (S1 to S4)


class _Cells:
    """Hits over a denominator, in total and for each configuration. The total can hide a configuration that
    fails (plan 12a: 96.4% without an object map and 7.2% with one give 52% together), so S1, S3 and S4 keep both."""

    def __init__(self) -> None:
        self.cells: dict[str, list[int]] = {}

    def add(self, config: str, hit: int, den: int = 1) -> None:
        cell = self.cells.setdefault(config, [0, 0])
        cell[0] += hit
        cell[1] += den

    def render(self) -> dict[str, Any]:
        num = sum(cell[0] for cell in self.cells.values())
        den = sum(cell[1] for cell in self.cells.values())
        return {**_metric(num, den),
                "by_config": {config: _metric(*cell) for config, cell in _sorted_configs(self.cells).items()}}


def _session_metrics(active: list[Pair]) -> dict[str, Any]:
    benign = [pair for pair in active if pair.row["group"] in BENIGN_GROUPS and pair.row["expect"] == "allow"]
    s1, s3, s4 = _Cells(), _Cells(), _Cells()
    for pair in benign:
        config = pair.row["config"]
        for ref in pair.row["refs"]:
            if ref["shown"] and not ref["echoed"]:
                s1.add(config, int(_verified(pair.rec, ref["value"])))
        if pair.rec["decision_path"] in JUDGED_PATHS:
            s3.add(config, int(pair.rec["decision_path"] in FAST_PATHS))
            s4.add(config, _jev_calls(pair.rec))
    # S2 checks every reference that was not an echo. An echo is a value the session sent first.
    s2_num = s2_den = 0
    for pair in active:
        for ref in pair.row["refs"]:
            if ref["echoed"]:
                continue
            s2_den += 1
            if not ref["shown"] and _verified(pair.rec, ref["value"]):
                s2_num += 1
    return {
        "S1": s1.render(),
        "S2": {"value": s2_num, "num": s2_num, "den": s2_den},
        "S3": s3.render(),
        "S4": s4.render(),
    }


# ---------------------------------------------------------------- defence (P1 to P5, P7)


def _defense_metrics(defend: list[Pair], active: list[Pair], pairs: list[Pair],
                     caps: dict[str, dict[str, bool]]) -> dict[str, Any]:
    p1, p2, p3 = _Tally(), _Tally(), _Tally()
    for pair in defend:
        row, rec = pair.row, pair.rec
        if rec["outcome"] == "unjudged":
            continue
        hit = rec["outcome"] in HIT_OUTCOMES
        if row["expect"] == "block":
            p1.add(row["category"], row["config"], hit)
            if hit:
                p3.add(row["category"], row["config"], _reason_matches(row, rec))
        else:
            p2.add(row["category"], row["config"], hit)

    measured = [pair for pair in active if not _degraded(pair.row)]
    unavailable = sum(pair.rec["decision_path"] == "jev_unavailable" for pair in measured)
    served = [pair for pair in active if pair.row["origin_served"] is not None]
    leaked = sum(pair.rec["outcome"] == "blocked" and pair.row["origin_served"] is True for pair in served)

    regressions = [pair for pair in pairs if pair.row["group"] == "regression"]
    must = [pair for pair in regressions
            if pair.row["status"] == "must" and not _missing(pair.row, caps)]
    gaps = [pair for pair in regressions
            if pair.row["status"] == "known_gap" and not _missing(pair.row, caps)]
    must_pass = sum(not _problems(pair.row, pair.rec) for pair in must)
    unexpected = sum(not _problems(pair.row, pair.rec) for pair in gaps)
    return {
        "P1": p1.render(),
        "P2": p2.render(),
        "P3": p3.render(),
        "P4": _metric(unavailable, len(measured)),
        "P5": {"value": leaked if served else None, "num": leaked, "den": len(served)},
        "P7": {**_metric(must_pass, len(must)), "known_gap": len(gaps), "unexpected_pass": unexpected},
    }


# ---------------------------------------------------------------- failures and label checks


def _failure(pair: Pair, problems: list[str]) -> dict[str, Any]:
    row, rec = pair.row, pair.rec
    detail = "；".join(problems)
    if row.get("delivered") is False and row["expect"] == "block":
        detail += "；载荷没有送到模型面前"
    return {
        "case": row["case"],
        "group": row["group"],
        "status": row["status"],
        "category": row["category"],
        "config": row["config"],
        "expect": row["expect"],
        "got": rec["decision_path"],
        "outcome": rec["outcome"],
        "request_id": row["request_id"],
        "jev": _jev_summary(rec),
        "detail": detail,
    }


def _failures(pairs: list[Pair], missing: list[dict[str, Any]], caps: dict[str, dict[str, bool]],
              exclude_suspicious: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    failures: list[dict[str, Any]] = []
    known_gaps: list[dict[str, Any]] = []
    for pair in pairs:
        row = pair.row
        lacks = _missing(row, caps)
        problems = _problems(row, pair.rec)
        if _known_gap(row):
            # Listed whatever the configuration: a gap that is not scored here is still a gap (plan 9.3).
            unexpected = not lacks and not problems
            known_gaps.append({
                "case": row["case"],
                "ref": row["ref"],
                "note": row["note"],
                "category": row["category"],
                "config": row["config"],
                "lacks": lacks,
                "unexpected_pass": unexpected,
            })
            if unexpected:
                failures.append(_failure(pair, ["意外通过：已知缺口的用例通过了，请把状态改为 must"]))
            continue
        if lacks or _label_excluded(pair, exclude_suspicious):
            continue
        if problems:
            failures.append(_failure(pair, problems))
    for row in missing:
        failures.append({
            "case": row["case"],
            "group": row["group"],
            "status": row["status"],
            "category": row["category"],
            "config": row["config"],
            "expect": row["expect"],
            "got": "记录缺失",
            "outcome": None,
            "request_id": row["request_id"],
            "jev": "",
            "detail": "没有找到这个请求 ID 的判定记录",
        })
    return failures, known_gaps


def _label_summary(pairs: list[Pair], exclude_suspicious: bool) -> dict[str, Any]:
    return {
        "applied": exclude_suspicious,
        "suspicious": [pair.row["case"] for pair in pairs if pair.suspicious],
        "bypass": [pair.row["case"] for pair in pairs if pair.bypass],
        "excluded": sum(_label_excluded(pair, exclude_suspicious) for pair in pairs),
    }


def _needs(pairs: list[Pair], caps: dict[str, dict[str, bool]]) -> dict[str, dict[str, Any]]:
    """Rows left out for a missing capability (plan 9.3): by capability and configuration, with the names of
    the regression cases among them, so the report can list them."""
    counts: dict[str, Counter[str]] = {}
    cases: dict[str, set[str]] = {}
    for pair in pairs:
        for name in _missing(pair.row, caps):
            counts.setdefault(name, Counter())[pair.row["config"]] += 1
            if pair.row["group"] == "regression":
                cases.setdefault(name, set()).add(pair.row["case"])
    return {
        name: {
            "counts": {config: counts[name][config] for config in sorted(counts[name], key=_config_position)},
            "cases": sorted(cases.get(name, set())),
        }
        for name in sorted(counts)
    }


def _config_position(config: str) -> tuple[int, str]:
    return (CONFIG_ORDER.index(config) if config in CONFIG_ORDER else len(CONFIG_ORDER), config)


# ---------------------------------------------------------------- costs


def _judge_ms(rec: dict[str, Any]) -> int | None:
    value = (((rec.get("trace") or {}).get("timing")) or {}).get("judge_ms")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _p95(values: list[int]) -> int | None:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)] if ordered else None


def _costs(decisions: list[dict[str, Any]]) -> dict[str, Any]:
    # A bypass never reached a decision, so it is not a judged record (plan 4.6). The lab has none, so its
    # figures do not move. calls_per_request is the cost line's figure; calls_per_judged_request is the same
    # figure under the name the plan uses for the window-wide count.
    judged = [rec for rec in decisions if rec["decision_path"] != "bypass"]
    calls = sum(_jev_calls(rec) for rec in decisions)
    judged_calls = sum(_jev_calls(rec) for rec in judged)
    fast = sum(rec["decision_path"] in FAST_PATHS for rec in judged)
    timings = [value for value in (_judge_ms(rec) for rec in decisions) if value is not None]
    failures = Counter(
        (rec.get("jev") or {}).get("failure") for rec in decisions if (rec.get("jev") or {}).get("failure")
    )
    per_judged = judged_calls / len(judged) if judged else None
    return {
        "requests": len(decisions),
        "jev_calls": calls,
        "judged_requests": len(judged),
        "calls_per_request": per_judged,
        "fast_share": fast / len(judged) if judged else None,
        "calls_per_judged_request": per_judged,
        "judge_ms_median": statistics.median(timings) if timings else None,
        "judge_ms_p95": _p95(timings),
        "jev_failures": dict(sorted(failures.items())),
    }


# ---------------------------------------------------------------- learning (L0 to L3, stability)


def _lmetric(correct: int, proposals: int, covered: int, truth_total: int,
             high: tuple[int, int] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "accuracy": _metric(correct, proposals),
        "coverage": _metric(covered, truth_total),
        "wrong": proposals - correct,
    }
    if high is not None:
        result["high"] = _metric(*high)
    return result


def _unique(items: list[dict[str, Any]]) -> int:
    return len({item["key"] for item in items})


def _template_matches(template: str, path: str) -> bool:
    wanted = template.strip("/").split("/")
    got = path.split("?", 1)[0].strip("/").split("/")
    if len(wanted) != len(got):
        return False
    for want, have in zip(wanted, got):
        if want.startswith("{") and want.endswith("}"):
            if not have:
                return False
        elif want != have:
            return False
    return True


def _route_matches(rec: dict[str, Any], method: str, route: str) -> bool:
    if rec.get("method") != method:
        return False
    paths = {rec.get("path"), rec.get("logical_path")} - {None}
    return any(_template_matches(route, path) for path in paths)


def _unseen(key: str, position: dict[str, Any], decisions: list[dict[str, Any]]) -> str:
    """Why a truth position was not learned (report section 4), in the groups of section 3.2."""
    if not position["learnable"]:
        why = f"（{position['why']}）" if position.get("why") else ""
        return f"没学到：规则学不到{why}"
    method, route = key.split(" ")[0], key.split(" ")[1]
    seen = [rec for rec in decisions if _route_matches(rec, method, route)]
    if any(rec["decision_path"] == "jev_deny" for rec in seen):
        return "没学到：被拒绝记录挡住"
    if seen:
        return "没学到：其他"
    return "没学到：流量不足"


def _conclusions(rnd: dict[str, Any], identity: set[str]) -> dict[str, dict[str, Any]]:
    """The current conclusion for each key of a round (plan 9.4). A pending judgement gives the tier or
    accepts_public it carries; otherwise the entry's own value counts, when the entry is active. Identity
    positions are not learning output, so they get no conclusion."""
    found: dict[str, dict[str, Any]] = {}
    for position in rnd["positions"]:
        if position["state"] in ACTIVE_STATES and position["key"] not in identity:
            found[position["key"]] = {
                "class": position.get("class"),
                "tier": position.get("tier"),
                "tier_reliability": position.get("reliability") if position.get("tier") is not None else None,
                "accepts_public": position.get("accepts_public"),
                "accepts_reliability": (position.get("reliability")
                                        if position.get("accepts_public") is not None else None),
            }
    for judgement in rnd["judgements"]:
        if judgement["key"] in identity:
            continue
        item = found.setdefault(judgement["key"], {
            "class": None, "tier": None, "tier_reliability": None,
            "accepts_public": None, "accepts_reliability": None,
        })
        if "tier" in judgement:
            item["tier"] = judgement["tier"]
            item["tier_reliability"] = judgement["reliability"]
        if "accepts_public" in judgement:
            item["accepts_public"] = judgement["accepts_public"]
            item["accepts_reliability"] = judgement["reliability"]
    return {key: item for key, item in found.items()
            if any(item[name] is not None for name in ("class", "tier", "accepts_public"))}


def _snapshot(conclusions: dict[str, dict[str, Any]]) -> set[tuple[Any, ...]]:
    """What a round concludes, field by field: the proposal set that the stability check compares."""
    return {
        (key, item["class"], item["tier"], item["tier_reliability"],
         item["accepts_public"], item["accepts_reliability"])
        for key, item in conclusions.items()
    }


def _learning(truth: dict[str, Any] | None, learned: dict[str, Any] | None,
              decisions: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None]:
    if truth is None or learned is None:
        absent = [name for name, doc in (("truth.json", truth), ("learned.json", learned)) if doc is None]
        return None, f"未提供 {'、'.join(absent)}，L0 到 L3 与稳定性未计算"

    request = {p["key"]: p for p in truth["request_positions"]}
    response = {p["key"]: p for p in truth["response_positions"]}
    non_objects = set(truth["non_objects"])
    identity = {item["key"] for item in truth["identity"]}
    rounds = learned["rounds"]
    last = rounds[-1] if rounds else {"positions": [], "judgements": []}
    concl = _conclusions(last, identity)
    candidates = [c for c in learned["bootstrap"] if c["key"] not in identity]
    truth_total = len(request) + len(response)

    # L0: cold-start candidates, which name a class from the route alone.
    def candidate_right(candidate: dict[str, Any]) -> bool:
        table = request if candidate["side"] == "request" else response
        return candidate["key"] in table and table[candidate["key"]]["class"] == candidate["class"]

    right0 = [c for c in candidates if candidate_right(c)]
    l0 = _lmetric(len(right0), len(candidates), _unique(right0), truth_total)

    # L1: request-position classes. A class on a response position is not scored in a round: it comes from
    # the cold-start candidate, and L0 scores it. A class on a non-object or an unknown key is wrong (3.2).
    props1 = [(key, found["class"]) for key, found in concl.items()
              if found["class"] is not None and key not in response]
    right1 = [key for key, cls in props1 if key in request and request[key]["class"] == cls]
    l1 = _lmetric(len(right1), len(props1), len(right1), len(request))

    # L2: response-position tiers. Every key with a tier conclusion is a proposal. A tier on a request
    # position, a non-object or an unknown key has no tier in the truth, so it is wrong.
    tiered = {key: p for key, p in response.items() if p.get("tier")}
    props2 = [(key, found) for key, found in concl.items() if found["tier"] is not None]
    right2 = [key for key, found in props2 if key in tiered and tiered[key]["tier"] == found["tier"]]
    high2 = [key for key in right2 if concl[key]["tier_reliability"] == "high"]
    l2 = _lmetric(len(right2), len(props2), len(right2), len(tiered), high=(len(high2), len(tiered)))

    # L3: request-position accepts_public, with the same rule as L2.
    props3 = [(key, found) for key, found in concl.items() if found["accepts_public"] is not None]
    right3 = [key for key, found in props3
              if key in request and request[key]["accepts_public"] == found["accepts_public"]]
    high3 = [key for key in right3 if concl[key]["accepts_reliability"] == "high"]
    l3 = _lmetric(len(right3), len(props3), len(right3), len(request), high=(len(high3), len(request)))

    stable = None
    if len(rounds) >= 2:
        stable = _snapshot(concl) == _snapshot(_conclusions(rounds[-2], identity))

    rows = _learning_rows(request, response, non_objects, concl, candidates, decisions)
    gates = [
        _gate(LEARNING_GATE_NAMES[0], l0["wrong"], "== 0", l0["wrong"] == 0),
        _gate(LEARNING_GATE_NAMES[1], l1["wrong"], "== 0", l1["wrong"] == 0),
        _gate(LEARNING_GATE_NAMES[2], l2["wrong"], "== 0", l2["wrong"] == 0),
        _gate(LEARNING_GATE_NAMES[3], l3["wrong"], "== 0", l3["wrong"] == 0),
        _gate(LEARNING_GATE_NAMES[4], None if stable is None else ("不变" if stable else "变化"), "不变", stable),
    ]
    metrics = {
        "L0": l0,
        "L1": l1,
        "L2": l2,
        "L3": l3,
        "stability": {"value": stable, "rounds": len(rounds)},
    }
    return {"metrics": metrics, "gates": gates, "rows": rows}, None


def _wrong_row(key: str, side: str, truth: dict[str, Any], found: dict[str, Any] | None,
               candidate: dict[str, Any] | None, why: str) -> dict[str, Any]:
    """A row for a key that the truth holds as a non-object, or does not hold at all."""
    return {
        "key": key,
        "side": side,
        "truth": truth,
        "learned": {
            "class": (found or {}).get("class") or (candidate or {}).get("class"),
            "tier": (found or {}).get("tier"),
            "accepts_public": (found or {}).get("accepts_public"),
        },
        "ok": False,
        "why": why,
    }


def _learning_rows(request: dict[str, Any], response: dict[str, Any], non_objects: set[str],
                   concl: dict[str, dict[str, Any]], candidates: list[dict[str, Any]],
                   decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per truth position and per wrong key (report section 4). A proposal that a metric counts as
    wrong gets a row with its reason, so the table explains each count."""
    candidate_of: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        candidate_of.setdefault((candidate["side"], candidate["key"]), candidate)

    rows: list[dict[str, Any]] = []
    for key, truth_position in request.items():
        found = concl.get(key)
        learned: dict[str, Any] = {}
        if found is None:
            why = _unseen(key, truth_position, decisions)
        else:
            mismatches: list[str] = []
            if found["class"] != truth_position["class"]:
                mismatches.append("类别不符")
            if found["accepts_public"] != truth_position["accepts_public"]:
                mismatches.append("接受公共来源不符")
            if found["tier"] is not None:
                mismatches.append("误学：请求位置没有档位")
            why = "；".join(mismatches)
            learned = {"class": found["class"], "accepts_public": found["accepts_public"], "tier": found["tier"]}
        rows.append({
            "key": key,
            "side": "request",
            "truth": {"class": truth_position["class"], "accepts_public": truth_position["accepts_public"]},
            "learned": learned,
            "ok": not why,
            "why": why,
        })

    for key, truth_position in response.items():
        found = concl.get(key)
        candidate = candidate_of.get(("response", key))
        # A class on a response position is not scored in a round; the table shows the candidate's class (L0).
        learned = {"class": candidate["class"] if candidate else None}
        mismatches = []
        if candidate is not None and candidate["class"] != truth_position["class"]:
            mismatches.append("类别不符")
        if truth_position["tier"] is None:
            # No tier in the truth: the position is left out of L2's denominator, and a tier proposed on it is wrong.
            if found is not None and found["tier"] is not None:
                learned["tier"] = found["tier"]
                learned["reliability"] = found["tier_reliability"]
                mismatches.append("误学：真值无档位")
        elif found is None or found["tier"] is None:
            mismatches.append(_unseen(key, truth_position, decisions))
        else:
            learned["tier"] = found["tier"]
            learned["reliability"] = found["tier_reliability"]
            if found["tier"] != truth_position["tier"]:
                mismatches.append("档位不符")
        if found is not None and found["accepts_public"] is not None:
            learned["accepts_public"] = found["accepts_public"]
            mismatches.append("误学：响应位置没有接受公共来源的标注")
        why = "；".join(mismatches)
        rows.append({
            "key": key,
            "side": "response",
            "truth": {"class": truth_position["class"], "tier": truth_position["tier"]},
            "learned": learned,
            "ok": not why,
            "why": why,
        })

    for key in sorted(non_objects):
        found = concl.get(key)
        candidate = candidate_of.get(("response", key)) or candidate_of.get(("request", key))
        if found is not None or candidate is not None:
            rows.append(_wrong_row(key, "non_object", {"object": False}, found, candidate, "误学：真值为非对象"))

    unknown = (set(concl) | {c["key"] for c in candidates}) - set(request) - set(response) - non_objects
    for key in sorted(unknown):
        found = concl.get(key)
        candidate = candidate_of.get(("response", key)) or candidate_of.get(("request", key))
        rows.append(_wrong_row(key, "unknown", {}, found, candidate, "误学：真值里没有这个位置"))
    return rows


# ---------------------------------------------------------------- baseline and flattening


def _flatten(metrics: dict[str, Any]) -> dict[str, float]:
    """The numbers the baseline compares, by name. A name is a metric, or metric/category/config."""
    flat: dict[str, float | None] = {}
    for name in ("S1", "S3"):
        if metrics.get(name):
            flat[name] = metrics[name]["value"]
            for config, cell in metrics[name]["by_config"].items():
                flat[f"{name}/{config}"] = cell["value"]
    for name in ("P1", "P2", "P3"):
        if metrics.get(name):
            flat[name] = metrics[name]["value"]
            for category, cells in metrics[name]["by_category"].items():
                for config, cell in cells.items():
                    flat[f"{name}/{category}/{config}"] = cell["value"]
    for name in ("L0", "L1", "L2", "L3"):
        if metrics.get(name):
            flat[f"{name}.accuracy"] = metrics[name]["accuracy"]["value"]
            flat[f"{name}.coverage"] = metrics[name]["coverage"]["value"]
    return {name: value for name, value in flat.items() if value is not None}


def compare_baseline(values: dict[str, float], baseline: dict[str, Any] | None) -> dict[str, Any]:
    """Compares each number with the baseline. A regression is a move in the wrong direction (only
    in-or-out comparisons: a metric that is not in the baseline is not compared)."""
    if baseline is None:
        return {"compared": False, "regressions": [], "improvements": [], "reference": {}, "absent": []}
    reference = baseline.get("values", {})
    compared = {name: reference[name] for name in values if reference.get(name) is not None}
    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    for name in sorted(compared):
        now, then = values[name], compared[name]
        lower = name.split("/", 1)[0] in LOWER_IS_BETTER
        worse = now > then + TOLERANCE if lower else now < then - TOLERANCE
        better = now < then - TOLERANCE if lower else now > then + TOLERANCE
        if worse:
            regressions.append({"name": name, "baseline": then, "value": now})
        elif better:
            improvements.append({"name": name, "baseline": then, "value": now})
    # A baseline name that this run does not produce is listed, so a missing number is never silently skipped.
    absent = sorted(name for name, value in reference.items() if value is not None and name not in values)
    return {"compared": True, "regressions": regressions, "improvements": improvements,
            "reference": compared, "absent": absent}


# ---------------------------------------------------------------- confidence threshold scan (plan 3.4)

# 0.50 to 0.90 in steps of 0.05, built from whole hundredths so that 0.60 is the float a probability of 0.6 equals.
CONFIDENCE_THRESHOLDS = tuple(hundredths / 100 for hundredths in range(50, 91, 5))


def allow_confidence(record: dict[str, Any]) -> float | None:
    """The confidence the edge logs as a decision's jev_confidence (xshield-edge sink.rs): the highest probability of
    the access question, the highest of the attack question, and the smaller of those two. For an allow whose answers
    are the most likely ones this is min(P(ALLOW), P(BENIGN)). None when a question has no probabilities."""
    jev = record.get("jev") or {}
    access = jev.get("access") or {}
    attack = jev.get("attack") or {}
    values = [*access.values(), *attack.values()]
    if not access or not attack or not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in values):
        return None
    return min(float(max(access.values())), float(max(attack.values())))


def confidence_scan(observations: list[dict[str, Any]], decisions: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The real model's allows judged again at each threshold, with no traffic (plan 3.4).

    A threshold T keeps an allow whose confidence is at least T: exactly T is still an allow, as WAF batch 7 has it.
    An allow below T becomes an unanswered judgement, which a site with on_jev_unavailable deny refuses. Only the
    jev_allow records change, and the cached_allow records that reuse one (trace.cache_source). fast_allow and every
    refusal stay as they are. A regression case with status known_gap is left out, as score() leaves it out of every
    metric but P7. The judgements counted are the records that carry a Jev answer; a judgement cut into batches counts
    once, since its record shows one batch. The count is first order: a request that changes can leave later requests
    with fewer values to see, and that effect is not counted.

    Returns None when no record holds an allow with its probabilities, which is how a run with the ideal model is told
    apart: its probabilities are fixed, so the scan is not printed for it.
    """
    records = {record["request_id"]: record for record in decisions}
    confidence: dict[str, float] = {}
    for request_id, record in records.items():
        if record["decision_path"] == "jev_allow":
            value = allow_confidence(record)
            if value is not None:
                confidence[request_id] = value
    if not confidence:
        return None

    def confidence_of(record: dict[str, Any]) -> float | None:
        """The confidence the decision rests on, or None when the decision is not an allow of the model."""
        if record["decision_path"] == "jev_allow":
            return confidence.get(record["request_id"])
        if record["decision_path"] == "cached_allow":
            return confidence.get((record.get("trace") or {}).get("cache_source"))
        return None

    benign_values: list[float] = []
    probe_values: list[float] = []
    benign_total = 0
    for row in observations:
        record = records.get(row["request_id"])
        if record is None or _known_gap(row):
            continue
        value = confidence_of(record)
        if row["expect"] == "allow":
            benign_total += 1
            if value is not None:
                benign_values.append(value)
        elif value is not None:
            probe_values.append(value)
    unresolved = sum(
        1 for record in decisions
        if record["decision_path"] == "cached_allow"
        and (record.get("trace") or {}).get("cache_source") not in confidence
    )
    return {
        "thresholds": [
            {
                "threshold": threshold,
                "benign_blocks": sum(value < threshold for value in benign_values),
                "leaks_closed": sum(value < threshold for value in probe_values),
                "unanswered": sum(value < threshold for value in confidence.values()),
            }
            for threshold in CONFIDENCE_THRESHOLDS
        ],
        "benign_total": benign_total,
        "probe_allows": len(probe_values),
        "allows": len(confidence),
        "judgements": sum(1 for record in decisions if _jev_calls(record)),
        "cache_unresolved": unresolved,
    }

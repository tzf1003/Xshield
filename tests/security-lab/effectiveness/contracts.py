"""The data contracts of the effectiveness measurement (plan section 9).

Five files pass between the parts of the pipeline:

- observations.jsonl: one scored request per line, written by a driver;
- decisions.jsonl: the gateway's decision records, in the console export format (docs/07 7.4);
- truth.json: what the origin knows about its objects, written by the site;
- learned.json: the object learning's proposals, round by round;
- report.json: the scorer's output (section 9.5), written by score.py.

Loaders check required fields and enum values and raise ContractError with the file
name and the line (or JSON location). Messages name fields and the values they expect,
never a request value, because decision records carry request values.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    """A file that breaks the contract. The message starts with the file name and location."""


GROUPS = frozenset({"train", "benign", "attack", "regression"})
EXPECTS = frozenset({"block", "allow"})
REASONS = frozenset({"access", "attack", "no_session", "limit"})
STATUSES = frozenset({"must", "known_gap"})
MODES = frozenset({"enforce", "observe"})
CAPABILITIES = frozenset({"tiers"})
TIERS = frozenset({"self", "org", "admin", "public"})
RELIABILITIES = frozenset({"low", "medium", "high"})
SIDES = frozenset({"request", "response"})
IDENTITIES = frozenset({"user", "org", "role"})
POSITION_STATES = frozenset({"pending", "proposed", "confirmed", "ambiguous", "suspended", "retired"})
DECISION_PATHS = frozenset({
    "bypass", "body_not_inspectable", "unknown_site", "fast_allow", "cached_allow",
    "jev_allow", "jev_deny", "jev_unavailable", "no_session",
})
OUTCOMES = frozenset({"allowed", "blocked", "would_block", "unjudged"})

Check = Callable[[Any], bool]
Fields = dict[str, tuple[Check, str]]


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def _is_ref(value: Any) -> bool:
    return (_is_dict(value) and _is_str(value.get("value")) and _is_str(value.get("class"))
            and _is_bool(value.get("shown")) and _is_bool(value.get("echoed")))


def _position_key(value: Any) -> bool:
    """A position key: "METHOD /route position", for example "GET /api/search results[].id"."""
    parts = value.split(" ") if isinstance(value, str) else []
    return len(parts) == 3 and parts[1].startswith("/") and parts[0].isupper()


def _one_of(allowed: frozenset[str]) -> Check:
    return lambda value: isinstance(value, str) and value in allowed


def _optional(check: Check) -> Check:
    return lambda value: value is None or check(value)


def _list_of(check: Check) -> Check:
    return lambda value: isinstance(value, list) and all(check(item) for item in value)


OBSERVATION: Fields = {
    "case": (_is_str, "字符串"),
    "group": (_one_of(GROUPS), "train、benign、attack 或 regression"),
    "category": (_is_str, "字符串"),
    "expect": (_one_of(EXPECTS), "block 或 allow"),
    "reason": (_optional(_one_of(REASONS)), "access、attack、no_session、limit 或 null"),
    "status": (_one_of(STATUSES), "must 或 known_gap"),
    "ref": (_optional(_is_str), "字符串或 null"),
    "config": (_is_str, "字符串"),
    "site": (_is_str, "字符串"),
    "mode": (_one_of(MODES), "enforce 或 observe"),
    "run": (_is_int, "整数"),
    "request_id": (_is_str, "字符串"),
    "setup_request_ids": (_list_of(_is_str), "字符串数组"),
    "client_status": (_is_int, "整数"),
    "origin_served": (_optional(_is_bool), "true、false 或 null"),
    "refs": (_list_of(_is_ref), "对象数组，每项含 value、class、shown、echoed"),
    "requires": (_list_of(_one_of(CAPABILITIES)), "能力名数组，目前只有 tiers"),
    "note": (_is_str, "字符串"),
}
# Optional: the driver's answer to "did the payload reach the model" (lab only). Used in the
# failure list to say so; never scored.
OBSERVATION_OPTIONAL: Fields = {
    "delivered": (_optional(_is_bool), "true、false 或 null"),
}

DECISION: Fields = {
    "request_id": (_is_str, "字符串"),
    "decision_path": (_one_of(DECISION_PATHS), "docs/07 7.4 列出的判定路径之一"),
    "outcome": (_one_of(OUTCOMES), "allowed、blocked、would_block 或 unjudged"),
    "method": (_is_str, "字符串"),
    "path": (_is_str, "字符串"),
}
DECISION_OPTIONAL: Fields = {
    "session": (_is_str, "字符串"),
    "trace": (_optional(_is_dict), "对象或 null"),
    "jev": (_optional(_is_dict), "对象或 null"),
}

TRUTH: Fields = {
    "site": (_is_str, "字符串"),
    "seed": (_is_int, "整数"),
    "classes": (_list_of(_is_str), "字符串数组"),
    "identity": (_list_of(_is_dict), "对象数组，每项含 key 与 identity"),
    "request_positions": (_list_of(_is_dict), "对象数组"),
    "response_positions": (_list_of(_is_dict), "对象数组"),
    "non_objects": (_list_of(_position_key), "位置键数组"),
}
IDENTITY: Fields = {
    "key": (_position_key, "“METHOD /路由 位置”格式的键"),
    "identity": (_one_of(IDENTITIES), "user、org 或 role"),
}
REQUEST_POSITION: Fields = {
    "key": (_position_key, "“METHOD /路由 位置”格式的键"),
    "class": (_is_str, "字符串"),
    "accepts_public": (_is_bool, "true 或 false"),
    "learnable": (_is_bool, "true 或 false"),
}
RESPONSE_POSITION: Fields = {
    "key": (_position_key, "“METHOD /路由 位置”格式的键"),
    "class": (_is_str, "字符串"),
    "tier": (_one_of(TIERS), "self、org、admin 或 public"),
    "learnable": (_is_bool, "true 或 false"),
}
TRUTH_OPTIONAL: Fields = {"why": (_is_str, "字符串")}

LEARNED: Fields = {
    "bootstrap": (_list_of(_is_dict), "对象数组"),
    "rounds": (_list_of(_is_dict), "对象数组"),
    "final_spec": (_is_dict, "对象"),
}
CANDIDATE: Fields = {
    "key": (_position_key, "“METHOD /路由 位置”格式的键"),
    "side": (_one_of(SIDES), "request 或 response"),
    "class": (_is_str, "字符串"),
    "uses": (_is_int, "整数"),
    "sessions": (_is_int, "整数"),
}
ROUND: Fields = {
    "round": (_is_int, "整数"),
    "run": (_is_dict, "对象"),
    "positions": (_list_of(_is_dict), "对象数组"),
    "judgements": (_list_of(_is_dict), "对象数组"),
}
POSITION: Fields = {
    "key": (_position_key, "“METHOD /路由 位置”格式的键"),
    "state": (_one_of(POSITION_STATES), "pending、proposed、confirmed、ambiguous、suspended 或 retired"),
    "class": (_optional(_is_str), "字符串或 null"),
    "source": (_optional(_is_str), "字符串或 null"),
    "tier": (_optional(_one_of(TIERS)), "self、org、admin、public 或 null"),
    "accepts_public": (_optional(_is_bool), "true、false 或 null"),
    "reliability": (_optional(_one_of(RELIABILITIES)), "low、medium、high 或 null"),
}
JUDGEMENT: Fields = {
    "key": (_position_key, "“METHOD /路由 位置”格式的键"),
    "tier": (_one_of(TIERS), "self、org、admin 或 public"),
    "reliability": (_one_of(RELIABILITIES), "low、medium 或 high"),
}

BASELINE: Fields = {"values": (_is_dict, "对象（指标名到数值）")}


def _check_fields(obj: Any, where: str, fields: Fields) -> None:
    if not isinstance(obj, dict):
        raise ContractError(f"{where}: 应为 JSON 对象")
    for name, (check, expected) in fields.items():
        if name not in obj:
            raise ContractError(f"{where}: 缺少必填字段 {name}")
        if not check(obj[name]):
            raise ContractError(f"{where}: 字段 {name} 应为 {expected}")


def _check_present(obj: dict, where: str, fields: Fields) -> None:
    """Checks only the optional fields that the object actually carries."""
    for name, (check, expected) in fields.items():
        if name in obj and not check(obj[name]):
            raise ContractError(f"{where}: 字段 {name} 应为 {expected}")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ContractError(f"{path.name}: 无法读取（{type(error).__name__}）") from error


def _read_jsonl(path: Path) -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = []
    for number, line in enumerate(_read_text(path).splitlines(), 1):
        if not line.strip():
            continue
        where = f"{path.name}:{number}"
        try:
            rows.append((where, json.loads(line)))
        except ValueError as error:
            raise ContractError(f"{where}: 不是合法的 JSON") from error
    return rows


def _read_json(path: Path) -> Any:
    try:
        return json.loads(_read_text(path))
    except ValueError as error:
        line = getattr(error, "lineno", 0)
        raise ContractError(f"{path.name}:{line}: 不是合法的 JSON") from error


def load_observations(path: Path) -> list[dict[str, Any]]:
    rows = []
    for where, obj in _read_jsonl(path):
        _check_fields(obj, where, OBSERVATION)
        _check_present(obj, where, OBSERVATION_OPTIONAL)
        if obj["expect"] == "block" and obj["reason"] is None:
            raise ContractError(f"{where}: expect 为 block 时 reason 不能为 null")
        if obj["expect"] == "allow" and obj["reason"] is not None:
            raise ContractError(f"{where}: expect 为 allow 时 reason 应为 null")
        rows.append(obj)
    return rows


def load_decisions(path: Path) -> list[dict[str, Any]]:
    first_line: dict[str, str] = {}
    rows = []
    for where, obj in _read_jsonl(path):
        _check_fields(obj, where, DECISION)
        _check_present(obj, where, DECISION_OPTIONAL)
        first = first_line.setdefault(obj["request_id"], where)
        if first != where:
            raise ContractError(f"{where}: request_id 与 {first} 重复")
        rows.append(obj)
    return rows


def load_truth(path: Path) -> dict[str, Any]:
    name = path.name
    doc = _read_json(path)
    _check_fields(doc, name, TRUTH)
    seen: dict[str, str] = {}
    for section, fields in (("request_positions", REQUEST_POSITION),
                            ("response_positions", RESPONSE_POSITION)):
        for index, position in enumerate(doc[section]):
            where = f"{name}:{section}[{index}]"
            _check_fields(position, where, fields)
            _check_present(position, where, TRUTH_OPTIONAL)
            if position["key"] in seen:
                raise ContractError(f"{where}: 位置键重复（与 {seen[position['key']]} 相同）")
            seen[position["key"]] = where
    for index, identity in enumerate(doc["identity"]):
        _check_fields(identity, f"{name}:identity[{index}]", IDENTITY)
    return doc


def load_learned(path: Path) -> dict[str, Any]:
    name = path.name
    doc = _read_json(path)
    _check_fields(doc, name, LEARNED)
    for index, candidate in enumerate(doc["bootstrap"]):
        _check_fields(candidate, f"{name}:bootstrap[{index}]", CANDIDATE)
    for number, rnd in enumerate(doc["rounds"]):
        where = f"{name}:rounds[{number}]"
        _check_fields(rnd, where, ROUND)
        for index, position in enumerate(rnd["positions"]):
            _check_fields(position, f"{where}.positions[{index}]", POSITION)
        for index, judgement in enumerate(rnd["judgements"]):
            _check_fields(judgement, f"{where}.judgements[{index}]", JUDGEMENT)
    return doc


def load_baseline(path: Path) -> dict[str, Any]:
    doc = _read_json(path)
    _check_fields(doc, path.name, BASELINE)
    for metric, value in doc["values"].items():
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise ContractError(f"{path.name}: 指标 {metric} 的基线应为数字或 null")
    return doc


def dump_json(path: Path, document: Any) -> None:
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

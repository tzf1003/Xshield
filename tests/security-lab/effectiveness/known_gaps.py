"""The learning known-gap list (plan 8 and 12b): the learning problems that the measurement shows today, each listed
once, so that the gates count only the problems nobody has listed yet.

An entry says what the problem is, where it was measured, and which batch of the learning-quality design fixes it:

- kind "wrong": a proposal the truth contradicts (L0 to L3). Matched by metric, key and, when the entry names one,
  the learned value.
- kind "unmodeled": a proposal on a key the truth does not hold at all (plan 12b, the first gate of the unmodeled
  positions). Matched by its pattern, with generated codes replaced by an ellipsis, so one entry covers every code.
- kind "miss": a truth position the learning did not learn, with the reason it has (for example suspended by the
  learning, plan 12b item 2). Matched by key.
- kind "failure": a scored request of the learned object map that does not meet its expectation (plan 12b, the
  benign blocks and the protection misses on the learned configuration). Matched by case name.

Rules, applied by `apply`:

- A listed problem does not fail a gate. An unlisted one does.
- An entry that matches nothing is stale: the problem is gone, so the entry must be deleted in the same change that
  fixed it (the fix that makes the case pass). A stale entry fails the gate that checks the list.
- The list is checked only when the learning segment ran and every probe ran. Otherwise nothing can be called
  stale, and the check says so.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

KINDS = frozenset({"wrong", "unmodeled", "miss", "failure"})
METRICS = frozenset({"L0", "L1", "L2", "L3"})
ELLIPSIS = "…"
# A generated code in a route or a path segment: SHR-028C8381 in GET /share/SHR-028C8381 path[1]. Its value changes
# with every share, so every code of one route is the same pattern.
GENERATED_CODE = re.compile(r"(?<=/)[A-Z]+-[0-9A-Za-z]+(?=[ /]|$)")


def pattern_of(key: str) -> str:
    """The key with each generated code replaced by an ellipsis (plan 12b, item 3)."""
    return GENERATED_CODE.sub(ELLIPSIS, key)


def apply(entries: Sequence[Mapping[str, Any]], *, wrong: Iterable[Mapping[str, Any]],
          unmodeled: Iterable[Mapping[str, Any]], misses: Iterable[Mapping[str, Any]],
          failures: Iterable[Mapping[str, Any]], check: bool) -> dict[str, Any]:
    """Matches the learning problems and the learned failures with the list.

    `wrong` items carry metric, key and learned; `unmodeled` items carry key and pattern; `misses` items carry key;
    `failures` items carry case and config. The result gives, for each group, the items the list covers and the ones
    it does not, the entries with their match counts, and the stale entries. With check False nothing is stale and
    `stale` is None."""
    wrong_items = list(wrong)
    unmodeled_items = list(unmodeled)
    miss_items = list(misses)
    failure_items = list(failures)
    counted = {id(item): 0 for item in (*wrong_items, *unmodeled_items, *miss_items, *failure_items)}
    matched: list[dict[str, Any]] = []
    for entry in entries:
        hits = [item for item in _candidates(entry, wrong_items, unmodeled_items, miss_items, failure_items)
                if _hits(entry, item)]
        for item in hits:
            counted[id(item)] += 1
        matched.append({**dict(entry), "matched": len(hits)})
    stale = [entry["id"] for entry in matched if entry["matched"] == 0] if check else None
    return {
        "entries": matched,
        "listed": {
            "wrong": [item for item in wrong_items if counted[id(item)]],
            "unmodeled": [item for item in unmodeled_items if counted[id(item)]],
        },
        "unlisted": {
            "wrong": [item for item in wrong_items if not counted[id(item)]],
            "unmodeled": [item for item in unmodeled_items if not counted[id(item)]],
        },
        "misses": [{**item, "gap": _gap_id(item, matched)} for item in miss_items],
        "failures": [item for item in failure_items if counted[id(item)]],
        "stale": stale,
    }


def _candidates(entry: Mapping[str, Any], wrong: list, unmodeled: list, misses: list,
                failures: list) -> list[Mapping[str, Any]]:
    return {"wrong": wrong, "unmodeled": unmodeled, "miss": misses, "failure": failures}[entry["kind"]]


def _hits(entry: Mapping[str, Any], item: Mapping[str, Any]) -> bool:
    kind = entry["kind"]
    if kind == "wrong":
        return (item["metric"] == entry["metric"] and item["key"] == entry["key"]
                and ("learned" not in entry or entry["learned"] == item.get("learned")))
    if kind == "unmodeled":
        return item["pattern"] == entry["pattern"]
    if kind == "miss":
        return item["key"] == entry["key"]
    return item["case"] == entry["case"] and item["config"] == entry["config"]


def _gap_id(item: Mapping[str, Any], matched: list[dict[str, Any]]) -> str | None:
    for entry in matched:
        if entry["kind"] == "miss" and entry["matched"] and item["key"] == entry["key"]:
            return entry["id"]
    return None

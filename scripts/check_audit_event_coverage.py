#!/usr/bin/env python3
"""Fail when a control endpoint can emit a management audit event the worker cannot publish.

The control plane appends one journal event per access attempt. The worker's
management-audit publisher accepts only events listed in its explicit
(event type, method, path) matrix; anything else stops publication of the whole
segment. Adding an endpoint without extending that matrix therefore silently
breaks audit publication, so this check compares the two sources textually.
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTROL = ROOT / "crates/xshield-control/src"
WORKER = ROOT / "crates/xshield-worker/src/control_audit.rs"

CONST = re.compile(r'(?:pub(?:\([a-z]+\))?\s+)?const\s+(\w+):\s*&str\s*=\s*"([^"]+)";')
ACTION = re.compile(
    r'AccessAction\s*\{\s*event_type:\s*"([^"]+)",\s*method:\s*"([^"]+)",\s*path:\s*((?:\w+::)*\w+|"[^"]+")\s*,',
)
# One match arm alternative: ("event" | "other", "METHOD", "path"), possibly over several lines.
MATRIX = re.compile(
    r'\(\s*((?:"[a-z_.]+"\s*\|?\s*)+),\s*"([A-Z*]+)"\s*,\s*"([^"]+)"\s*,?\s*\)',
)


def control_sources() -> dict[pathlib.Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in sorted(CONTROL.rglob("*.rs"))
            if "tests" not in path.relative_to(CONTROL).parts}


def module_files(path: pathlib.Path, qualifier: str | None) -> list[pathlib.Path]:
    """Files that may define a constant referenced from `path` (qualified or imported from `super`)."""
    if qualifier:
        return [CONTROL / f"{qualifier}.rs", CONTROL / qualifier / "mod.rs"]
    parent = path.parent
    return [parent / "mod.rs", parent.with_suffix(".rs"), CONTROL / "lib.rs"]


def resolve(name: str, path: pathlib.Path, per_file: dict[pathlib.Path, dict[str, str]]) -> str | None:
    if name.startswith('"'):
        return name.strip('"')
    *qualifiers, bare = name.split("::")
    if not qualifiers and bare in per_file[path]:
        return per_file[path][bare]
    for candidate in module_files(path, qualifiers[-1] if qualifiers else None):
        if bare in per_file.get(candidate, {}):
            return per_file[candidate][bare]
    return None


def main() -> int:
    sources = control_sources()
    per_file = {path: dict(CONST.findall(text)) for path, text in sources.items()}

    emitted: dict[tuple[str, str, str], str] = {}
    unresolved: list[str] = []
    for path, text in sources.items():
        for event_type, method, raw_path in ACTION.findall(text):
            resolved = resolve(raw_path, path, per_file)
            where = str(path.relative_to(ROOT))
            if resolved is None:
                unresolved.append(f"{where}: {event_type} {method} path={raw_path}")
            else:
                emitted[(event_type, method, resolved)] = where

    worker_text = WORKER.read_text(encoding="utf-8")
    # The publisher first asks `supports(event_type)`; an event type missing there skips
    # the management parser entirely, even when the matrix below lists it.
    supports_body = worker_text.split("fn supports(", 1)[1].split("\n}\n", 1)[0]
    supported = set(re.findall(r'"([a-z_.]+)"', supports_body))
    unsupported = sorted({event_type for event_type, _, _ in emitted} - supported)
    for event_type in unsupported:
        print(f"NOT IN supports(): {event_type}", file=sys.stderr)
    matrix = {
        (event_type, method, route)
        for events, method, route in MATRIX.findall(worker_text)
        for event_type in re.findall(r'"([a-z_.]+)"', events)
    }
    missing = sorted((triple, where) for triple, where in emitted.items() if triple not in matrix)

    for line in unresolved:
        print(f"UNRESOLVED path constant: {line}", file=sys.stderr)
    for (event_type, method, path), where in missing:
        print(f"NOT PUBLISHABLE: {event_type} {method} {path}  (emitted in {where})", file=sys.stderr)
    if unresolved or missing or unsupported:
        print("Extend crates/xshield-worker/src/control_audit.rs (supports + validate_targets) "
              "and its tests for each entry above.", file=sys.stderr)
        return 1
    print(f"ok: {len(emitted)} control audit events are accepted by the worker publisher")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

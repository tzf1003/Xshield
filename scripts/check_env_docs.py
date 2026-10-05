#!/usr/bin/env python3
"""Fail when production code reads an XSHIELD_* environment variable no document mentions.

Operators configure the control plane, edge and worker only through environment
variables, so a variable that exists in code but not in the docs is invisible to
them (a secret nobody knows to rotate, a switch nobody can find). This is a text
level guard like check_audit_event_coverage.py: it finds quoted names in non-test
Rust sources and looks for the same name in docs/*.md, README.md and the console
README. It does not check that the documented meaning is right, only that one
exists.

Test-only variables (the console and browser-loop harnesses) are exempt; they are
set by test scaffolding, never by an operator.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = re.compile(r'"(XSHIELD_[A-Z0-9_]+)"')
MENTION = re.compile(r"XSHIELD_[A-Z0-9_]+")
# Set by test harnesses only; an operator never configures these.
TEST_ONLY = re.compile(r"^XSHIELD_(CONSOLE_TEST_|TEST_|BROWSER_LOOP_)")


def is_test_source(path: Path) -> bool:
    parts = path.relative_to(ROOT).parts
    return "tests" in parts or path.name == "tests.rs" or path.name.endswith("_tests.rs")


def read_by_code() -> dict[str, Path]:
    found: dict[str, Path] = {}
    for path in sorted((ROOT / "crates").rglob("*.rs")):
        if is_test_source(path):
            continue
        for name in NAME.findall(path.read_text(encoding="utf-8", errors="replace")):
            if not TEST_ONLY.match(name):
                found.setdefault(name, path)
    return found


def documented() -> set[str]:
    names: set[str] = set()
    paths = [*sorted((ROOT / "docs").glob("*.md")), ROOT / "README.md", ROOT / "web/console/README.md"]
    for path in paths:
        names.update(MENTION.findall(path.read_text(encoding="utf-8", errors="replace")))
    return names


def main() -> int:
    code = read_by_code()
    missing = sorted(set(code) - documented())
    if missing:
        print("environment variables read by code but not documented:")
        for name in missing:
            print(f"  {name}  ({code[name].relative_to(ROOT)})")
        print("Document each in docs/19 (deployment) or the chapter that owns the feature.")
        return 1
    print(f"ok: {len(code)} environment variables read by code are all documented")
    return 0


if __name__ == "__main__":
    sys.exit(main())

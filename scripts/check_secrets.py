#!/usr/bin/env python3
"""Fail when a tracked file contains something that looks like a real credential.

A deliberately small, dependency-free scan so it runs the same on a laptop and in
CI: high-precision patterns for private keys, cloud and VCS tokens and
credentials embedded in URLs, plus long hex literals assigned to key-like names.
It reads only files `git ls-files` reports, skips binary and generated files, and
never prints a matched value, only the file, line and rule.

It is not a replacement for a history-wide scanner such as gitleaks: it cannot
see deleted history and it knows nothing about provider-specific formats beyond
the list below. A finding that is a synthetic test value goes in ALLOW with the
reason, so the exception is reviewed like any other change.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_BYTES = 2_000_000
SKIP_SUFFIXES = {".docx", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".pdf", ".lock"}
SKIP_NAMES = {"Cargo.lock", "package-lock.json"}

RULES: dict[str, re.Pattern[str]] = {
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    "aws-access-key-id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "stripe-live-key": re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "url-credentials": re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@'\"<>$]+:[^/\s:@'\"<>$]{4,}@(?!localhost\b|127\.0\.0\.1\b|\[::1\])[^/\s'\"<>]+"),
}
KEY_ASSIGNMENT = re.compile(
    r"""(?ix)\b[a-z0-9_]*(?:key|secret|token|password)[a-z0-9_]*["']?\s*[:=]\s*["']?([0-9a-f]{64})\b"""
)

# (path, rule) -> why a match there is not a credential.
ALLOW: dict[tuple[str, str], str] = {
    ("crates/xshield-control/src/identity.rs", "url-credentials"):
        "negative test: an IdP URL with embedded credentials must be rejected; user:pass is a placeholder",
}


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.decode("utf-8", "replace")
    return [ROOT / name for name in out.split("\0") if name]


def synthetic(hex_value: str) -> bool:
    """A 64-hex test value built from a few repeated digits (aaaa…, 0123…0123…)."""
    return len(set(hex_value)) <= 6


def scan(path: Path) -> list[tuple[int, str]]:
    if path.suffix in SKIP_SUFFIXES or path.name in SKIP_NAMES:
        return []
    try:
        if path.stat().st_size > MAX_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    if b"\0" in data:
        return []
    findings: list[tuple[int, str]] = []
    for number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
        for rule, pattern in RULES.items():
            if pattern.search(line):
                findings.append((number, rule))
        for match in KEY_ASSIGNMENT.finditer(line):
            if not synthetic(match.group(1).lower()):
                findings.append((number, "key-like-hex-literal"))
    return findings


def main() -> int:
    failures: list[str] = []
    used_allow: set[tuple[str, str]] = set()
    for path in tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        for number, rule in scan(path):
            if (relative, rule) in ALLOW:
                used_allow.add((relative, rule))
                continue
            failures.append(f"{relative}:{number}: {rule}")
    stale = sorted(set(ALLOW) - used_allow)
    for relative, rule in stale:
        failures.append(f"{relative}: allowlist entry for {rule} matches nothing; remove it")
    if failures:
        print("possible credentials in tracked files (values are not printed):")
        for failure in failures:
            print(f"  {failure}")
        print("Remove the value, or add (path, rule) to ALLOW in scripts/check_secrets.py with the reason it is synthetic.")
        return 1
    print(f"ok: no credential-shaped values in {len(tracked_files())} tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main())

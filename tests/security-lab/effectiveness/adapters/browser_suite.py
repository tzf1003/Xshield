"""The browser suite's results as observation rows (plan 4.6 and batch 6).

The suite writes one results.json per run, `run-NN/results.json`: a JSON array with one row per probe.
This module reads those files from a folder or from a zip and turns each scored row into an observation.
An archive is never extracted and nothing in it is run: a zip is read member by member, in memory.

Mapping, row by row:

- probeId becomes case. trafficClass (attack or benign) becomes group. category stays the suite's own.
- expected block or allow is scored. expected observe is recorded by the suite and never scored; it is
  counted, not measured.
- outcome unsupported or not_run was never sent; it is skipped and counted.
- The request ID is response.headers["x-xshield-request-id"], looked up without regard to case. A row with
  no response has an empty request ID, which matches no decision record, so the scorer counts it as a
  missing record.
- outcome business_error is scored from the decision record like any other row. The origin's status code
  is kept as client_status for the report and never decides anything.
- The expected reason is not stated by the suite, so it is inferred and the report says so: a block sent
  without a session cookie expects no_session, except on the login route (an entry); a Broken Access
  Control probe expects access; any other block expects attack.
"""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

RESULTS_NAME = "results.json"
RUN_DIR = re.compile(r"run-(\d+)")
RUN_PATTERN = re.compile(r"(?:^|/)run-(\d+)/" + re.escape(RESULTS_NAME) + r"$")
MAX_RESULTS_BYTES = 64 * 1024 * 1024
REQUEST_ID_HEADER = "x-xshield-request-id"
SCORED_EXPECTS = frozenset({"block", "allow"})
UNRUN_OUTCOMES = frozenset({"unsupported", "not_run"})
TRAFFIC_GROUPS = frozenset({"attack", "benign"})
ACCESS_CATEGORIES = frozenset({"Broken Access Control"})
LOGIN_PATH = "/rest/user/login"
BUSINESS_ERROR = "business_error"
BUSINESS_NOTE = "源站业务错误（business_error），按判定记录计分"


class SuiteError(ValueError):
    """The suite's results cannot be read. The message names the file or the row, never a request value."""


@dataclass(frozen=True)
class SuiteRun:
    number: int
    name: str  # the path inside the folder or the zip, for messages
    rows: list[dict[str, Any]]


@dataclass
class Conversion:
    """The observation rows of a suite, and what was left out of them."""

    observations: list[dict[str, Any]] = field(default_factory=list)
    observe: int = 0  # expected observe: recorded by the suite, not scored
    unrun: int = 0  # outcome unsupported or not_run: never sent
    business_error: list[str] = field(default_factory=list)  # case names of the business_error rows
    unmatched: int = 0  # scored rows with no request ID


def read_runs(source: Path) -> list[SuiteRun]:
    """Every run of a suite output folder or zip, in run order."""
    if not source.exists():
        raise SuiteError(f"{source.name}：不存在")
    if source.is_dir():
        runs = _runs_in_folder(source)
    elif zipfile.is_zipfile(source):
        runs = _runs_in_zip(source)
    else:
        raise SuiteError(f"{source.name}：既不是目录，也不是 zip 文件")
    if not runs:
        raise SuiteError(f"{source.name}：没有 run-NN/{RESULTS_NAME}")
    numbers = [run.number for run in runs]
    if len(set(numbers)) != len(numbers):
        raise SuiteError(f"{source.name}：运行编号重复")
    return sorted(runs, key=lambda run: run.number)


def _runs_in_folder(folder: Path) -> list[SuiteRun]:
    runs = []
    for run_dir in sorted(folder.iterdir()):
        match = RUN_DIR.fullmatch(run_dir.name)
        results = run_dir / RESULTS_NAME
        if match is None or not run_dir.is_dir() or not results.is_file():
            continue
        if results.stat().st_size > MAX_RESULTS_BYTES:
            raise SuiteError(f"{run_dir.name}/{RESULTS_NAME}：文件超过 64 MiB")
        name = f"{run_dir.name}/{RESULTS_NAME}"
        runs.append(SuiteRun(int(match.group(1)), name, _rows(results.read_bytes(), name)))
    return runs


def _runs_in_zip(source: Path) -> list[SuiteRun]:
    runs = []
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            match = RUN_PATTERN.search(info.filename)
            if match is None or info.is_dir():
                continue
            if info.file_size > MAX_RESULTS_BYTES:
                raise SuiteError(f"{info.filename}：文件超过 64 MiB")
            with archive.open(info) as member:  # read in memory; nothing is written to disk
                data = member.read(MAX_RESULTS_BYTES + 1)
            runs.append(SuiteRun(int(match.group(1)), info.filename, _rows(data, info.filename)))
    return runs


def _rows(data: bytes, name: str) -> list[dict[str, Any]]:
    try:
        rows = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SuiteError(f"{name}：不是合法的 JSON") from error
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise SuiteError(f"{name}：应为对象数组")
    return rows


def executed_window(runs: list[SuiteRun]) -> tuple[int, int] | None:
    """The first start and the last finish of the probes that were sent, in Unix milliseconds."""
    starts, ends = [], []
    for run in runs:
        for row in run.rows:
            if row.get("outcome") in UNRUN_OUTCOMES:
                continue
            start, end = _millis(row.get("startedAt")), _millis(row.get("completedAt"))
            if start is not None and end is not None:
                starts.append(start)
                ends.append(end)
    if not starts:
        return None
    return min(starts), max(ends)


def _millis(text: Any) -> int | None:
    if not isinstance(text, str):
        return None
    try:
        return int(datetime.fromisoformat(text).timestamp() * 1000)
    except ValueError:
        return None


def to_observations(runs: list[SuiteRun], *, site: str, config: str, mode: str) -> Conversion:
    """Maps every row of every run (plan 4.6). `mode` is the site's mode, read from the decision records."""
    result = Conversion()
    for run in runs:
        for index, row in enumerate(run.rows, 1):
            observation = _observation(run, index, row, site=site, config=config, mode=mode, result=result)
            if observation is not None:
                result.observations.append(observation)
    return result


def _observation(run: SuiteRun, index: int, row: dict[str, Any], *, site: str, config: str, mode: str,
                 result: Conversion) -> dict[str, Any] | None:
    where = f"{run.name} 第 {index} 行"
    probe = row.get("probeId")
    if not isinstance(probe, str) or not probe:
        raise SuiteError(f"{where}：缺少 probeId")
    if row.get("trafficClass") not in TRAFFIC_GROUPS:
        raise SuiteError(f"{where}：trafficClass 应为 attack 或 benign")
    expected = row.get("expected")
    if expected == "observe":
        result.observe += 1
        return None
    if expected not in SCORED_EXPECTS:
        raise SuiteError(f"{where}：expected 应为 block、allow 或 observe")
    if row.get("outcome") in UNRUN_OUTCOMES:
        result.unrun += 1
        return None

    request = _mapping(row.get("request"))
    response = _mapping(row.get("response"))
    request_id = _request_id(response)
    category = row.get("category") if isinstance(row.get("category"), str) else "未分类"
    note = ""
    if row.get("outcome") == BUSINESS_ERROR:
        note = BUSINESS_NOTE
        result.business_error.append(probe)
    if not request_id:
        result.unmatched += 1
    return {
        "case": probe,
        "group": row["trafficClass"],
        "category": category,
        "expect": expected,
        "reason": _expected_reason(expected, category, request),
        "status": "must",
        "ref": None,
        "config": config,
        "site": site,
        "mode": mode,
        "run": run.number,
        "request_id": request_id,
        "setup_request_ids": [],
        "client_status": _client_status(row, response),
        "origin_served": None,
        "refs": [],
        "requires": [],
        "note": note,
    }


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _request_id(response: dict[str, Any]) -> str:
    headers = _mapping(response.get("headers"))
    for name, value in headers.items():
        if name.lower() == REQUEST_ID_HEADER and isinstance(value, str):
            return value
    return ""


def _client_status(row: dict[str, Any], response: dict[str, Any]) -> int:
    for value in (response.get("status"), row.get("status")):
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return 0  # no response: the contract needs an integer, and 0 is not an HTTP status


def _expected_reason(expected: str, category: str, request: dict[str, Any]) -> str | None:
    if expected == "allow":
        return None
    headers = _mapping(request.get("headers"))
    has_cookie = any(name.lower() == "cookie" for name in headers)
    path = urlsplit(request.get("url") if isinstance(request.get("url"), str) else "").path
    if not has_cookie and not path.startswith(LOGIN_PATH):
        return "no_session"
    if category in ACCESS_CATEGORIES:
        return "access"
    return "attack"

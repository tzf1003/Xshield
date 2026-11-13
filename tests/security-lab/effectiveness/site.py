"""The `site` command (plan 4.6, 5.3 and batch 6): scores a real site.

The inputs are the browser suite's results (a folder or a zip, read by adapters/browser_suite.py) and the
gateway's decision records: a file (--decisions) or the console's export (--control with --site). The
command sends no traffic. The console password comes only from the XSHIELD_CONSOLE_PASSWORD environment
variable; it is never written to a file or printed, and the session cookie stays in memory.

A real site has no origin truth, so the rules that need it are not measured: S1 and S2 (no shown or echoed
values), P5 (no served record) and P7 (no regression cases). The ideal-model rule for P4 does not apply to the
real Jev, and the rates are reported without a target (plan 3.4 and question 2). What gates a real-site run is
the missing-record count and the learning counts.
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters.browser_suite import Conversion, SuiteError, executed_window, read_runs, to_observations
from .cli import PASSWORD_ENV, _commit
from .contracts import ContractError, dump_json, load_decisions, load_learned, load_truth
from .report import render_markdown, render_terminal, report_document
from .score import confidence_scan, score

WINDOW_MARGIN_MILLIS = 5 * 60 * 1000
EXPORT_LIMIT = 100_000  # the console's cap on one export (crates/xshield-control/src/requests.rs)
REQUEST_TIMEOUT_SECONDS = 60
UNMEASURED_GATES = ("S2 误核验数", "P7 意外通过数", "P4 未判定请求数（理想模型下必须为 0）")
LEARNING_GATE = "L0 误学数"


class SiteError(RuntimeError):
    """A problem that stops the run before scoring. The message never carries the password or a cookie."""


def run(args: argparse.Namespace) -> int:
    started = datetime.now(timezone.utc)
    clock = time.monotonic()
    try:
        return _score_site(args, started, clock)
    except (SiteError, SuiteError, ContractError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


def _score_site(args: argparse.Namespace, started: datetime, clock: float) -> int:
    if args.decisions is not None and args.control:
        raise SiteError("--decisions 与 --control 只能给一个")
    password = ""
    if args.control:
        password = os.environ.get(PASSWORD_ENV, "")
        if not password:
            raise SiteError(f"请在环境变量 {PASSWORD_ENV} 中设置控制台口令")
    label = args.site or "站点"
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    runs = read_runs(args.suite_results)
    decisions_path = out / "decisions.jsonl"
    objects: dict[str, Any] | None = None
    spec: dict[str, Any] | None = None

    if args.control:
        window = executed_window(runs)
        if window is None:
            raise SiteError("套件里没有发出过的探针，无法确定导出的时间窗；如有判定记录文件，请改用 --decisions")
        since, until = window
        with _Console(args.control) as console:
            console.login(password)
            console.export(args.site, since - WINDOW_MARGIN_MILLIS, until + WINDOW_MARGIN_MILLIS, decisions_path)
            spec = console.site_spec(args.site)
            if args.objects is None:
                objects = console.get_json(_site_path(args.site, "/objects"))
    else:
        load_decisions(args.decisions)  # checked before it is copied into the output folder
        _copy(args.decisions, decisions_path)
    if args.objects is not None:
        objects = _json_object(args.objects)

    decisions = load_decisions(decisions_path)
    if len(decisions) >= EXPORT_LIMIT:
        raise SiteError(f"导出达到 {EXPORT_LIMIT} 条上限，判定记录可能不全，请缩小时间窗")
    mode_text, row_mode = _site_mode(decisions)
    converted = to_observations(runs, site=label, config=label, mode=row_mode)

    truth = load_truth(args.truth) if args.truth is not None else None
    learned = None
    if objects is not None:
        learned = learned_from_objects(objects, spec)
        learned_path = out / "learned.json"
        dump_json(learned_path, learned)
        load_learned(learned_path)  # the written file must meet the contract

    result = score(converted.observations, decisions, truth=truth, learned=learned,
                   exclude_suspicious=True, probe_values_from_record=True)
    result["confidence_scan"] = confidence_scan(converted.observations, decisions)  # a site's Jev is a real model
    _apply_real_site_rules(result, has_learning=learned is not None)
    result["label_checks"]["business_error"] = converted.business_error
    result["label_checks"]["conflict"] = converted.conflicts
    result["skipped"].extend(_suite_skips(converted))
    result["passed"] = all(gate["ok"] is not False for gate in result["gates"])

    meta = {
        "commit": _commit(),
        "mode": "site",
        "jev": "真实 Jev（站点的判定记录；本命令不发流量）",
        "seed": None,
        "started": started.isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - clock, 3),
        "site": label,
        "note": (f"站点模式：{mode_text}；套件计分行 {converted.scored_rows} 个，"
                 f"对应请求 {converted.requests} 个；origin_served 未知，P5 未执行"),
    }
    _write_observations(out / "observations.jsonl", converted.observations)
    if args.truth is not None:
        _copy(args.truth, out / "truth.json")
    dump_json(out / "report.json", report_document(result, meta))
    (out / "report.md").write_text(render_markdown(result, meta), encoding="utf-8")
    print(render_terminal(result, meta))
    print(f"报告：{out / 'report.md'}")
    return 0 if result["passed"] else 1


# ---------------------------------------------------------------- site rules


def _apply_real_site_rules(result: dict[str, Any], has_learning: bool) -> None:
    """Marks what a real site cannot measure as not measured, and says why (plan 4.6, 5.2)."""
    gates = {gate["name"]: gate for gate in result["gates"]}
    metrics = result["metrics"]
    # A zero with no references is not a measurement: S2 stays a count of nothing, so its gate must not pass.
    metrics["S2"] = {"value": None, "num": 0, "den": 0}
    metrics["P7"]["unexpected_pass"] = None  # no regression cases: a zero here would read as a measured pass
    for name in UNMEASURED_GATES:
        _unset_gate(gates, name)
    skipped = [item for item in result["skipped"] if item["section"] != "P6、L4、L5"]
    if has_learning:
        metrics["L0"] = None
        _unset_gate(gates, LEARNING_GATE)
        skipped.append({"section": "L0", "why": "真实站点没有冷启动候选（bootstrap），不计算"})
    skipped += [
        {"section": "S1、S2", "why": "真实站点没有源站的展示与回显记录，不计算"},
        {"section": "P4", "why": "真实 Jev 模式不设门槛（方案 3.4），未判定率只报告"},
        {"section": "P5", "why": "真实站点没有源站的 served 记录（origin_served 为 null），未执行"},
        {"section": "P7", "why": "真实站点没有回归用例，未执行"},
        {"section": "P6、L4、L5", "why": "完整模式专用，站点模式不计算"},
    ]
    result["skipped"] = skipped


def _unset_gate(gates: dict[str, dict[str, Any]], name: str) -> None:
    gate = gates.get(name)
    if gate is not None:
        gate["value"] = None
        gate["ok"] = None


def _suite_skips(converted: Conversion) -> list[dict[str, str]]:
    items = []
    if converted.observe:
        items.append({"section": "套件行", "why": f"expected 为 observe 的 {converted.observe} 条只记录、不计分"})
    if converted.unrun:
        items.append({"section": "套件行", "why": f"outcome 为 unsupported 或 not_run 的 {converted.unrun} 条没有发出，跳过"})
    if not converted.observations:
        items.append({"section": "套件行", "why": "没有可计分的行（expected 为 block 或 allow，且已发出）"})
    return items


def _site_mode(decisions: list[dict[str, Any]]) -> tuple[str, str]:
    """The site's mode as its decision records show it: (text for the report, mode of each row)."""
    blocked = sum(1 for record in decisions if record["outcome"] == "blocked")
    would_block = sum(1 for record in decisions if record["outcome"] == "would_block")
    if would_block and not blocked:
        return "观察模式（判定记录里有本应拦截的请求，没有实际拦截）", "observe"
    if blocked and not would_block:
        return "拦截模式", "enforce"
    if blocked and would_block:
        return "混合（观察与拦截的记录同时出现，检查导出的时间窗）", "enforce"
    return "无法判断（判定记录里没有拦截或本应拦截的记录）", "enforce"


# ---------------------------------------------------------------- the object map as learned.json


def learned_from_objects(objects: dict[str, Any], spec: dict[str, Any] | None) -> dict[str, Any]:
    """The console's object map (GET /api/sites/{name}/objects) as learned.json, plan 9.4.

    A real site has no cold start and no rounds to compare: the map as it stands is the one round. Its positions
    are the entries' own state, class and judgement; its judgements are the proposals still waiting."""
    positions = []
    for slot in _list_of_objects(objects, "slots"):
        positions.append({
            "key": slot.get("key"),
            "state": slot.get("state"),
            "class": slot.get("class"),
            "source": slot.get("source"),
            "tier": slot.get("tier"),
            "accepts_public": slot.get("accepts_public"),
            "reliability": slot.get("reliability"),
        })
    judgements = []
    for item in _list_of_objects(objects, "judgements"):
        judgement: dict[str, Any] = {"key": item.get("key"), "reliability": item.get("reliability")}
        if "tier" in item:
            judgement["tier"] = item["tier"]
        elif "accepts_public" in item:
            judgement["accepts_public"] = item["accepts_public"]
        else:
            raise SiteError("对象表的提议既没有 tier，也没有 accepts_public")
        judgements.append(judgement)
    one_round = {
        "round": 1,
        "run": {"started_millis": None, "finished_millis": None, "error": None},
        "positions": positions,
        "judgements": judgements,
    }
    return {"bootstrap": [], "rounds": [one_round], "final_spec": spec or {}}


def _list_of_objects(objects: dict[str, Any], name: str) -> list[dict[str, Any]]:
    items = objects.get(name) or []
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        raise SiteError(f"对象表的 {name} 应为对象数组")
    return items


# ---------------------------------------------------------------- the console


def _site_path(site: str, suffix: str = "") -> str:
    return f"/api/sites/{urllib.parse.quote(site, safe='')}{suffix}"


class _Console:
    """One session on the console. The cookie lives in memory and is dropped at the end."""

    def __init__(self, base_url: str) -> None:
        parts = urllib.parse.urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise SiteError("--control 应为 http:// 或 https:// 开头的地址")
        self._base = base_url.rstrip("/")
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self._signed_in = False

    def __enter__(self) -> _Console:
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._signed_in:
            try:
                with self._send("POST", "/api/logout"):
                    pass
            except SiteError:
                pass  # the session expires on its own; a failed sign-out changes no result

    def login(self, password: str) -> None:
        with self._send("POST", "/api/login", body={"password": password}) as response:
            body = _parse_json(response.read(), "/api/login")
        if not isinstance(body, dict) or body.get("authenticated") is not True:
            raise SiteError("控制台没有确认登录")
        self._signed_in = True

    def export(self, site: str, since: int, until: int, target: Path) -> None:
        query = {"format": "jsonl", "site": site, "since_millis": since, "until_millis": until, "scope": "all"}
        with self._send("GET", "/api/requests/export", query=query) as response, target.open("wb") as handle:
            shutil.copyfileobj(response, handle)

    def site_spec(self, site: str) -> dict[str, Any]:
        body = self.get_json(_site_path(site))
        spec = body.get("spec") if isinstance(body, dict) else None
        if not isinstance(spec, dict):
            raise SiteError("控制台的站点配置里没有 spec")
        return spec

    def get_json(self, path: str) -> Any:
        with self._send("GET", path) as response:
            return _parse_json(response.read(), path)

    def _send(self, method: str, path: str, *, query: dict[str, Any] | None = None,
              body: Any = None) -> Any:
        url = self._base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            return self._opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
        except urllib.error.HTTPError as error:
            raise SiteError(f"控制台返回 HTTP {error.code}（{_error_code(error)}），路径 {path}") from None
        except OSError as error:
            raise SiteError(f"无法连接控制台（{type(error).__name__}），路径 {path}") from None


def _error_code(error: urllib.error.HTTPError) -> str:
    """The console's error code only; its message can carry request data, so it is not printed."""
    try:
        code = json.loads(error.read(4096).decode("utf-8")).get("error")
    except (OSError, ValueError, AttributeError):
        return "没有错误码"
    return code if isinstance(code, str) else "没有错误码"


def _parse_json(data: bytes, path: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SiteError(f"控制台 {path} 的响应不是 JSON") from error


# ---------------------------------------------------------------- files


def _json_object(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SiteError(f"{path.name}：不是合法的 JSON") from error
    if not isinstance(document, dict):
        raise SiteError(f"{path.name}：应为 JSON 对象")
    return document


def _copy(source: Path, target: Path) -> None:
    if source.resolve() != target.resolve():
        shutil.copyfile(source, target)


def _write_observations(path: Path, rows: list[dict[str, Any]]) -> None:
    text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")

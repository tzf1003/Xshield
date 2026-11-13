"""Tests of the `site` command and the browser-suite adapter (plan 4.6 and batch 6).

The mapping rules, the three label checks, the missing-record rule, the password rules and the console
flow are covered with hand-written fixtures. The console is a stub HTTP server on the loopback address;
no real site, no model and no network outside the machine are involved. Every run writes into a
temporary folder."""

from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from effectiveness.adapters.browser_suite import (
    BUSINESS_NOTE,
    SuiteError,
    executed_window,
    read_runs,
    to_observations,
)
from effectiveness.builders import decision, entry, jev, source
from effectiveness.cli import PASSWORD_ENV, main
from effectiveness.contracts import ContractError, load_learned, load_observations, load_truth
from effectiveness.report import _label_lines
from effectiveness.score import _costs, _label_flags, score
from effectiveness.site import learned_from_objects

ROOT = Path(__file__).resolve().parents[3]
JUICE_TRUTH = ROOT / "tests" / "security-lab" / "sites" / "juice.truth.json"
CONSOLE_PASSWORD = "synthetic-console-password-0001"
SESSION_TOKEN = "synthetic-session-token-0002"


def suite_row(probe: str, *, traffic: str = "attack", expected: str = "block", outcome: str = "allowed",
              category: str = "Injection", cookie: bool = True, url: str = "http://juice.test/rest/basket/3",
              request_id: str | None = "req_x", header: str = "x-xshield-request-id",
              status: int | None = 403, sent: bool = True) -> dict[str, Any]:
    """One row of a run's results.json, shaped like the browser suite writes it."""
    if not sent:
        return {"probeId": probe, "category": category, "trafficClass": traffic, "expected": expected,
                "outcome": outcome, "status": None, "request": None, "response": None, "notes": []}
    request_headers = {"accept": "application/json"}
    if cookie:
        request_headers["cookie"] = "<redacted>"
    response_headers = {"content-type": "application/json"}
    if request_id is not None:
        response_headers[header] = request_id
    return {
        "probeId": probe, "category": category, "mode": "ui_click", "trafficClass": traffic,
        "expected": expected, "profile": "safe", "outcome": outcome, "status": status,
        "startedAt": "2026-11-09T04:07:09+08:00", "completedAt": "2026-11-09T04:07:10+08:00",
        "request": {"method": "GET", "url": url, "headers": request_headers},
        "response": {"status": status, "url": url, "headers": response_headers},
        "networkError": None, "notes": [],
    }


def write_suite(folder: Path, runs: dict[int, list[dict[str, Any]]]) -> Path:
    for number, rows in runs.items():
        directory = folder / f"run-{number:02d}"
        directory.mkdir(parents=True)
        (directory / "results.json").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    return folder


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    path.write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records), encoding="utf-8")
    return path


def run_cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def gate(report: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in report["gates"] if item["name"] == name]
    if len(matches) != 1:
        raise AssertionError(f"gate {name!r} not found exactly once")
    return matches[0]


class _Fixture(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)


class AdapterTests(_Fixture):
    def rows_run_one(self) -> list[dict[str, Any]]:
        return [
            suite_row("block-with-session", category="Injection", request_id="req_1"),
            suite_row("no-session-ftp", category="Sensitive Data Exposure", cookie=False,
                      url="http://juice.test/ftp/x.md", request_id="req_2", header="X-Xshield-Request-Id"),
            suite_row("login-without-session", category="Injection", cookie=False,
                      url="http://juice.test/rest/user/login", request_id="req_3"),
            suite_row("access-with-session", category="Broken Access Control", request_id="req_4"),
            suite_row("observe-only", expected="observe", request_id="req_5"),
            suite_row("never-sent", outcome="not_run", sent=False),
            suite_row("benign-allowed", traffic="benign", expected="allow", category="Improper Input Validation",
                      request_id="req_6", status=200),
            suite_row("business-error", outcome="business_error", status=404, request_id="req_7"),
            suite_row("no-response-header", request_id=None, status=None),
        ]

    def test_each_row_maps_to_its_observation(self) -> None:
        folder = write_suite(self.root / "suite", {1: self.rows_run_one(), 2: [
            suite_row("second-run-probe", request_id="req_8")]})
        runs = read_runs(folder)
        self.assertEqual([run.number for run in runs], [1, 2])
        converted = to_observations(runs, site="juice", config="juice", mode="observe")
        by_case = {row["case"]: row for row in converted.observations}

        self.assertEqual(set(by_case), {"block-with-session", "no-session-ftp", "login-without-session",
                                        "access-with-session", "benign-allowed", "business-error",
                                        "no-response-header", "second-run-probe"})
        self.assertEqual((converted.observe, converted.unrun), (1, 1))
        self.assertEqual(converted.unmatched, 1)
        self.assertEqual(converted.business_error, ["business-error"])

        self.assertEqual(by_case["block-with-session"]["reason"], "attack")
        self.assertEqual(by_case["no-session-ftp"]["reason"], "no_session")
        self.assertEqual(by_case["no-session-ftp"]["request_id"], "req_2")
        self.assertEqual(by_case["login-without-session"]["reason"], "attack")
        self.assertEqual(by_case["access-with-session"]["reason"], "access")
        self.assertIsNone(by_case["benign-allowed"]["reason"])
        self.assertEqual(by_case["benign-allowed"]["group"], "benign")
        self.assertEqual(by_case["benign-allowed"]["client_status"], 200)
        self.assertEqual(by_case["business-error"]["note"], BUSINESS_NOTE)
        self.assertEqual(by_case["business-error"]["client_status"], 404)
        self.assertEqual(by_case["no-response-header"]["request_id"], "")
        self.assertEqual(by_case["no-response-header"]["client_status"], 0)
        self.assertEqual(by_case["second-run-probe"]["run"], 2)
        self.assertEqual(by_case["block-with-session"]["mode"], "observe")
        self.assertTrue(all(row["origin_served"] is None for row in converted.observations))

    def test_rows_that_share_a_request_and_labels_become_one_observation(self) -> None:
        shared = {"traffic": "benign", "expected": "allow", "category": "Improper Input Validation",
                  "url": "http://juice.test/rest/user/login", "request_id": "req_shared", "status": 200}
        folder = write_suite(self.root / "suite", {1: [suite_row("login-admin", **shared),
                                                       suite_row("login-jim", **shared),
                                                       suite_row("login-bob", **shared)]})
        converted = to_observations(read_runs(folder), site="juice", config="juice", mode="observe")
        self.assertEqual([row["case"] for row in converted.observations], ["login-admin"])
        self.assertIn("合并 3 行：login-jim、login-bob", converted.observations[0]["note"])
        self.assertEqual((converted.scored_rows, converted.requests, converted.conflicts), (3, 1, []))
        # One request is one benign observation in the scorer's denominator.
        origin = decision("req_shared", path="fast_allow", outcome="allowed", session="s1", route="/rest/user/login")
        self.assertEqual(score(converted.observations, [origin])["metrics"]["S3"]["den"], 1)

    def test_rows_that_share_a_request_with_different_labels_are_not_scored(self) -> None:
        folder = write_suite(self.root / "suite", {1: [
            suite_row("attack-side", category="Injection", request_id="req_clash"),
            suite_row("benign-side", traffic="benign", expected="allow", category="Improper Input Validation",
                      request_id="req_clash", status=200),
        ]})
        converted = to_observations(read_runs(folder), site="juice", config="juice", mode="observe")
        self.assertEqual(converted.observations, [])
        self.assertEqual(converted.conflicts, [{"request_id": "req_clash", "cases": ["attack-side", "benign-side"]}])
        self.assertEqual((converted.scored_rows, converted.requests), (2, 1))

    def test_an_unsent_observe_row_is_counted_as_unsent_not_observed(self) -> None:
        folder = write_suite(self.root / "suite", {1: [
            suite_row("observe-sent", expected="observe", request_id="req_9"),
            suite_row("observe-never-sent", expected="observe", outcome="not_run", sent=False),
        ]})
        converted = to_observations(read_runs(folder), site="juice", config="juice", mode="observe")
        self.assertEqual((converted.observe, converted.unrun), (1, 1))
        self.assertEqual(converted.observations, [])

    def test_the_rows_pass_the_observation_contract(self) -> None:
        folder = write_suite(self.root / "suite", {1: self.rows_run_one()})
        converted = to_observations(read_runs(folder), site="juice", config="juice", mode="enforce")
        path = self.root / "observations.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in converted.observations), encoding="utf-8")
        self.assertEqual(len(load_observations(path)), len(converted.observations))

    def test_a_zip_is_read_in_memory_and_nothing_is_extracted(self) -> None:
        folder = write_suite(self.root / "source", {1: self.rows_run_one()})
        archive = self.root / "batch.zip"
        base = "batch-full-20261109"
        with zipfile.ZipFile(archive, "w") as handle:
            for path in sorted(folder.rglob("results.json")):
                handle.write(path, f"{base}/{path.parent.name}/results.json")
        target = self.root / "reading"
        target.mkdir()
        (target / "batch.zip").write_bytes(archive.read_bytes())
        before = sorted(item.name for item in target.iterdir())

        from_zip = to_observations(read_runs(target / "batch.zip"), site="juice", config="juice", mode="enforce")
        from_folder = to_observations(read_runs(folder), site="juice", config="juice", mode="enforce")
        self.assertEqual(from_zip.observations, from_folder.observations)
        self.assertEqual(sorted(item.name for item in target.iterdir()), before)

    def test_a_malformed_row_is_named_by_file_and_position(self) -> None:
        rows = [suite_row("fine"), suite_row("broken", traffic="other")]
        folder = write_suite(self.root / "suite", {1: rows})
        with self.assertRaises(SuiteError) as caught:
            to_observations(read_runs(folder), site="juice", config="juice", mode="enforce")
        message = str(caught.exception)
        self.assertIn("run-01/results.json 第 2 行", message)
        self.assertIn("trafficClass", message)

    def test_a_missing_path_and_a_folder_without_runs_are_named(self) -> None:
        with self.assertRaises(SuiteError) as missing:
            read_runs(self.root / "absent")
        self.assertIn("不存在", str(missing.exception))
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(SuiteError) as none_found:
            read_runs(empty)
        self.assertIn("run-NN/results.json", str(none_found.exception))

    def test_the_executed_window_spans_the_probes_that_were_sent(self) -> None:
        rows = [suite_row("sent", request_id="req_9"), suite_row("never", outcome="not_run", sent=False)]
        folder = write_suite(self.root / "suite", {1: rows})
        window = executed_window(read_runs(folder))
        self.assertIsNotNone(window)
        start, end = window or (0, 0)
        self.assertEqual(end - start, 1000)
        self.assertEqual(start, 1794168429000)  # 2026-11-09T04:07:09+08:00 in Unix milliseconds


class SiteRuleTests(unittest.TestCase):
    """The scorer's share of the site rules (plan 4.6): the all-values suspicious check, the cost line and
    the label section that lists a conflict."""

    def test_a_site_probe_is_suspicious_only_when_every_value_it_carries_was_verified(self) -> None:
        shown = decision("req_show", path="fast_allow", outcome="allowed", session="s1", route="/api/search")
        records = {"req_show": shown}
        row = {"expect": "block", "reason": "access", "refs": []}

        def probe(*values: dict[str, Any]) -> dict[str, Any]:
            return decision("req_probe", path="jev_deny", outcome="blocked", session="s1",
                            route="/rest/basket/3", values=list(values))

        verified = entry("42", verified=True, sources=[source("req_show")])
        unverified = entry("43", verified=False, sources=[source("req_show")])
        second = entry("44", verified=True, sources=[source("req_show")])
        self.assertEqual(_label_flags(row, probe(), records, from_record=True), (False, False))
        self.assertEqual(_label_flags(row, probe(verified, unverified), records, from_record=True), (False, False))
        self.assertEqual(_label_flags(row, probe(verified, second), records, from_record=True), (True, False))

    def test_the_cost_line_counts_judged_records_and_leaves_bypass_out(self) -> None:
        decisions = [
            decision("req_bypass", path="bypass", outcome="allowed", session="s1", route="/assets/x.json"),
            decision("req_fast", path="fast_allow", outcome="allowed", session="s1", route="/api/a"),
            decision("req_jev", path="jev_allow", outcome="allowed", session="s1", route="/api/b",
                     jev_record=jev(access="ALLOW", attack="BENIGN")),
        ]
        costs = _costs(decisions)
        self.assertEqual((costs["requests"], costs["judged_requests"]), (3, 2))
        self.assertEqual(costs["fast_share"], 0.5)
        self.assertEqual(costs["calls_per_judged_request"], 0.5)
        self.assertEqual(costs["calls_per_request"], 0.5)

    def test_a_conflict_is_listed_in_the_label_section(self) -> None:
        lines = _label_lines({"applied": False, "suspicious": [], "bypass": [], "excluded": 0,
                              "conflict": [{"request_id": "req_clash", "cases": ["attack-side", "benign-side"]}]})
        self.assertIn("- 标签冲突（同一请求 ID 的标签不一致，全部不计分）：1 个请求", lines)
        self.assertIn("  - 请求 req_clash：attack-side、benign-side", lines)


class SiteRunTests(_Fixture):
    """The whole command on a small fixture: a suite and a decision file."""

    def fixture(self, *, with_missing: bool) -> tuple[Path, Path]:
        rows = [
            # Check 1: the target was shown to this session by a search, so the label is suspicious.
            suite_row("suspicious-basket-read", category="Broken Access Control", url="http://juice.test/rest/basket/3",
                      request_id="req_sus"),
            # Check 2: the probe took the bypass path (a static asset is not judged).
            suite_row("bypass-asset", category="Broken Anti Automation", cookie=False,
                      url="http://juice.test/assets/i18n/x.json", request_id="req_bypass"),
            # Check 3: the origin answered with a business error; the record decides.
            suite_row("business-error-hit", category="Broken Access Control", outcome="business_error",
                      status=404, request_id="req_bs"),
            # A real miss: an injection the gateway let through.
            suite_row("injection-missed", category="Injection", request_id="req_miss"),
            suite_row("benign-passes", traffic="benign", expected="allow", category="Improper Input Validation",
                      request_id="req_ok", status=200),
        ]
        if with_missing:
            rows.append(suite_row("record-never-written", request_id="req_absent"))
        suite = write_suite(self.root / "suite", {1: rows})
        leaked = "VALUE-MARKER-4242"
        # decision()'s `path` is the decision path (docs/07 7.4); `route` is the request path.
        records = [
            decision("req_show", path="fast_allow", outcome="allowed", session="s1", route="/api/search"),
            decision("req_sus", path="fast_allow", outcome="allowed", session="s1", route="/rest/basket/3",
                     values=[entry(leaked, verified=True, sources=[source("req_show")])]),
            decision("req_bypass", path="bypass", outcome="allowed", session="s2", route="/assets/i18n/x.json"),
            decision("req_bs", path="jev_deny", outcome="blocked", session="s3", route="/rest/basket/9",
                     jev_record=jev(access="DENY", attack="BENIGN")),
            decision("req_miss", path="fast_allow", outcome="allowed", session="s4", route="/rest/products/search"),
            decision("req_ok", path="fast_allow", outcome="allowed", session="s5", route="/api/ok"),
        ]
        return suite, write_jsonl(self.root / "decisions.jsonl", records)

    def test_labels_are_listed_and_the_suspicious_probe_leaves_the_rate(self) -> None:
        suite, decisions = self.fixture(with_missing=False)
        out = self.root / "out"
        status, stdout, stderr = run_cli("site", "--decisions", str(decisions), "--suite-results", str(suite),
                                         "--out", str(out), "--site", "juice")
        self.assertEqual(status, 0, stderr)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        markdown = (out / "report.md").read_text(encoding="utf-8")
        self.assertIn("标签可疑（目标对象在本会话里展示过）：1 条，suspicious-basket-read", markdown)
        self.assertIn("不经判定（探针走了旁路）：1 条，bypass-asset", markdown)
        self.assertIn("源站业务错误（套件标 business_error）：1 条，business-error-hit", markdown)
        self.assertIn("站点模式：", markdown)
        self.assertIn("origin_served 未知，P5 未执行", markdown)

        # Block probes: the suspicious and the bypass ones leave the rate; the hit and the miss stay (1 of 2).
        p1 = report["metrics"]["P1"]
        self.assertEqual((p1["num"], p1["den"]), (1, 2))
        self.assertEqual((report["metrics"]["P3"]["num"], report["metrics"]["P3"]["den"]), (1, 1))
        self.assertEqual((report["metrics"]["P2"]["num"], report["metrics"]["P2"]["den"]), (0, 1))
        failure_cases = [item["case"] for item in report["failures"]]
        self.assertIn("injection-missed", failure_cases)
        self.assertNotIn("suspicious-basket-read", failure_cases)

    def test_real_site_gates_are_not_passed_by_absence(self) -> None:
        suite, decisions = self.fixture(with_missing=False)
        out = self.root / "out"
        self.assertEqual(run_cli("site", "--decisions", str(decisions), "--suite-results", str(suite),
                                 "--out", str(out))[0], 0)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertIsNone(gate(report, "S2 误核验数")["ok"])
        self.assertIsNone(gate(report, "P4 未判定请求数（理想模型下必须为 0）")["ok"])
        self.assertIsNone(gate(report, "P5 被拦请求到达源站数")["ok"])
        self.assertIsNone(gate(report, "P7 意外通过数")["ok"])
        self.assertIsNone(report["metrics"]["S2"]["value"])
        self.assertTrue(gate(report, "记录缺失数")["ok"])
        skipped = {item["section"] for item in report["meta"]["skipped"]}
        self.assertTrue({"S1、S2", "P5", "P7", "P6、L4、L5"} <= skipped)

    def test_a_row_without_its_record_fails_the_missing_record_gate(self) -> None:
        suite, decisions = self.fixture(with_missing=True)
        out = self.root / "out"
        status, stdout, _ = run_cli("site", "--decisions", str(decisions), "--suite-results", str(suite),
                                    "--out", str(out))
        self.assertEqual(status, 1)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertFalse(gate(report, "记录缺失数")["ok"])
        missing = [item for item in report["failures"] if item["got"] == "记录缺失"]
        self.assertEqual([item["case"] for item in missing], ["record-never-written"])
        self.assertIn("记录缺失", stdout)

    def test_the_report_names_cases_and_ids_but_never_a_request_value(self) -> None:
        suite, decisions = self.fixture(with_missing=True)
        out = self.root / "out"
        run_cli("site", "--decisions", str(decisions), "--suite-results", str(suite), "--out", str(out))
        for name in ("report.md", "report.json"):
            self.assertNotIn("VALUE-MARKER-4242", (out / name).read_text(encoding="utf-8"))

    def test_decisions_and_control_cannot_both_be_given(self) -> None:
        suite, decisions = self.fixture(with_missing=False)
        status, _, err = run_cli("site", "--decisions", str(decisions), "--control", "http://127.0.0.1:1",
                                 "--site", "juice", "--suite-results", str(suite), "--out", str(self.root / "o"))
        self.assertEqual(status, 2)
        self.assertIn("只能给一个", err)

    def test_the_truth_and_an_object_map_give_learning_numbers(self) -> None:
        suite, decisions = self.fixture(with_missing=False)
        objects = self.root / "objects.json"
        objects.write_text(json.dumps({
            "slots": [
                {"key": "POST /api/BasketItems body.BasketId", "side": "request", "class": "basket",
                 "state": "confirmed", "source": "admin", "accepts_public": False, "reliability": "high"},
                {"key": "POST /api/BasketItems body.ProductId", "side": "request", "class": "product",
                 "state": "proposed", "source": "rule", "accepts_public": None, "reliability": None},
            ],
            "judgements": [
                {"id": "x", "key": "POST /api/BasketItems body.ProductId", "accepts_public": True,
                 "votes": 30, "sessions": 6, "public_per_mille": 950, "reliability": "high"},
            ],
        }), encoding="utf-8")
        out = self.root / "out"
        status, _, stderr = run_cli("site", "--decisions", str(decisions), "--suite-results", str(suite),
                                    "--out", str(out), "--truth", str(JUICE_TRUTH), "--objects", str(objects))
        self.assertIn(status, (0, 1), stderr)
        learned = load_learned(out / "learned.json")
        self.assertEqual(learned["bootstrap"], [])
        self.assertEqual(len(learned["rounds"]), 1)
        report = json.loads((out / "report.json").read_text(encoding="utf-8"))
        self.assertIsNone(report["metrics"]["L0"])
        self.assertEqual(report["metrics"]["L1"]["wrong"], 0)
        self.assertEqual(report["metrics"]["L3"]["wrong"], 0)
        self.assertIsNone(gate(report, "学习稳定性（不加数据再跑一轮，提议集合不变）")["ok"])
        self.assertTrue((out / "truth.json").exists())


class ConsoleFlowTests(_Fixture):
    """The console path against a stub server: login, export window, site and object map, logout."""

    def setUp(self) -> None:
        super().setUp()
        self.calls: list[tuple[str, str, dict[str, list[str]], str]] = []
        self.records = [
            decision("req_ok", path="fast_allow", outcome="allowed", session="s5", route="/api/ok"),
            decision("req_bs", path="jev_deny", outcome="blocked", session="s3", route="/rest/basket/9",
                     jev_record=jev(access="DENY", attack="BENIGN")),
        ]
        self.objects = {
            "slots": [{"key": "POST /api/BasketItems body.BasketId", "side": "request", "class": "basket",
                       "state": "confirmed", "source": "admin", "accepts_public": False, "reliability": "high"}],
            "judgements": [],
        }
        self.server = self.start_stub()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)

    def start_stub(self) -> ThreadingHTTPServer:
        owner = self
        export_lines = "".join(json.dumps(record) + "\n" for record in self.records).encode("utf-8")

        class Stub(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # keep the test output quiet
                return

            def _reply(self, status: int, body: Any, *, raw: bytes | None = None, cookie: bool = False) -> None:
                data = raw if raw is not None else json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if cookie:
                    self.send_header("Set-Cookie", f"session={SESSION_TOKEN}; Path=/; HttpOnly")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _record(self, body: str) -> None:
                from urllib.parse import parse_qs, urlsplit
                parts = urlsplit(self.path)
                owner.calls.append((self.command, parts.path, parse_qs(parts.query), body))

            def _signed_in(self) -> bool:
                return SESSION_TOKEN in (self.headers.get("Cookie") or "")

            def do_POST(self) -> None:  # noqa: N802 - the stdlib's name
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8")
                self._record(body)
                if self.path == "/api/login":
                    if json.loads(body or "{}").get("password") == CONSOLE_PASSWORD:
                        self._reply(200, {"authenticated": True}, cookie=True)
                    else:
                        self._reply(401, {"error": "INVALID_PASSWORD"})
                elif self.path == "/api/logout":
                    self._reply(200, {"authenticated": False})
                else:
                    self._reply(404, {"error": "NOT_FOUND"})

            def do_GET(self) -> None:  # noqa: N802
                self._record("")
                if not self._signed_in():
                    self._reply(401, {"error": "UNAUTHENTICATED"})
                    return
                path = self.path.split("?", 1)[0]
                if path == "/api/requests/export":
                    self._reply(200, None, raw=export_lines)
                elif path == "/api/sites/juice":
                    self._reply(200, {"name": "juice", "version": 3, "spec": {"objects": {"slots": []}}})
                elif path == "/api/sites/juice/objects":
                    self._reply(200, owner.objects)
                else:
                    self._reply(404, {"error": "NOT_FOUND"})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def environment(self, password: str | None) -> dict[str, str]:
        env = {"no_proxy": "127.0.0.1,localhost", "NO_PROXY": "127.0.0.1,localhost"}
        if password is not None:
            env[PASSWORD_ENV] = password
        return env

    def test_export_objects_and_learned_file_come_from_the_console(self) -> None:
        suite = write_suite(self.root / "suite", {1: [
            suite_row("block-bs", category="Broken Access Control", outcome="blocked", request_id="req_bs"),
            suite_row("benign-ok", traffic="benign", expected="allow", category="Improper Input Validation",
                      request_id="req_ok", status=200),
        ]})
        out = self.root / "out"
        with mock.patch.dict(os.environ, self.environment(CONSOLE_PASSWORD)):
            status, _, stderr = run_cli("site", "--control", self.base_url(), "--site", "juice",
                                        "--suite-results", str(suite), "--out", str(out), "--truth", str(JUICE_TRUTH))
        self.assertIn(status, (0, 1), stderr)
        exports = [call for call in self.calls if call[1] == "/api/requests/export"]
        self.assertEqual(len(exports), 1)
        query = exports[0][2]
        self.assertEqual(query["site"], ["juice"])
        self.assertEqual(query["scope"], ["all"])
        self.assertEqual(query["format"], ["jsonl"])
        since, until = int(query["since_millis"][0]), int(query["until_millis"][0])
        self.assertLess(since, until)
        self.assertEqual(until - since, 2 * 5 * 60 * 1000 + 1000)
        self.assertEqual(len((out / "decisions.jsonl").read_text(encoding="utf-8").splitlines()), 2)
        learned = load_learned(out / "learned.json")
        self.assertEqual(learned["rounds"][0]["positions"][0]["class"], "basket")
        self.assertEqual(learned["final_spec"], {"objects": {"slots": []}})
        self.assertTrue(any(call[1] == "/api/logout" for call in self.calls))

    def test_the_password_comes_only_from_the_environment(self) -> None:
        suite = write_suite(self.root / "suite", {1: [suite_row("probe", request_id="req_bs")]})
        with mock.patch.dict(os.environ, self.environment(None)):
            os.environ.pop(PASSWORD_ENV, None)
            status, _, err = run_cli("site", "--control", self.base_url(), "--site", "juice",
                                     "--suite-results", str(suite), "--out", str(self.root / "o"))
        self.assertEqual(status, 2)
        self.assertIn(PASSWORD_ENV, err)
        self.assertEqual([call for call in self.calls if call[1] == "/api/login"], [])

    def test_a_wrong_password_stops_before_any_export_and_is_not_echoed(self) -> None:
        suite = write_suite(self.root / "suite", {1: [suite_row("probe", request_id="req_bs")]})
        out = self.root / "out"
        with mock.patch.dict(os.environ, self.environment("not-the-password-value")):
            status, stdout, err = run_cli("site", "--control", self.base_url(), "--site", "juice",
                                          "--suite-results", str(suite), "--out", str(out))
        self.assertEqual(status, 2)
        self.assertIn("INVALID_PASSWORD", err)
        self.assertNotIn("not-the-password-value", err + stdout)
        self.assertFalse(any(call[1] == "/api/requests/export" for call in self.calls))

    def test_no_output_file_holds_the_password_or_the_cookie(self) -> None:
        suite = write_suite(self.root / "suite", {1: [
            suite_row("block-bs", category="Broken Access Control", outcome="blocked", request_id="req_bs")]})
        out = self.root / "out"
        with mock.patch.dict(os.environ, self.environment(CONSOLE_PASSWORD)):
            run_cli("site", "--control", self.base_url(), "--site", "juice", "--suite-results", str(suite),
                    "--out", str(out))
        written = [path for path in out.rglob("*") if path.is_file()]
        self.assertTrue(written)
        for path in written:
            data = path.read_bytes()
            self.assertNotIn(CONSOLE_PASSWORD.encode(), data, path.name)
            self.assertNotIn(SESSION_TOKEN.encode(), data, path.name)


class LearnedConversionTests(_Fixture):
    def test_the_object_map_becomes_one_round_that_meets_the_contract(self) -> None:
        objects = {
            "slots": [
                {"key": "GET /rest/basket/{id} path[2]", "state": "confirmed", "class": "basket", "source": "admin",
                 "tier": None, "accepts_public": False, "reliability": "high"},
                {"key": "POST /rest/user/login authentication.bid", "state": "confirmed", "class": "basket",
                 "source": "admin", "tier": "self", "accepts_public": None, "reliability": "high"},
            ],
            "judgements": [
                {"id": "a", "key": "POST /rest/user/login authentication.bid", "tier": "self", "units": 4,
                 "seen_values": 4, "agreement_per_mille": 990, "reliability": "high"},
                {"id": "b", "key": "POST /api/BasketItems body.ProductId", "accepts_public": True, "votes": 3,
                 "sessions": 3, "public_per_mille": 900, "reliability": "medium"},
            ],
        }
        learned = learned_from_objects(objects, {"objects": {"slots": []}})
        self.assertEqual(learned["bootstrap"], [])
        self.assertEqual(len(learned["rounds"]), 1)
        self.assertEqual(learned["rounds"][0]["judgements"][0], {
            "key": "POST /rest/user/login authentication.bid", "reliability": "high", "tier": "self"})
        self.assertEqual(learned["rounds"][0]["judgements"][1]["accepts_public"], True)
        path = self.root / "learned.json"
        path.write_text(json.dumps(learned), encoding="utf-8")
        load_learned(path)

    def test_a_judgement_with_no_value_is_refused(self) -> None:
        from effectiveness.site import SiteError
        with self.assertRaises(SiteError):
            learned_from_objects({"slots": [], "judgements": [{"key": "GET /x y", "reliability": "low"}]}, None)


class JuiceTruthTests(unittest.TestCase):
    def test_the_truth_file_meets_the_contract_and_uses_template_keys(self) -> None:
        import re
        truth = load_truth(JUICE_TRUTH)
        self.assertEqual(truth["site"], "juice")
        keys = [position["key"] for position in truth["request_positions"] + truth["response_positions"]]
        keys += truth["non_objects"]
        self.assertTrue(keys)
        for key in keys:
            route = key.split(" ")[1]
            self.assertIsNone(re.search(r"/\d", route), key)  # numeric ids are written as {id}
        self.assertTrue(all(position["class"] for position in truth["request_positions"]))

    def test_a_broken_truth_is_refused_by_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.truth.json"
            path.write_text(json.dumps({"site": "juice"}), encoding="utf-8")
            with self.assertRaises(ContractError) as caught:
                load_truth(path)
            self.assertIn("broken.truth.json", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

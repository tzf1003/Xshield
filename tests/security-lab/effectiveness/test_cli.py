"""Command-line tests (plan sections 5.3 and 10, batch 1): exit codes 0, 1 and 2, the three
fixture groups end to end, and the script entry point. Every run writes into a temporary folder,
never into target/."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

from effectiveness import jev_relay
from effectiveness.cli import main

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCRIPT = ROOT / "scripts" / "measure_effectiveness.py"
SECTIONS = ["## 1 结论", "## 2 记分表", "## 3 防护明细", "## 4 学习明细", "## 5 回归用例",
            "## 6 失败清单", "## 7 成本", "## 8 未执行的部分"]


def run_cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def score_args(group: str, out: Path, *extra: str) -> list[str]:
    folder = FIXTURES / group
    args = ["score", "--observations", str(folder / "observations.jsonl"),
            "--decisions", str(folder / "decisions.jsonl"), "--out", str(out)]
    for name, flag in (("truth.json", "--truth"), ("learned.json", "--learned")):
        if (folder / name).exists():
            args += [flag, str(folder / name)]
    return [*args, *extra]


class CommandTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.out = Path(directory.name)

    def write_json(self, name: str, document: dict[str, Any]) -> Path:
        path = self.out / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_the_fixture_groups_exit_0_1_1_and_write_the_report(self):
        for group, code in {"all-correct": 0, "one-error-each": 1, "missing-and-skip": 1}.items():
            with self.subTest(group=group):
                target = self.out / group
                status, _, err = run_cli(*score_args(group, target))
                self.assertEqual(status, code, err)
                report = (target / "report.md").read_text(encoding="utf-8")
                self.assertEqual([line for line in report.splitlines() if line.startswith("## ")], SECTIONS)
                document = json.loads((target / "report.json").read_text(encoding="utf-8"))
                self.assertEqual(document["passed"], code == 0)
                self.assertTrue((target / "observations.jsonl").exists())

    def test_the_failing_group_names_the_planted_gates(self):
        _, out, _ = run_cli(*score_args("one-error-each", self.out / "b"))
        for name in ("S2 误核验数", "P5 被拦请求到达源站数", "学习稳定性"):
            self.assertIn(name, out)

    def test_the_missing_group_names_the_record_and_the_skipped_learning(self):
        _, out, _ = run_cli(*score_args("missing-and-skip", self.out / "c"))
        self.assertIn("记录缺失", out)
        self.assertIn("学习段 SKIP", out)

    def test_a_baseline_regression_fails_the_run_and_an_improvement_passes(self):
        worse = self.write_json("worse.json", {"values": {"S3": 0.9}})
        better = self.write_json("better.json", {"values": {"S3": 0.4}})
        status, _, _ = run_cli(*score_args("all-correct", self.out / "w", "--baseline", str(worse)))
        self.assertEqual(status, 1)
        status, _, _ = run_cli(*score_args("all-correct", self.out / "i", "--baseline", str(better)))
        self.assertEqual(status, 0)

    def test_the_lab_refuses_the_modes_that_are_not_built_and_prints_nothing_to_stdout(self):
        for args, text in ((["lab", "--mode", "full"], "批次 7"),
                           (["lab", "--keep"], "批次 5"), (["lab", "--update-baseline"], "批次 8")):
            with self.subTest(args=args):
                status, out, err = run_cli(*args)
                self.assertEqual(status, 2)
                self.assertIn(text, err)
                self.assertEqual(out, "")

    def test_live_without_its_settings_is_an_error_and_never_falls_back(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("XSHIELD_JEV_ENDPOINT", None)
            os.environ.pop("XSHIELD_JEV_API_KEY", None)
            status, out, err = run_cli("lab", "--jev", "live", "--out", str(self.out / "live"))
        self.assertEqual(status, 2)
        self.assertIn("XSHIELD_JEV_ENDPOINT", err)
        self.assertEqual(out, "")
        self.assertFalse((self.out / "live").exists())  # refused before anything is written

    def test_record_without_its_settings_is_an_error_and_never_falls_back(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("XSHIELD_JEV_ENDPOINT", None)
            os.environ.pop("XSHIELD_JEV_API_KEY", None)
            status, out, err = run_cli("lab", "--jev", "record", "--out", str(self.out / "record"))
        self.assertEqual(status, 2)
        self.assertIn("--jev record", err)
        self.assertIn("XSHIELD_JEV_API_KEY", err)
        self.assertEqual(out, "")
        self.assertFalse((self.out / "record").exists())

    def test_replay_without_a_recording_is_an_error_and_needs_no_settings(self):
        with mock.patch.object(jev_relay, "DEFAULT_RECORDING", self.out / "missing.jsonl"), mock.patch.dict(os.environ):
            os.environ.pop("XSHIELD_JEV_ENDPOINT", None)
            os.environ.pop("XSHIELD_JEV_API_KEY", None)
            status, out, err = run_cli("lab", "--jev", "replay", "--out", str(self.out / "replay"))
        self.assertEqual(status, 2)
        self.assertIn("没有录制文件", err)
        self.assertEqual(out, "")
        self.assertFalse((self.out / "replay").exists())  # refused before the output folder is made

    def test_site_needs_decisions_or_a_console(self):
        status, _, err = run_cli("site", "--suite-results", "dir")
        self.assertEqual(status, 2)
        self.assertIn("site 需要 --decisions", err)

    def test_a_password_on_the_command_line_is_refused_without_echo(self):
        for flag in ("--password", "--pass=s3cret-value"):
            with self.subTest(flag=flag):
                status, out, err = run_cli("site", "--control", "http://127.0.0.1:1", "--site", "x",
                                           "--suite-results", "dir", flag)
                self.assertEqual(status, 2)
                self.assertIn("XSHIELD_CONSOLE_PASSWORD", err)
                self.assertNotIn("s3cret-value", err + out)

    def test_a_usage_error_exits_2(self):
        status, _, _ = run_cli("score")
        self.assertEqual(status, 2)

    def test_an_unreadable_input_exits_2(self):
        missing = str(self.out / "none.jsonl")
        status, _, err = run_cli("score", "--observations", missing, "--decisions", missing,
                                 "--out", str(self.out / "x"))
        self.assertEqual(status, 2)
        self.assertIn("error:", err)

    def test_help_exits_0(self):
        status, _, _ = run_cli("--help")
        self.assertEqual(status, 0)

    def test_the_script_entry_point_runs_the_scorer(self):
        done = subprocess.run([sys.executable, str(SCRIPT), *score_args("all-correct", self.out / "s")],
                              capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("结论：通过", done.stdout)

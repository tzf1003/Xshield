"""Report tests (plan section 7, batch 1): the eight sections, the stated skip, dashes for empty
denominators, the terminal summary, and the rule that no request value is ever quoted."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from effectiveness.builders import decision, entry, jev, observation, reference, suspicious_probe
from effectiveness.contracts import load_decisions, load_learned, load_observations, load_truth
from effectiveness.report import conclusion, render_markdown, render_terminal, report_document, score_rows
from effectiveness.score import score

FIXTURES = Path(__file__).resolve().parent / "fixtures"
META = {"commit": "abc1234", "mode": "score", "jev": "未指定", "seed": 1,
        "started": "2026-11-13T00:00:00+00:00", "seconds": 0.5}
SECTIONS = ["## 1 结论", "## 2 记分表", "## 3 防护明细", "## 4 学习明细", "## 5 回归用例",
            "## 6 失败清单", "## 7 成本", "## 8 未执行的部分"]
MARKER = "MARKER-7731-VALUE"


def fixture_result(group: str, baseline: dict | None = None) -> dict:
    folder = FIXTURES / group
    truth = load_truth(folder / "truth.json") if (folder / "truth.json").exists() else None
    learned = load_learned(folder / "learned.json") if (folder / "learned.json").exists() else None
    return score(load_observations(folder / "observations.jsonl"), load_decisions(folder / "decisions.jsonl"),
                 truth=truth, learned=learned, baseline=baseline)


class ReportTests(unittest.TestCase):
    def test_all_eight_sections_appear_in_order(self):
        text = render_markdown(fixture_result("all-correct"), META)
        self.assertEqual([line for line in text.splitlines() if line.startswith("## ")], SECTIONS)

    def test_a_skipped_learning_section_is_stated_in_the_conclusion_and_section_eight(self):
        result = fixture_result("missing-and-skip")
        text = render_markdown(result, META)
        self.assertIn("学习段未执行", conclusion(result, META))
        self.assertIn("学习段未执行：未提供 truth.json、learned.json", text)
        self.assertIn("- 学习段：未提供 truth.json、learned.json", text)

    def test_the_conclusion_names_the_failed_gate(self):
        self.assertIn("结论：失败（未通过的门槛：记录缺失数）", conclusion(fixture_result("missing-and-skip"), META))

    def test_an_unexecuted_gate_is_shown_as_unexecuted(self):
        rows = {row[0]: row for row in score_rows(fixture_result("missing-and-skip"))}
        self.assertEqual(rows["L1 误学数"][1], "—")
        self.assertEqual(rows["L1 误学数"][5], "未执行")

    def test_an_empty_denominator_renders_as_a_dash(self):
        rows = {row[0]: row for row in score_rows(score([], []))}
        self.assertEqual(rows["S1 正常引用核验率"][1], "—")
        self.assertEqual(rows["P1 拦截率（总体）"][1], "—")

    def test_terminal_prints_the_first_ten_failures_and_the_total(self):
        rows = [observation(f"probe-{number}", request_id=f"x{number}") for number in range(12)]
        text = render_terminal(score(rows, []), META)
        self.assertIn("失败（前 10 条，共 12 条）", text)
        self.assertEqual(sum(line.startswith("  - ") for line in text.splitlines()), 10)

    def test_the_report_never_quotes_a_request_value(self):
        rows = [observation("probe", request_id="p1", refs=[reference(MARKER)]),
                observation("gone", request_id="p2", refs=[reference(MARKER)])]
        recs = [decision("p1", path="fast_allow", outcome="allowed", route=f"/api/patients/{MARKER}",
                         values=[entry(MARKER)])]
        result = score(rows, recs)
        self.assertEqual(len(result["failures"]), 2)
        for text in (render_markdown(result, META), render_terminal(result, META),
                     json.dumps(report_document(result, META), ensure_ascii=False)):
            self.assertNotIn(MARKER, text)

    def test_a_known_gap_that_passes_names_the_fix_and_its_phenomenon(self):
        rows = [observation("gap", request_id="g1", group="regression", status="known_gap", ref="P1-2",
                            reason="attack", note="UNION 查询没有被判为攻击")]
        result = score(rows, [decision("g1", jev_record=jev(access="ALLOW", attack="ATTACK"))])
        text = render_markdown(result, META)
        self.assertIn("请把状态改为 must", text)
        self.assertIn("UNION 查询没有被判为攻击", text)
        self.assertIn("P7 意外通过数", conclusion(result, META))

    def test_a_category_regression_is_listed_and_fails_the_overall_row(self):
        rows = [observation("probe", request_id="p1")]
        result = score(rows, [decision("p1", path="fast_allow", outcome="allowed")],
                       baseline={"values": {"P1/idor_direct/truth": 1.0}})
        text = render_markdown(result, META)
        self.assertIn("基线比较：退步 1 项", text)
        self.assertIn("- 退步：P1/idor_direct/truth，基线 100.0%，本次 0.0%", text)
        verdicts = {row[0]: row[5] for row in score_rows(result)}
        self.assertEqual(verdicts["P1 拦截率（总体）"], "否")

    def test_the_label_block_lists_the_flagged_probe(self):
        rows, recs = suspicious_probe()
        text = render_markdown(score(rows, recs), META)
        self.assertIn("标签可疑（目标对象在本会话里展示过）：1 条，probe", text)
        self.assertIn("未应用：探针全部留在分母里（靶场模式）。", text)

    def test_report_json_carries_the_section_nine_keys(self):
        document = report_document(fixture_result("all-correct"), META)
        for key in ("meta", "metrics", "gates", "baseline", "failures", "known_gaps", "learning", "passed"):
            self.assertIn(key, document)
        self.assertEqual(set(document["baseline"]), {"compared", "regressions", "improvements"})
        self.assertTrue(document["passed"])

"""Tests of the confidence threshold scan (plan 3.4, batch 9) and of how the report prints it.

The rule under test is WAF batch 7's: an allow whose confidence, the smaller of P(ALLOW) and P(BENIGN), is below the
threshold becomes an unanswered judgement; an allow at exactly the threshold stays. Each case builds its own records,
so a failing case names the rule it broke.
"""

from __future__ import annotations

import unittest
from typing import Any

from effectiveness.builders import decision, observation
from effectiveness.report import render_markdown
from effectiveness.score import CONFIDENCE_THRESHOLDS, allow_confidence, confidence_scan, score

META = {"commit": "abc1234", "mode": "lab", "jev": "record", "seed": 1,
        "started": "2026-11-13T00:00:00+00:00", "seconds": 0.5}


def probabilities(allowed: float, benign: float) -> dict[str, Any]:
    """A Jev record of a judgement whose answers are ALLOW (allowed) and BENIGN (benign), as the gateway writes it."""
    return {"state": "{}", "failure": None, "response": None,
            "access": {"ALLOW": allowed, "DENY": round(1 - allowed, 4), "UNKNOWN": 0.0},
            "attack": {"BENIGN": benign, "ATTACK": round(1 - benign, 4), "UNKNOWN": 0.0},
            "conclusion": None, "millis": 1}


def allowed(request_id: str, *, confidence: float, benign_answer: float = 0.95, expect: str = "allow",
            status: str = "must") -> tuple[dict[str, Any], dict[str, Any]]:
    """An observation and a jev_allow record whose confidence is `confidence` (its access answer is the low one)."""
    row = observation(request_id, request_id=request_id, group="benign" if expect == "allow" else "attack",
                      category="benign_list" if expect == "allow" else "injection_sqli", expect=expect,
                      reason=None if expect == "allow" else "attack", status=status)
    record = decision(request_id, path="jev_allow", outcome="allowed",
                      jev_record=probabilities(confidence, benign_answer))
    return row, record


def cached(request_id: str, source: str) -> dict[str, Any]:
    """A cached allow that reuses the Jev allow of `source` (trace.cache_source, docs/07 7.4)."""
    record = decision(request_id, path="cached_allow", outcome="allowed")
    record["trace"]["cache_source"] = source
    return record


def scan_at(threshold: float, result: dict[str, Any]) -> dict[str, Any]:
    [item] = [entry for entry in result["thresholds"] if entry["threshold"] == threshold]
    return item


class ScanRuleTests(unittest.TestCase):
    def test_the_thresholds_run_from_fifty_to_ninety_hundredths_in_steps_of_five(self):
        self.assertEqual(CONFIDENCE_THRESHOLDS, (0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9))

    def test_an_allow_exactly_at_the_threshold_stays_an_allow(self):
        row, record = allowed("b1", confidence=0.6)
        result = confidence_scan([row], [record])
        self.assertEqual(scan_at(0.6, result)["benign_blocks"], 0)  # equal: kept (WAF batch 7, the rule is >=)
        self.assertEqual(scan_at(0.65, result)["benign_blocks"], 1)  # below: an unanswered judgement
        self.assertEqual(scan_at(0.55, result)["benign_blocks"], 0)

    def test_the_smaller_of_the_two_answers_is_the_confidence(self):
        row, record = allowed("b1", confidence=0.95, benign_answer=0.55)  # only BENIGN is low
        self.assertEqual(allow_confidence(record), 0.55)
        result = confidence_scan([row], [record])
        self.assertEqual(scan_at(0.55, result)["benign_blocks"], 0)
        self.assertEqual(scan_at(0.6, result)["benign_blocks"], 1)

    def test_a_refusal_and_a_fast_allow_are_never_changed(self):
        row = observation("b2", request_id="b2", group="benign", category="benign_list", expect="allow", reason=None)
        fast = decision("b2", path="fast_allow", outcome="allowed")
        refused = decision("p1", path="jev_deny", outcome="blocked", jev_record=probabilities(0.4, 0.9))
        probe = observation("p1", request_id="p1", group="attack", category="idor_direct", expect="block")
        allow_row, allow_record = allowed("b3", confidence=0.95)
        result = confidence_scan([row, probe, allow_row], [fast, refused, allow_record])
        self.assertEqual(result["allows"], 1)  # only the jev_allow record has a confidence
        self.assertEqual(scan_at(0.9, result)["benign_blocks"], 0)
        self.assertEqual(scan_at(0.9, result)["leaks_closed"], 0)

    def test_a_cached_allow_follows_the_allow_it_reuses(self):
        source_row, source = allowed("s1", confidence=0.55)
        reuse_row = observation("b4", request_id="b4", group="benign", category="benign_list", expect="allow",
                                reason=None)
        result = confidence_scan([source_row, reuse_row], [source, cached("b4", source="s1")])
        self.assertEqual(result["benign_total"], 2)
        # Both are refused: the source is a benign allow below 0.60 too, and the cached reuse takes its confidence.
        self.assertEqual(scan_at(0.6, result)["benign_blocks"], 2)
        self.assertEqual(scan_at(0.5, result)["benign_blocks"], 0)
        self.assertEqual(result["cache_unresolved"], 0)

    def test_a_cached_allow_without_its_source_record_is_counted_and_not_changed(self):
        reuse_row = observation("b5", request_id="b5", group="benign", category="benign_list", expect="allow",
                                reason=None)
        extra_row, extra = allowed("b6", confidence=0.95)
        result = confidence_scan([reuse_row, extra_row], [extra, cached("b5", source="gone")])
        self.assertEqual(result["cache_unresolved"], 1)
        self.assertEqual(scan_at(0.9, result)["benign_blocks"], 0)

    def test_a_probe_the_model_allowed_is_a_leak_that_a_threshold_closes(self):
        row, record = allowed("p2", confidence=0.55, expect="block")
        result = confidence_scan([row], [record])
        self.assertEqual(result["probe_allows"], 1)
        self.assertEqual(scan_at(0.6, result)["leaks_closed"], 1)
        self.assertEqual(scan_at(0.5, result)["leaks_closed"], 0)

    def test_unanswered_counts_every_allow_below_the_threshold_and_every_call(self):
        row, record = allowed("b7", confidence=0.55)
        setup = decision("setup", path="jev_allow", outcome="allowed", jev_record=probabilities(0.7, 0.9))
        refusal = decision("r1", path="jev_deny", outcome="blocked", jev_record=probabilities(0.9, 0.9))
        result = confidence_scan([row], [record, setup, refusal])
        self.assertEqual(result["calls"], 3)
        self.assertEqual(scan_at(0.6, result)["unanswered"], 1)  # the setup allow (0.7) is kept at 0.6
        self.assertEqual(scan_at(0.75, result)["unanswered"], 2)

    def test_a_known_gap_case_is_left_out_as_score_leaves_it_out(self):
        # score()'s population rule: a regression case with status known_gap is measured only by P7.
        row = observation("g1", request_id="g1", group="regression", category="idor_direct", expect="block",
                          status="known_gap")
        record = decision("g1", path="jev_allow", outcome="allowed", jev_record=probabilities(0.55, 0.95))
        result = confidence_scan([row], [record])
        self.assertEqual(result["probe_allows"], 0)
        self.assertEqual(scan_at(0.9, result)["leaks_closed"], 0)
        self.assertEqual(scan_at(0.6, result)["unanswered"], 1)  # the call was still made, so it still counts

    def test_the_confidence_is_the_edge_jev_confidence_so_each_question_counts_its_highest_answer(self):
        record = decision("b9", path="jev_allow", outcome="allowed", jev_record=probabilities(0.3, 0.95))
        self.assertEqual(allow_confidence(record), 0.7)  # access: the highest is DENY at 0.7, the edge logs that

    def test_a_run_without_any_allow_with_probabilities_has_no_scan(self):
        refused = decision("r2", path="jev_deny", outcome="blocked", jev_record=probabilities(0.9, 0.9))
        self.assertIsNone(confidence_scan([], [refused]))
        self.assertIsNone(allow_confidence({"jev": {"access": {"ALLOW": 0.9}, "attack": {}}}))


class ScanReportTests(unittest.TestCase):
    def result_with_scan(self) -> dict[str, Any]:
        rows, records = [], []
        for request_id, value in (("b1", 0.6), ("b2", 0.55)):
            row, record = allowed(request_id, confidence=value)
            rows.append(row)
            records.append(record)
        result = score(rows, records)
        result["confidence_scan"] = confidence_scan(rows, records)
        return result

    def test_the_scan_section_has_a_row_per_threshold_and_the_first_order_note(self):
        text = render_markdown(self.result_with_scan(), META)
        self.assertIn("### 置信度门槛扫描（3.4）", text)
        self.assertIn("| 0.50 |", text)
        self.assertIn("| 0.90 |", text)
        self.assertIn("一阶估计", text)
        self.assertIn("恰好等于门槛的放行保留", text)

    def test_the_section_is_not_printed_without_a_scan(self):
        result = score([], [])
        self.assertNotIn("置信度门槛扫描", render_markdown(result, META))

    def test_the_replay_miss_rate_is_one_line_in_the_cost_section(self):
        meta = {**META, "jev": "replay",
                "jev_relay": {"mode": "replay", "calls": 10, "misses": 2, "recorded": 0, "failures": 0}}
        text = render_markdown(score([], []), meta)
        self.assertIn("- 回放未命中率：2 / 10 次调用（20.0%）", text)

    def test_a_record_line_says_what_was_written(self):
        meta = {**META, "jev": "record",
                "jev_relay": {"mode": "record", "calls": 12, "misses": 0, "recorded": 11, "failures": 1}}
        text = render_markdown(score([], []), meta)
        self.assertIn("- 录制：11 条应答写入录制文件（转发 12 次，没有得到可用应答 1 次）", text)


if __name__ == "__main__":
    unittest.main()

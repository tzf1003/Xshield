"""Scorer tests (plan sections 3 and 10, batch 1).

Each metric has a case that scores when the input is right and a case that loses the point when
the input is deliberately wrong. The inputs come from builders.py.
"""

from __future__ import annotations

import copy
import unittest
from typing import Any

from effectiveness.builders import (
    candidate,
    decision,
    entry,
    jev,
    jev_failed,
    judgement,
    learned_doc,
    learning_round,
    observation,
    position,
    reference,
    suspicious_probe,
    truth_doc,
)
from effectiveness.score import compare_baseline, score

DELETE = "DELETE /api/patients/{id} path[2]"
POST = "POST /api/patients/{id}/notes path[2]"
SEARCH = "GET /api/search results[].id"
COMMENTS = "GET /api/comments comments[].author.id"
PAGE = "GET /api/search page"
LEARN_TRUTH = truth_doc(
    request=[(DELETE, "patient", False), (POST, "patient", True)],
    response=[(SEARCH, "patient", "public"), (COMMENTS, "doctor", "org")],
    non_objects=(PAGE,),
)


def gate(result: dict[str, Any], prefix: str) -> dict[str, Any]:
    found = [item for item in result["gates"] if item["name"].startswith(prefix)]
    if len(found) != 1:
        raise AssertionError(f"{prefix}: {[item['name'] for item in result['gates']]}")
    return found[0]


def benign(request_id: str) -> dict[str, Any]:
    return observation(request_id, request_id=request_id, group="benign", category="benign_list",
                       expect="allow", reason=None)


def right_positions() -> list[dict[str, Any]]:
    return [position(DELETE, cls="patient", accepts=False), position(POST, cls="patient", accepts=True),
            position(SEARCH, cls="patient"), position(COMMENTS, cls="doctor")]


def right_judgements() -> list[dict[str, Any]]:
    return [judgement(SEARCH, "public"), judgement(COMMENTS, "org")]


def right_bootstrap() -> list[dict[str, Any]]:
    return [candidate(SEARCH, "response", "patient"), candidate(DELETE, "request", "patient"),
            candidate(POST, "request", "patient")]


def learning_score(*rounds: tuple[list[dict[str, Any]], list[dict[str, Any]]],
                   bootstrap: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Scores learning alone: each round is (positions, judgements)."""
    docs = [learning_round(number, copy.deepcopy(positions), copy.deepcopy(judgements))
            for number, (positions, judgements) in enumerate(rounds, 1)]
    learned = learned_doc(docs, right_bootstrap() if bootstrap is None else bootstrap)
    return score([], [], truth=LEARN_TRUTH, learned=learned)


class SessionValueTests(unittest.TestCase):
    def shown_value(self, verified: bool) -> dict[str, Any]:
        rows = [observation("benign", request_id="b1", group="benign", category="benign_list",
                            expect="allow", reason=None, refs=[reference("101", shown=True)])]
        recs = [decision("b1", path="fast_allow", outcome="allowed", values=[entry("101", verified=verified)])]
        return score(rows, recs)["metrics"]["S1"]

    def test_s1_scores_a_shown_value_that_the_session_verified(self):
        metric = self.shown_value(verified=True)
        self.assertEqual((metric["value"], metric["num"], metric["den"]), (1.0, 1, 1))

    def test_s1_loses_the_point_when_the_shown_value_is_not_verified(self):
        self.assertEqual(self.shown_value(verified=False)["value"], 0.0)

    def test_s1_is_none_without_a_shown_value(self):
        result = score([benign("b1")], [decision("b1", path="fast_allow", outcome="allowed")])
        self.assertIsNone(result["metrics"]["S1"]["value"])

    def probe_with_value(self, verified: bool, echoed: bool = False) -> dict[str, Any]:
        rows = [observation("probe", request_id="p1", refs=[reference("205", echoed=echoed)])]
        recs = [decision("p1", values=[entry("205", verified=verified)], jev_record=jev())]
        return score(rows, recs)

    def test_s2_counts_a_value_verified_without_being_shown(self):
        result = self.probe_with_value(verified=True)
        self.assertEqual(result["metrics"]["S2"]["value"], 1)
        self.assertIs(gate(result, "S2 误核验数")["ok"], False)

    def test_s2_is_zero_when_the_value_is_not_verified(self):
        result = self.probe_with_value(verified=False)
        self.assertEqual(result["metrics"]["S2"]["value"], 0)
        self.assertIs(gate(result, "S2 误核验数")["ok"], True)

    def test_s2_leaves_out_an_echo(self):
        result = self.probe_with_value(verified=True, echoed=True)
        self.assertEqual((result["metrics"]["S2"]["value"], result["metrics"]["S2"]["den"]), (0, 0))


class ActivityTests(unittest.TestCase):
    def test_s3_and_s4_count_only_judged_benign_requests(self):
        rows = [benign("b1"), benign("b2"), benign("b3")]
        recs = [decision("b1", path="fast_allow", outcome="allowed"),
                decision("b2", path="jev_allow", outcome="allowed", jev_record=jev("ALLOW", "BENIGN")),
                decision("b3", path="jev_unavailable", outcome="unjudged", jev_record=jev_failed("JEV_TIMEOUT"))]
        metrics = score(rows, recs)["metrics"]
        self.assertEqual(metrics["S3"]["value"], 0.5)
        self.assertEqual(metrics["S4"]["value"], 0.5)

    def test_s3_loses_the_point_when_a_fast_allow_needs_jev(self):
        rows = [benign("b1"), benign("b2")]
        right = [decision("b1", path="fast_allow", outcome="allowed"),
                 decision("b2", path="fast_allow", outcome="allowed")]
        wrong = [decision("b1", path="jev_allow", outcome="allowed", jev_record=jev("ALLOW", "BENIGN")),
                 decision("b2", path="fast_allow", outcome="allowed")]
        self.assertEqual(score(rows, right)["metrics"]["S3"]["value"], 1.0)
        self.assertEqual(score(rows, wrong)["metrics"]["S3"]["value"], 0.5)
        self.assertEqual(score(rows, wrong)["metrics"]["S4"]["value"], 0.5)


class DefenceTests(unittest.TestCase):
    def test_p1_counts_an_expected_block_that_was_blocked(self):
        result = score([observation("probe", request_id="p1")], [decision("p1", jev_record=jev())])
        self.assertEqual(result["metrics"]["P1"]["value"], 1.0)
        self.assertEqual(result["failures"], [])

    def test_p1_loses_the_point_when_an_expected_block_is_allowed(self):
        result = score([observation("probe", request_id="p1")],
                       [decision("p1", path="fast_allow", outcome="allowed")])
        self.assertEqual(result["metrics"]["P1"]["value"], 0.0)
        self.assertEqual(result["failures"][0]["detail"], "应拦截，实际放行")

    def test_p2_counts_an_expected_allow_that_was_blocked(self):
        right = score([benign("b1")], [decision("b1", path="fast_allow", outcome="allowed")])
        self.assertEqual(right["metrics"]["P2"]["value"], 0.0)
        wrong = score([benign("b1")], [decision("b1", jev_record=jev())])
        self.assertEqual(wrong["metrics"]["P2"]["value"], 1.0)
        self.assertEqual(wrong["failures"][0]["detail"], "应放行，实际拦截")

    def test_p3_scores_the_reason_of_each_block(self):
        rows = [observation("probe", request_id="p1", category="injection", reason="attack")]
        right = score(rows, [decision("p1", jev_record=jev(access="ALLOW", attack="ATTACK"))])
        self.assertEqual(right["metrics"]["P3"]["value"], 1.0)
        wrong = score(rows, [decision("p1", jev_record=jev(access="DENY", attack="BENIGN"))])
        self.assertEqual(wrong["metrics"]["P1"]["value"], 1.0)
        self.assertEqual(wrong["metrics"]["P3"]["value"], 0.0)
        self.assertEqual(wrong["failures"][0]["detail"], "拦截原因不符，应为 注入（attack=ATTACK）")
        # An access probe blocked on an attack answer, with the access answer ALLOW, is a wrong reason.
        access = score([observation("probe", request_id="p1")],
                       [decision("p1", jev_record=jev(access="ALLOW", attack="ATTACK"))])
        self.assertEqual(access["metrics"]["P3"]["value"], 0.0)
        self.assertEqual(access["failures"][0]["detail"], "拦截原因不符，应为 越权（access=DENY）")

    def test_p4_counts_an_unjudged_request(self):
        rows = [benign("b1"), benign("b2")]
        right = score(rows, [decision("b1", path="fast_allow", outcome="allowed"),
                             decision("b2", path="fast_allow", outcome="allowed")])
        self.assertEqual(right["metrics"]["P4"]["value"], 0.0)
        self.assertIs(gate(right, "P4")["ok"], True)
        wrong = score(rows, [decision("b1", path="fast_allow", outcome="allowed"),
                             decision("b2", path="jev_unavailable", outcome="unjudged",
                                      jev_record=jev_failed("JEV_TIMEOUT"))])
        self.assertEqual((wrong["metrics"]["P4"]["num"], wrong["metrics"]["P4"]["den"]), (1, 2))
        self.assertIs(gate(wrong, "P4")["ok"], False)

    def test_p4_leaves_out_a_request_that_hit_the_call_limit(self):
        rows = [observation("limit", request_id="l1", category="limit_session", reason="limit")]
        result = score(rows, [decision("l1", path="jev_unavailable", outcome="blocked",
                                       jev_record=jev_failed("JEV_CALL_LIMIT"))])
        self.assertIsNone(result["metrics"]["P4"]["value"])
        self.assertIsNone(gate(result, "P4")["ok"])
        self.assertEqual(result["metrics"]["P1"]["value"], 1.0)

    def test_p5_counts_a_blocked_request_that_reached_the_origin(self):
        wrong = score([observation("probe", request_id="p1", origin_served=True)],
                      [decision("p1", jev_record=jev())])
        self.assertEqual(wrong["metrics"]["P5"]["value"], 1)
        self.assertIs(gate(wrong, "P5")["ok"], False)
        self.assertIn("被拦请求已到达源站", wrong["failures"][0]["detail"])
        right = score([observation("probe", request_id="p1", origin_served=False)],
                      [decision("p1", jev_record=jev())])
        self.assertEqual(right["metrics"]["P5"]["value"], 0)
        self.assertIs(gate(right, "P5")["ok"], True)
        # An allowed request may reach the origin; that is not a leak.
        allowed = score([observation("allow", request_id="a1", group="benign", category="benign_list",
                                     expect="allow", reason=None, origin_served=True)],
                        [decision("a1", path="fast_allow", outcome="allowed")])
        self.assertEqual(allowed["metrics"]["P5"]["value"], 0)

    def test_p5_is_none_when_no_origin_outcome_is_recorded(self):
        result = score([observation("probe", request_id="p1", origin_served=None)],
                       [decision("p1", jev_record=jev())])
        self.assertIsNone(result["metrics"]["P5"]["value"])
        self.assertIsNone(gate(result, "P5")["ok"])

    def test_p7_scores_must_cases(self):
        rows = [observation("must", request_id="m1", group="regression", ref="P0-2")]
        right = score(rows, [decision("m1", jev_record=jev())])
        self.assertEqual(right["metrics"]["P7"]["value"], 1.0)
        self.assertIs(gate(right, "P7 must")["ok"], True)
        wrong = score(rows, [decision("m1", path="fast_allow", outcome="allowed")])
        self.assertEqual(wrong["metrics"]["P7"]["value"], 0.0)
        self.assertIs(gate(wrong, "P7 must")["ok"], False)
        self.assertEqual(wrong["failures"][0]["group"], "regression")

    def test_a_known_gap_that_passes_is_an_unexpected_pass(self):
        rows = [observation("gap", request_id="g1", group="regression", status="known_gap", ref="P1-2",
                            reason="attack")]
        result = score(rows, [decision("g1", jev_record=jev(access="ALLOW", attack="ATTACK"))])
        self.assertEqual(result["metrics"]["P7"]["unexpected_pass"], 1)
        self.assertIs(gate(result, "P7 意外通过数")["ok"], False)
        self.assertTrue(result["known_gaps"][0]["unexpected_pass"])
        self.assertIn("请把状态改为 must", result["failures"][0]["detail"])

    def test_a_known_gap_that_still_fails_is_expected(self):
        rows = [observation("gap", request_id="g1", group="regression", status="known_gap", ref="P1-2",
                            reason="attack")]
        result = score(rows, [decision("g1", path="fast_allow", outcome="allowed")])
        self.assertEqual(result["metrics"]["P7"]["unexpected_pass"], 0)
        self.assertIs(gate(result, "P7 意外通过数")["ok"], True)
        self.assertFalse(result["known_gaps"][0]["unexpected_pass"])
        self.assertEqual(result["failures"], [])


class PopulationTests(unittest.TestCase):
    def test_a_known_gap_is_left_out_of_every_metric_but_p7(self):
        rows = [observation("gap", request_id="g1", group="regression", status="known_gap", ref="P1-2",
                            reason="attack")]
        result = score(rows, [decision("g1", path="fast_allow", outcome="allowed")])
        self.assertIsNone(result["metrics"]["P1"]["value"])
        self.assertEqual(result["counts"]["scored"], 0)
        self.assertEqual(result["counts"]["known_gap_cases"], 1)

    def test_a_configuration_without_tiers_is_needs_tiers_not_a_failure(self):
        rows = [observation("tiered", request_id="t1", config="none", requires=("tiers",))]
        result = score(rows, [decision("t1", path="fast_allow", outcome="allowed")])
        self.assertEqual(result["needs_tiers"], {"none": 1})
        self.assertEqual(result["failures"], [])
        self.assertIsNone(result["metrics"]["P1"]["value"])
        self.assertTrue(result["passed"])

    def test_a_configuration_with_tiers_is_scored(self):
        truth = truth_doc(request=[], response=[(SEARCH, "patient", "public")])
        rows = [observation("tiered", request_id="t1", config="truth", requires=("tiers",))]
        result = score(rows, [decision("t1", path="fast_allow", outcome="allowed")], truth=truth)
        self.assertEqual(result["needs_tiers"], {})
        self.assertEqual(result["metrics"]["P1"]["value"], 0.0)
        self.assertEqual(result["failures"][0]["detail"], "应拦截，实际放行")


class LabelCheckTests(unittest.TestCase):
    def test_the_lab_keeps_a_suspicious_probe_in_the_denominator(self):
        rows, recs = suspicious_probe()
        result = score(rows, recs)
        self.assertEqual(result["metrics"]["P1"]["value"], 1.0)
        self.assertEqual(result["label_checks"]["suspicious"], ["probe"])
        self.assertFalse(result["label_checks"]["applied"])

    def test_the_site_mode_takes_a_suspicious_probe_out_and_says_so(self):
        rows, recs = suspicious_probe()
        result = score(rows, recs, exclude_suspicious=True)
        self.assertIsNone(result["metrics"]["P1"]["value"])
        self.assertEqual(result["label_checks"]["excluded"], 1)
        self.assertEqual(result["failures"], [])

    def test_a_bypass_probe_is_flagged_and_taken_out_when_asked(self):
        rows = [observation("probe", request_id="p1")]
        recs = [decision("p1", path="bypass", outcome="allowed")]
        kept = score(rows, recs)
        self.assertEqual(kept["label_checks"]["bypass"], ["probe"])
        self.assertEqual(kept["metrics"]["P1"]["value"], 0.0)
        taken = score(rows, recs, exclude_suspicious=True)
        self.assertEqual(taken["label_checks"]["excluded"], 1)
        self.assertEqual(taken["failures"], [])


class MissingRecordTests(unittest.TestCase):
    def test_a_request_without_a_record_fails_the_missing_gate(self):
        result = score([observation("probe", request_id="p9")], [])
        self.assertEqual(gate(result, "记录缺失数")["value"], 1)
        self.assertIs(gate(result, "记录缺失数")["ok"], False)
        self.assertEqual(result["failures"][0]["got"], "记录缺失")
        self.assertFalse(result["passed"])

    def test_every_request_with_a_record_passes_the_missing_gate(self):
        result = score([observation("probe", request_id="p9")], [decision("p9", jev_record=jev())])
        self.assertIs(gate(result, "记录缺失数")["ok"], True)


class CostTests(unittest.TestCase):
    def test_a_call_that_hit_the_limit_is_not_counted_as_a_jev_call(self):
        recs = [decision("a", path="jev_unavailable", outcome="blocked", jev_record=jev_failed("JEV_CALL_LIMIT")),
                decision("b", path="jev_allow", outcome="allowed", jev_record=jev())]
        result = score([], recs)
        self.assertEqual(result["costs"]["jev_calls"], 1)
        self.assertEqual(result["costs"]["jev_failures"], {"JEV_CALL_LIMIT": 1})


class ZeroDenominatorTests(unittest.TestCase):
    def test_empty_input_gives_none_and_fails_no_gate(self):
        result = score([], [])
        metrics = result["metrics"]
        for name in ("S1", "S3", "S4", "P1", "P2", "P3", "P4", "P5", "P7"):
            self.assertIsNone(metrics[name]["value"], name)
        self.assertEqual(metrics["S2"]["value"], 0)
        self.assertIsNone(gate(result, "记录缺失数")["ok"])
        self.assertTrue(result["passed"])


class LearningTests(unittest.TestCase):
    def test_a_right_round_scores_every_learning_metric(self):
        result = learning_score((right_positions(), right_judgements()), (right_positions(), right_judgements()))
        metrics = result["metrics"]
        self.assertEqual(metrics["L0"]["accuracy"]["value"], 1.0)
        self.assertEqual(metrics["L0"]["coverage"]["value"], 0.75)
        self.assertEqual(metrics["L1"]["accuracy"]["value"], 1.0)
        self.assertEqual(metrics["L1"]["coverage"]["value"], 1.0)
        self.assertEqual(metrics["L2"]["accuracy"]["value"], 1.0)
        self.assertEqual(metrics["L2"]["high"]["value"], 1.0)
        self.assertEqual(metrics["L3"]["accuracy"]["value"], 1.0)
        self.assertEqual(metrics["L3"]["coverage"]["value"], 1.0)
        self.assertIs(metrics["stability"]["value"], True)
        for prefix in ("L0 误学数", "L1 误学数", "L2 误学数", "L3 误学数", "学习稳定性"):
            self.assertIs(gate(result, prefix)["ok"], True, prefix)

    def test_l1_loses_the_point_for_a_wrong_class(self):
        positions = right_positions()
        positions[0] = position(DELETE, cls="doctor", accepts=False)
        result = learning_score((positions, right_judgements()), (positions, right_judgements()))
        self.assertEqual((result["metrics"]["L1"]["accuracy"]["value"], result["metrics"]["L1"]["wrong"]), (0.5, 1))
        self.assertIs(gate(result, "L1 误学数")["ok"], False)

    def test_l1_counts_a_proposal_on_a_non_object_as_wrong(self):
        positions = right_positions() + [position(PAGE, cls="patient")]
        result = learning_score((positions, right_judgements()), (positions, right_judgements()))
        self.assertEqual(result["metrics"]["L1"]["wrong"], 1)
        self.assertAlmostEqual(result["metrics"]["L1"]["accuracy"]["value"], 2 / 3)
        self.assertIs(gate(result, "L1 误学数")["ok"], False)
        rows = {row["key"]: row for row in result["learning"]}
        self.assertEqual(rows[PAGE]["why"], "误学：真值为非对象")

    def test_l2_counts_a_tier_on_a_request_position_as_wrong(self):
        judgements = right_judgements() + [judgement(DELETE, "self")]
        result = learning_score((right_positions(), judgements), (right_positions(), judgements))
        self.assertEqual(result["metrics"]["L2"]["wrong"], 1)
        self.assertAlmostEqual(result["metrics"]["L2"]["accuracy"]["value"], 2 / 3)
        self.assertIs(gate(result, "L2 误学数")["ok"], False)

    def test_l3_loses_the_point_for_a_wrong_accepts_public(self):
        positions = right_positions()
        positions[1] = position(POST, cls="patient", accepts=False)
        result = learning_score((positions, right_judgements()), (positions, right_judgements()))
        self.assertEqual((result["metrics"]["L3"]["accuracy"]["value"], result["metrics"]["L3"]["wrong"]), (0.5, 1))
        self.assertIs(gate(result, "L3 误学数")["ok"], False)

    def test_l0_counts_a_wrong_cold_start_candidate(self):
        bootstrap = right_bootstrap() + [candidate(COMMENTS, "response", "patient")]
        result = learning_score((right_positions(), right_judgements()), (right_positions(), right_judgements()),
                                bootstrap=bootstrap)
        self.assertEqual(result["metrics"]["L0"]["wrong"], 1)
        self.assertAlmostEqual(result["metrics"]["L0"]["accuracy"]["value"], 0.75)
        self.assertIs(gate(result, "L0 误学数")["ok"], False)

    def test_a_key_the_truth_does_not_have_counts_as_wrong(self):
        judgements = right_judgements() + [judgement("GET /api/nowhere items[].id", "public")]
        result = learning_score((right_positions(), judgements), (right_positions(), judgements))
        self.assertEqual(result["metrics"]["L2"]["wrong"], 1)
        self.assertEqual(len([row for row in result["learning"] if row["side"] == "unknown"]), 1)

    def test_stability_fails_when_the_last_round_changes_a_judgement(self):
        changed = [judgement(SEARCH, "public", "medium"), judgement(COMMENTS, "org")]
        result = learning_score((right_positions(), right_judgements()), (right_positions(), changed))
        self.assertIs(result["metrics"]["stability"]["value"], False)
        self.assertIs(gate(result, "学习稳定性")["ok"], False)

    def test_stability_is_unknown_with_one_round(self):
        result = learning_score((right_positions(), right_judgements()))
        self.assertIsNone(result["metrics"]["stability"]["value"])
        self.assertIsNone(gate(result, "学习稳定性")["ok"])

    def test_learning_is_skipped_without_the_learned_file(self):
        result = score([], [], truth=LEARN_TRUTH)
        self.assertIsNone(result["metrics"]["L1"])
        self.assertIsNone(gate(result, "L1 误学数")["ok"])
        self.assertTrue(result["passed"])
        self.assertIn("学习段", [item["section"] for item in result["skipped"]])


class BaselineTests(unittest.TestCase):
    def test_a_drop_in_a_higher_is_better_metric_is_a_regression(self):
        result = compare_baseline({"S3": 0.5}, {"values": {"S3": 0.9}})
        self.assertEqual(result["regressions"], [{"name": "S3", "baseline": 0.9, "value": 0.5}])

    def test_a_rise_in_a_lower_is_better_metric_is_a_regression(self):
        result = compare_baseline({"P2/idor_direct/truth": 0.2}, {"values": {"P2/idor_direct/truth": 0.1}})
        self.assertEqual(len(result["regressions"]), 1)

    def test_a_fall_in_a_lower_is_better_metric_is_an_improvement(self):
        result = compare_baseline({"P2": 0.0}, {"values": {"P2": 0.1}})
        self.assertEqual(result["regressions"], [])
        self.assertEqual(len(result["improvements"]), 1)

    def test_equal_values_are_neither(self):
        result = compare_baseline({"S3": 0.5}, {"values": {"S3": 0.5}})
        self.assertEqual((result["regressions"], result["improvements"]), ([], []))

    def test_a_name_missing_from_the_baseline_is_not_compared(self):
        result = compare_baseline({"S3": 0.1}, {"values": {}})
        self.assertTrue(result["compared"])
        self.assertEqual(result["reference"], {})
        self.assertEqual(result["regressions"], [])

    def test_no_baseline_means_no_comparison(self):
        self.assertFalse(compare_baseline({"S3": 0.1}, None)["compared"])

    def test_the_score_fails_its_baseline_gate_on_a_regression(self):
        rows = [observation("probe", request_id="p1")]
        result = score(rows, [decision("p1", path="fast_allow", outcome="allowed")],
                       baseline={"values": {"P1": 1.0}})
        self.assertIs(gate(result, "基线比较")["ok"], False)
        self.assertFalse(result["passed"])

    def test_the_score_passes_its_baseline_gate_when_nothing_moves_the_wrong_way(self):
        rows = [observation("probe", request_id="p1")]
        result = score(rows, [decision("p1", path="fast_allow", outcome="allowed")],
                       baseline={"values": {"P1": 0.0}})
        self.assertIs(gate(result, "基线比较")["ok"], True)

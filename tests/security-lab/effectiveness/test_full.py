"""Tests of the full mode (plan 5.2 and 10, batch 7) that need no gateway, PostgreSQL or network: the arithmetic of L4
and L5, the natural-order variant, the two-pass comparison, P6 through the scorer, the wiring of the session-table
case, and the full-mode sections of the report. The full run itself is the acceptance check."""

from __future__ import annotations

import copy
import json
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from clinic_traffic import ATTACKERS_MAX, run_training
from effectiveness import full, probes, regressions
from effectiveness.builders import decision, observation
from effectiveness.report import _consequence_lines, render_markdown, report_document
from effectiveness.score import (
    CONSEQUENCE_FIELD, CONSISTENCY_ENFORCE_GROUP, CONSISTENCY_GROUP, POLLUTED_SET_SITE, POLLUTED_SITE, baseline_values,
    compare_baseline, score,
)

ROOT = Path(__file__).resolve().parents[3]
CONTEXT_RS = ROOT / "crates" / "xshield-judge" / "src" / "context.rs"
LAYERS = ("L0", "L1", "L2", "L3")
META = {"commit": "abc1234", "mode": "full", "jev": "理想模型", "seed": 1, "started": "2026-11-13T00:00:00+00:00",
        "seconds": 0.5, "unsent": {}, "jev_relay": None, "timings": {}, "two_pass": None}
SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE, SITE_EVICT = "clinic-truth", "clinic-truth-limit", "clinic-truth-observe", \
    "clinic-truth-evict"


def learning_of(**layers: tuple) -> dict:
    """What score.learning_metrics returns, from each layer's (learnable, right, wrong[, reliability]) keys. The
    reliability is a dict from a right key to its reliability; a layer without one has none."""
    keys: dict = {}
    metrics: dict = {}
    for layer in LAYERS:
        learnable, right, wrong, *reliability = layers.get(layer, ([], [], [], {}))
        keys[layer] = {"learnable": list(learnable), "right": list(right), "wrong": list(wrong),
                       "reliability": dict(reliability[0]) if reliability else {}}
        accuracy = len(set(right) & set(learnable)) / len(learnable) if learnable else None
        metrics[layer] = {"accuracy": {"value": accuracy}}
    return {"metrics": metrics, "keys": keys, "conclusions": {}}


def learned_with(key: str, *agreements: int) -> dict:
    """A learned file whose rounds judge `key`, once per round, with the given agreement per mille."""
    return {"rounds": [{"judgements": [{"key": key, "agreement_per_mille": value}]} for value in agreements]}


class FullSizeTests(unittest.TestCase):
    def test_the_sizes_are_the_plans(self):
        self.assertEqual(full.FULL_DOCTORS, 48)
        self.assertEqual(full.CONVERGENCE_USERS, (3, 6, 12, 24))
        self.assertEqual(full.POLLUTION_SHARE, 0.10)
        self.assertLess(full.CONVERGENCE_USERS[-1], full.FULL_DOCTORS)

    def test_the_session_limit_matches_the_gateway_source(self):
        match = re.search(r"pub const SESSIONS_MAX: usize = ([\d_]+);", CONTEXT_RS.read_text(encoding="utf-8"))
        self.assertIsNotNone(match, "SESSIONS_MAX is not in context.rs")
        self.assertEqual(int(match.group(1).replace("_", "")), regressions.SESSIONS_MAX)

    def test_the_flood_overflows_the_session_table(self):
        self.assertGreater(regressions.FLOOD_LOGINS, regressions.SESSIONS_MAX)


class AttackerShareTests(unittest.TestCase):
    def test_attack_sessions_are_ten_per_cent_of_all_sessions(self):
        for benign in (48, 192, 480):
            attackers = full.attacker_count(benign)
            self.assertAlmostEqual(attackers / (attackers + benign), full.POLLUTION_SHARE, delta=0.01)
        self.assertEqual(full.attacker_count(0), 0)


class ConvergenceTests(unittest.TestCase):
    def test_a_layer_is_at_the_top_with_no_wrong_proposal_and_the_top_positions_and_reliabilities(self):
        top = full.right_reliabilities(learning_of(L2=(["p", "q"], ["p", "q"], [], {"p": "high", "q": "high"}))
                                       ["keys"]["L2"])
        at = learning_of(L2=(["p", "q"], ["p", "q"], [], {"p": "high", "q": "high"}))["keys"]["L2"]
        lower = learning_of(L2=(["p", "q"], ["p", "q"], [], {"p": "medium", "q": "high"}))["keys"]["L2"]
        wrong = learning_of(L2=(["p", "q"], ["p", "q"], ["z"], {"p": "high", "q": "high"}))["keys"]["L2"]
        self.assertTrue(full.at_top(at, top))
        self.assertFalse(full.at_top(lower, top))
        self.assertFalse(full.at_top(wrong, top))

    def test_each_layer_names_the_first_user_count_at_which_it_is_at_its_top(self):
        points = [
            (3, learning_of(L0=(["a", "b", "c", "d"], ["a", "b"], []), L1=(["x"], ["x"], ["z"]),
                            L2=(["p", "q"], ["p", "q"], [], {"p": "medium", "q": "medium"}),
                            L3=(["m"], ["m"], [], {"m": "high"}))),
            (6, learning_of(L0=(["a", "b", "c", "d"], ["a", "b", "c", "d"], []), L1=(["x"], ["x"], ["z"]),
                            L2=(["p", "q"], ["p", "q"], [], {"p": "high", "q": "medium"}),
                            L3=(["m"], ["m"], [], {"m": "high"}))),
            (12, learning_of(L0=(["a", "b", "c", "d"], ["a", "b", "c", "d"], []), L1=(["x"], ["x"], []),
                             L2=(["p", "q"], ["p", "q"], [], {"p": "high", "q": "high"}),
                             L3=(["m"], ["m"], ["n"], {"m": "high"}))),
            (24, learning_of(L0=(["a", "b", "c", "d"], ["a", "b", "c", "d"], []), L1=(["x"], ["x"], []),
                             L2=(["p", "q"], ["p", "q"], [], {"p": "high", "q": "high"}),
                             L3=(["m"], ["m"], [], {"m": "high"}))),
        ]
        result = full.convergence(points)
        self.assertEqual(result["first_top"], {"L0": 6, "L1": 12, "L2": 12, "L3": 3})
        self.assertEqual([row["users"] for row in result["points"]], [3, 6, 12, 24])
        first_point = result["points"][0]["layers"]["L0"]
        self.assertEqual((first_point["right"], first_point["learnable"], first_point["at_top"]), (2, 4, False))
        self.assertEqual(result["points"][2]["layers"]["L2"]["high"], 2)
        self.assertEqual(result["points"][1]["layers"]["L1"]["wrong"], 1)

    def test_a_layer_never_at_its_top_is_reported_as_none(self):
        result = full.convergence([(3, learning_of(L0=(["a"], [], []))), (6, learning_of(L0=(["a"], ["a"], ["z"])))])
        self.assertIsNone(result["first_top"]["L0"])

    def test_the_convergence_needs_a_point(self):
        with self.assertRaises(ValueError):
            full.convergence([])


class PollutionTests(unittest.TestCase):
    def test_false_learns_and_lost_positions_are_counted_per_layer(self):
        clean = learning_of(L0=(["a", "b", "c"], ["a", "b"], []))
        polluted = learning_of(L0=(["a", "b", "c"], ["a"], ["z"]), L2=([], [], ["w"]))
        result = full.pollution(clean, polluted, attackers=21, benign_sessions=192)
        self.assertEqual(result["layers"]["L0"], {"wrong_clean": 0, "wrong_polluted": 1, "lost": ["b"], "weaker": []})
        self.assertEqual(result["false_learns"], 2)
        self.assertEqual(result["lost"], 1)
        self.assertEqual(result["weaker"], 0)
        self.assertAlmostEqual(result["share"], 21 / 213)

    def test_a_position_learned_with_a_lower_reliability_is_lost_and_also_weaker(self):
        clean = learning_of(L2=(["p", "q"], ["p", "q"], [], {"p": "high", "q": "medium"}))
        polluted = learning_of(L2=(["p", "q"], ["p", "q"], [], {"p": "medium", "q": "medium"}))
        result = full.pollution(clean, polluted, attackers=21, benign_sessions=192)
        self.assertEqual(result["layers"]["L2"], {"wrong_clean": 0, "wrong_polluted": 0, "lost": ["p"], "weaker": ["p"]})
        self.assertEqual((result["lost"], result["weaker"]), (1, 1))

    def test_attack_requests_are_counted_by_category_and_by_what_the_observation_run_did(self):
        requests = [("pollution_walk", "would_block"), ("pollution_walk", "would_block"),
                    ("pollution_delete", "allowed"), ("pollution_read", "allowed"), ("pollution_read", "unjudged")]
        result = full.pollution(learning_of(), learning_of(), attackers=1, benign_sessions=9,
                                attack_requests=requests)
        self.assertEqual(result["attack_requests"], {
            "pollution_walk": {"requests": 2, "would_block": 2, "allowed": 0, "other": 0},
            "pollution_delete": {"requests": 1, "would_block": 0, "allowed": 1, "other": 0},
            "pollution_read": {"requests": 2, "would_block": 0, "allowed": 1, "other": 1},
        })


class AttackRequestTests(unittest.TestCase):
    def test_only_the_requests_of_the_attack_sessions_are_counted_with_their_outcomes(self):
        rows = [
            {"group": "attack", "session": "attacker/0", "category": "pollution_walk", "request_id": "r1"},
            {"group": "attack", "session": "doctor_3/0", "category": "function_level", "request_id": "r2"},
            {"group": "train", "session": "attacker/0", "category": "train_home", "request_id": "r3"},
            {"group": "attack", "session": "attacker/1", "category": "pollution_read", "request_id": "r4"},
            {"group": "attack", "session": "attacker/1", "category": "pollution_delete", "request_id": "r5"},
        ]
        self.assertEqual(full.attack_requests(rows, {"r1": "would_block", "r4": "allowed"}),
                         [("pollution_walk", "would_block"), ("pollution_read", "allowed"),
                          ("pollution_delete", "unjudged")])


class NaturalOrderTests(unittest.TestCase):
    def test_the_last_round_that_judged_the_key_gives_the_agreement(self):
        learned = {"rounds": [
            {"judgements": [{"key": full.NATURAL_ORDER_KEY, "agreement_per_mille": 1000}]},
            {"judgements": [{"key": full.NATURAL_ORDER_KEY, "reliability": "high"}, {"key": "other", "agreement_per_mille": 5}]},
            {"judgements": [{"key": full.NATURAL_ORDER_KEY, "agreement_per_mille": 979}]},
        ]}
        self.assertEqual(full.public_agreement(learned), 979)

    def test_a_key_no_round_judged_has_no_agreement(self):
        self.assertIsNone(full.public_agreement({"rounds": [{"judgements": []}]}))
        self.assertIsNone(full.public_agreement(None))

    def test_the_two_orders_are_compared_beside_the_threshold_with_the_tier_each_one_learned(self):
        ordered = learned_with(full.NATURAL_ORDER_KEY, 1000)
        natural = learned_with(full.NATURAL_ORDER_KEY, 979)
        ordered_metrics = {"conclusions": {full.NATURAL_ORDER_KEY: {"tier": "public", "tier_reliability": "high"}}}
        natural_metrics = {"conclusions": {full.NATURAL_ORDER_KEY: {"tier": "public", "tier_reliability": "medium"}}}
        self.assertEqual(full.natural_order(ordered, natural, ordered_metrics=ordered_metrics,
                                            natural_metrics=natural_metrics), {
            "key": full.NATURAL_ORDER_KEY, "threshold": 980,
            "ordered": {"agreement": 1000, "tier": "public", "reliability": "high"},
            "natural": {"agreement": 979, "tier": "public", "reliability": "medium"},
        })
        self.assertIsNone(full.natural_order(ordered, natural)["natural"]["tier"])


class GateTests(unittest.TestCase):
    def test_the_natural_order_gate_passes_only_when_the_natural_search_result_learns_public_at_high(self):
        def natural(tier: str | None, reliability: str | None) -> dict:
            return {"natural": {"agreement": 971, "tier": tier, "reliability": reliability}}

        self.assertTrue(full.natural_order_gate(natural("public", "high"))["ok"])
        self.assertFalse(full.natural_order_gate(natural("public", "medium"))["ok"])
        self.assertFalse(full.natural_order_gate(natural("own", "high"))["ok"])
        self.assertFalse(full.natural_order_gate(natural(None, None))["ok"])
        self.assertFalse(full.natural_order_gate(None)["ok"])
        self.assertEqual(full.natural_order_gate(natural("public", "high"))["value"], "public，high")

    def test_the_polluted_search_then_delete_position_must_not_learn_to_accept_public_sources(self):
        self.assertTrue(full.polluted_delete_gate({"delete_accepts_public": None})["ok"])
        self.assertTrue(full.polluted_delete_gate({"delete_accepts_public": False})["ok"])
        self.assertFalse(full.polluted_delete_gate({"delete_accepts_public": True})["ok"])
        self.assertFalse(full.polluted_delete_gate(None)["ok"])
        self.assertEqual(full.polluted_delete_gate({"delete_accepts_public": None})["value"], "没有结论")

    def test_the_pollution_reads_the_delete_conclusion_of_the_polluted_run(self):
        polluted = learning_of()
        polluted["conclusions"] = {full.POLLUTED_DELETE_KEY: {"accepts_public": True}}
        result = full.pollution(learning_of(), polluted, attackers=21, benign_sessions=192)
        self.assertIs(result["delete_accepts_public"], True)
        without = full.pollution(learning_of(), learning_of(), attackers=1, benign_sessions=9)
        self.assertIsNone(without["delete_accepts_public"])


def _result(**overrides) -> dict:
    """The parts of a report that comparable() reads, with timings and request IDs that a second run would change."""
    result = {
        "metrics": {"S1": {"value": 1.0, "num": 1, "den": 1}},
        "gates": [{"name": "S2", "value": 0, "limit": "== 0", "ok": True}],
        "counts": {"train": 3},
        "failures": [{"case": "p0-1-pad-200", "config": "truth", "got": "allow", "request_id": "r1", "seconds": 0.1}],
        "known_gaps": [{"case": "p1-1-rotation", "unexpected_pass": False, "request_id": "r2"}],
        "learning": [{"key": "L0", "ok": True, "why": "", "seconds": 1.0}],
        "convergence": None, "pollution": None, "natural_order": None,
    }
    result.update(overrides)
    return result


class TwoPassTests(unittest.TestCase):
    def test_timings_and_request_ids_do_not_count_as_a_difference(self):
        second = _result(failures=[{"case": "p0-1-pad-200", "config": "truth", "got": "allow", "request_id": "r9",
                                    "seconds": 7.0}])
        self.assertEqual(full.differences(full.comparable(_result()), full.comparable(second)), [])

    def test_a_changed_metric_or_natural_order_value_is_named(self):
        second = _result(metrics={"S1": {"value": 0.5, "num": 1, "den": 2}},
                         natural_order={"key": "k", "threshold": 980, "ordered": 1000, "natural": 979})
        self.assertEqual(full.differences(full.comparable(_result()), full.comparable(second)),
                         ["metrics", "natural_order"])

    def test_the_gate_fails_when_any_part_differs(self):
        self.assertEqual(full.two_pass_gate([]), {"name": full.TWO_PASS_GATE, "value": 0, "limit": "== 0", "ok": True})
        self.assertFalse(full.two_pass_gate(["metrics"])["ok"])
        self.assertEqual(full.two_pass_gate(["metrics", "gates"])["value"], 2)


def _enforced(case: str, outcome: str) -> tuple[dict, dict]:
    """An enforcement-mode row and its decision: blocked, or allowed."""
    request_id = f"e-{case}"
    blocked = outcome == "blocked"
    row = observation(case, request_id=request_id, config="truth", group="regression", category="regression",
                      expect="block" if blocked else "allow")
    return row, decision(request_id, path="jev_deny" if blocked else "jev_allow", outcome=outcome)


def _observed(case: str, counterpart: str, outcome: str) -> tuple[dict, dict]:
    """An observation-mode row of the consistency batch, named after the enforcement site it is compared with."""
    request_id = f"o-{case}-{counterpart}"
    row = observation(case, request_id=request_id, config="truth-observe", group=CONSISTENCY_GROUP,
                      category=CONSISTENCY_GROUP, expect="block")
    row.update(mode="observe", counterpart=counterpart)
    return row, decision(request_id, path="jev_deny" if outcome == "would_block" else "jev_allow", outcome=outcome)


def _enforcement_half(case: str, outcome: str) -> tuple[dict, dict]:
    """A row of the enforcement half of the consistency batch (its site is clinic-p6-enforce), and its decision."""
    request_id = f"p-{case}"
    row = observation(case, request_id=request_id, config="p6-enforce", group=CONSISTENCY_ENFORCE_GROUP,
                      category=CONSISTENCY_ENFORCE_GROUP, expect="block")
    return row, decision(request_id, path="jev_deny" if outcome == "blocked" else "jev_allow", outcome=outcome)


def _consistency_sample() -> tuple[list[dict], list[dict]]:
    pairs = [
        _enforcement_half("c1", "blocked"), _enforcement_half("c2", "allowed"),
        _enforcement_half("c3", "blocked"), _enforcement_half("c4", "allowed"),
        _observed("c1", "clinic-p6-enforce", "would_block"),  # agree
        _observed("c2", "clinic-p6-enforce", "would_block"),  # differ
        _observed("c3", "clinic-p6-enforce", "allowed"),      # differ
        _observed("c4", "clinic-p6-enforce", "allowed"),      # agree
        _observed("c5", "clinic-none", "would_block"),        # no enforcement row to compare with: not compared
    ]
    return [row for row, _ in pairs], [record for _, record in pairs]


class ConsistencyTests(unittest.TestCase):
    def test_p6_counts_the_requests_on_which_the_two_modes_disagree(self):
        observations, decisions = _consistency_sample()
        result = score(observations, decisions)
        self.assertEqual(result["metrics"]["P6"], {"value": 2, "num": 2, "den": 4})
        self.assertEqual(result["counts"]["consistency"], 5)

    def test_the_p6_gate_passes_only_with_no_difference_and_at_least_one_request_compared(self):
        self.assertTrue(full.consistency_gate({"value": None, "num": 0, "den": 4})["ok"])
        self.assertFalse(full.consistency_gate({"value": 2, "num": 2, "den": 4})["ok"])
        self.assertFalse(full.consistency_gate({"value": None, "num": 0, "den": 0})["ok"])
        self.assertFalse(full.consistency_gate(None)["ok"])
        self.assertEqual(full.consistency_gate({"value": 0, "num": 0, "den": 4})["value"], 0)

    def test_p6_is_empty_when_nothing_is_compared(self):
        row, record = _enforced("c1", "blocked")
        self.assertEqual(score([row], [record])["metrics"]["P6"], {"value": None, "num": 0, "den": 0})


def _probers(*sites: str) -> dict[str, mock.Mock]:
    """Probers that send nothing: wants() is False, so run_all only records which cases it begins."""
    probers: dict[str, mock.Mock] = {}
    for site in sites:
        prober = mock.Mock()
        prober.wants.return_value = False
        probers[site] = prober
    return probers


def _begun(probers: dict[str, mock.Mock]) -> list[str]:
    return [call.args[0].case for prober in probers.values() for call in prober.begin.call_args_list]


def _session_prober(listing: dict, *, edge_port: int = 9999) -> mock.MagicMock:
    prober = mock.MagicMock()
    prober.notes = {}
    prober.site.host = "clinic-truth-evict.lab"
    prober.edge.port = edge_port
    prober.login.return_value = "doctor-session"
    prober.request.side_effect = [SimpleNamespace(reply=SimpleNamespace(json=lambda: listing)),
                                  SimpleNamespace(reply=SimpleNamespace(json=lambda: {}))]
    return prober


class EvictionCaseTests(unittest.TestCase):
    def test_the_eviction_case_runs_in_the_full_mode_only(self):
        self.assertEqual(regressions.full_only_names(), ("b11-session-eviction",))
        quick = _probers(SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE)
        regressions.run_all(quick, full=False)
        self.assertIn("p0-1-pad-200", _begun(quick))
        self.assertNotIn("b11-session-eviction", _begun(quick))
        everything = _probers(SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE, SITE_EVICT)
        regressions.run_all(everything, full=True)
        self.assertIn("b11-session-eviction", _begun(everything))

    def test_the_full_mode_needs_the_eviction_site(self):
        with self.assertRaises(probes.ProbeError):
            regressions.run_all(_probers(SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE), full=True)

    def test_the_flood_is_plain_logins_from_its_own_address_and_is_timed(self):
        prober = _session_prober({"patients": [{"id": 7}]})
        with mock.patch.object(regressions, "FLOOD_LOGINS", 3), \
                mock.patch.object(regressions, "_source_of", side_effect=lambda index: f"127.0.2.{index}"), \
                mock.patch.object(regressions.labkit, "request", return_value=SimpleNamespace(status=302)) as flood:
            regressions.session_eviction(prober)
        self.assertEqual(prober.login.call_args.kwargs["source"], "127.0.2.3")
        self.assertEqual(len(flood.call_args_list), 3)
        for call in flood.call_args_list:
            self.assertEqual(call.kwargs["source"], "127.0.2.4")
            self.assertEqual(call.args[2:4], ("POST", "/login"))
        self.assertEqual(prober.notes["b11-session-eviction"]["logins"], 3)
        self.assertIn("seconds", prober.notes["b11-session-eviction"])
        self.assertEqual(prober.request.call_args.args[2], "/api/patients/7")
        self.assertTrue(prober.request.call_args.kwargs["scored"])

    def test_a_refused_flood_login_stops_the_case_before_the_scored_open(self):
        prober = _session_prober({"patients": [{"id": 7}]})
        replies = [SimpleNamespace(status=302), SimpleNamespace(status=500)]
        with mock.patch.object(regressions, "FLOOD_LOGINS", 3), \
                mock.patch.object(regressions, "_source_of", side_effect=lambda index: f"127.0.2.{index}"), \
                mock.patch.object(regressions.labkit, "request", side_effect=replies):
            with self.assertRaises(probes.ProbeError):
                regressions.session_eviction(prober)
        self.assertEqual(prober.request.call_count, 1)  # the listing only


class TrafficArgumentTests(unittest.TestCase):
    def test_the_attack_sessions_stay_within_the_loopback_addresses(self):
        origin = SimpleNamespace(seed=1, doctor_count=12, doctors={})  # validation stops before any traffic
        with self.assertRaises(ValueError):
            run_training(None, origin, 1, 1, 1, attackers=ATTACKERS_MAX + 1)
        with self.assertRaises(ValueError):
            run_training(None, origin, 1, 1, 1, attackers=-1)


class FullReportTests(unittest.TestCase):
    def test_the_full_sections_are_rendered_and_documented(self):
        observations, decisions = _consistency_sample()
        result = score(observations, decisions)
        result["convergence"] = full.convergence([(3, learning_of(L0=(["a"], [], []))),
                                                  (48, learning_of(L0=(["a"], ["a"], [])))])
        result["pollution"] = full.pollution(learning_of(L0=(["a", "b"], ["a", "b"], [])),
                                             learning_of(L0=(["a", "b"], ["a"], ["z"])),
                                             attackers=21, benign_sessions=192,
                                             attack_requests=[("pollution_walk", "would_block"),
                                                              ("pollution_read", "allowed")])
        result["natural_order"] = full.natural_order(learned_with(full.NATURAL_ORDER_KEY, 1000),
                                                     learned_with(full.NATURAL_ORDER_KEY, 979))
        meta = {**META, "timings": {"b11-session-eviction": {"logins": 20200, "seconds": 61.5}},
                "two_pass": {"differing": [], "seconds": [200.0, 201.0]}}
        text = render_markdown(result, meta)
        for fragment in ("### 收敛成本（L4）", "首次到顶", "### 抗污染（L5）", "发现：混入攻击后误学 1 个位置",
                         "攻击会话的请求：每个都本应拦截", "搜索后打开", "### 删除穿插在搜索之间（自然顺序，门槛）",
                         "门槛未通过：自然顺序下公共搜索结果没有学到档位",
                         "两遍核对：两遍的记分、门槛、失败项和学习明细逐位相同",
                         "比较的请求有 4 个", "b11-session-eviction）：20200 次登录，用时 61.5 秒"):
            self.assertIn(fragment, text)
        document = report_document(result, meta)
        for key in ("convergence", "pollution", "natural_order"):
            self.assertIn(key, document)
        json.dumps(document, ensure_ascii=False)  # the machine-readable report is JSON


CLEAN_SITE = "clinic-learned"  # the clean run's site, which the consequence rows are compared with


def _consequence_run(clean: list[tuple[str, str, str]],
                     polluted: dict[str, list[tuple[str, str, str]]]) -> tuple[list[dict], list[dict]]:
    """Rows and decisions from (case, expect, outcome) triples: the clean run's rows, and each polluted site's rows, which
    carry the consequence marks. A site's sessions are its own, so no record reads another site's traffic."""
    observations: list[dict] = []
    decisions: list[dict] = []
    for site, probes_ in [(CLEAN_SITE, clean), *polluted.items()]:
        consequence = site != CLEAN_SITE
        for number, (case, expect, outcome) in enumerate(probes_):
            request_id = f"{site}/{case}/{number}"
            row = observation(case, request_id=request_id, group="attack" if expect == "block" else "benign",
                              category="idor_direct", expect=expect)
            row["site"] = site
            if consequence:
                row.update({CONSEQUENCE_FIELD: "consequence", "counterpart": CLEAN_SITE})
            observations.append(row)
            decisions.append(decision(request_id, path="jev_deny" if expect == "block" else "jev_allow",
                                      outcome=outcome, session=site))
    return observations, decisions


def _site_measure(site: str = POLLUTED_SITE, **fields: object) -> dict:
    """One polluted site's comparison, with every count the report reads."""
    item: dict = {"counterpart": CLEAN_SITE, "probes": 4, "compared": 4, "missed": 0, "over": 0, "incomparable": 0,
                  "missed_cases": [], "over_cases": []}
    item.update(fields)
    return item


class ConsequenceTests(unittest.TestCase):
    def test_an_attack_the_clean_run_blocked_and_the_site_lets_through_is_missed(self):
        observations, decisions = _consequence_run(
            clean=[("a1", "block", "blocked"), ("a2", "block", "blocked")],
            polluted={POLLUTED_SITE: [("a1", "block", "blocked"), ("a2", "block", "allowed")]})
        item = score(observations, decisions)["metrics"]["L5"][POLLUTED_SITE]
        self.assertEqual((item["compared"], item["missed"], item["over"], item["incomparable"]), (2, 1, 0, 0))
        self.assertEqual(item["missed_cases"], [{"case": "a2", "run": 1, "category": "idor_direct"}])
        self.assertEqual(item["counterpart"], CLEAN_SITE)

    def test_a_benign_request_the_clean_run_let_through_and_the_site_blocks_is_over_blocked(self):
        observations, decisions = _consequence_run(
            clean=[("b1", "allow", "allowed"), ("b2", "allow", "allowed")],
            polluted={POLLUTED_SET_SITE: [("b1", "allow", "allowed"), ("b2", "allow", "blocked")]})
        item = score(observations, decisions)["metrics"]["L5"][POLLUTED_SET_SITE]
        self.assertEqual((item["compared"], item["missed"], item["over"], item["incomparable"]), (2, 0, 1, 0))
        self.assertEqual([case["case"] for case in item["over_cases"]], ["b2"])

    def test_a_probe_the_two_sides_do_not_agree_on_is_incomparable(self):
        observations, decisions = _consequence_run(
            clean=[("a1", "block", "blocked"), ("a2", "block", "blocked"), ("a3", "block", "blocked")],
            polluted={POLLUTED_SITE: [("a1", "block", "unjudged"), ("a3", "block", "blocked")]})  # a2 is not run at all
        item = score(observations, decisions)["metrics"]["L5"][POLLUTED_SITE]
        self.assertEqual((item["compared"], item["missed"], item["over"], item["incomparable"]), (1, 0, 0, 2))

    def test_a_case_repeated_within_a_run_lines_up_in_the_order_it_was_run(self):
        # A journey repeats a case within one run (the same step for the same user): the k-th row meets the k-th row.
        observations, decisions = _consequence_run(
            clean=[("j1", "allow", "allowed"), ("j1", "allow", "allowed")],
            polluted={POLLUTED_SITE: [("j1", "allow", "allowed"), ("j1", "allow", "blocked")]})
        item = score(observations, decisions)["metrics"]["L5"][POLLUTED_SITE]
        self.assertEqual((item["compared"], item["missed"], item["over"], item["incomparable"]), (2, 0, 1, 0))
        self.assertEqual([case["case"] for case in item["over_cases"]], ["j1"])

    def test_a_repeated_case_the_other_side_has_fewer_of_is_incomparable(self):
        observations, decisions = _consequence_run(
            clean=[("j1", "allow", "allowed"), ("j1", "allow", "allowed")],
            polluted={POLLUTED_SITE: [("j1", "allow", "allowed")]})
        item = score(observations, decisions)["metrics"]["L5"][POLLUTED_SITE]
        self.assertEqual((item["compared"], item["over"], item["incomparable"]), (1, 0, 1))

    def test_identical_configurations_agree_on_every_probe(self):
        probes_ = [("a1", "block", "blocked"), ("b1", "allow", "allowed")]
        observations, decisions = _consequence_run(clean=probes_, polluted={POLLUTED_SET_SITE: probes_})
        item = score(observations, decisions)["metrics"]["L5"][POLLUTED_SET_SITE]
        self.assertEqual((item["compared"], item["missed"], item["over"], item["incomparable"]), (2, 0, 0, 0))

    def test_the_consequence_rows_count_in_no_other_metric(self):
        clean = [("a1", "block", "blocked"), ("b1", "allow", "allowed")]
        observations, decisions = _consequence_run(
            clean=clean, polluted={POLLUTED_SITE: [("a1", "block", "allowed"), ("b1", "allow", "blocked")]})
        plain, _ = _consequence_run(clean=clean, polluted={})
        with_rows, without_rows = score(observations, decisions), score(plain, decisions)
        self.assertEqual(with_rows["counts"]["scored"], without_rows["counts"]["scored"])
        self.assertEqual({name: value for name, value in with_rows["metrics"].items() if name != "L5"},
                         {name: value for name, value in without_rows["metrics"].items() if name != "L5"})

    def test_no_polluted_site_means_no_consequence(self):
        observations, decisions = _consequence_run(clean=[("a1", "block", "blocked")], polluted={})
        self.assertIsNone(score(observations, decisions)["metrics"]["L5"])


class ConsequenceBaselineTests(unittest.TestCase):
    def test_only_the_missed_attacks_of_the_polluted_site_enter_the_baseline(self):
        metrics = {"L5": {POLLUTED_SITE: _site_measure(missed=2), POLLUTED_SET_SITE: _site_measure(POLLUTED_SET_SITE, missed=0)}}
        self.assertEqual(baseline_values(metrics), {"L5/clinic-polluted/missed": 2})
        self.assertEqual(baseline_values({"L5": None}), {})

    def test_the_polluted_site_misses_may_only_go_down(self):
        baseline = {"values": {"L5/clinic-polluted/missed": 2}}
        worse = compare_baseline({"L5/clinic-polluted/missed": 3}, baseline)
        better = compare_baseline({"L5/clinic-polluted/missed": 1}, baseline)
        self.assertEqual([item["name"] for item in worse["regressions"]], ["L5/clinic-polluted/missed"])
        self.assertEqual([item["name"] for item in better["improvements"]], ["L5/clinic-polluted/missed"])


class ConsequenceGateTests(unittest.TestCase):
    def _measure(self, *, polluted_missed: int = 2, set_missed: int = 0, over: int = 0, incomparable: int = 0,
                 compared: int = 4) -> dict:
        return {
            POLLUTED_SITE: _site_measure(missed=polluted_missed, over=over, incomparable=incomparable, compared=compared),
            POLLUTED_SET_SITE: _site_measure(POLLUTED_SET_SITE, missed=set_missed, over=over, incomparable=incomparable,
                                        compared=compared),
        }

    def test_the_polluted_misses_are_reported_and_the_gates_pass(self):
        self.assertEqual([gate["ok"] for gate in full.consequence_gates(self._measure(polluted_missed=2))],
                         [True, True, True])

    def test_a_missed_attack_of_the_set_site_fails_only_the_set_gate(self):
        self.assertEqual([gate["ok"] for gate in full.consequence_gates(self._measure(set_missed=1))],
                         [True, False, True])

    def test_an_over_blocked_benign_request_of_either_site_fails_the_benign_gate(self):
        self.assertEqual([gate["ok"] for gate in full.consequence_gates(self._measure(over=1))], [False, True, True])

    def test_a_probe_the_two_sides_do_not_agree_on_fails_the_match_gate(self):
        self.assertEqual([gate["ok"] for gate in full.consequence_gates(self._measure(incomparable=1))],
                         [True, True, False])

    def test_a_site_with_nothing_compared_fails_the_set_and_match_gates(self):
        self.assertEqual([gate["ok"] for gate in full.consequence_gates(self._measure(compared=0))],
                         [True, False, False])

    def test_a_missing_measure_fails_every_gate(self):
        self.assertEqual([gate["ok"] for gate in full.consequence_gates(None)], [False, False, False])


class SetPositionTests(unittest.TestCase):
    SPEC = {"objects": {"classes": [{"id": "patient", "name": "患者"}], "slots": [
        {"key": "DELETE /api/patients/{id} path[2]", "class": "patient", "source": "rule",
         "accepts_public": True, "reliability": "medium"},
        {"key": "GET /api/search results[].id", "class": "patient", "source": "rule", "tier": "public",
         "reliability": "high"},
    ]}}

    def test_each_listed_position_refuses_public_sources_at_high_reliability(self):
        before = copy.deepcopy(self.SPEC)
        result = full.set_public_positions(self.SPEC, [{"key": "DELETE /api/patients/{id} path[2]"}])
        slots = {slot["key"]: slot for slot in result["objects"]["slots"]}
        self.assertEqual((slots["DELETE /api/patients/{id} path[2]"]["accepts_public"],
                          slots["DELETE /api/patients/{id} path[2]"]["reliability"]), (False, "high"))
        self.assertEqual(slots["GET /api/search results[].id"], before["objects"]["slots"][1])
        self.assertEqual(self.SPEC, before, "the configuration given is not changed")

    def test_an_empty_list_leaves_the_configuration_as_it_is(self):
        self.assertEqual(full.set_public_positions(self.SPEC, []), self.SPEC)

    def test_a_listed_position_the_configuration_does_not_declare_is_an_error(self):
        with self.assertRaises(ValueError):
            full.set_public_positions(self.SPEC, [{"key": "GET /api/nowhere path[1]"}])


class PollutionSharesTests(unittest.TestCase):
    def test_the_positions_the_polluted_run_left_open_are_kept_with_their_shares(self):
        shares = [{"key": "DELETE /api/patients/{id} path[2]", "public_per_mille": 106, "pending_per_mille": 40,
                   "votes": 198, "sessions": 40}]
        result = full.pollution(learning_of_clean(), learning_of_clean(), attackers=21, benign_sessions=192,
                                set_shares=shares)
        self.assertEqual(result["set_shares"], shares)
        self.assertEqual(full.pollution(learning_of_clean(), learning_of_clean(), attackers=0,
                                        benign_sessions=0)["set_shares"], [])


def learning_of_clean() -> dict:
    return learning_of(L0=(["a"], ["a"], []))


class ConsequenceReportTests(unittest.TestCase):
    def test_the_table_names_both_sites_and_lists_the_missed_cases_and_the_set_positions(self):
        missed = [{"case": "idor_public_source/delete", "run": 1, "category": "idor_public_source"}]
        pollution = {
            "consequence": {POLLUTED_SITE: _site_measure(missed=1, missed_cases=missed),
                            POLLUTED_SET_SITE: _site_measure(POLLUTED_SET_SITE)},
            "set_shares": [{"key": "DELETE /api/patients/{id} path[2]", "public_per_mille": 106, "pending_per_mille": 40,
                            "votes": 198, "sessions": 40}],
        }
        text = "\n".join(_consequence_lines(pollution))
        for fragment in ("### 防护后果", "| 原样使用（clinic-polluted） | 4 | 1 | 0 |",
                         "| 照一栏设定之后（clinic-polluted-set） | 4 | 0 | 0 |",
                         "`idor_public_source/delete`（idor_public_source，第 1 遍）",
                         "`DELETE /api/patients/{id} path[2]`", "106‰", "40‰", "198"):
            self.assertIn(fragment, text)

    def test_without_a_consequence_nothing_is_rendered(self):
        self.assertEqual(_consequence_lines({"consequence": None}), [])
        self.assertEqual(_consequence_lines({}), [])


if __name__ == "__main__":
    unittest.main()

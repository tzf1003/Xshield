"""Tests of the full mode (plan 5.2 and 10, batch 7) that need no gateway, PostgreSQL or network: the arithmetic of L4
and L5, the natural-order variant, the two-pass comparison, P6 through the scorer, the wiring of the session-table
case, and the full-mode sections of the report. The full run itself is the acceptance check."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from clinic_traffic import ATTACKERS_MAX, run_training
from effectiveness import full, probes, regressions
from effectiveness.builders import decision, observation
from effectiveness.report import render_markdown, report_document
from effectiveness.score import CONSISTENCY_GROUP, score

ROOT = Path(__file__).resolve().parents[3]
CONTEXT_RS = ROOT / "crates" / "xshield-judge" / "src" / "context.rs"
LAYERS = ("L0", "L1", "L2", "L3")
META = {"commit": "abc1234", "mode": "full", "jev": "理想模型", "seed": 1, "started": "2026-11-13T00:00:00+00:00",
        "seconds": 0.5, "unsent": {}, "jev_relay": None, "timings": {}, "two_pass": None}
SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE, SITE_EVICT = "clinic-truth", "clinic-truth-limit", "clinic-truth-observe", \
    "clinic-truth-evict"


def learning_of(**layers: tuple[list[str], list[str], list[str]]) -> dict:
    """What score.learning_metrics returns, from each layer's (learnable, right, wrong) keys."""
    keys: dict = {}
    metrics: dict = {}
    for layer in LAYERS:
        learnable, right, wrong = layers.get(layer, ([], [], []))
        keys[layer] = {"learnable": list(learnable), "right": list(right), "wrong": list(wrong)}
        accuracy = len(set(right) & set(learnable)) / len(learnable) if learnable else None
        metrics[layer] = {"accuracy": {"value": accuracy}}
    return {"metrics": metrics, "keys": keys}


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
    def test_a_layer_is_fully_correct_with_no_wrong_proposal_and_every_learnable_position_right(self):
        self.assertTrue(full.fully_correct({"learnable": ["a"], "right": ["a"], "wrong": []}))
        self.assertFalse(full.fully_correct({"learnable": ["a"], "right": ["a"], "wrong": ["z"]}))
        self.assertFalse(full.fully_correct({"learnable": ["a", "b"], "right": ["a"], "wrong": []}))

    def test_each_layer_names_the_first_user_count_at_which_it_is_fully_correct(self):
        points = [
            (3, learning_of(L0=(["a", "b", "c", "d"], ["a", "b"], []), L1=(["x"], [], []),
                            L2=([], [], ["q"]), L3=(["m"], ["m"], []))),
            (6, learning_of(L0=(["a", "b", "c", "d"], ["a", "b", "c", "d"], []), L1=(["x"], ["x"], ["z"]),
                            L2=([], [], []), L3=(["m"], ["m"], []))),
            (12, learning_of(L0=(["a", "b", "c", "d"], ["a", "b", "c", "d"], []), L1=(["x"], ["x"], []),
                             L2=([], [], []), L3=(["m"], ["m"], ["n"]))),
            (24, learning_of(L0=(["a", "b", "c", "d"], ["a", "b", "c", "d"], []), L1=(["x"], ["x"], []),
                             L2=([], [], []), L3=(["m"], ["m"], []))),
        ]
        result = full.convergence(points)
        self.assertEqual(result["first_fully_correct"], {"L0": 6, "L1": 12, "L2": 6, "L3": 3})
        self.assertEqual([row["users"] for row in result["points"]], [3, 6, 12, 24])
        self.assertEqual(result["points"][0]["layers"]["L0"]["right"], 2)
        self.assertFalse(result["points"][0]["layers"]["L0"]["fully_correct"])
        self.assertEqual(result["points"][1]["layers"]["L1"]["wrong"], 1)

    def test_a_layer_never_fully_correct_is_reported_as_none(self):
        result = full.convergence([(3, learning_of(L0=(["a"], [], [])))])
        self.assertIsNone(result["first_fully_correct"]["L0"])


class PollutionTests(unittest.TestCase):
    def test_false_learns_and_lost_positions_are_counted_per_layer(self):
        clean = learning_of(L0=(["a", "b", "c"], ["a", "b"], []))
        polluted = learning_of(L0=(["a", "b", "c"], ["a"], ["z"]), L2=([], [], ["w"]))
        result = full.pollution(clean, polluted, attackers=21, benign_sessions=192)
        self.assertEqual(result["layers"]["L0"], {"wrong_clean": 0, "wrong_polluted": 1, "lost": ["b"]})
        self.assertEqual(result["false_learns"], 2)
        self.assertEqual(result["lost"], 1)
        self.assertAlmostEqual(result["share"], 21 / 213)


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

    def test_the_two_orders_are_compared_beside_the_threshold(self):
        ordered = learned_with(full.NATURAL_ORDER_KEY, 1000)
        natural = learned_with(full.NATURAL_ORDER_KEY, 979)
        self.assertEqual(full.natural_order(ordered, natural),
                         {"key": full.NATURAL_ORDER_KEY, "threshold": 980, "ordered": 1000, "natural": 979})


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


def _consistency_sample() -> tuple[list[dict], list[dict]]:
    pairs = [
        _enforced("c1", "blocked"), _enforced("c2", "allowed"), _enforced("c3", "blocked"), _enforced("c4", "allowed"),
        _observed("c1", "clinic-truth", "would_block"),  # agree
        _observed("c2", "clinic-truth", "would_block"),  # differ
        _observed("c3", "clinic-truth", "allowed"),      # differ
        _observed("c4", "clinic-truth", "allowed"),      # agree
        _observed("c5", "clinic-none", "would_block"),   # no enforcement row to compare with: not compared
    ]
    return [row for row, _ in pairs], [record for _, record in pairs]


class ConsistencyTests(unittest.TestCase):
    def test_p6_counts_the_requests_on_which_the_two_modes_disagree(self):
        observations, decisions = _consistency_sample()
        result = score(observations, decisions)
        self.assertEqual(result["metrics"]["P6"], {"value": 2, "num": 2, "den": 4})
        self.assertEqual(result["counts"]["consistency"], 5)

    def test_p6_is_report_only(self):
        observations, decisions = _consistency_sample()
        result = score(observations, decisions)
        self.assertFalse(any("P6" in gate["name"] for gate in result["gates"]))

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
                                             attackers=21, benign_sessions=192)
        result["natural_order"] = full.natural_order(learned_with(full.NATURAL_ORDER_KEY, 1000),
                                                     learned_with(full.NATURAL_ORDER_KEY, 979))
        meta = {**META, "timings": {"b11-session-eviction": {"logins": 20200, "seconds": 61.5}},
                "two_pass": {"differing": [], "seconds": [200.0, 201.0]}}
        text = render_markdown(result, meta)
        for fragment in ("### 收敛成本（L4）", "### 抗污染（L5）", "发现：混入攻击后误学 1 个位置",
                         "### 删除穿插在搜索之间（自然顺序，只报告）", "两遍核对：两遍的记分、门槛、失败项和学习明细逐位相同",
                         "同一批 4 个请求", "b11-session-eviction）：20200 次登录，用时 61.5 秒"):
            self.assertIn(fragment, text)
        document = report_document(result, meta)
        for key in ("convergence", "pollution", "natural_order"):
            self.assertIn(key, document)
        json.dumps(document, ensure_ascii=False)  # the machine-readable report is JSON


if __name__ == "__main__":
    unittest.main()

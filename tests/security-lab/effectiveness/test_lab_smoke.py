"""Smoke tests of the gateway segment of the protection-effectiveness lab (plan 10, batch 4).

Most tests run without the gateway binary: the regression table, the probe selection, the path point, the
cross-class probe and the start of the edge are checked with the labkit and origin objects replaced. The last
class runs a small lab for real; it is skipped when xshield-edge is not built (cargo build -p xshield-edge).
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import labkit
from clinic_origin import DEFAULT_SEED, QUICK_DOCTORS, ClinicOrigin
from clinic_traffic import Evidence, run_training
from effectiveness import contracts, lab, probes, regressions
from effectiveness.score import score

# The review findings of plan 4.5 (P2-6 is not here: its list cannot be built on this origin, see regressions.py).
EXPECTED_CASES = (
    "p0-1-pad-200", "p0-1-multipart", "p0-1-text-plain", "p0-1-long-value", "p0-1-big-upload", "p0-1-big-json",
    "p0-2-limit-then-inject",
    "p0-3-fake-cookie-metrics", "p0-3-fake-cookie-export", "p0-3-function-level", "p0-3-function-level-metrics",
    "p0-3-function-route-word",
    "p1-1-rotation", "p1-2-search-id-then-open", "p1-3-preflight", "p1-4-conditional-304",
    "p1-5-observe-learns-would-block", "p1-9-big-form", "p1-9-big-form-on-object",
    "p2-1-mass-assignment", "p2-3-header-injection", "p2-5-prompt-injection",
    "p3-method-override",
)


def make_prober(origin: Any = None, only: frozenset[str] = frozenset(), jev: Any = None) -> probes.Prober:
    """A prober without an edge: the tests below never send a request through one. No `jev` is the live run."""
    site = probes.Site(name="clinic-truth", config="truth", mode="enforce", origin=origin)
    return probes.Prober(None, site, probes.Pool(), jev=jev, only=only)


def make_origin(test: unittest.TestCase, doctors: int = QUICK_DOCTORS) -> ClinicOrigin:
    """An origin that is bound but never served. Its listening socket is closed when the test ends."""
    origin = ClinicOrigin(seed=DEFAULT_SEED, doctors=doctors)
    test.addCleanup(origin.server.server_close)
    return origin


class RegressionTableTests(unittest.TestCase):
    def test_the_table_has_every_review_case_of_plan_4_5_but_p2_6(self):
        names = regressions.case_names()
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(sorted(names), sorted(EXPECTED_CASES))

    def test_every_case_has_a_valid_status_expectation_site_and_reason(self):
        sites = {lab.SITE_NONE, lab.SITE_TRUTH, lab.SITE_LIMIT, lab.SITE_OBSERVE}
        for case in regressions.CASES:
            with self.subTest(case=case.name):
                self.assertIn(case.status, {"must", "known_gap"})
                self.assertIn(case.expect, {"block", "allow"})
                self.assertIn(case.site, sites)
                if case.expect == "block":
                    self.assertIn(case.reason, contracts.REASONS)
                else:
                    self.assertIsNone(case.reason)

    def test_the_function_level_cases_need_a_function_table_and_expect_access(self):
        by_name = {case.name: case for case in regressions.CASES}
        for name in ("p0-3-function-level", "p0-3-function-level-metrics", "p0-3-function-route-word"):
            with self.subTest(case=name):
                self.assertEqual(by_name[name].requires, ("functions",))
                self.assertEqual((by_name[name].expect, by_name[name].reason), ("block", "access"))


class ProbeSelectionTests(unittest.TestCase):
    META = probes.Score("injection_sqli/search/atk-sqli-01", "attack", "injection_sqli", "block", "attack")

    def test_a_case_outside_only_is_neither_selected_nor_sent(self):
        p = make_prober(only=frozenset({"injection_cmd"}))
        with mock.patch.object(probes.Prober, "request") as request:
            probes.send_at_point(p, "search", "1' OR 1=1--", self.META)
        request.assert_not_called()
        self.assertFalse(p.wants(self.META))

    def test_a_case_named_by_its_category_is_selected(self):
        self.assertTrue(make_prober(only=frozenset({"injection_sqli"})).wants(self.META))


class PathPointTests(unittest.TestCase):
    """A payload that does not fit one path segment is not sent to the path point, for attacks and for benign
    text alike (plan 4.3), and the number that were not sent is counted for the report."""

    def test_an_attack_with_a_separator_skips_the_path_point_and_is_counted(self):
        p = make_prober()
        row = {"id": "atk-ssrf-01", "class": "ssrf", "text": "http://169.254.169.254/", "note": "n"}
        with mock.patch.object(probes, "send_at_point") as send:
            probes.injection(p, row)
        self.assertEqual([call.args[1] for call in send.call_args_list], ["search", "json", "form"])
        self.assertEqual(p.unsent, {"attack": 1, "benign": 0})

    def test_an_attack_without_a_separator_goes_to_all_four_points(self):
        p = make_prober()
        row = {"id": "atk-sqli-01", "class": "sqli", "text": "' OR 1=1--", "note": "n"}
        with mock.patch.object(probes, "send_at_point") as send:
            probes.injection(p, row)
        self.assertEqual([call.args[1] for call in send.call_args_list], list(probes.ATTACK_POINTS))
        self.assertEqual(p.unsent, {"attack": 0, "benign": 0})

    def test_a_benign_text_with_a_backslash_is_not_expected_at_the_path_point(self):
        p = make_prober()
        row = {"id": "b-1", "class": "name", "text": "C:\\Users\\doctor", "note": "n"}
        with mock.patch.object(probes, "send_at_point") as send:
            probes.benign_text(p, row)
        self.assertEqual([call.args[1] for call in send.call_args_list], ["search", "json", "form"])
        self.assertEqual(p.unsent, {"attack": 0, "benign": 1})


class CrossClassProbeTests(unittest.TestCase):
    def sent(self, p: probes.Prober) -> tuple[list[str], list[str], list[tuple[str, ...]]]:
        """The logins, the request paths and the `requires` of each scored request, with the requests faked."""
        began: list[probes.Score] = []
        begin = probes.Prober.begin

        def record(prober: probes.Prober, meta: probes.Score) -> None:
            began.append(meta)
            begin(prober, meta)

        with mock.patch.object(probes.Prober, "request") as request, mock.patch.object(probes.Prober, "begin", record):
            probes.idor_cross_class(p)
        logins = [call.kwargs["form"]["username"] for call in request.call_args_list if "form" in call.kwargs]
        paths = [call.args[2] for call in request.call_args_list]
        return logins, paths, [meta.requires for meta in began]

    def test_the_live_jev_also_gets_the_page_probe_from_the_second_doctor(self):
        origin = make_origin(self)
        # Prescription 1 is one of the first doctor's own: that doctor reading it would be a legitimate read.
        self.assertNotEqual(origin.owner_of("prescription", "1"), probes.DOCTOR_B)
        logins, paths, requires = self.sent(make_prober(origin=origin))  # no ideal model: the live run
        self.assertEqual(logins, [probes.account(probes.DOCTOR_A), probes.account(probes.DOCTOR_B)])
        self.assertEqual(paths[-1], "/api/prescriptions/1")
        self.assertEqual(requires, [("classes",), ()])

    def test_the_ideal_model_gets_no_page_probe(self):
        origin = make_origin(self)
        logins, paths, requires = self.sent(make_prober(origin=origin, jev=object()))  # any Jev: the ideal run
        self.assertEqual(logins, [probes.account(probes.DOCTOR_A)])
        self.assertNotIn("/api/prescriptions/1", paths)
        self.assertEqual(requires, [("classes",)])


class StartEdgeTests(unittest.TestCase):
    def test_a_failed_start_is_retried_once_and_the_note_carries_the_first_error(self):
        started = object()
        ports: list[int] = []

        def edge(sites_file: Any, jev_url: str, port: int, records_file: Any = None, *, jev_key: str) -> object:
            ports.append(port)
            if len(ports) == 1:
                raise RuntimeError("xshield-edge did not start:\nbind: address already in use")
            return started

        err = io.StringIO()
        with mock.patch.object(labkit, "Edge", side_effect=edge), \
                mock.patch.object(labkit, "free_port", side_effect=[1111, 2222]), \
                contextlib.redirect_stderr(err):
            result = labkit.start_edge(Path("sites.json"), "http://127.0.0.1:9", None)
        self.assertIs(result, started)
        self.assertEqual(ports, [1111, 2222])
        self.assertIn("retrying once", err.getvalue())
        self.assertIn("bind: address already in use", err.getvalue())

    def test_two_failed_starts_raise_with_both_attempts(self):
        def edge(*args: Any, **kwargs: Any) -> object:
            raise RuntimeError("xshield-edge did not start:\nboom")

        with mock.patch.object(labkit, "Edge", side_effect=edge), \
                mock.patch.object(labkit, "free_port", side_effect=[1111, 2222]), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError) as caught:
                labkit.start_edge(Path("sites.json"), "http://127.0.0.1:9", None)
        message = str(caught.exception)
        self.assertIn("attempt 1", message)
        self.assertIn("attempt 2", message)
        self.assertEqual(message.count("boom"), 2)


class RefusalEvidenceTests(unittest.TestCase):
    """The administrator's refusals are evidence only when the origin answered them (plan 4.5, the functions item)."""

    def refused_units(self, served: bool) -> set[str]:
        origin = make_origin(self, 2)

        def send(host: str, method: str, target: str, **options: Any) -> labkit.Sent:
            status = 403 if "/api/admin/search" in target else 200
            return labkit.Sent(labkit.Reply(status, None, [], b"{}"), None, served)

        evidence = Evidence()
        run_training(send, origin, DEFAULT_SEED, 2, 1, evidence=evidence)
        return set(evidence.refused_units)

    def test_a_refusal_the_origin_answered_is_evidence(self):
        self.assertEqual(len(self.refused_units(served=True)), 2)

    def test_a_refusal_the_gateway_gave_is_not_evidence(self):
        self.assertEqual(self.refused_units(served=False), set())


# The small run does not start the learning stage (it needs PostgreSQL); the learning stage has its own tests.
SKIPPED_LEARNING = {"status": "skip", "why": "测试里不跑学习段", "learned_path": None, "final_spec": None}


@unittest.skipUnless(labkit.EDGE.exists(), "xshield-edge is not built (cargo build -p xshield-edge)")
class SmallLabRunTests(unittest.TestCase):
    def test_a_small_run_scores_the_gateway_segment_and_says_the_learning_is_skipped(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            # The probes name three doctors (A, B and C, see probes.py), so the small run needs three.
            options = lab.Options(seed=DEFAULT_SEED, users=3, logins=1,
                                  only=frozenset({"injection_sqli", "no_session"}), out=out)
            with mock.patch.object(lab, "_learning", return_value=SKIPPED_LEARNING):
                code = lab.execute(options)
            report = (out / "report.md").read_text(encoding="utf-8")
            document = json.loads((out / "report.json").read_text(encoding="utf-8"))
            observations = contracts.load_observations(out / "observations.jsonl")
            decisions = contracts.load_decisions(out / "decisions.jsonl")
            truth = contracts.load_truth(out / "truth.json")
        self.assertEqual(code, 0)
        self.assertIn("学习段：SKIP（测试里不跑学习段）", report)
        self.assertEqual(document["meta"]["unsent"], {
            "attack": sum(probes.splits_path(row["text"]) for row in probes.quick_attacks()),
            "benign": sum(probes.splits_path(row["text"]) for row in probes.quick_benign()),
        })
        # The administrator search of each ordinary doctor expects a block and sits outside the benign group.
        # One refusal per ordinary doctor of the training, and one per journey user on each object-map site.
        refused = [row for row in observations if row["category"] == "function_level"]
        self.assertEqual(len(refused), options.users + lab.JOURNEY_USERS * len(lab.JOURNEY_SITES))
        self.assertTrue(all(row["group"] == "attack" and row["expect"] == "block" and row["requires"] == ["functions"]
                            for row in refused))
        # Every scored request has its decision record, and the same inputs give the same verdict.
        records = {record["request_id"] for record in decisions}
        self.assertTrue(all(row["request_id"] in records for row in observations))
        self.assertEqual(score(observations, decisions, truth=truth)["passed"], code == 0)


class LearningStageSeamTests(unittest.TestCase):
    """The seam between the lab and the learning stage: a module that cannot be imported is a skip with the reason,
    and the learned site takes the saved configuration under its own name, origin and mode."""

    def test_a_learning_module_that_cannot_be_imported_is_a_skip_with_the_reason(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict("sys.modules", {"effectiveness.learning": None}):
            result = lab._learning({}, {}, Path(folder))
        self.assertEqual(result["status"], "skip")
        self.assertIn("导入失败", result["why"])
        self.assertIsNone(result["final_spec"])

    def test_the_learned_site_keeps_the_saved_configuration_under_its_own_name_origin_and_mode(self):
        saved = {"name": "clinic-none", "hosts": ["clinic-none.lab"], "origin": "http://127.0.0.1:1111",
                 "mode": "observe", "on_jev_unavailable": "deny", "objects": {"classes": [{"id": "patient"}]}}
        spec = lab._learned_spec(saved, mock.Mock(port=2222))
        self.assertEqual((spec["name"], spec["hosts"], spec["origin"], spec["mode"]),
                         ("clinic-learned", ["clinic-learned.lab"], "http://127.0.0.1:2222", "enforce"))
        self.assertEqual(spec["objects"], saved["objects"])
        self.assertEqual(saved["name"], "clinic-none")  # the saved document is copied, not changed

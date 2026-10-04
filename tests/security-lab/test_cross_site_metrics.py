"""Pure scoring checks for independently labeled local shadow observations."""

import importlib.util
import json
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("idor_lab", ROOT / "scripts/test_idor_lab.py")
LAB = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAB)


class CrossSiteMetricsTests(unittest.TestCase):
    def row(self, site, case, truth, expected, edge, model):
        return {"site_id": site, "case": case, "truth_class": truth,
                "expected_choice": expected, "origin_status": 200,
                "edge_status": edge, "edge_request_id": f"{site}-{case}",
                "model_choice": model}

    def test_shadow_errors_are_not_edge_benefit(self):
        reports = [
            {"site_id": "site_a", "observations": [
                self.row("site_a", "own", "benign", "ALLOW", 200, "ALLOW"),
                self.row("site_a", "cross", "malicious", "DENY", 403, "ALLOW")
            ]},
            {"site_id": "site_b", "observations": [
                self.row("site_b", "own", "benign", "ALLOW", 503, "DENY"),
                self.row("site_b", "cross", "malicious", "DENY", 403, "UNKNOWN")
            ]},
        ]
        report = LAB.summarize_observations(reports, True)
        self.assertEqual(report["edge_scores"]["malicious_denied"], 2)
        self.assertEqual(report["edge_scores"]["edge_error"], 1)
        self.assertEqual(report["edge_scores"]["benign_denied"], 0)
        self.assertEqual(report["shadow_scores"]["correct_allow"], 1)
        self.assertEqual(report["shadow_scores"]["false_allow"], 1)
        self.assertEqual(report["shadow_scores"]["false_deny"], 1)
        self.assertEqual(report["shadow_scores"]["abstain"], 1)
        self.assertFalse(report["model_influenced_edge"])

    def test_duplicate_scope_or_request_cannot_count_twice(self):
        row = self.row("site_a", "own", "benign", "ALLOW", 200, None)
        with self.assertRaises(RuntimeError):
            LAB.summarize_observations([
                {"site_id": "site_a", "observations": [row]},
                {"site_id": "site_a", "observations": [row]},
            ], False)

    def test_label_class_must_match_expected_decision(self):
        row = self.row("site_a", "cross", "malicious", "ALLOW", 403, "ALLOW")
        with self.assertRaisesRegex(RuntimeError, "conflicts with fixture truth"):
            LAB.summarize_observations([{"site_id": "site_a", "observations": [row]}], True)

    def test_static_labels_are_two_distinct_site_fixtures(self):
        source = json.loads((ROOT / "tests/security-lab/independent_labels.json").read_text())
        sites = source["sites"]
        self.assertEqual(set(sites), {"orders", "invoices"})
        self.assertNotEqual(sites["orders"]["site_id"], sites["invoices"]["site_id"])
        for site in sites.values():
            self.assertEqual([x["truth_class"] for x in site["labels"]],
                             ["benign", "malicious"])
            self.assertTrue(all("model_choice" not in x for x in site["labels"]))

    def test_label_checksum_drift_stops_evaluation(self):
        labels, digest = LAB.load_independent_labels()
        self.assertEqual(labels["dataset_id"], "xshield_lab_cross_site_r1")
        self.assertEqual(len(digest), 64)
        with mock.patch.dict("os.environ", {"XSHIELD_LAB_LABEL_SHA256": "0" * 64}):
            with self.assertRaisesRegex(RuntimeError, "label file changed"):
                LAB.load_independent_labels()


if __name__ == "__main__":
    unittest.main()

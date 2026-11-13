"""Unit tests for the learning known-gap list (known_gaps.py, plan 8 and 12b): what the list covers, what it leaves
unlisted, and which entries are stale. The repository's own list must load under the contract as well."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from effectiveness import contracts, known_gaps

LIST = Path(__file__).resolve().parents[1] / "effectiveness-known-gaps.json"
KEY = "GET /api/admin/export patients[].id"


def wrong(metric: str, key: str, learned: str) -> dict:
    return {"metric": metric, "key": key, "learned": learned, "side": "response"}


def entry(**fields) -> dict:
    return {"ref": "学习质量设计稿 2.1", "lq": "LQ-2", "note": "", **fields}


class PatternTests(unittest.TestCase):
    def test_a_generated_code_becomes_an_ellipsis_and_the_rest_of_the_key_stays(self):
        self.assertEqual(known_gaps.pattern_of("GET /share/SHR-028C8381 path[1]"), "GET /share/… path[1]")
        self.assertEqual(known_gaps.pattern_of("GET /share/SHR-028C8381 patient.id"), "GET /share/… patient.id")

    def test_a_key_without_a_generated_code_is_its_own_pattern(self):
        for key in ("GET /api/patients/{id} path[2]", "GET /api/search results[].id", "POST /api/token patients[].id"):
            with self.subTest(key=key):
                self.assertEqual(known_gaps.pattern_of(key), key)


class ApplyTests(unittest.TestCase):
    def apply(self, entries, *, wrong_items=(), unmodeled=(), misses=(), failures=(), check=True):
        return known_gaps.apply(entries, wrong=wrong_items, unmodeled=unmodeled, misses=misses,
                                failures=failures, check=check)

    def test_a_listed_wrong_proposal_is_listed_and_an_unlisted_one_is_not(self):
        listed = wrong("L0", KEY, "export")
        unlisted = wrong("L0", "GET /api/visits/{id} id", "patient")
        result = self.apply([entry(id="w1", kind="wrong", metric="L0", key=KEY, learned="export")],
                            wrong_items=[listed, unlisted])
        self.assertEqual(result["listed"]["wrong"], [listed])
        self.assertEqual(result["unlisted"]["wrong"], [unlisted])
        self.assertEqual(result["entries"][0]["matched"], 1)
        self.assertEqual(result["stale"], [])

    def test_the_learned_value_must_match_when_the_entry_names_one(self):
        item = wrong("L0", KEY, "admin")
        result = self.apply([entry(id="w1", kind="wrong", metric="L0", key=KEY, learned="export")], wrong_items=[item])
        self.assertEqual(result["unlisted"]["wrong"], [item])
        self.assertEqual(result["stale"], ["w1"])

    def test_an_entry_without_a_learned_value_matches_any_value_of_its_metric_and_key(self):
        item = wrong("L1", KEY, "admin")
        result = self.apply([entry(id="w2", kind="wrong", metric="L1", key=KEY)], wrong_items=[item])
        self.assertEqual(result["listed"]["wrong"], [item])
        self.assertEqual(result["stale"], [])

    def test_the_metric_must_match(self):
        item = wrong("L1", KEY, "export")
        result = self.apply([entry(id="w3", kind="wrong", metric="L0", key=KEY, learned="export")], wrong_items=[item])
        self.assertEqual(result["unlisted"]["wrong"], [item])
        self.assertEqual(result["stale"], ["w3"])

    def test_an_unmodeled_pattern_covers_every_code_of_its_route(self):
        items = [
            {"key": "GET /share/SHR-1 path[1]", "pattern": "GET /share/… path[1]", "learned": "share"},
            {"key": "GET /share/SHR-2 path[1]", "pattern": "GET /share/… path[1]", "learned": "share"},
        ]
        result = self.apply([entry(id="u1", kind="unmodeled", pattern="GET /share/… path[1]")], unmodeled=items)
        self.assertEqual(result["listed"]["unmodeled"], items)
        self.assertEqual(result["unlisted"]["unmodeled"], [])
        self.assertEqual(result["entries"][0]["matched"], 2)

    def test_a_miss_names_the_entry_that_lists_it_and_an_unlisted_miss_has_no_gap(self):
        misses = [
            {"key": "POST /api/patients/{id}/notes path[2]", "why": "没学到：接受公共来源未提议"},
            {"key": "GET /api/visits/{id} path[2]", "why": "没学到：被自动暂停"},
        ]
        result = self.apply([entry(id="m1", kind="miss", key=misses[0]["key"])], misses=misses)
        self.assertEqual(result["misses"][0]["gap"], "m1")
        self.assertIsNone(result["misses"][1]["gap"])

    def test_a_failure_is_matched_by_its_case_and_its_config(self):
        failures = [
            {"case": "train/101/0/open-created", "config": "learned"},
            {"case": "train/101/0/open-created", "config": "truth"},
        ]
        result = self.apply([entry(id="f1", kind="failure", case="train/101/0/open-created", config="learned")],
                            failures=failures)
        self.assertEqual(result["failures"], [failures[0]])
        self.assertEqual(result["stale"], [])

    def test_an_entry_that_matches_nothing_is_stale_only_when_the_check_runs(self):
        gone = entry(id="gone", kind="unmodeled", pattern="GET /x")
        self.assertEqual(self.apply([gone], check=True)["stale"], ["gone"])
        self.assertIsNone(self.apply([gone], check=False)["stale"])

    def test_the_repository_list_loads_under_the_contract(self):
        entries = contracts.load_known_gaps(LIST)
        self.assertEqual(len({item["id"] for item in entries}), len(entries))
        self.assertTrue(all(item["kind"] in known_gaps.KINDS for item in entries))
        self.assertTrue(all(item["lq"].startswith("LQ-") for item in entries))


class ContractTests(unittest.TestCase):
    def test_a_duplicate_id_and_a_missing_field_are_refused(self):
        valid = entry(id="a", kind="unmodeled", pattern="GET /x", learned="")
        cases = {
            "duplicate": [valid, dict(valid)],
            "no pattern": [{k: v for k, v in valid.items() if k != "pattern"}],
        }
        with tempfile.TemporaryDirectory() as folder:
            for name, entries in cases.items():
                with self.subTest(case=name):
                    path = Path(folder) / f"{name.replace(' ', '-')}.json"
                    path.write_text(json.dumps({"entries": entries}, ensure_ascii=False), encoding="utf-8")
                    with self.assertRaises(contracts.ContractError):
                        contracts.load_known_gaps(path)


if __name__ == "__main__":
    unittest.main()

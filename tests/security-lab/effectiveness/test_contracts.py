"""Contract tests (plan section 9): required fields, enum values, and messages that name the file
and line but never echo a value from the file."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from effectiveness.builders import decision, judgement, learned_doc, learning_round, observation, truth_doc
from effectiveness.contracts import (
    ContractError,
    load_baseline,
    load_decisions,
    load_learned,
    load_observations,
    load_truth,
)

MARKER = "MARKER-GROUP-4412"


class ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)

    def write(self, name: str, *documents: object, raw: str | None = None) -> Path:
        path = self.dir / name
        if raw is not None:
            path.write_text(raw, encoding="utf-8")
        else:
            path.write_text("".join(json.dumps(doc, ensure_ascii=False) + "\n" for doc in documents),
                            encoding="utf-8")
        return path

    def message(self, loader, path: Path) -> str:
        with self.assertRaises(ContractError) as caught:
            loader(path)
        return str(caught.exception)

    def test_a_block_without_a_reason_is_rejected_with_its_line(self):
        bad = observation("bad", request_id="r2")
        bad["reason"] = None
        text = self.message(load_observations, self.write("observations.jsonl", observation("ok"), bad))
        self.assertIn("observations.jsonl:2", text)
        self.assertIn("reason", text)

    def test_an_allow_with_a_reason_is_rejected(self):
        bad = observation("bad", group="benign", category="benign_list", expect="allow", reason=None)
        bad["reason"] = "access"
        text = self.message(load_observations, self.write("observations.jsonl", bad))
        self.assertIn("expect 为 allow 时 reason 应为 null", text)

    def test_a_wrong_value_names_the_allowed_values_and_never_echoes_it(self):
        bad = observation("bad")
        bad["group"] = MARKER
        text = self.message(load_observations, self.write("observations.jsonl", bad))
        self.assertIn("group", text)
        self.assertIn("train、benign、attack 或 regression", text)
        self.assertNotIn(MARKER, text)

    def test_a_missing_required_field_is_named(self):
        bad = observation("bad")
        del bad["run"]
        self.assertIn("缺少必填字段 run", self.message(load_observations, self.write("observations.jsonl", bad)))

    def test_invalid_json_points_at_its_line(self):
        path = self.write("decisions.jsonl", raw=json.dumps(decision("r1")) + "\n{not json\n")
        text = self.message(load_decisions, path)
        self.assertIn("decisions.jsonl:2", text)
        self.assertIn("不是合法的 JSON", text)

    def test_a_repeated_request_id_points_at_the_first_line(self):
        text = self.message(load_decisions, self.write("decisions.jsonl", decision("r1"), decision("r1")))
        self.assertIn("decisions.jsonl:2", text)
        self.assertIn("decisions.jsonl:1", text)

    def test_a_truth_position_key_may_appear_once(self):
        key = "GET /api/search results[].id"
        doc = truth_doc(request=[(key, "patient", False)], response=[(key, "patient", "public")])
        self.assertIn("位置键重复", self.message(load_truth, self.write("truth.json", doc)))

    def test_a_truth_tier_must_be_a_known_tier(self):
        doc = truth_doc(request=[], response=[("GET /api/search results[].id", "patient", "vip")])
        self.assertIn("字段 tier 应为 self、org、admin、public 或 null",
                      self.message(load_truth, self.write("truth.json", doc)))

    def test_a_response_position_may_have_no_tier(self):
        doc = truth_doc(request=[], response=[("GET /api/search results[].id", "patient", None)])
        self.assertIsNone(load_truth(self.write("truth.json", doc))["response_positions"][0]["tier"])

    def learned_with(self, judgements: list[dict]) -> Path:
        return self.write("learned.json", raw=json.dumps(learned_doc([learning_round(1, [], judgements)], [])))

    def test_a_judgement_carries_a_tier_or_accepts_public(self):
        path = self.learned_with([judgement("GET /api/search results[].id", "public"),
                                  judgement("DELETE /api/patients/{id} path[2]", accepts=False)])
        self.assertEqual(len(load_learned(path)["rounds"][0]["judgements"]), 2)

    def test_a_judgement_with_both_or_neither_is_rejected(self):
        both = dict(judgement("GET /api/search results[].id", "public"), accepts_public=True)
        neither = {"key": "GET /api/search results[].id", "reliability": "high"}
        for bad in (both, neither):
            with self.subTest(bad=bad):
                text = self.message(load_learned, self.learned_with([bad]))
                self.assertIn("应恰好含 tier 或 accepts_public 其中一个", text)
                self.assertIn("judgements[0]", text)

    def test_a_judgement_value_is_checked(self):
        bad_tier = judgement("GET /api/search results[].id", "vip")
        self.assertIn("字段 tier 应为 self、org、admin 或 public",
                      self.message(load_learned, self.learned_with([bad_tier])))
        bad_accepts = judgement("DELETE /api/patients/{id} path[2]", accepts=False)
        bad_accepts["accepts_public"] = "yes"
        self.assertIn("字段 accepts_public 应为 true 或 false",
                      self.message(load_learned, self.learned_with([bad_accepts])))

    def test_learned_needs_its_final_spec(self):
        doc = {"bootstrap": [], "rounds": []}
        self.assertIn("缺少必填字段 final_spec", self.message(load_learned, self.write("learned.json", doc)))

    def test_a_baseline_value_is_a_number_or_null(self):
        bad = self.write("bad.json", raw=json.dumps({"groups": {"quick": {"seed": 1, "commit": "c", "values": {"S3": "0.5"}}}}))
        self.assertIn("应为数字或 null", self.message(load_baseline, bad))
        good = self.write("good.json", raw=json.dumps({"groups": {"quick": {"seed": 1, "commit": "c", "values": {"S3": None, "S1": 0.5}}}}))
        self.assertEqual(load_baseline(good)["groups"]["quick"]["values"], {"S3": None, "S1": 0.5})

    def test_a_missing_file_is_a_contract_error(self):
        self.assertIn("无法读取", self.message(load_observations, self.dir / "absent.jsonl"))

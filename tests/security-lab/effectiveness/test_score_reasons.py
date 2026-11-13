"""The reason a position was not learned reads the training segment's records only (score.py, lab.py).

A protection probe that Jev denied on the same route is not a refusal the learning saw, so it must not turn the
reason into "被拒绝记录挡住". A refusal in the training segment does, and so does a score run without a training list.
"""

from __future__ import annotations

import unittest

from effectiveness.score import score

KEY = "GET /api/x path[1]"
BLOCKED = "没学到：被拒绝记录挡住"
TRUTH = {"request_positions": [{"key": KEY, "class": "patient", "accepts_public": False, "learnable": True}],
         "response_positions": [], "non_objects": [], "identity": []}
LEARNED = {"rounds": [], "bootstrap": []}


def record(request_id: str, decision_path: str) -> dict:
    return {"request_id": request_id, "method": "GET", "path": "/api/x", "logical_path": "/api/x",
            "decision_path": decision_path, "site": "clinic-truth", "jev": {}, "trace": {}}


def reason_of(result: dict, key: str):
    """The why of the learning row of `key`, wherever the result keeps its rows."""
    stack = [result]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("key") == key and "why" in node:
                return node["why"]
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


class ReasonTests(unittest.TestCase):
    def test_a_protection_denial_is_not_a_refusal_the_learning_saw(self):
        training = [record("t1", "jev_allow")]
        decisions = [*training, record("p1", "jev_deny")]
        result = score([], decisions, truth=TRUTH, learned=LEARNED, training=training)
        self.assertEqual(reason_of(result, KEY), "没学到：其他")

    def test_a_refusal_in_the_training_segment_blocks_the_position(self):
        training = [record("t1", "jev_deny")]
        result = score([], training, truth=TRUTH, learned=LEARNED, training=training)
        self.assertEqual(reason_of(result, KEY), BLOCKED)

    def test_a_score_run_without_a_training_list_reads_every_record(self):
        result = score([], [record("d1", "jev_deny")], truth=TRUTH, learned=LEARNED)
        self.assertEqual(reason_of(result, KEY), BLOCKED)


if __name__ == "__main__":
    unittest.main()

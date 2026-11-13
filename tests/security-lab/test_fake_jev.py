"""Tests for the scripted Jev (fake_jev.py) and the attack and benign corpus in corpus/.

Run from the repository root:
    python3 -m unittest discover -s tests/security-lab -p "test_*.py"
"""

from __future__ import annotations

import http.client
import json
import unittest
from collections import Counter
from pathlib import Path

from fake_jev import FakeJev, attack_forms_of, judge, normalize

CORPUS = Path(__file__).resolve().parent / "corpus"
ATTACK_CLASSES = ("sqli", "cmd", "traversal", "xss", "nosql", "ssti", "ssrf")
BENIGN_CLASSES = ("name", "clinic", "keyword", "path_url", "math", "code_markup", "json", "contact", "long")
ROW_KEYS = {"id", "class", "text", "quick", "note"}


def load(name: str) -> list[dict]:
    rows = []
    for number, line in enumerate((CORPUS / name).read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError as error:
                raise AssertionError(f"{name}:{number}: not JSON ({error})") from error
    return rows


def value(at: str, text: str, kind: str = "input", **extra: object) -> dict:
    return {"at": at, "kind": kind, "value": text, "seen_as": [], **extra}


def document(path: str, values: list[dict], *, method: str = "GET", entry: bool = False) -> dict:
    return {"state": {"entry": {"matched": entry},
                      "request": {"method": method, "path": path, "truncated": False, "values": values}}}


def choices(document_: dict, attack_forms: tuple[str, ...] | None = None) -> tuple[str, str]:
    answers = judge(document_, attack_forms)["answers"]
    return answers["access"]["choice"], answers["attack"]["choice"]


# Documents the lab has sent, with the answers the marker rules gave before the ideal model existed.
GOLDEN = [
    ("login: the password is input, the username a reference seen nowhere",
     document("/login", [value("body.csrf", "2cf06ae12e64f8d6"), value("body.password", "<redacted>"),
                         value("body.username", "doctor_a", kind="reference")], method="POST", entry=True),
     "ALLOW", "BENIGN"),
    ("an unseen patient id is refused",
     document("/api/patients/PT-7004", [value("path[2]", "PT-7004", kind="reference")]),
     "DENY", "BENIGN"),
    ("a verified patient id is allowed",
     document("/api/patients/PT-7002", [value("path[2]", "PT-7002", kind="reference", verified=True,
                                              seen_as=["id @ GET /api/search [patient]"])]),
     "ALLOW", "BENIGN"),
    ("a share code on the entry is input",
     document("/share/SHR-93A1", [value("path[2]", "SHR-93A1", kind="reference")], entry=True),
     "ALLOW", "BENIGN"),
    ("an attempt is refused",
     document("/api/patients/PT-7001", [value("path[2]", "PT-7001", kind="reference", attempt="over_privilege",
                                              seen_as=["id @ GET /api/search [patient] (tier public, reliability high)"])]),
     "DENY", "BENIGN"),
    ("an unseen body id is refused",
     document("/api/notes", [value("body.patient_id", "PT-7004", kind="reference")], method="POST"),
     "DENY", "BENIGN"),
    ("a typed name is input",
     document("/api/patients", [value("body.name", "林小雨")], method="POST"),
     "ALLOW", "BENIGN"),
    ("a marker in a query",
     document("/api/search", [value("query.q", "1' or 1=1--")]),
     "ALLOW", "ATTACK"),
    ("traversal in a query",
     document("/api/search", [value("query.q", "../../etc/passwd")]),
     "ALLOW", "ATTACK"),
    ("a benign relative path carries a marker",
     document("/api/search", [value("query.q", "../README.md")]),
     "ALLOW", "ATTACK"),
    ("a URL-encoded injection escapes the markers",
     document("/api/search", [value("query.q", "%27%20OR%201%3D1--")]),
     "ALLOW", "BENIGN"),
    ("a command in a form",
     document("/api/notes", [value("body.note", "x; cat /etc/passwd")], method="POST"),
     "ALLOW", "ATTACK"),
    ("an apostrophe name",
     document("/api/search", [value("query.q", "O'Brien")]),
     "ALLOW", "BENIGN"),
    ("a script tag in a value",
     document("/api/search", [value("query.q", "<script>alert(1)</script>")]),
     "ALLOW", "ATTACK"),
]


class CorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.attacks = load("attacks.jsonl")
        cls.benign = load("benign.jsonl")

    def test_rows_are_well_formed(self) -> None:
        for rows, prefix in ((self.attacks, "atk"), (self.benign, "ben")):
            for row in rows:
                with self.subTest(row=row.get("id")):
                    self.assertEqual(set(row), ROW_KEYS)
                    self.assertIsInstance(row["quick"], bool)
                    self.assertTrue(isinstance(row["text"], str) and row["text"].strip())
                    self.assertTrue(isinstance(row["note"], str) and row["note"])
                    self.assertRegex(row["id"], rf"^{prefix}-[a-z_]+-\d{{2}}$")
                    self.assertEqual(row["id"].split("-")[1], row["class"])

    def test_ids_are_unique(self) -> None:
        ids = [row["id"] for row in self.attacks + self.benign]
        self.assertEqual(len(ids), len(set(ids)))

    def test_texts_are_unique_within_each_file(self) -> None:
        for rows in (self.attacks, self.benign):
            texts = [row["text"] for row in rows]
            self.assertEqual(len(texts), len(set(texts)))

    def test_every_attack_class_has_at_least_fifteen_rows(self) -> None:
        counts = Counter(row["class"] for row in self.attacks)
        self.assertEqual(set(counts), set(ATTACK_CLASSES))
        for klass in ATTACK_CLASSES:
            with self.subTest(klass=klass):
                self.assertGreaterEqual(counts[klass], 15)

    def test_benign_rows_cover_the_false_positive_classes(self) -> None:
        self.assertEqual(set(Counter(row["class"] for row in self.benign)), set(BENIGN_CLASSES))

    def test_each_file_holds_about_one_hundred_fifty_rows(self) -> None:
        for rows in (self.attacks, self.benign):
            self.assertGreaterEqual(len(rows), 140)
            self.assertLessEqual(len(rows), 170)

    def test_quick_subsets_hold_about_thirty_rows(self) -> None:
        for rows in (self.attacks, self.benign):
            self.assertTrue(25 <= sum(row["quick"] for row in rows) <= 35)
        quick = Counter(row["class"] for row in self.attacks if row["quick"])
        for klass in ATTACK_CLASSES:
            with self.subTest(klass=klass):
                self.assertGreaterEqual(quick[klass], 2)

    def test_attack_and_benign_texts_do_not_overlap(self) -> None:
        self.assertEqual({row["text"] for row in self.attacks} & {row["text"] for row in self.benign}, set())
        attack_forms = {normalize(row["text"]) for row in self.attacks}
        self.assertEqual(attack_forms & {normalize(row["text"]) for row in self.benign}, set())

    def test_no_benign_text_contains_an_attack_text(self) -> None:
        # Otherwise the ideal model would judge that benign text ATTACK.
        forms = attack_forms_of(row["text"] for row in self.attacks)
        for row in self.benign:
            with self.subTest(row=row["id"]):
                text = normalize(row["text"])
                self.assertEqual([form for form in forms if form in text], [])

    def test_the_ideal_model_judges_each_row_as_its_file_says(self) -> None:
        forms = attack_forms_of(row["text"] for row in self.attacks)
        for rows, expected in ((self.attacks, "ATTACK"), (self.benign, "BENIGN")):
            for row in rows:
                with self.subTest(row=row["id"]):
                    shown = document("/api/search", [value("query.q", row["text"])])
                    self.assertEqual(choices(shown, forms)[1], expected)


class MarkerRulesTest(unittest.TestCase):
    def test_answers_are_those_the_marker_rules_gave_before(self) -> None:
        for name, document_, access, attack in GOLDEN:
            with self.subTest(name):
                self.assertEqual(choices(document_), (access, attack))

    def test_the_ideal_model_is_off_by_default(self) -> None:
        jev = FakeJev()
        self.addCleanup(jev.server.server_close)  # bound but never started, so no shutdown()
        self.assertIsNone(jev.attack_forms)


class IdealModelTest(unittest.TestCase):
    forms = attack_forms_of(["' OR 1=1--", "../../etc/passwd"])

    def test_the_text_is_found_in_any_encoding(self) -> None:
        for text in ("1' or 1=1--", "' Or 1=1--", "%27%20OR%201%3D1--", "%2527%2520OR%25201%253D1--",
                     "＇　ＯＲ　１＝１－－", "%27+OR+1%3D1--"):
            with self.subTest(text=text):
                self.assertEqual(choices(document("/api/search", [value("query.q", text)]), self.forms)[1], "ATTACK")

    def test_the_text_is_found_in_the_path(self) -> None:
        self.assertEqual(choices(document("/api/items/%27%20OR%201%3D1--", []), self.forms)[1], "ATTACK")

    def test_a_text_split_over_two_values_is_not_found(self) -> None:
        split = document("/api/search", [value("query.a", "' OR"), value("query.b", "1=1--")])
        self.assertEqual(choices(split, self.forms)[1], "BENIGN")

    def test_a_relative_path_with_a_marker_is_benign(self) -> None:
        benign = document("/api/search", [value("query.q", "../README.md")])
        self.assertEqual(choices(benign, self.forms)[1], "BENIGN")
        self.assertEqual(choices(benign)[1], "ATTACK")

    def test_the_access_rules_are_unchanged(self) -> None:
        unseen = document("/api/patients/PT-7004", [value("path[2]", "PT-7004", kind="reference")])
        attempt = document("/api/patients/PT-7001", [value("path[2]", "PT-7001", kind="reference",
                                                           attempt="over_privilege", seen_as=["x"])])
        self.assertEqual(choices(unseen, self.forms), ("DENY", "BENIGN"))
        self.assertEqual(choices(attempt, self.forms), ("DENY", "BENIGN"))

    def test_attack_texts_are_normalized_sorted_and_unique(self) -> None:
        self.assertEqual(attack_forms_of(["B", "a", "A", "%41"]), ("a", "b"))

    def test_blank_or_non_string_attack_texts_are_refused(self) -> None:
        for texts in ([""], ["%20"], [" "], [1]):
            with self.subTest(texts=texts), self.assertRaises(ValueError):
                attack_forms_of(texts)


class KindTest(unittest.TestCase):
    """The ideal model reads the kind in the brackets of a sighting; the marker rules take any sighting."""
    forms = attack_forms_of(["' OR 1=1--"])

    def patient(self, *seen_as: str, **extra: object) -> dict:
        return document("/api/patients/PT-7002", [value("path[2]", "PT-7002", kind="reference", object="patient",
                                                        seen_as=list(seen_as), **extra)])

    def test_a_value_shown_only_as_another_kind_is_refused(self) -> None:
        shown = self.patient("id @ GET /api/visits/{id} [visit] (tier self, reliability high)")
        self.assertEqual(choices(shown, self.forms), ("DENY", "BENIGN"))

    def test_without_attack_texts_the_same_state_is_allowed_as_before(self) -> None:
        shown = self.patient("id @ GET /api/visits/{id} [visit] (tier self, reliability high)")
        self.assertEqual(choices(shown), ("ALLOW", "BENIGN"))

    def test_a_value_shown_as_the_same_kind_is_allowed(self) -> None:
        shown = self.patient("id @ GET /api/search [patient] (tier public, reliability high)")
        self.assertEqual(choices(shown, self.forms), ("ALLOW", "BENIGN"))

    def test_an_entry_without_brackets_still_counts(self) -> None:
        self.assertEqual(choices(self.patient("id @ GET /api/search"), self.forms), ("ALLOW", "BENIGN"))

    def test_one_sighting_of_the_same_kind_is_enough(self) -> None:
        shown = self.patient("id @ GET /api/visits/{id} [visit]", "patients[].id @ GET /api/search [patient]")
        self.assertEqual(choices(shown, self.forms), ("ALLOW", "BENIGN"))

    def test_brackets_in_a_list_field_do_not_hide_the_kind(self) -> None:
        shown = self.patient("patients[].id @ GET /api/search [patient] (tier public, reliability high)")
        self.assertEqual(choices(shown, self.forms), ("ALLOW", "BENIGN"))

    def test_a_value_without_an_object_is_judged_as_before(self) -> None:
        shown = document("/api/patients/PT-7002", [value("path[2]", "PT-7002", kind="reference",
                                                       seen_as=["id @ GET /api/visits/{id} [visit]"])])
        self.assertEqual(choices(shown, self.forms), ("ALLOW", "BENIGN"))

    def test_a_verified_value_is_shown_whatever_its_kind(self) -> None:
        shown = self.patient("id @ GET /api/visits/{id} [visit]", verified=True)
        self.assertEqual(choices(shown, self.forms), ("ALLOW", "BENIGN"))


class FunctionTest(unittest.TestCase):
    """The function rules (docs/02 2.2): an attempt is refused, and an unknown function is refused on an operations path."""

    def with_function(self, path: str, function: dict, method: str = "GET") -> dict:
        document_ = document(path, [], method=method)
        document_["state"]["request"]["function"] = function
        return document_

    def test_an_attempt_is_refused_whatever_else_the_request_says(self) -> None:
        attempt = self.with_function("/api/admin/export", {"tier": "admin", "attempt": "over_privilege"}, "POST")
        self.assertEqual(choices(attempt), ("DENY", "BENIGN"))

    def test_an_unknown_function_on_an_operations_path_is_refused(self) -> None:
        for path in ("/metrics", "/actuator/health", "/server-status", "/api/Backup/list", "/Admin/users"):
            with self.subTest(path=path):
                self.assertEqual(choices(self.with_function(path, {"known": False})), ("DENY", "BENIGN"))

    def test_an_unknown_function_on_an_ordinary_path_is_judged_on_its_values(self) -> None:
        self.assertEqual(choices(self.with_function("/api/comments", {"known": False})), ("ALLOW", "BENIGN"))

    def test_without_a_function_the_answer_is_the_same_as_before(self) -> None:
        plain = document("/api/admin/search", [])
        self.assertEqual(choices(plain), ("ALLOW", "BENIGN"))
        self.assertNotIn("function", plain["state"]["request"])


class UnsentPathIdTest(unittest.TestCase):
    """A digit segment of the path needs a path value that carries it, in every batch (plan 3.5)."""

    def test_a_path_id_carried_by_a_path_value_is_judged_by_the_rules_as_before(self) -> None:
        shown = value("path[2]", "7005", "reference", verified=True)
        self.assertEqual(choices(document("/api/patients/7005/notes", [shown], method="POST")), ("ALLOW", "BENIGN"))
        unshown = value("path[2]", "7005", "reference")
        self.assertEqual(choices(document("/api/patients/7005/notes", [unshown], method="POST")), ("DENY", "BENIGN"))

    def test_a_path_id_without_a_path_value_is_refused_while_the_same_values_are_allowed_without_it(self) -> None:
        batch = document("/api/patients/7005/notes", [value("body.field00", "正常的文字")], method="POST")
        self.assertEqual(choices(batch), ("DENY", "BENIGN"))
        without_id = document("/api/feedback", [value("body.field00", "正常的文字")], method="POST")
        self.assertEqual(choices(without_id), ("ALLOW", "BENIGN"))

    def test_a_path_without_a_digit_segment_is_not_affected(self) -> None:
        names = document("/api/patients/PT-7001/notes", [value("body.field00", "正常的文字")], method="POST")
        self.assertEqual(choices(names), ("ALLOW", "BENIGN"))
        mixed = document("/api/v2a/7005x", [])
        self.assertEqual(choices(mixed), ("ALLOW", "BENIGN"))

    def test_the_ideal_model_refuses_it_too(self) -> None:
        batch = document("/api/patients/7005/notes", [value("body.field00", "正常的文字")], method="POST")
        self.assertEqual(choices(batch, attack_forms_of(["zzz-not-in-the-request"])), ("DENY", "BENIGN"))

    def test_only_a_path_position_carries_the_id(self) -> None:
        batch = document("/api/patients/7005/notes", [value("body.patient", "7005")], method="POST")
        self.assertEqual(choices(batch), ("DENY", "BENIGN"))


class ServedTest(unittest.TestCase):
    def serve(self, attack_texts: list[str] | None = None) -> FakeJev:
        jev = FakeJev(attack_texts)
        jev.start()
        self.addCleanup(jev.stop)
        return jev

    def post(self, jev: FakeJev, body: dict) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", jev.port, timeout=10)
        try:
            connection.request("POST", "/v1/systemone", body=json.dumps(body),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read() or b"{}")
        finally:
            connection.close()

    def test_without_attack_texts_the_reply_is_the_marker_judgement(self) -> None:
        jev = self.serve()
        for name, document_, _access, _attack in GOLDEN:
            with self.subTest(name):
                self.assertEqual(self.post(jev, document_), (200, judge(document_)))

    def test_the_scripted_outage_still_answers_503(self) -> None:
        jev = self.serve()
        status, _reply = self.post(jev, document("/api/search", [value("query.q", "JEVDOWN")]))
        self.assertEqual(status, 503)

    def test_each_state_is_recorded_and_a_text_is_found_in_a_call(self) -> None:
        jev = self.serve(["' OR 1=1--"])
        benign = document("/api/search", [value("query.q", "O'Brien")])
        attack = document("/api/search", [value("query.q", "%27%20OR%201%3D1--")])
        self.assertEqual(self.post(jev, benign), (200, judge(benign, jev.attack_forms)))
        self.assertEqual(self.post(jev, attack)[1]["answers"]["attack"]["choice"], "ATTACK")
        self.assertEqual([state["request"]["values"][0]["value"] for state in jev.states],
                         ["O'Brien", "%27%20OR%201%3D1--"])
        self.assertTrue(jev.carries("O'Brien"))
        self.assertTrue(jev.carries("' OR 1=1--", call=1))
        self.assertFalse(jev.carries("' OR 1=1--", call=0))
        self.assertTrue(jev.carries("' OR 1=1--", since=1))
        self.assertFalse(jev.carries("' OR 1=1--", since=2))
        self.assertFalse(jev.carries("DROP TABLE"))

    def test_a_blank_text_cannot_be_looked_for(self) -> None:
        jev = self.serve()
        for text in ("", "  ", "%20"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                jev.carries(text)


if __name__ == "__main__":
    unittest.main()

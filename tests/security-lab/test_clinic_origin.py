"""Unit tests for the clinic origin and its benign training traffic (plan 4.1, 4.2 and 10, batch 2).

The tests talk to the origin directly, without the edge. The origin has no object-level authorization on
purpose, so every refusal the lab expects comes from the edge; here the origin must answer the way the
clinic is meant to, and its ground truth must match what it answered.
"""

from __future__ import annotations

import unittest
from typing import Any
from urllib.parse import quote

import labkit
from clinic_origin import ADMINS, DEFAULT_SEED, PASSWORD, ClinicOrigin, site_spec
from clinic_traffic import Evidence, run_training

HOST = "clinic-truth.lab"


def _send(origin: ClinicOrigin, method: str, target: str, *, token: str | None = None,
          **options: Any) -> labkit.Reply:
    if token:
        options["cookie"] = f"SID={token}"
    return labkit.request(origin.port, HOST, method, target, **options)


def _token(reply: labkit.Reply) -> str:
    for name, value in reply.headers:
        if name.lower() == "set-cookie" and value.startswith("SID="):
            return value[len("SID="):].split(";", 1)[0]
    raise AssertionError(f"no session cookie in an answer with status {reply.status}")


def _login(origin: ClinicOrigin, account: str) -> str:
    reply = _send(origin, "POST", "/login", form={"username": account, "password": PASSWORD})
    if reply.status != 302:
        raise AssertionError(f"login as {account} answered {reply.status}")
    return _token(reply)


def _field_positions(value: Any, prefix: str = "") -> set[str]:
    """The field positions of an answer, with list items written as [] (the way the edge names them)."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            found.add(path)
            found |= _field_positions(item, path)
    elif isinstance(value, list):
        for item in value:
            found |= _field_positions(item, f"{prefix}[]")
    return found


def _longest_list(value: Any) -> int:
    if isinstance(value, dict):
        return max((_longest_list(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return max([len(value)] + [_longest_list(item) for item in value])
    return 0


class ClinicOriginTest(unittest.TestCase):
    def setUp(self) -> None:
        self.origin = ClinicOrigin(DEFAULT_SEED, 12)
        self.origin.start()
        self.addCleanup(self.origin.stop)

    def owned(self, doctor_id: str) -> list[str]:
        return [pid for pid, patient in self.origin.patients.items()
                if patient["owner"] == doctor_id and not patient["deleted"]]

    def test_doctor_reads_her_own_data(self) -> None:
        token = _login(self.origin, "doctor_101")
        home = _send(self.origin, "GET", "/api/home", token=token)
        self.assertEqual(home.status, 200)
        self.assertEqual(home.json()["doctor"]["id"], "101")
        self.assertNotIn("role", home.json())

        listing = _send(self.origin, "GET", "/api/patients", token=token)
        self.assertEqual(listing.status, 200)
        self.assertEqual([item["id"] for item in listing.json()["patients"]], self.owned("101")[:7])
        etag = dict(listing.headers)["ETag"]
        again = _send(self.origin, "GET", "/api/patients", token=token, headers={"If-None-Match": etag})
        self.assertEqual(again.status, 304)

        pid = self.owned("101")[0]
        detail = _send(self.origin, "GET", f"/api/patients/{pid}", token=token).json()
        self.assertEqual(detail["id"], pid)
        visit = detail["visits"][0]["id"]
        self.assertEqual(_send(self.origin, "GET", f"/api/visits/{visit}", token=token).status, 200)
        number = detail["prescriptions"][0]["id"]
        self.assertEqual(_send(self.origin, "GET", f"/api/prescriptions/{number}", token=token).status, 200)
        report = next(rid for rid, item in self.origin.reports.items() if item["patient"] == pid)
        self.assertEqual(_send(self.origin, "GET", f"/api/reports/{report}", token=token).status, 200)
        commented = next(iter(self.origin.comments))
        comments = _send(self.origin, "GET", f"/api/patients/{commented}/comments", token=token)
        self.assertEqual(comments.status, 200)
        self.assertIn("phone", comments.json()["comments"][0]["author"])

        found = _send(self.origin, "GET", f"/api/search?q={quote('内科', safe='')}", token=token)
        self.assertEqual(found.status, 200)
        self.assertTrue(found.json()["results"])
        directory = _send(self.origin, "GET", "/api/directory", token=token)
        self.assertEqual(directory.status, 200)
        self.assertLessEqual(len(directory.json()["doctors"]), 7)

    def test_doctor_writes_her_own_data(self) -> None:
        token = _login(self.origin, "doctor_101")
        created = _send(self.origin, "POST", "/api/patients", token=token, json_body={"name": "O'Brien"})
        self.assertEqual(created.status, 201)
        new_id = created.json()["id"]
        self.assertEqual(_send(self.origin, "GET", f"/api/patients/{new_id}", token=token).status, 200)
        noted = _send(self.origin, "POST", f"/api/patients/{new_id}/notes", token=token, json_body={"text": "复诊"})
        self.assertEqual(noted.status, 201)
        updated = _send(self.origin, "PUT", f"/api/patients/{new_id}", token=token, json_body={"name": "王小明"})
        self.assertEqual(updated.status, 200)
        code = _send(self.origin, "POST", f"/api/patients/{new_id}/share", token=token).json()["code"]
        colleague = _login(self.origin, "doctor_102")
        redeemed = _send(self.origin, "GET", f"/share/{code}", token=colleague)
        self.assertEqual(redeemed.status, 200)
        self.assertEqual(redeemed.json()["patient"]["id"], new_id)
        attached = _send(self.origin, "POST", f"/api/patients/{new_id}/attachments", token=token, body=b"x" * 60000)
        self.assertEqual(attached.json()["bytes"], 60000)
        self.assertEqual(_send(self.origin, "DELETE", f"/api/patients/{new_id}", token=token).status, 200)
        self.assertEqual(_send(self.origin, "GET", f"/api/patients/{new_id}", token=token).status, 404)
        intake = {f"field{number}": "值" for number in range(120)}
        self.assertEqual(_send(self.origin, "POST", "/api/forms/intake", token=token, form=intake).json()["received"],
                         120)

    def test_session_routes(self) -> None:
        self.assertEqual(_send(self.origin, "POST", "/login",
                               form={"username": "doctor_101", "password": "wrong"}).status, 401)
        self.assertEqual(_send(self.origin, "GET", "/api/home").status, 401)
        token = _login(self.origin, "doctor_101")
        refreshed = _send(self.origin, "POST", "/api/session/refresh", token=token)
        self.assertEqual(refreshed.status, 200)
        new_token = _token(refreshed)
        self.assertNotEqual(new_token, token)
        self.assertEqual(_send(self.origin, "GET", "/api/home", token=token).status, 401)
        self.assertEqual(_send(self.origin, "GET", "/api/home", token=new_token).status, 200)
        options = _send(self.origin, "OPTIONS", "/api/patients")
        self.assertEqual(options.status, 204)
        self.assertIn(("Access-Control-Allow-Origin", "*"), options.headers)
        self.assertEqual(_send(self.origin, "GET", "/metrics").status, 200)
        self.assertEqual(_send(self.origin, "GET", "/static/app.js").status, 200)
        issued = _send(self.origin, "POST", "/api/token", form={"username": "doctor_101", "password": PASSWORD})
        self.assertEqual(issued.status, 200)
        self.assertEqual(issued.json()["user"]["id"], "101")
        self.assertEqual(sorted(item["id"] for item in issued.json()["patients"]), sorted(self.owned("101")[:7]))

    def test_no_object_level_authorization(self) -> None:
        token = _login(self.origin, "doctor_101")
        victim = self.owned("102")[0]
        self.assertEqual(_send(self.origin, "GET", f"/api/patients/{victim}", token=token).status, 200)
        self.assertEqual(_send(self.origin, "PUT", f"/api/patients/{victim}", token=token,
                               json_body={"name": "改"}).status, 200)
        self.assertEqual(_send(self.origin, "DELETE", f"/api/patients/{victim}", token=token).status, 200)

    def test_administrator_endpoints_refuse_doctors(self) -> None:
        doctor = _login(self.origin, "doctor_101")
        admin = _login(self.origin, "admin_1")
        self.assertIn("admin_1", ADMINS)
        name = quote(self.origin.patients[self.owned("102")[0]]["name"], safe="")
        self.assertEqual(_send(self.origin, "GET", f"/api/admin/search?q={name}", token=doctor).status, 403)
        self.assertEqual(_send(self.origin, "GET", "/api/admin/export", token=doctor).status, 403)
        self.assertEqual(_send(self.origin, "GET", f"/api/admin/search?q={name}", token=admin).status, 200)
        self.assertEqual(_send(self.origin, "GET", "/api/admin/export", token=admin).status, 200)
        self.assertEqual(_send(self.origin, "GET", "/api/home", token=admin).json()["role"], "admin")

    def test_profile_update_grants_the_administrator_role(self) -> None:
        token = _login(self.origin, "doctor_101")
        self.assertEqual(_send(self.origin, "POST", "/api/profile", token=token,
                               json_body={"role": "admin"}).status, 200)
        self.assertEqual(_send(self.origin, "GET", "/api/admin/export", token=token).status, 200)

    def test_shown_and_owner_match_the_answers(self) -> None:
        token = _login(self.origin, "doctor_101")
        victim = self.owned("102")[0]
        detail = _send(self.origin, "GET", f"/api/patients/{victim}", token=token).json()
        shown = self.origin.shown_of(token)
        self.assertIn(("patient", victim), shown)
        self.assertEqual(self.origin.owner_of("patient", victim), "102")
        for visit in detail["visits"]:
            self.assertIn(("visit", visit["id"]), shown)
            self.assertEqual(self.origin.owner_of("visit", visit["id"]), "102")
        for item in detail["prescriptions"]:
            self.assertIn(("prescription", str(item["id"])), shown)
            self.assertEqual(self.origin.owner_of("prescription", str(item["id"])), "102")
        found = _send(self.origin, "GET", f"/api/search?q={quote('外科', safe='')}", token=token).json()["results"]
        self.assertTrue(found)
        for item in found:
            self.assertIn(("patient", item["id"]), self.origin.shown_of(token))
            owner = self.origin.owner_of("patient", item["id"])
            self.assertEqual(self.origin.doctors[owner]["dept"], "外科")
        self.assertIsNone(self.origin.owner_of("patient", "99999"))
        self.assertEqual(self.origin.owner_of("doctor", "102"), "102")

    def test_lists_and_fields_stay_within_the_limits(self) -> None:
        token = _login(self.origin, "doctor_101")
        admin = _login(self.origin, "admin_1")
        commented = next(iter(self.origin.comments))
        answers = [
            _send(self.origin, "GET", "/api/patients", token=token),
            _send(self.origin, "GET", f"/api/patients/{self.owned('101')[0]}", token=token),
            _send(self.origin, "GET", f"/api/search?q={quote('内科', safe='')}", token=token),
            _send(self.origin, "GET", "/api/directory", token=token),
            _send(self.origin, "GET", f"/api/patients/{commented}/comments", token=token),
            _send(self.origin, "GET", "/api/admin/export", token=admin),
        ]
        for answer in answers:
            self.assertEqual(answer.status, 200)
            self.assertLessEqual(_longest_list(answer.json()), 7)
            self.assertLess(len(_field_positions(answer.json())), 16)

    def test_same_seed_gives_the_same_data_and_a_truth_in_plan_format(self) -> None:
        def build(seed: int) -> ClinicOrigin:
            origin = ClinicOrigin(seed, 12)
            self.addCleanup(origin.server.server_close)
            return origin

        first, second, other = build(DEFAULT_SEED), build(DEFAULT_SEED), build(DEFAULT_SEED + 1)
        self.assertEqual(first.snapshot(), second.snapshot())
        self.assertNotEqual(first.snapshot(), other.snapshot())
        truth = self.origin.truth()
        self.assertEqual(set(truth), {"site", "seed", "classes", "identity", "request_positions",
                                      "response_positions", "non_objects"})
        self.assertEqual(truth["site"], "clinic")
        self.assertEqual(truth["seed"], DEFAULT_SEED)
        for item in truth["request_positions"] + truth["response_positions"]:
            if not item["learnable"]:
                self.assertIn("why", item, item["key"])

    def test_site_spec_declares_the_truth_only_when_asked(self) -> None:
        none = site_spec("none", 18080)
        truth_site = site_spec("truth", 18080)
        identities = {slot["identity"] for slot in none["objects"]["slots"] if "identity" in slot}
        self.assertEqual(identities, {"user", "org", "role"})
        self.assertFalse(any("accepts_public" in slot for slot in none["objects"]["slots"]))
        self.assertTrue(any("accepts_public" in slot for slot in truth_site["objects"]["slots"]))
        self.assertEqual(truth_site["on_jev_unavailable"], "deny")
        with self.assertRaises(ValueError):
            site_spec("half", 18080)


class TrainingTrafficTest(unittest.TestCase):
    def direct_run(self, seed: int) -> tuple[list[dict[str, Any]], Evidence]:
        origin = ClinicOrigin(seed, 12)
        origin.start()
        self.addCleanup(origin.stop)

        def direct(host: str, method: str, target: str, **options: Any) -> labkit.Sent:
            return labkit.Sent(labkit.request(origin.port, host, method, target, **options), None, False)

        evidence = Evidence()
        return run_training(direct, origin, seed, 12, 4, evidence=evidence), evidence

    def test_same_seed_sends_the_same_requests(self) -> None:
        first, evidence = self.direct_run(DEFAULT_SEED)
        second, _ = self.direct_run(DEFAULT_SEED)

        def sequence(rows: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
            return [(row["session"], row["request"], row["note"],
                     tuple((ref["class"], ref["value"]) for ref in row["refs"])) for row in rows]

        self.assertEqual(sequence(first), sequence(second))
        self.assertTrue(all(row["group"] == "train" and row["expect"] == "allow" for row in first))
        unexpected = [row["case"] for row in first if row["client_status"] not in row["expected_status"]]
        self.assertEqual(unexpected, [])

    def test_the_evidence_reaches_the_high_counts(self) -> None:
        _, evidence = self.direct_run(DEFAULT_SEED)
        self.assertGreaterEqual(len(evidence.search_units), 10)
        self.assertGreaterEqual(len(evidence.public_views), 20)
        shared = sum(1 for viewers in evidence.public_views.values() if len(viewers) >= 2)
        self.assertGreaterEqual(shared * 1000 // len(evidence.public_views), 980)
        self.assertGreaterEqual(len(evidence.refused_units), 10)
        self.assertGreaterEqual(len(evidence.deleted_sessions), 40)
        self.assertGreaterEqual(len(evidence.noted_sessions), 40)

    def test_bad_arguments_are_refused_before_any_request(self) -> None:
        origin = ClinicOrigin(DEFAULT_SEED, 12)
        self.addCleanup(origin.server.server_close)

        def refuse(*args: Any, **options: Any) -> labkit.Sent:
            raise AssertionError("no request may be sent")

        with self.assertRaises(ValueError):
            run_training(refuse, origin, DEFAULT_SEED + 1, 12, 4)
        with self.assertRaises(ValueError):
            run_training(refuse, origin, DEFAULT_SEED, 13, 4)
        with self.assertRaises(ValueError):
            run_training(refuse, origin, DEFAULT_SEED, 12, 0)


if __name__ == "__main__":
    unittest.main()

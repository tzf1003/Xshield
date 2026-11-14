"""Tests of the learning stage (plan 5.1, batch 5).

The unit tests need no PostgreSQL: the database tools and the control process are replaced by fakes,
and they check what the stage does to them, including the cleanup after success, failure and an
interrupt. The end-to-end test runs the real control on a throwaway database, and is skipped (reported
as skipped, not passed) when no PostgreSQL answers.
"""

from __future__ import annotations

import copy
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import labkit
from clinic_origin import ClinicOrigin, DEFAULT_SEED, site_spec
from clinic_traffic import Evidence, TRAINING_MODE, _attack_texts, run_training
from effectiveness import learning
from effectiveness.contracts import load_learned
from effectiveness.learning import LearningError, MAX_ROUNDS, _Learner, _public_share_doc, _round_doc, _with_entries
from fake_jev import FakeJev

# A stand-in for the control: it listens on the port the stage gives it, and does nothing else.
FAKE_CONTROL = """
import os, socket, time
host, port = os.environ["XSHIELD_CONTROL_LISTEN"].rsplit(":", 1)
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((host, int(port)))
listener.listen()
while True:
    time.sleep(0.1)
"""


def _refused(port: int) -> bool:
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
    except OSError:
        return True
    return False


def _decision_line(site: str, at_millis: int) -> dict[str, Any]:
    return {"at_millis": at_millis, "request_id": "req_test", "site": site, "decision_path": "fast_allow",
            "outcome": "allowed", "method": "GET", "path": "/api/home", "logical_path": "/api/home"}


class ImportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.spec = site_spec("none", 1)

    def _file(self, rows: list[str]) -> Path:
        path = Path(self.scratch.name) / "decisions.jsonl"
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        return path

    def test_rows_move_fifteen_minutes_back_and_the_file_is_unchanged(self) -> None:
        line = json.dumps(_decision_line("clinic-none", 1_800_000_000_000))
        path = self._file([line])
        before = path.read_text(encoding="utf-8")
        rows = learning._import_rows(path, self.spec)
        self.assertEqual([moment for moment, _ in rows], [1_800_000_000_000 - 15 * 60_000])
        imported = json.loads(rows[0][1])
        self.assertEqual(imported["at_millis"], 1_800_000_000_000 - 15 * 60_000)
        self.assertEqual(imported["request_id"], "req_test")
        self.assertEqual(path.read_text(encoding="utf-8"), before)

    def test_a_row_of_another_site_is_refused_with_its_line(self) -> None:
        path = self._file([json.dumps(_decision_line("clinic-none", 1)), json.dumps(_decision_line("clinic-truth", 2))])
        with self.assertRaisesRegex(LearningError, r"decisions\.jsonl:2 的站点是 'clinic-truth'"):
            learning._import_rows(path, self.spec)

    def test_an_empty_file_has_nothing_to_learn(self) -> None:
        with self.assertRaisesRegex(LearningError, "没有决策记录"):
            learning._import_rows(self._file([""]), self.spec)

    def test_identity_positions_must_be_declared_by_the_base(self) -> None:
        truth = {"identity": [{"key": "GET /api/home doctor.id", "identity": "org"}]}
        with self.assertRaisesRegex(LearningError, "身份位置 GET /api/home doctor.id"):
            learning._check_identity(self.spec, truth)
        learning._check_identity(self.spec, {"identity": [{"key": "GET /api/home doctor.id", "identity": "user"}]})


class SkipTest(unittest.TestCase):
    def test_without_the_client_tools_the_stage_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as scratch, mock.patch.object(learning.shutil, "which", return_value=None):
            result = learning.run(Path(scratch) / "missing.jsonl", site_spec("none", 1), None, Path(scratch) / "out")
        self.assertEqual(result["status"], "skip")
        self.assertIn("createdb", result["why"])
        self.assertIsNone(result["learned_path"])

    def test_a_refused_server_is_a_skip_with_the_reason(self) -> None:
        refused = subprocess.CompletedProcess(["createdb"], 2, "", "connection refused\nmore")
        with tempfile.TemporaryDirectory() as scratch:
            decisions = Path(scratch) / "decisions.jsonl"
            decisions.write_text(json.dumps(_decision_line("clinic-none", 1_800_000_000_000)) + "\n", encoding="utf-8")
            with mock.patch.object(learning.shutil, "which", return_value="/usr/bin/x"), \
                    mock.patch.object(learning, "_run_tool", return_value=refused):
                result = learning.run(decisions, site_spec("none", 1), None, Path(scratch) / "out")
        self.assertEqual(result["status"], "skip")
        self.assertIn("connection refused", result["why"])
        self.assertIsNone(result["final_spec"])


class ConfirmationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = site_spec("none", 1)
        self.names = {"patient": "患者"}

    def test_every_position_becomes_a_slot_and_declared_ones_stay(self) -> None:
        items = [
            ("GET /api/home doctor.id", "patient", "患者"),          # the administrator's identity: kept as it is
            ("GET /api/patients/{id} path[2]", "patient", "患者"),
            ("GET /api/visits/{id} patient_id", "patient", "患者"),  # a field: still a slot, so tiers can be judged
            ("GET /share/SHR-1 patient.id", "patients", "patients"),
        ]
        result, written = _with_entries(self.spec, items, self.names)
        self.assertEqual(written, 3)
        slots = {slot["key"]: slot for slot in result["objects"]["slots"]}
        self.assertEqual(slots["GET /api/home doctor.id"]["identity"], "user")
        self.assertEqual(slots["GET /api/patients/{id} path[2]"], {"key": "GET /api/patients/{id} path[2]",
                                                                   "class": "patient", "source": "rule"})
        self.assertEqual(set(result["objects"]), set(self.spec["objects"]), "no other part of the object map is written")
        classes = [entry["id"] for entry in result["objects"]["classes"]]
        self.assertEqual(classes.count("patient"), 1)
        self.assertIn("patients", classes)
        self.assertEqual(next(entry for entry in result["objects"]["classes"] if entry["id"] == "patients")["name"],
                         "patients")

    def test_the_same_confirmation_twice_writes_nothing_more(self) -> None:
        items = [("GET /api/patients/{id} path[2]", "patient", "患者")]
        once, first = _with_entries(self.spec, items, self.names)
        twice, second = _with_entries(once, items, self.names)
        self.assertEqual((first, second), (1, 0))
        self.assertEqual(twice, once)

    def test_the_configuration_given_is_not_changed(self) -> None:
        before = copy.deepcopy(self.spec)
        _with_entries(self.spec, [("GET /api/patients/{id} path[2]", "patient", "患者")], self.names)
        self.assertEqual(self.spec, before)


class RoundDocumentTest(unittest.TestCase):
    def _snapshot(self) -> dict[str, Any]:
        return {
            "slots": [
                {"key": "GET /api/home doctor.id", "state": "confirmed", "class": "doctor", "source": "admin",
                 "tier": None, "accepts_public": None, "reliability": None, "dismissed": False},
                {"key": "GET /api/search results[].id", "state": "proposed", "class": "patient", "source": "rule",
                 "dismissed": False},
            ],
            "judgements": [
                {"id": "a1", "key": "GET /api/patients patients[].id", "tier": "self", "units": 12,
                 "seen_values": 40, "agreement_per_mille": 990, "reliability": "high", "last_seen": None},
                {"id": "a2", "key": "DELETE /api/patients/{id} path[2]", "accepts_public": False, "votes": 48,
                 "sessions": 12, "public_per_mille": 0, "reliability": "medium", "last_seen": None},
            ],
        }

    def test_the_round_matches_the_contract_the_scorer_reads(self) -> None:
        run_row = {"at": "2026-11-13T11:00:00.250Z", "duration_ms": 300, "error": None, "proposals": 2,
                   "tightened": 0, "paused": 0}
        doc = _round_doc(1, run_row, self._snapshot())
        self.assertEqual(doc["run"]["started_millis"] + 300, doc["run"]["finished_millis"])
        self.assertEqual(doc["positions"][0]["source"], "admin", "identity positions stay in the snapshot")
        self.assertEqual(doc["positions"][1]["state"], "proposed")
        self.assertEqual(doc["judgements"][0], {"key": "GET /api/patients patients[].id", "reliability": "high",
                                                "tier": "self", "units": 12, "seen_values": 40,
                                                "agreement_per_mille": 990})
        self.assertEqual(doc["judgements"][1], {"key": "DELETE /api/patients/{id} path[2]", "reliability": "medium",
                                                "accepts_public": False, "votes": 48, "sessions": 12,
                                                "public_per_mille": 0})
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "learned.json"
            path.write_text(json.dumps({"bootstrap": [], "rounds": [doc], "final_spec": {}, "events": []}),
                            encoding="utf-8")
            loaded = load_learned(path)
        self.assertEqual(loaded["rounds"][0]["round"], 1)

    def test_a_learning_run_that_failed_stops_the_stage(self) -> None:
        run_row = {"at": "2026-11-13T11:00:00Z", "duration_ms": 5, "error": "decision log unreadable",
                   "proposals": 0, "tightened": 0, "paused": 0}
        with self.assertRaisesRegex(LearningError, "第 2 轮学习失败：decision log unreadable"):
            _round_doc(2, run_row, self._snapshot())


class PublicShareTest(unittest.TestCase):
    """A public share the control lists keeps the five fields the scorer reads, and nothing else (plan 9.4)."""

    def test_a_share_keeps_the_five_fields_the_scorer_reads(self) -> None:
        listed = {"id": 7, "key": "DELETE /api/patients/{id} path[2]", "public_per_mille": 106, "pending_per_mille": 40,
                  "votes": 198, "sessions": 12, "last_seen": "2026-11-13T11:00:00Z", "tier": None}
        self.assertEqual(_public_share_doc(listed), {"key": "DELETE /api/patients/{id} path[2]", "public_per_mille": 106,
                                                     "pending_per_mille": 40, "votes": 198, "sessions": 12})


class ConvergenceTest(unittest.TestCase):
    """The loop: rounds until two in a row confirm nothing, then one stability restart; at most MAX_ROUNDS."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)

    def _learner(self, confirmed: list[int]) -> tuple[_Learner, list[int], list[int]]:
        learner = _Learner(["control"], "postgresql://db", Path(self.scratch.name), lambda message: None, "clinic-none")
        learns: list[int] = []
        confirms: list[int] = []
        counts = iter(confirmed)

        def learn(number: int) -> tuple[dict[str, Any], dict[str, Any]]:
            learns.append(number)
            return {"round": number}, {"slots": [], "judgements": [], "classes": [], "events": []}

        def confirm(number: int, snapshot: dict[str, Any]) -> int:
            confirms.append(number)
            return next(counts)

        learner.learn = learn  # type: ignore[method-assign]
        learner.confirm = confirm  # type: ignore[method-assign]
        return learner, learns, confirms

    def test_two_quiet_rounds_then_one_stability_restart(self) -> None:
        learner, learns, confirms = self._learner([2, 1, 0, 0])
        rounds = learner.converge()
        self.assertEqual([doc["round"] for doc in rounds], [1, 2, 3, 4, 5])
        self.assertEqual(learns, [1, 2, 3, 4, 5])
        self.assertEqual(confirms, [1, 2, 3, 4])  # the stability restart confirms nothing

    def test_a_site_that_never_settles_stops_at_the_cap_without_a_stability_restart(self) -> None:
        learner, learns, confirms = self._learner([1] * MAX_ROUNDS)
        rounds = learner.converge()
        self.assertEqual(len(rounds), MAX_ROUNDS)
        self.assertEqual(learns, list(range(1, MAX_ROUNDS + 1)))
        self.assertEqual(confirms, list(range(1, MAX_ROUNDS + 1)))

    def test_nothing_to_confirm_from_the_start(self) -> None:
        learner, learns, _ = self._learner([0, 0])
        self.assertEqual(len(learner.converge()), 3)
        self.assertEqual(learns, [1, 2, 3])


class _FakeBootstrapApi:
    """The control's answers to the calls round 0 makes; every configuration saved is recorded in `puts`."""

    def __init__(self, spec: dict[str, Any], candidates: list[dict[str, Any]]) -> None:
        self.spec = spec
        self.candidates = candidates
        self.puts: list[dict[str, Any]] = []

    def call(self, method: str, path: str, document: Any = None, *, expect: tuple[int, ...] = (200,),
             raw: bytes | None = None, content_type: str | None = None) -> Any:
        if path.endswith("/objects/bootstrap"):
            return {"candidates": self.candidates}
        if method == "PUT":
            self.puts.append(document)
            return {}
        if method == "GET":
            return {"spec": copy.deepcopy(self.spec), "version": 1}
        return {}  # POST /api/sites


class BootstrapSelectionTest(unittest.TestCase):
    """Round 0 confirms what the console preselects (no note, no conflict); the rest is kept apart, with its note."""

    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.spec = site_spec("none", 1)

    @staticmethod
    def _candidate(key: str, **fields: Any) -> dict[str, Any]:
        candidate = {"key": key, "side": "request", "kind": "patient", "name": "患者", "uses": 40, "sessions": 9,
                     "note": None, "conflict": None}
        candidate.update(fields)
        return candidate

    def test_a_candidate_with_a_note_or_a_conflict_is_not_written(self) -> None:
        clear = "GET /api/patients/{id} path[2]"
        candidates = [
            self._candidate(clear),
            self._candidate("GET /api/visits/{id} path[2]", note="名字较短，可能是缩写，请确认类别"),
            self._candidate("GET /api/patients/{id} path[3]", conflict="doctor"),
            self._candidate("GET /api/x/{id} path[2]", note="使用次数少，请确认"),
        ]
        api = _FakeBootstrapApi(self.spec, candidates)
        learner = _Learner(["control"], "postgresql://db", Path(self.scratch.name), lambda message: None,
                           self.spec["name"])
        learner.api = api  # type: ignore[assignment]
        with mock.patch.object(learner, "_await_partitions"), mock.patch.object(learner, "_await_startup_pass"):
            learner.setup(self.spec, [])

        self.assertEqual(len(api.puts), 1)
        before = {slot["key"] for slot in self.spec.get("objects", {}).get("slots", [])}
        written = {slot["key"] for slot in api.puts[0]["spec"]["objects"]["slots"]} - before
        self.assertEqual(written, {clear}, "only the preselected candidate becomes a slot")
        self.assertEqual([item["key"] for item in learner.bootstrap], [clear])
        self.assertNotIn("note", learner.bootstrap[0], "learned.json's bootstrap keeps the scorer's fields only")
        self.assertEqual([item["key"] for item in learner.bootstrap_unpicked], [
            "GET /api/visits/{id} path[2]", "GET /api/patients/{id} path[3]", "GET /api/x/{id} path[2]"])
        self.assertEqual(learner.bootstrap_unpicked[0]["note"], "名字较短，可能是缩写，请确认类别")
        self.assertIsNone(learner.bootstrap_unpicked[0]["conflict"])
        self.assertIsNone(learner.bootstrap_unpicked[1]["note"])
        self.assertEqual(learner.bootstrap_unpicked[1]["conflict"], "doctor")


class CleanupTest(unittest.TestCase):
    """The database is dropped and the control process stopped on success, failure and an interrupt."""

    def setUp(self) -> None:
        if os.name == "nt":
            self.skipTest("the stand-in control is a POSIX process")
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.fake = Path(self.scratch.name) / "fake_control.py"
        self.fake.write_text(FAKE_CONTROL, encoding="utf-8")
        self.port = labkit.free_port()
        self.tools: list[tuple[str, ...]] = []

        def tool(name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
            self.tools.append((name, *arguments))
            return subprocess.CompletedProcess([name], 0, "", "")

        for patch in (
            mock.patch.object(learning, "_run_tool", side_effect=tool),
            mock.patch.object(learning, "_password_hash", return_value="hash-for-the-test"),
            mock.patch.object(learning._Api, "login", return_value=None),
            mock.patch.object(labkit, "free_port", return_value=self.port),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def _learn(self, **stages: Any) -> dict[str, Any]:
        with mock.patch.multiple(_Learner, **stages):
            return learning._learn([(0, b"{}")], site_spec("none", 1), Path(self.scratch.name) / "out",
                                   lambda message: None, command=[sys.executable, str(self.fake)])

    def _names(self, tool: str) -> list[str]:
        return [call[-1] for call in self.tools if call[0] == tool]

    def assertDatabaseDropped(self) -> None:
        created = self._names("createdb")
        self.assertEqual(len(created), 1, "the stage creates one database")
        self.assertEqual(self._names("dropdb"), created, "the database it created is the one dropped")

    def test_success_stops_the_process_and_drops_the_database(self) -> None:
        result = self._learn(setup=lambda self_, base, rows: None, converge=lambda self_: [],
                             final_spec=lambda self_: {"objects": {}})
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["learned_path"].exists())
        self.assertTrue(_refused(self.port), "the control process is still listening")
        self.assertDatabaseDropped()

    def test_a_failure_stops_the_process_and_drops_the_database(self) -> None:
        def failing_setup(self_: _Learner, base: Any, rows: Any) -> None:
            raise LearningError("the control refused the import")

        with self.assertRaisesRegex(LearningError, "refused the import"):
            self._learn(setup=failing_setup)
        self.assertTrue(_refused(self.port), "the control process is still listening")
        self.assertDatabaseDropped()

    def test_an_interrupt_stops_the_process_and_drops_the_database(self) -> None:
        def interrupted(self_: _Learner) -> None:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self._learn(setup=lambda self_, base, rows: None, converge=interrupted)
        self.assertTrue(_refused(self.port), "the control process is still listening")
        self.assertDatabaseDropped()

    @unittest.skipIf(os.name == "nt", "os.kill with SIGTERM terminates the process on Windows")
    def test_sigterm_is_an_interrupt_while_the_stage_runs(self) -> None:
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(KeyboardInterrupt):
            with learning._terminate_as_interrupt():
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(1)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)


def _postgres_answers() -> bool:
    if learning.shutil.which("createdb") is None or learning.shutil.which("dropdb") is None:
        return False
    try:
        with learning._TemporaryDatabase(learning._database_base_url()):
            return True
    except learning._NoDatabase:
        return False


class LearnsOnPostgresTest(unittest.TestCase):
    """The real control learns the clinic's training traffic on a throwaway database, and nothing is left behind."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _postgres_answers():
            raise unittest.SkipTest("no PostgreSQL answers (createdb and dropdb, and XSHIELD_TEST_DATABASE_BASE_URL or PG*)")

    def test_the_stage_learns_the_training_traffic(self) -> None:
        labkit.build_edge()
        with tempfile.TemporaryDirectory() as scratch:
            decisions = Path(scratch) / "decisions.jsonl"
            sites = Path(scratch) / "sites.json"
            out = Path(scratch) / "learning"
            origin = ClinicOrigin(seed=DEFAULT_SEED, doctors=12)
            jev = FakeJev(attack_texts=_attack_texts())
            origin.start()
            edge: labkit.Edge | None = None
            try:
                jev.start()
                sites.write_text(json.dumps([site_spec("none", origin.port, mode=TRAINING_MODE)], ensure_ascii=False),
                                 encoding="utf-8")
                edge = labkit.Edge(sites, jev.url, labkit.free_port(), decisions)
                running = edge

                def through_edge(host: str, method: str, target: str, **options: Any) -> labkit.Sent:
                    return labkit.exchange(running, origin.was_served, host, method, target, **options)

                run_training(through_edge, origin, DEFAULT_SEED, 12, 4, config="none", mode=TRAINING_MODE,
                             evidence=Evidence())
            finally:
                if edge is not None:
                    edge.stop()
                jev.stop()
                origin.stop()
            result = learning.run(decisions, site_spec("none", origin.port, mode=TRAINING_MODE), None, out,
                                  log=lambda message: None)
            self.assertEqual(result["status"], "ok", result["why"])
            learned = load_learned(result["learned_path"])
            document = json.loads(result["learned_path"].read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(learned["rounds"]), 3)
        self.assertEqual([doc["round"] for doc in learned["rounds"]], list(range(1, len(learned["rounds"]) + 1)))
        self.assertIn("events", document)
        self.assertIn("bootstrap_unpicked", document)
        self.assertIsInstance(document["public_shares"], list, "the last round's public shares are kept (batch 10)")
        for share in document["public_shares"]:
            self.assertEqual(set(share), {"key", "public_per_mille", "pending_per_mille", "votes", "sessions"})
        for item in document["bootstrap_unpicked"]:
            self.assertTrue(item["note"] is not None or item["conflict"] is not None,
                            "an unpicked candidate has a note or a conflict")
        self.assertEqual(result["final_spec"]["name"], "clinic-none")


if __name__ == "__main__":
    unittest.main()

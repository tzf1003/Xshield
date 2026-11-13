"""Tests of the record and replay Jev (plan 6 and batch 9). None of them calls a real model or needs a key.

The record tests use a stub sender or a scripted endpoint on loopback, which stands in for the real Jev. The end-to-end
class runs the lab twice, once recording against that stand-in and once replaying with a refusing address and a
tripwire on every outbound call; it is skipped when xshield-edge is not built (cargo build -p xshield-edge).
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from unittest import mock

import labkit
from clinic_origin import DEFAULT_SEED
from effectiveness import jev_relay, lab
from fake_jev import FakeJev

RECORD_KEY = "lab-record-key-9c2e"  # a synthetic key: it must never reach a recording
REFUSED = AssertionError("replay must not send anything")
SKIPPED_LEARNING = {"status": "skip", "why": "测试里不跑学习段", "learned_path": None, "final_spec": None}


def judgement(*, age: int = 3, passed: int = 0, path: str = "/x", model: str = "m",
              questions: dict[str, Any] | None = None) -> bytes:
    """A judgement body in the shape the edge sends (judge::state::request_body)."""
    state = {"entry": {"matched": False}, "session": {"age_seconds": age, "entries_passed": passed},
             "recent": [], "request": {"method": "GET", "path": path, "values": []}}
    body = {"model": model, "state": state, "questions": questions if questions is not None else {"access": {}}}
    return json.dumps(body).encode("utf-8")


def reply(choice: str = "ALLOW") -> bytes:
    answers = {"access": {"type": "choice", "choice": choice, "probabilities": {choice: 0.9, "DENY": 0.05, "UNKNOWN": 0.05}}}
    return json.dumps({"answers": answers}).encode("utf-8")


def post(url: str, body: bytes, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    """A request to a relay on loopback, without any proxy from the environment."""
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", **(headers or {})})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def recording_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class RequestDigestTests(unittest.TestCase):
    def test_the_wall_clock_age_is_not_part_of_the_digest(self):
        self.assertEqual(jev_relay.request_digest(judgement(age=3)), jev_relay.request_digest(judgement(age=97)))

    def test_a_changed_state_question_or_model_gives_another_digest(self):
        base = jev_relay.request_digest(judgement())
        self.assertNotEqual(base, jev_relay.request_digest(judgement(passed=1)))
        self.assertNotEqual(base, jev_relay.request_digest(judgement(path="/y")))
        self.assertNotEqual(base, jev_relay.request_digest(judgement(model="other")))
        self.assertNotEqual(base, jev_relay.request_digest(judgement(questions={"access": {"instructions": "v2"}})))

    def test_the_order_of_the_keys_does_not_matter(self):
        first = json.dumps({"model": "m", "state": {"a": 1, "b": 2}, "questions": {}}).encode()
        second = json.dumps({"questions": {}, "state": {"b": 2, "a": 1}, "model": "m"}).encode()
        self.assertEqual(jev_relay.request_digest(first), jev_relay.request_digest(second))

    def test_a_body_that_is_not_json_is_keyed_by_its_bytes(self):
        self.assertEqual(jev_relay.request_digest(b"not json"), jev_relay.request_digest(b"not json"))
        self.assertNotEqual(jev_relay.request_digest(b"not json"), jev_relay.request_digest(b"other"))


class RecordingFileTests(unittest.TestCase):
    def write(self, text: str) -> Path:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "recording.jsonl"
        path.write_text(text, encoding="utf-8")
        return path

    def test_a_missing_file_is_an_error_that_names_it(self):
        path = Path(tempfile.mkdtemp()) / "absent.jsonl"
        with self.assertRaisesRegex(jev_relay.RelayError, "没有录制文件"):
            jev_relay.load_recording(path)

    def test_an_empty_file_is_an_error(self):
        with self.assertRaisesRegex(jev_relay.RelayError, "没有任何应答"):
            jev_relay.load_recording(self.write("\n"))

    def test_a_line_that_is_not_a_reply_is_an_error_with_its_place(self):
        digest = "a" * 64
        bad = {
            "not json": "{",
            "extra field": json.dumps({"digest": digest, "status": 200, "body": "", "key": "x"}),
            "short digest": json.dumps({"digest": "abc", "status": 200, "body": ""}),
            "status out of range": json.dumps({"digest": digest, "status": 700, "body": ""}),
            "body not text": json.dumps({"digest": digest, "status": 200, "body": {}}),
        }
        for name, line in bad.items():
            with self.subTest(name), self.assertRaisesRegex(jev_relay.RelayError, r"quick\.jsonl:1|recording\.jsonl:1"):
                jev_relay.load_recording(self.write(line + "\n"))

    def test_replies_under_one_digest_keep_their_order(self):
        digest = "b" * 64
        text = "".join(json.dumps({"digest": digest, "status": 200, "body": f"r{n}"}) + "\n" for n in (1, 2))
        queue = jev_relay.load_recording(self.write(text))[digest]
        self.assertEqual([entry.body for entry in queue], ["r1", "r2"])


class RecordTests(unittest.TestCase):
    def relay(self, sender, *, recording: Path | None = None) -> jev_relay.JevRelay:
        folder = tempfile.mkdtemp()
        relay = jev_relay.JevRelay(jev_relay.RECORD, recording=recording or Path(folder) / "rec.jsonl",
                                   endpoint="https://real.example/judge", key=RECORD_KEY, sender=sender)
        self.addCleanup(relay.stop)
        return relay

    def test_a_reply_is_returned_and_written_under_its_digest_with_no_headers_and_no_key(self):
        seen: list[tuple[str, bytes, dict[str, str]]] = []

        def sender(url: str, body: bytes, headers: Any) -> tuple[int, bytes]:
            seen.append((url, body, dict(headers)))
            return 200, reply("ALLOW")

        relay = self.relay(sender)
        relay.start()
        status, answer = relay.answer(judgement(), {"Authorization": f"Bearer {RECORD_KEY}", "Accept": "application/json",
                                                    "Connection": "keep-alive"})
        relay.stop()
        self.assertEqual((status, answer), (200, reply("ALLOW")))
        self.assertEqual(seen[0][0], "https://real.example/judge")
        self.assertEqual(seen[0][2].get("Authorization"), f"Bearer {RECORD_KEY}")  # forwarded verbatim
        self.assertNotIn("Connection", seen[0][2])  # hop-by-hop headers are not
        text = Path(relay.recording).read_text(encoding="utf-8")
        self.assertNotIn(RECORD_KEY, text)
        self.assertNotIn("Authorization", text)
        [line] = recording_lines(Path(relay.recording))
        self.assertEqual(set(line), {"digest", "status", "body"})
        self.assertEqual(line["digest"], jev_relay.request_digest(judgement()))
        self.assertEqual((relay.calls, relay.recorded, relay.failures), (1, 1, 0))

    def test_a_connection_that_fails_is_an_http_error_and_writes_nothing(self):
        def sender(url: str, body: bytes, headers: Any) -> tuple[int, bytes]:
            raise TimeoutError("no reply")

        relay = self.relay(sender)
        relay.start()
        status, _ = relay.answer(judgement(), {})
        relay.stop()
        self.assertEqual(status, 502)
        self.assertEqual(Path(relay.recording).read_text(encoding="utf-8"), "")  # nothing written for it
        self.assertEqual((relay.calls, relay.recorded, relay.failures), (1, 0, 1))

    def test_a_reply_that_carries_the_key_is_not_written_and_is_a_failure(self):
        def sender(url: str, body: bytes, headers: Any) -> tuple[int, bytes]:
            return 401, json.dumps({"error": f"bad key {RECORD_KEY}"}).encode()

        relay = self.relay(sender)
        relay.start()
        status, _ = relay.answer(judgement(), {})
        relay.stop()
        self.assertEqual(status, 502)
        self.assertNotIn(RECORD_KEY, Path(relay.recording).read_text(encoding="utf-8"))
        self.assertEqual(relay.failures, 1)

    def test_a_reply_that_is_not_2xx_is_a_failure_and_is_not_written(self):
        # A limit, an authentication failure or a server error is not an answer, and its body carries no key here, so
        # only the status makes it a failure. A recording that held it would hand replay a non-answer.
        for code in (429, 401, 500, 503):
            with self.subTest(status=code):
                def sender(url: str, body: bytes, headers: Any, code: int = code) -> tuple[int, bytes]:
                    return code, b'{"error":"refused"}'

                relay = self.relay(sender)
                relay.start()
                status, _ = relay.answer(judgement(), {})
                relay.stop()
                self.assertEqual(status, 502)
                self.assertEqual(Path(relay.recording).read_text(encoding="utf-8"), "")  # nothing written for it
                self.assertEqual((relay.calls, relay.recorded, relay.failures), (1, 0, 1))

    def test_a_record_needs_the_endpoint_and_the_key(self):
        with self.assertRaisesRegex(jev_relay.RelayError, "地址和密钥"):
            jev_relay.JevRelay(jev_relay.RECORD, recording=Path(tempfile.mkdtemp()) / "x.jsonl", endpoint="", key="")


class ReplayTests(unittest.TestCase):
    def write_recording(self, rows: list[dict[str, Any]]) -> Path:
        folder = tempfile.mkdtemp()
        path = Path(folder) / "rec.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path

    def replay(self, recording: Path) -> jev_relay.JevRelay:
        relay = jev_relay.JevRelay(jev_relay.REPLAY, recording=recording, sender=lambda *args: _refuse())
        self.addCleanup(relay.stop)
        return relay

    def test_a_recorded_request_gets_its_reply_in_recorded_order_and_a_new_one_gets_unknown(self):
        digest = jev_relay.request_digest(judgement())
        recording = self.write_recording([
            {"digest": digest, "status": 200, "body": reply("ALLOW").decode()},
            {"digest": digest, "status": 200, "body": reply("DENY").decode()},
        ])
        relay = self.replay(recording)
        first = relay.answer(judgement(age=40), {})
        second = relay.answer(judgement(age=41), {})
        third = relay.answer(judgement(), {})  # a third call with the same digest has no recorded reply left
        unseen = relay.answer(judgement(path="/other"), {})
        self.assertEqual(first, (200, reply("ALLOW")))
        self.assertEqual(second, (200, reply("DENY")))
        self.assertEqual(json.loads(third[1])["answers"]["access"]["choice"], "UNKNOWN")
        self.assertEqual(json.loads(unseen[1])["answers"]["attack"]["choice"], "UNKNOWN")
        self.assertEqual((relay.calls, relay.misses), (4, 2))

    def test_a_replayed_status_other_than_200_is_replayed_as_it_was(self):
        digest = jev_relay.request_digest(judgement())
        relay = self.replay(self.write_recording([{"digest": digest, "status": 503, "body": "{}"}]))
        self.assertEqual(relay.answer(judgement(), {}), (503, b"{}"))
        self.assertEqual(relay.misses, 0)

    def test_replay_never_calls_its_sender(self):
        relay = self.replay(self.write_recording([{"digest": "c" * 64, "status": 200, "body": "{}"}]))
        relay.answer(judgement(), {})  # a miss: UNKNOWN, and no call to the sender (which would raise)
        self.assertEqual(relay.misses, 1)

    def test_the_http_round_trip_gives_the_recorded_reply_to_the_edge(self):
        digest = jev_relay.request_digest(judgement())
        relay = self.replay(self.write_recording([{"digest": digest, "status": 200, "body": reply("DENY").decode()}]))
        relay.start()
        status, answer = post(relay.url, judgement(), {"Authorization": "Bearer anything"})
        self.assertEqual((status, answer), (200, reply("DENY")))

    def test_the_summary_has_counts_and_no_path_or_key(self):
        relay = self.replay(self.write_recording([{"digest": "d" * 64, "status": 200, "body": "{}"}]))
        summary = relay.summary()
        self.assertEqual(summary, {"mode": "replay", "calls": 0, "misses": 0, "recorded": 0, "failures": 0})


def _refuse() -> Any:
    raise REFUSED


class LoopbackRecordTests(unittest.TestCase):
    """A record through real HTTP: the relay sends to a scripted endpoint on loopback, through the default sender."""

    def test_the_default_sender_forwards_the_key_to_the_endpoint_and_keeps_it_out_of_the_file(self):
        seen: list[str] = []

        class Upstream(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                seen.append(self.headers.get("Authorization", ""))
                data = reply("ALLOW")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                return

        upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)
        folder = tempfile.mkdtemp()
        relay = jev_relay.JevRelay(jev_relay.RECORD, recording=Path(folder) / "rec.jsonl",
                                   endpoint=f"http://127.0.0.1:{upstream.server_address[1]}/judge", key=RECORD_KEY)
        self.addCleanup(relay.stop)
        relay.start()
        status, answer = post(relay.url, judgement(), {"Authorization": f"Bearer {RECORD_KEY}"})
        relay.stop()
        self.assertEqual((status, answer), (200, reply("ALLOW")))
        self.assertEqual(seen, [f"Bearer {RECORD_KEY}"])
        self.assertNotIn(RECORD_KEY, Path(relay.recording).read_text(encoding="utf-8"))


@unittest.skipUnless(labkit.EDGE.exists(), "xshield-edge is not built (cargo build -p xshield-edge)")
class RecordThenReplayTests(unittest.TestCase):
    """The acceptance of batch 9: a replay gives the metrics of its record, and it sends nothing."""

    def test_a_replay_gives_the_metrics_of_its_record_and_sends_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            real = FakeJev()  # stands in for the real Jev: a scripted endpoint on loopback, no key, no network
            real.start()
            self.addCleanup(real.stop)
            only = frozenset({"injection_sqli", "no_session"})
            record_out = root / "record"
            with mock.patch.object(lab, "_learning", return_value=SKIPPED_LEARNING):
                record_code = lab.execute(
                    lab.Options(seed=DEFAULT_SEED, users=3, logins=1, only=only, out=record_out, jev="record"),
                    live=(real.url, RECORD_KEY))
            recording = record_out / lab.RECORDING_NAME
            record = json.loads((record_out / "report.json").read_text(encoding="utf-8"))
            self.assertIn(record_code, (0, 1))  # the gates of this small run decide 0 or 1; a failed record is 2
            self.assertEqual(record["meta"]["jev_relay"]["failures"], 0)
            for written in record_out.rglob("*"):  # the key reaches no output file: reports, logs, sites, recording
                if written.is_file():
                    text = written.read_text(encoding="utf-8", errors="replace")
                    self.assertNotIn(RECORD_KEY, text, written.name)

            # The refusing address: a port that was just free, so nothing listens on it. The replay must not reach it,
            # and the tripwire on the lab's own opener fails the run if anything tries to.
            refusing = f"http://127.0.0.1:{labkit.free_port()}/judge"
            with mock.patch.object(lab, "_learning", return_value=SKIPPED_LEARNING), \
                    mock.patch.object(jev_relay, "DEFAULT_RECORDING", recording), \
                    mock.patch.object(jev_relay, "_opener", side_effect=REFUSED):
                replay_code = lab.execute(
                    lab.Options(seed=DEFAULT_SEED, users=3, logins=1, only=only, out=root / "replay", jev="replay"),
                    live=(refusing, RECORD_KEY))
            replay = json.loads((root / "replay" / "report.json").read_text(encoding="utf-8"))
            replay_text = (root / "replay" / "report.md").read_text(encoding="utf-8")
            record_text = (record_out / "report.md").read_text(encoding="utf-8")

        self.assertEqual(replay_code, record_code)
        self.assertEqual(replay["metrics"], record["metrics"])
        self.assertEqual(replay["gates"], record["gates"])
        self.assertEqual(replay["counts"], record["counts"])
        self.assertEqual(replay["needs"], record["needs"])
        self.assertEqual(replay["costs"]["jev_calls"], record["costs"]["jev_calls"])
        self.assertEqual(replay["meta"]["jev_relay"]["calls"], record["meta"]["jev_relay"]["calls"])
        self.assertEqual(replay["meta"]["jev_relay"]["misses"], 0)
        self.assertEqual(_without_ids(replay["failures"]), _without_ids(record["failures"]))
        self.assertEqual(_without_ids(replay["known_gaps"]), _without_ids(record["known_gaps"]))
        self.assertIsNotNone(record["confidence_scan"])  # a real model's run always gets the scan (plan 3.4)
        self.assertEqual(replay["confidence_scan"], record["confidence_scan"])
        self.assertIn("### 置信度门槛扫描（3.4）", replay_text)
        self.assertIn("- 回放未命中率：0 / ", replay_text)
        self.assertIn("- 录制：", record_text)


class RecordAbortTests(unittest.TestCase):
    """A record that an error cuts short still says that its recording is incomplete (acceptance, batch 9)."""

    def test_an_error_that_cuts_a_record_short_still_says_the_recording_is_incomplete(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            relay = jev_relay.JevRelay(jev_relay.RECORD, recording=root / lab.RECORDING_NAME,
                                       endpoint="https://real.example/judge", key=RECORD_KEY,
                                       sender=lambda url, body, headers: (429, b'{"error":"limit"}'))
            relay.answer(judgement(), {})  # the real Jev limits this judgement: a failure, and nothing is written
            options = lab.Options(seed=DEFAULT_SEED, users=3, logins=1, only=frozenset({"no_session"}),
                                  out=root / "record", jev="record")
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(lab, "_open_relay", return_value=relay), \
                    mock.patch.object(labkit, "build_edge"), \
                    mock.patch.object(lab, "_training", side_effect=RuntimeError("the public search for 外科 failed")), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = lab.execute(options, live=("https://real.example/judge", RECORD_KEY))
        self.assertEqual(code, 2)
        self.assertIn("error: the public search for 外科 failed", stderr.getvalue())
        self.assertIn("录制不完整：1 次调用没有得到可用的应答", stderr.getvalue())
        self.assertNotIn(RECORD_KEY, stderr.getvalue())


def _without_ids(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The failure and known-gap rows without request ids, which the edge makes new in every run."""
    return [{key: value for key, value in item.items() if key != "request_id"} for item in items]


@unittest.skipUnless(jev_relay.DEFAULT_RECORDING.exists(), "no recording is committed yet (plan 6, batch 9)")
class CommittedRecordingTests(unittest.TestCase):
    def test_the_committed_recording_loads_and_holds_no_credential(self):
        text = jev_relay.DEFAULT_RECORDING.read_text(encoding="utf-8")
        self.assertTrue(jev_relay.load_recording(jev_relay.DEFAULT_RECORDING))
        for word in ("Authorization", "Bearer", "api_key", "API_KEY"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()

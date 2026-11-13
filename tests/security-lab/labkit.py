"""Plumbing shared by the security lab runners: the edge process, the HTTP client and the paths.

scripts/test_idor_lab.py (docs/04 section 4.3) and the clinic traffic (tests/security-lab/clinic_traffic.py)
both run the real xshield-edge against a lab origin and the scripted Jev in fake_jev.py. Standard
library only, so the lab runs anywhere the Rust toolchain does.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Lock, Thread
from typing import IO, Any

ROOT = Path(__file__).resolve().parents[2]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
EDGE = TARGET / ("debug/xshield-edge.exe" if os.name == "nt" else "debug/xshield-edge")
# A lab-only key for the context hashes; nothing outside a lab run uses it.
CONTEXT_KEY_HEX = "5b" * 32
_source_notice_printed = False


def build_edge() -> None:
    """Builds the edge binary the labs run. CARGO_TARGET_DIR moves the output."""
    subprocess.run(["cargo", "build", "--quiet", "--locked", "-p", "xshield-edge", "--bin", "xshield-edge"],
                   cwd=ROOT, check=True)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def loopback_source(index: int) -> str | None:
    """The local address 127.0.1.<index> when this system lets a client bind to it, else None.

    Linux routes the whole of 127/8 to loopback, so each simulated user can send from its own
    address and count against its own address budget (docs/07 section 7.6). macOS and Windows bind
    only 127.0.0.1 unless an alias is added; there the caller uses 127.0.0.1 and one line says so.
    """
    global _source_notice_printed
    address = f"127.0.1.{index}"
    try:
        with socket.socket() as probe:
            probe.bind((address, 0))
        return address
    except OSError:
        if not _source_notice_printed:
            _source_notice_printed = True
            print(f"note: cannot bind {address} on this system; lab clients share 127.0.0.1", flush=True)
        return None


@dataclass
class Reply:
    status: int
    request_id: str | None
    headers: list[tuple[str, str]]
    body: bytes

    def json(self) -> dict:
        return json.loads(self.body) if self.body else {}


@dataclass
class Sent:
    reply: Reply
    record: dict | None
    served: bool


def request(port: int, host: str, method: str, target: str, *, cookie: str | None = None,
            form: dict[str, str] | None = None, json_body: dict | None = None,
            body: bytes | None = None, headers: dict[str, str] | None = None,
            source: str | None = None) -> Reply:
    """One request through the edge on 127.0.0.1:port, sent from `source` when one is given."""
    sent_headers = {"Host": host}
    if headers:
        sent_headers.update(headers)
    if cookie:
        sent_headers["Cookie"] = cookie
    payload = b""
    if body is not None:
        payload = body
    elif json_body is not None:
        payload = json.dumps(json_body, ensure_ascii=False).encode()
        sent_headers["Content-Type"] = "application/json"
    elif form is not None:
        payload = urllib.parse.urlencode(form).encode()
        sent_headers["Content-Type"] = "application/x-www-form-urlencoded"
    sent_headers["Content-Length"] = str(len(payload))
    source_address = (source, 0) if source else None
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10, source_address=source_address)
    try:
        connection.request(method, target, body=payload, headers=sent_headers)
        response = connection.getresponse()
        return Reply(response.status, response.getheader("X-Xshield-Request-Id"),
                     response.getheaders(), response.read())
    finally:
        connection.close()


def exchange(edge: Edge, was_served: Callable[[str], bool], host: str, method: str, target: str, *,
             source: str | None = None, **options: Any) -> Sent:
    """A request through the edge, with its decision record and whether the origin served it."""
    reply = request(edge.port, host, method, target, source=source, **options)
    record = edge.record_for(reply.request_id) if reply.request_id else None
    served = reply.request_id is not None and was_served(reply.request_id)
    return Sent(reply, record, served)


class Edge:
    """A running xshield-edge child process and the decision records it writes.

    With records_file, every decision record is also appended to that file as one JSON line, so a
    scorer reads decisions.jsonl exactly as the edge printed it (docs/07 section 7.4).
    """

    def __init__(self, sites_file: Path, jev_url: str, port: int, records_file: Path | None = None) -> None:
        env = {key: value for key, value in os.environ.items() if not key.startswith("XSHIELD_")}
        env.update({
            "XSHIELD_EDGE_LISTEN_PORTS": str(port),
            "XSHIELD_EDGE_SITES_FILE": str(sites_file),
            "XSHIELD_CONTEXT_KEY_HEX": CONTEXT_KEY_HEX,
            "XSHIELD_JEV_ROUTE": "direct",
            "XSHIELD_JEV_API_KEY": "lab-only-key",
            "XSHIELD_JEV_ENDPOINT": jev_url,
        })
        self.port = port
        self.lock = Lock()
        self.records: list[dict] = []
        self.stderr: list[str] = []
        self._sink: IO[str] | None = records_file.open("w", encoding="utf-8") if records_file else None
        self.process = subprocess.Popen(
            [str(EDGE)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        self._stdout_reader = Thread(target=self._read_stdout, daemon=True)
        self._stdout_reader.start()
        Thread(target=self._read_stderr, daemon=True).start()
        try:
            self._wait_listening()
        except Exception:
            self.stop()  # never leave a half-started edge running
            raise

    def _read_stdout(self) -> None:
        for line in self.process.stdout:  # one JSON decision record per line
            try:
                record = json.loads(line)
            except ValueError:
                continue
            with self.lock:
                self.records.append(record)
                if self._sink is not None:
                    self._sink.write(line if line.endswith("\n") else line + "\n")

    def _read_stderr(self) -> None:
        for line in self.process.stderr:
            with self.lock:
                self.stderr.append(line.rstrip())

    def _wait_listening(self) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("xshield-edge did not start:\n" + "\n".join(self.stderr_tail()))

    def record_for(self, request_id: str) -> dict | None:
        deadline = time.monotonic() + 5
        while True:
            with self.lock:
                for record in self.records:
                    if record.get("request_id") == request_id:
                        return record
            if time.monotonic() > deadline:
                return None
            time.sleep(0.002)  # the record is written just after the response, a few milliseconds later

    def stderr_tail(self, lines: int = 40) -> list[str]:
        with self.lock:
            return self.stderr[-lines:]

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self._stdout_reader.join(timeout=5)  # the last records are written before the file closes
        with self.lock:
            if self._sink is not None:
                self._sink.close()
                self._sink = None

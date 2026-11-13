"""The record and replay Jev of the protection-effectiveness lab (plan 6, batch 9).

`record` stands between the edge and the real Jev. Each judgement request goes to the real endpoint unchanged, and
the reply is written to a file under the digest of the request. `replay` answers from that file alone: the replies
recorded under one digest come back in the order they were recorded, so a replay of the same run gets the same
answers and sends nothing. A digest that is not in the file gets UNKNOWN for both questions and is counted as a miss.

The digest is SHA-256 of the request body as canonical JSON. The body holds the questions, which carry the
instruction text, so a changed instruction changes the digest (the instruction version); it also holds the state
and the model. Two parts are left out. `state.session.age_seconds` is the wall clock, which differs between any two
runs, and the instructions never read it. The file holds digests, statuses and replies, and nothing else: no request
headers and no key. A record run refuses to write a line that contains its key.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from typing import IO, Any

RECORD = "record"
REPLAY = "replay"
DEFAULT_RECORDING = Path(__file__).resolve().parent / "recordings" / "quick.jsonl"
UPSTREAM_TIMEOUT_SECONDS = 60
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
DIGEST = re.compile(r"[0-9a-f]{64}")
# Headers that belong to one connection, not to the request, and the two that urllib sets itself.
HOP_BY_HOP = frozenset({"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
                        "transfer-encoding", "upgrade", "host", "content-length"})
# What replay answers for a request it has no recording of: UNKNOWN for both questions. The edge reads an unusable
# answer as a failure (JEV_UNKNOWN), which the site's on_jev_unavailable decides.
UNKNOWN_REPLY = json.dumps({
    "model": "replay",
    "answers": {
        "access": {"type": "choice", "choice": "UNKNOWN", "probabilities": {"ALLOW": 0.0, "DENY": 0.0, "UNKNOWN": 1.0}},
        "attack": {"type": "choice", "choice": "UNKNOWN", "probabilities": {"BENIGN": 0.0, "ATTACK": 0.0, "UNKNOWN": 1.0}},
    },
}, separators=(",", ":"))
REPLY_HEADERS = frozenset({"digest", "status", "body"})

Sender = Callable[[str, bytes, Mapping[str, str]], tuple[int, bytes]]


class RelayError(RuntimeError):
    """A recording that cannot be read, or a settings problem. The message never carries a key or a reply."""


@dataclass(frozen=True)
class Entry:
    """One recorded reply: the HTTP status the real Jev gave, and its body as text."""

    status: int
    body: str


def request_digest(body: bytes) -> str:
    """The key of a judgement request (see the module docstring). A body that is not JSON is keyed by its bytes."""
    try:
        document = json.loads(body)
    except ValueError:
        return hashlib.sha256(body).hexdigest()
    state = document.get("state") if isinstance(document, dict) else None
    if isinstance(state, dict) and isinstance(state.get("session"), dict):
        session = {name: value for name, value in state["session"].items() if name != "age_seconds"}
        document = {**document, "state": {**state, "session": session}}
    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_recording(path: Path) -> dict[str, deque[Entry]]:
    """The recorded replies of a file, grouped by digest in the order they were written. A missing file, an empty
    one and a line that is not a reply are errors: replay never runs on a partial reading."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        raise RelayError(f"没有录制文件 {path}") from None
    entries: dict[str, deque[Entry]] = defaultdict(deque)
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        digest, entry = _parse_reply(line, f"{path.name}:{number}")
        entries[digest].append(entry)
    if not entries:
        raise RelayError(f"录制文件 {path} 里没有任何应答")
    return entries


def _parse_reply(line: str, where: str) -> tuple[str, Entry]:
    try:
        row = json.loads(line)
    except ValueError:
        raise RelayError(f"{where}: 不是 JSON") from None
    if not isinstance(row, dict) or set(row) != REPLY_HEADERS:
        raise RelayError(f"{where}: 应当只有 digest、status、body 三个字段")
    digest, status, body = row["digest"], row["status"], row["body"]
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise RelayError(f"{where}: digest 应为 64 位小写十六进制")
    if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
        raise RelayError(f"{where}: status 应为 HTTP 状态码")
    if not isinstance(body, str):
        raise RelayError(f"{where}: body 应为字符串")
    return digest, Entry(status, body)


def post_upstream(url: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, bytes]:
    """POSTs one judgement request to the real endpoint, with the headers the edge sent. An HTTP status of any kind is
    an answer; a connection that fails raises OSError."""
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with _opener(url).open(request, timeout=UPSTREAM_TIMEOUT_SECONDS) as reply:
            return reply.status, reply.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _opener(url: str) -> urllib.request.OpenerDirector:
    """A loopback address is reached directly; any other address goes through the environment's proxy settings."""
    if urllib.parse.urlsplit(url).hostname in LOOPBACK_HOSTS:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener()


class JevRelay:
    """A loopback HTTP endpoint that the edge uses as its Jev. Point the edge at `url` after `start`, and stop the relay
    after the edges have stopped. `record` needs the real endpoint and its key; `replay` needs the recording only and
    never opens a connection to anything.

    Counts: `calls` is every judgement request the relay saw. In replay, `misses` counts the requests that had no
    recorded reply. In record, `recorded` counts the replies written, and `failures` counts the requests that got no
    usable reply from the real endpoint, or whose reply carried the key; those are not written, so the recording is
    incomplete and the run must say so.
    """

    def __init__(self, mode: str, *, recording: Path, endpoint: str = "", key: str = "",
                 sender: Sender = post_upstream) -> None:
        if mode not in (RECORD, REPLAY):
            raise ValueError(f"unknown relay mode {mode!r}")
        if mode == RECORD and not (endpoint and key):
            raise RelayError("录制需要真实 Jev 的地址和密钥")
        self.mode = mode
        self.recording = recording
        self.endpoint = endpoint
        self._key = key
        self._sender = sender
        self._lock = Lock()
        self._replies: dict[str, deque[Entry]] = load_recording(recording) if mode == REPLAY else {}
        self._file: IO[str] | None = None
        self._started = False
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server.relay = self  # type: ignore[attr-defined]
        self.port: int = self._server.server_address[1]
        self.calls = 0
        self.misses = 0
        self.recorded = 0
        self.failures = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/judge"

    def start(self) -> None:
        if self.mode == RECORD:
            self.recording.parent.mkdir(parents=True, exist_ok=True)
            self._file = self.recording.open("w", encoding="utf-8")
        self._started = True
        Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self._started:
            self._server.shutdown()
            self._started = False
        self._server.server_close()
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None

    def answer(self, body: bytes, headers: Mapping[str, str]) -> tuple[int, bytes]:
        """The reply to one request from the edge: the recorded one in replay, the real one in record."""
        digest = request_digest(body)
        if self.mode == REPLAY:
            return self._replay(digest)
        return self._forward(digest, body, headers)

    def _replay(self, digest: str) -> tuple[int, bytes]:
        with self._lock:
            self.calls += 1
            queue = self._replies.get(digest)
            if queue:
                entry = queue.popleft()
                return entry.status, entry.body.encode("utf-8")
            self.misses += 1
        return 200, UNKNOWN_REPLY.encode("utf-8")

    def _forward(self, digest: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, bytes]:
        forwarded = {name: value for name, value in headers.items() if name.lower() not in HOP_BY_HOP}
        try:
            status, reply = self._sender(self.endpoint, body, forwarded)
            text = reply.decode("utf-8")
        except (OSError, http.client.HTTPException, ValueError):
            # A failed connection, or a reply that is not text, is not recorded. Its caller sees an HTTP error.
            with self._lock:
                self.calls += 1
                self.failures += 1
            return 502, b'{"error":"upstream"}'
        line = json.dumps({"digest": digest, "status": status, "body": text}, ensure_ascii=False)
        with self._lock:
            self.calls += 1
            if self._key in line:  # the key must never reach the file; the recording is then incomplete
                self.failures += 1
                return 502, b'{"error":"upstream"}'
            if self._file is not None:
                self._file.write(line + "\n")
                self._file.flush()
            self.recorded += 1
        return status, reply

    def summary(self) -> dict[str, Any]:
        """The counts the report prints (no path, no key, no reply)."""
        with self._lock:
            return {"mode": self.mode, "calls": self.calls, "misses": self.misses, "recorded": self.recorded,
                    "failures": self.failures}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:
        relay: JevRelay = self.server.relay  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        status, reply = relay.answer(body, dict(self.headers.items()))
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the edge's timeout passed first and it has closed the connection

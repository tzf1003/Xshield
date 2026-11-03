"""A scripted stand-in for the Jev judgement endpoint (docs/02 section 2.2).

CI cannot call a model, so the lab points XSHIELD_JEV_ENDPOINT here. Each answer
is fixed by the script below: the chosen option gets probability 0.9 and every
other option 0.05, so a run always gives the same result.

Script:
- a request value containing JEVDOWN gets HTTP 503 (provider unavailable);
- a value containing JEVSLOW gets its answer after one second, which a site
  with a 100 ms timeout turns into JEV_TIMEOUT;
- access is DENY when a value is an attempt (attempt over_privilege: the
  session saw it only in public responses, and its position takes none of
  them), and DENY when the request carries an object reference (kind
  "reference") that the session was never shown, except for the input the
  entry itself needs (the share code under /share/, the login form). Otherwise
  ALLOW;
- attack is ATTACK when a value or the path carries injection, path traversal
  or command execution text, and BENIGN otherwise.

Every judgement body is kept in `bodies`, so the lab can check what Jev was shown.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread

ACCESS_OPTIONS = ("ALLOW", "DENY", "UNKNOWN")
ATTACK_OPTIONS = ("BENIGN", "ATTACK", "UNKNOWN")
ATTACK_MARKERS = ("union select", "or 1=1", "../", "; cat ", "<script>")
ENTRY_INPUT_PATHS = ("/login",)
ENTRY_INPUT_PREFIXES = ("/share/",)


def _probabilities(options: tuple[str, ...], choice: str) -> dict[str, float]:
    return {option: 0.9 if option == choice else 0.05 for option in options}


def _answer(choice: str, options: tuple[str, ...]) -> dict:
    return {"type": "choice", "choice": choice, "probabilities": _probabilities(options, choice)}


def selects_object(value: dict) -> bool:
    """Whether a value names an existing record (docs/01 section 1.5).

    A path segment or query value counts when the edge labels it a reference.
    A body field counts only when it is an identifier, so free text typed into
    a body (the name of a new patient, a note) never selects anything.
    """
    at = str(value.get("at", ""))
    if at.startswith("body."):
        field = at.rsplit(".", 1)[-1].lower()
        return field == "id" or field.endswith("_id")
    return value.get("kind") == "reference"


def judge(document: dict) -> dict:
    """The answers the script gives for one judgement document."""
    state = document["state"]
    request = state["request"]
    path = request["path"]
    values = request.get("values", [])
    entry_input = state["entry"]["matched"] and (
        path in ENTRY_INPUT_PATHS or path.startswith(ENTRY_INPUT_PREFIXES)
    )
    # An attempt is refused whatever else the request says: the origin showed the
    # value only to the public, and the position takes no public sighting.
    attempt = any(value.get("attempt") == "over_privilege" for value in values)
    unseen = any(
        selects_object(value) and not value.get("verified") and not value.get("seen_as")
        for value in values
    ) and not entry_input
    text = " ".join([path, *(str(value.get("value", "")) for value in values)]).lower()
    access = "DENY" if attempt or unseen else "ALLOW"
    attack = "ATTACK" if any(marker in text for marker in ATTACK_MARKERS) else "BENIGN"
    return {
        "model": "fake-jev",
        "answers": {
            "access": _answer(access, ACCESS_OPTIONS),
            "attack": _answer(attack, ATTACK_OPTIONS),
        },
    }


class FakeJev:
    """The scripted endpoint on a loopback port, run in-process by the lab."""

    def __init__(self) -> None:
        self.lock = Lock()
        self.bodies: list[dict] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.service = self
        self.port: int = self.server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/systemone"

    def start(self) -> None:
        Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        document = json.loads(self.rfile.read(length))
        service: FakeJev = self.server.service  # type: ignore[attr-defined]
        with service.lock:
            service.bodies.append(document)
        values = document["state"]["request"].get("values", [])
        text = " ".join(str(value.get("value", "")) for value in values)
        if "JEVDOWN" in text:
            status, reply = 503, {"error": "unavailable"}
        else:
            if "JEVSLOW" in text:
                time.sleep(1.0)
            status, reply = 200, judge(document)
        data = json.dumps(reply).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the edge's timeout passed first and it has closed the connection

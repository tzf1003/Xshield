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

Ideal model (`FakeJev(attack_texts=...)`, the measurement's reference, see
tests/security-lab/corpus): the access rules are the same, but attack is ATTACK
exactly when one of the given texts lies wholly inside the path or inside one value,
once both sides are normalized by `normalize`. Each judgement's `state` is kept in
`states`, and `carries` tells whether a text reached Jev. Without `attack_texts` the
marker rules above apply, unchanged.
"""

from __future__ import annotations

import json
import time
import unicodedata
from collections.abc import Iterable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from urllib.parse import unquote_plus

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


def normalize(text: str) -> str:
    """The form the ideal model compares in: percent-decoded (a '+' is a space) until
    stable, then NFKC-folded (full-width characters become ASCII) and case-folded.
    """
    current = str(text)
    while True:
        decoded = unquote_plus(current)
        if decoded == current:
            break
        current = decoded
    return unicodedata.normalize("NFKC", current).casefold()


def attack_forms_of(texts: Iterable[str]) -> tuple[str, ...]:
    """The normalized attack texts the ideal model looks for, sorted and de-duplicated.

    A blank text is refused: it would sit inside every value and judge everything ATTACK.
    """
    forms: set[str] = set()
    for text in texts:
        if not isinstance(text, str):
            raise ValueError("attack texts must be strings")
        form = normalize(text)
        if not form.strip():
            raise ValueError("attack texts must not be blank")
        forms.add(form)
    return tuple(sorted(forms))


def _items(request: dict) -> list[str]:
    """The strings the ideal model reads from a request: its path and each of its values."""
    return [str(request["path"]), *(str(value.get("value", "")) for value in request.get("values", []))]


def _carried(forms: tuple[str, ...], items: Iterable[str]) -> bool:
    """Whether one normalized form lies wholly inside one normalized item."""
    texts = [normalize(item) for item in items]
    return any(form in text for form in forms for text in texts)


def judge(document: dict, attack_forms: tuple[str, ...] | None = None) -> dict:
    """The answers the script gives for one judgement document.

    With `attack_forms` (from `attack_forms_of`) the attack answer is the ideal model's;
    without it, the marker rules.
    """
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
    access = "DENY" if attempt or unseen else "ALLOW"
    if attack_forms is None:
        text = " ".join([path, *(str(value.get("value", "")) for value in values)]).lower()
        attack = "ATTACK" if any(marker in text for marker in ATTACK_MARKERS) else "BENIGN"
    else:
        attack = "ATTACK" if _carried(attack_forms, _items(request)) else "BENIGN"
    return {
        "model": "fake-jev",
        "answers": {
            "access": _answer(access, ACCESS_OPTIONS),
            "attack": _answer(attack, ATTACK_OPTIONS),
        },
    }


class FakeJev:
    """The scripted endpoint on a loopback port, run in-process by the lab.

    `attack_texts` switches the attack answer to the ideal model (see `judge`). Every
    judgement body is kept in `bodies`, and its `state` in `states`, in arrival order.
    """

    def __init__(self, attack_texts: Iterable[str] | None = None) -> None:
        self.lock = Lock()
        self.bodies: list[dict] = []
        self.states: list[dict] = []
        self.attack_forms = None if attack_texts is None else attack_forms_of(attack_texts)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.service = self
        self.port: int = self.server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1/systemone"

    def carries(self, text: str, call: int | None = None) -> bool:
        """Whether `text` lies wholly inside one path or value Jev was shown, after `normalize`.

        `call` picks one judgement by its index in `states` (0 is the first); without it any
        judgement counts. It tells a payload that never reached the model from one the model
        judged wrongly.
        """
        form = normalize(text)
        if not form.strip():
            raise ValueError("a blank text is inside every request")
        with self.lock:
            states = list(self.states) if call is None else [self.states[call]]
        return any(form in normalize(item) for state in states for item in _items(state["request"]))

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
            service.states.append(document["state"])
        values = document["state"]["request"].get("values", [])
        text = " ".join(str(value.get("value", "")) for value in values)
        if "JEVDOWN" in text:
            status, reply = 503, {"error": "unavailable"}
        else:
            if "JEVSLOW" in text:
                time.sleep(1.0)
            status, reply = 200, judge(document, service.attack_forms)
        data = json.dumps(reply).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the edge's timeout passed first and it has closed the connection

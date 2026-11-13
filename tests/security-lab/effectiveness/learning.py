"""The learning stage of the effectiveness lab (plan 5.1, batch 5): the object map learned from the
training decisions, through the control plane the console talks to.

The stage starts a throwaway PostgreSQL database and xshield-control on it, then does what the
administrator does with the object map, through the same HTTP API the console uses:

- round 0: the training decisions are imported with their time moved 15 minutes back (the control
  reads decisions that are at least 10 minutes old), and the cold-start candidates the console
  preselects (no note and no conflict, BootstrapList.tsx `startsPicked`) are confirmed as they are;
  the others are kept apart in learned.json as `bootstrap_unpicked`, with their note and conflict;
- rounds 1 to n: the control is restarted, which runs one learning pass at start-up; the object map
  is read, and what the pass proposes is confirmed as it is (classes of positions, tiers, accepts-public).
  The rounds stop when two in a row propose nothing; one more restart then checks stability;
- the result is learned.json (plan 9.4) and the final site configuration.

Nothing here reads the truth to decide what to confirm. The truth is used only to check that the
base configuration declares the administrator's identity positions, which the lab declares. Every
confirmed position is written as an `objects.slots` entry (plan 5.1), never as a field kind.

Without a usable PostgreSQL (createdb or dropdb missing, or the server refuses the connection) the
stage returns status "skip" with the reason. A failure of the pipeline itself raises LearningError.

A learned.json made from a real site keeps the share codes (`/share/SHR-...`, access codes in the paths)
as they appear in the position keys. Treat it like that site's decision log: do not commit it to the
repository, paste it into a PR, or put it in a shared folder. The lab's codes are synthetic.

Run it alone for debugging, from tests/security-lab:
    python3 -m effectiveness.learning --decisions FILE --out DIR [--truth FILE]
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import getpass
import http.client
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

import labkit
from clinic_origin import site_spec
from clinic_traffic import TRAINING_MODE

from .contracts import dump_json, load_truth

# The control reads decision rows that are at least 10 minutes old (LAG_MILLIS); the import moves
# every row 15 minutes back, so the first pass already reads all of them.
LAG_SHIFT_MILLIS = 15 * 60_000
# Plan 5.1 and 10: at most six rounds, counting the stability check.
MAX_ROUNDS = 6
# Rounds in a row that confirm nothing before the stability check.
QUIET_ROUNDS = 2
IMPORT_LINES = 1_000
RUN_TIMEOUT_SECONDS = 60.0
START_TIMEOUT_SECONDS = 20.0
STARTUP_GRACE_SECONDS = 2.0
DAY_MILLIS = 86_400_000
CONTROL_BINARY = "xshield-control.exe" if os.name == "nt" else "xshield-control"
# The numbers the control counted behind a judgement, kept in learned.json beside its value.
EVIDENCE_FIELDS = ("units", "seen_values", "agreement_per_mille", "votes", "sessions", "public_per_mille")

Log = Callable[[str], None]
Command = list[str]


class LearningError(RuntimeError):
    """The pipeline itself failed: the control plane refused a call, or a learning pass did not finish."""


class _NoDatabase(RuntimeError):
    """There is no PostgreSQL to learn on. The stage is skipped with this reason."""


def unavailable_reason() -> str | None:
    """Why the learning stage cannot run here (the client tools are missing, or the server refuses), or None when it can.
    It creates and drops a throwaway database to find out, so a run that needs the stage can stop before any work."""
    if shutil.which("createdb") is None or shutil.which("dropdb") is None:
        return "找不到 createdb 或 dropdb，PATH 里没有 PostgreSQL 客户端"
    try:
        with _TemporaryDatabase(_database_base_url()):
            pass
    except _NoDatabase as error:
        return str(error)
    return None


def run(decisions_path: Path, base_spec: dict[str, Any], truth: dict[str, Any] | None, out_dir: Path, *,
        log: Log = print) -> dict[str, Any]:
    """Runs the learning stage over the training decisions (the module docstring says how).

    `base_spec` is the lab's site configuration for the training traffic (`site_spec("none", port)`):
    its name must be the site name the decisions carry. The returned `final_spec` is the configuration
    as the control saved it, under the base's name and origin; the caller renames it and sets its mode
    for the configuration it runs.

    Returns {"status": "ok", "why": "", "learned_path": Path, "final_spec": dict} when the stage ran, or
    {"status": "skip", "why": reason, "learned_path": None, "final_spec": None} without PostgreSQL.
    """
    if shutil.which("createdb") is None or shutil.which("dropdb") is None:
        return _skipped("找不到 createdb 或 dropdb，PATH 里没有 PostgreSQL 客户端")
    rows = _import_rows(decisions_path, base_spec)
    _check_identity(base_spec, truth)
    try:
        return _learn(rows, base_spec, out_dir, log)
    except _NoDatabase as error:
        return _skipped(str(error))


def _learn(rows: list[tuple[int, bytes]], base_spec: dict[str, Any], out_dir: Path, log: Log, *,
           command: Command | None = None) -> dict[str, Any]:
    """The stage itself. `command` replaces the built control binary; the tests use a stand-in."""
    with _terminate_as_interrupt(), contextlib.ExitStack() as stack:
        database = stack.enter_context(_TemporaryDatabase(_database_base_url()))
        out_dir.mkdir(parents=True, exist_ok=True)
        if command is None:
            command = [str(_build_control())]
        learner = _Learner(command, database.url, out_dir, log, base_spec["name"])
        stack.callback(learner.stop)
        learner.start("setup")
        learner.setup(base_spec, rows)
        rounds = learner.converge()
        final_spec = learner.final_spec()
    # `events` is what the control's automatic changes left over the last round (tightenings and pauses); the
    # scorer does not read it, and it explains the positions the rounds show.
    # `bootstrap_unpicked`: what round 0 did not confirm, since the console does not preselect it. The scorer ignores it.
    learned = {"bootstrap": learner.bootstrap, "bootstrap_unpicked": learner.bootstrap_unpicked, "rounds": rounds,
               "final_spec": final_spec, "events": learner.last_events}
    learned_path = out_dir / "learned.json"
    dump_json(learned_path, learned)
    return {"status": "ok", "why": "", "learned_path": learned_path, "final_spec": final_spec}


def _skipped(reason: str) -> dict[str, Any]:
    return {"status": "skip", "why": reason, "learned_path": None, "final_spec": None}


# ---------------------------------------------------------------- inputs

def _import_rows(decisions_path: Path, base_spec: dict[str, Any]) -> list[tuple[int, bytes]]:
    """The decision rows as (moved time, import line), each moved LAG_SHIFT_MILLIS back. The file is not changed."""
    site = base_spec["name"]
    rows: list[tuple[int, bytes]] = []
    for number, text in enumerate(decisions_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not text.strip():
            continue
        where = f"{decisions_path.name}:{number}"
        try:
            record = json.loads(text)
        except ValueError as error:
            raise LearningError(f"{where} 不是 JSON：{error}") from error
        if not isinstance(record, dict):
            raise LearningError(f"{where} 不是 JSON 对象")
        if record.get("site") != site:
            raise LearningError(f"{where} 的站点是 {record.get('site')!r}，站点配置是 {site!r}")
        if not isinstance(record.get("at_millis"), int):
            raise LearningError(f"{where} 没有整数的 at_millis")
        record["at_millis"] -= LAG_SHIFT_MILLIS
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        rows.append((record["at_millis"], line))
    if not rows:
        raise LearningError(f"{decisions_path.name} 没有决策记录，没有可以学习的内容")
    return rows


def _check_identity(base_spec: dict[str, Any], truth: dict[str, Any] | None) -> None:
    """The administrator's identity positions must be declared in the base configuration: learning
    starts from them, and the scorer leaves them out of the proposals."""
    if truth is None:
        return
    declared = {slot.get("key"): slot.get("identity")
                for slot in (base_spec.get("objects") or {}).get("slots") or []}
    for item in truth["identity"]:
        if declared.get(item["key"]) != item["identity"]:
            raise LearningError(f"站点配置没有声明身份位置 {item['key']}（应为 {item['identity']}）")


# ---------------------------------------------------------------- the object map, as the console writes it

def _with_entries(spec: dict[str, Any], items: list[tuple[str, str, str]],
                  names: dict[str, str]) -> tuple[dict[str, Any], int]:
    """The configuration with each confirmed position declared as a slot of source `rule`, and a class the
    configuration lacks added under its name. A position the configuration already declares is not replaced.
    Returns the new configuration and how many slots it added.

    Plan 5.1 writes every confirmed position as `objects.slots`. The console writes a field name (`id`,
    `patient_id`) as a field kind instead, but the tier judgement only reads slot entries (`judge_tiers`), so
    a field kind would leave every such response position without a tier."""
    result = copy.deepcopy(spec)
    objects = result.setdefault("objects", {})
    classes = objects.setdefault("classes", [])
    slots = objects.setdefault("slots", [])
    declared = {slot["key"] for slot in slots}
    class_ids = {entry["id"] for entry in classes}
    written = 0
    for key, kind, name in items:
        if key in declared:
            continue
        slots.append({"key": key, "class": kind, "source": "rule"})
        declared.add(key)
        written += 1
        if kind not in class_ids:
            classes.append({"id": kind, "name": names.get(kind) or name})
            class_ids.add(kind)
    return result, written


# ---------------------------------------------------------------- documents

def _millis(text: str) -> int:
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 1000)


def _position_doc(row: dict[str, Any]) -> dict[str, Any]:
    return {"key": row["key"], "state": row["state"], "class": row.get("class"), "source": row.get("source"),
            "tier": row.get("tier"), "accepts_public": row.get("accepts_public"),
            "reliability": row.get("reliability")}


def _judgement_body(item: dict[str, Any]) -> dict[str, Any]:
    """The body of `judgement/confirm` for one proposal: its value and how sure the rules are."""
    body: dict[str, Any] = {"reliability": item["reliability"]}
    if "tier" in item:
        body["tier"] = item["tier"]
    else:
        body["accepts_public"] = item["accepts_public"]
    return body


def _judgement_doc(item: dict[str, Any]) -> dict[str, Any]:
    """The judgement with the evidence the control counted for it, so each value can be read beside its numbers."""
    evidence = {name: item[name] for name in EVIDENCE_FIELDS if name in item}
    return {"key": item["key"], **_judgement_body(item), **evidence}


def _round_doc(number: int, run_row: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    if run_row.get("error"):
        raise LearningError(f"第 {number} 轮学习失败：{run_row['error']}")
    started = _millis(run_row["at"])
    return {
        "round": number,
        "run": {"started_millis": started, "finished_millis": started + int(run_row["duration_ms"]), "error": None,
                "proposals": run_row["proposals"], "tightened": run_row["tightened"], "paused": run_row["paused"]},
        "positions": [_position_doc(row) for row in snapshot["slots"]],
        "judgements": [_judgement_doc(item) for item in snapshot["judgements"]],
    }


def _first_line(text: str | None) -> str:
    lines = (text or "").strip().splitlines()
    return lines[0] if lines else "没有输出"


# ---------------------------------------------------------------- processes and database

def _database_base_url() -> str:
    """The server of the throwaway databases, read the way scripts/test_postgres.sh reads it."""
    explicit = os.environ.get("XSHIELD_TEST_DATABASE_BASE_URL")
    if explicit:
        return explicit.rstrip("/")
    user = os.environ.get("PGUSER") or getpass.getuser()
    return f"postgresql://{user}@{os.environ.get('PGHOST', 'localhost')}:{os.environ.get('PGPORT', '5432')}"


def _connection_arguments(base_url: str) -> tuple[list[str], dict[str, str]]:
    """The host, port and user of the server for createdb and dropdb, and its password in the environment,
    never on the command line. The base URL names no database."""
    parts = urlsplit(base_url)
    arguments: list[str] = []
    if parts.hostname:
        arguments += ["-h", parts.hostname]
    if parts.port:
        arguments += ["-p", str(parts.port)]
    if parts.username:
        arguments += ["-U", unquote(parts.username)]
    environment = dict(os.environ)
    if parts.password is not None:
        environment["PGPASSWORD"] = unquote(parts.password)
    return arguments, environment


def _run_tool(tool: str, *arguments: str, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run([tool, *arguments], capture_output=True, text=True, check=False, env=environment)


class _TemporaryDatabase:
    """A database of a random name, created on entry and dropped on exit whatever happened."""

    def __init__(self, base_url: str) -> None:
        self.name = f"xshield_learning_{os.getpid()}_{secrets.token_hex(4)}"
        self.url = f"{base_url}/{self.name}"
        self.arguments, self.environment = _connection_arguments(base_url)

    def __enter__(self) -> _TemporaryDatabase:
        # --no-password: fail at once when no password is available. Without it, libpq can wait for one on stdin.
        created = _run_tool("createdb", "--no-password", *self.arguments, self.name, environment=self.environment)
        if created.returncode != 0:
            raise _NoDatabase(f"无法连接 PostgreSQL（createdb：{_first_line(created.stderr)}）")
        return self

    def __exit__(self, *_: object) -> bool:
        dropped = _run_tool("dropdb", "--no-password", *self.arguments, "--if-exists", self.name, environment=self.environment)
        if dropped.returncode != 0:
            manual = " ".join(["dropdb", *self.arguments, "--if-exists", self.name])
            print(f"学习段：没能删除临时库 {self.name}（{_first_line(dropped.stderr)}）。"
                  f"请手动删除：{manual}", file=sys.stderr)
        return False


def _build_control() -> Path:
    try:
        subprocess.run(["cargo", "build", "--quiet", "--locked", "-p", "xshield-control", "--bin", "xshield-control"],
                       cwd=labkit.ROOT, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise LearningError(f"编译 xshield-control 失败：{error}") from error
    binary = labkit.TARGET / "debug" / CONTROL_BINARY
    if not binary.exists():
        raise LearningError(f"编译后没有 {binary}")
    return binary


def _password_hash(command: Command, password: str) -> str:
    """The hash of this run's one-time administrator password. The password goes in on stdin, never in argv."""
    done = subprocess.run([*command, "hash-password"], input=password + "\n", capture_output=True, text=True,
                          check=False)
    if done.returncode != 0 or not done.stdout.strip():
        raise LearningError(f"xshield-control hash-password 失败（{_first_line(done.stderr)}）")
    return done.stdout.strip()


@contextlib.contextmanager
def _terminate_as_interrupt() -> Iterator[None]:
    """A SIGTERM to the lab raises KeyboardInterrupt in the stage, so its cleanup runs the same way."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def interrupt(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


class _Control:
    """One control process on a loopback port of its own, with its log beside the other outputs."""

    def __init__(self, command: Command, env: dict[str, str], log_path: Path) -> None:
        self.command = command
        self.env = env
        self.log_path = log_path
        self.process: subprocess.Popen[bytes] | None = None
        self.port = 0
        self._log: Any = None

    def start(self) -> int:
        self.port = labkit.free_port()
        self._log = self.log_path.open("wb")
        env = dict(self.env, XSHIELD_CONTROL_LISTEN=f"127.0.0.1:{self.port}")
        self.process = subprocess.Popen(self.command, env=env, stdout=self._log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while True:
            if self.process.poll() is not None:
                raise LearningError(f"xshield-control 启动即退出（退出码 {self.process.returncode}）：{self.log_tail()}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return self.port
            except OSError:
                if time.monotonic() > deadline:
                    raise LearningError(f"xshield-control 在 {START_TIMEOUT_SECONDS:.0f} 秒内没有开始监听：{self.log_tail()}")
                time.sleep(0.05)

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def log_tail(self, lines: int = 8) -> str:
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return "（没有日志）"
        return " | ".join(text[-lines:]) or "（日志为空）"

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self._log is not None:
            self._log.close()
            self._log = None


class _Api:
    """The control plane's HTTP API on one loopback port, with the session cookie of the login."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.cookie = ""

    def _send(self, method: str, path: str, body: bytes | None, content_type: str) -> tuple[int, bytes, str | None]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        headers: dict[str, str] = {}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if body is not None:
            headers["Content-Type"] = content_type
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read(), response.getheader("Set-Cookie")
        finally:
            connection.close()

    def login(self, password: str) -> None:
        status, _, cookie = self._send("POST", "/api/login", json.dumps({"password": password}).encode(),
                                       "application/json")
        if status != 200 or not cookie:
            raise LearningError(f"登录控制台失败（{status}）")
        self.cookie = cookie.split(";", 1)[0]

    def call(self, method: str, path: str, document: Any = None, *, expect: tuple[int, ...] = (200,),
             raw: bytes | None = None, content_type: str = "application/json") -> Any:
        body = raw if raw is not None else (None if document is None else json.dumps(document, ensure_ascii=False).encode())
        status, data, _ = self._send(method, path, body, content_type)
        if status not in expect:
            code = ""
            with contextlib.suppress(ValueError, AttributeError):
                code = json.loads(data).get("error", "")
            raise LearningError(f"{method} {path} 返回 {status}（{code or '无错误码'}）")
        return json.loads(data) if data else None


def _is_picked(candidate: dict[str, Any]) -> bool:
    """The console preselects a candidate with no note and no conflict (BootstrapList.tsx `startsPicked`)."""
    return candidate.get("note") is None and candidate.get("conflict") is None


def _candidate_doc(item: dict[str, Any]) -> dict[str, Any]:
    """A cold-start candidate as learned.json keeps it: the fields the scorer reads."""
    return {"key": item["key"], "side": item["side"], "class": item["kind"], "uses": item["uses"],
            "sessions": item["sessions"]}


class _Learner:
    """The control plane for one stage: the process, the site, and the rounds run on it."""

    def __init__(self, command: Command, database_url: str, out_dir: Path, log: Log, site: str) -> None:
        self.command = command
        self.database_url = database_url
        self.out_dir = out_dir
        self.log = log
        self.site = site
        self.password = secrets.token_urlsafe(18)
        self.hash: str | None = None
        self.control: _Control | None = None
        self.api: _Api | None = None
        self.bootstrap: list[dict[str, Any]] = []
        self.bootstrap_unpicked: list[dict[str, Any]] = []
        self.last_events: list[dict[str, Any]] = []
        self.confirmed: set[tuple[str, ...]] = set()

    @property
    def site_path(self) -> str:
        return f"/api/sites/{quote(self.site, safe='')}"

    def start(self, label: str) -> None:
        """Starts a control process on the database, and logs in. The log is `control-<label>.log`."""
        if self.hash is None:
            self.hash = _password_hash(self.command, self.password)
        env = {key: value for key, value in os.environ.items() if not key.startswith("XSHIELD_")}
        env.update({
            "XSHIELD_DATABASE_URL": self.database_url,
            "XSHIELD_ADMIN_PASSWORD_HASH": self.hash,
            "XSHIELD_CONTROL_PLAIN_HTTP": "true",
        })
        self.control = _Control(self.command, env, self.out_dir / f"control-{label}.log")
        self.api = _Api(self.control.start())
        self.api.login(self.password)

    def stop(self) -> None:
        if self.control is not None:
            self.control.stop()
        self.control = None
        self.api = None

    def _api(self) -> _Api:
        if self.api is None:
            raise LearningError("没有运行中的控制台")
        return self.api

    def _settle(self) -> int:
        """Waits until no learning run is going, then returns the newest run id: a process may only be
        stopped between runs, since an unfinished run blocks the site's learning for 30 minutes."""
        deadline = time.monotonic() + RUN_TIMEOUT_SECONDS
        while True:
            runs = self._api().call("GET", f"{self.site_path}/objects/runs?limit=48")["runs"]
            if all(run["duration_ms"] is not None for run in runs):
                return max((run["id"] for run in runs), default=0)
            if time.monotonic() > deadline:
                raise LearningError("学习运行 60 秒内没有结束")
            time.sleep(0.2)

    def _wait_run(self, after: int) -> dict[str, Any]:
        """The learning run the process started at its start-up: the first finished run after `after`."""
        deadline = time.monotonic() + RUN_TIMEOUT_SECONDS
        while True:
            runs = self._api().call("GET", f"{self.site_path}/objects/runs?limit=48")["runs"]
            finished = [run for run in runs if run["id"] > after and run["duration_ms"] is not None]
            if finished:
                return max(finished, key=lambda run: run["id"])
            if self.control is None or not self.control.alive():
                raise LearningError(f"控制台在学习结束前退出：{self.control.log_tail() if self.control else ''}")
            if time.monotonic() > deadline:
                raise LearningError("启动时的学习 60 秒内没有结束")
            time.sleep(0.2)

    def setup(self, base_spec: dict[str, Any], rows: list[tuple[int, bytes]]) -> None:
        """Imports the training decisions, creates the site, and confirms the cold-start candidates (round 0)."""
        # The rows go in before the site exists. A learning pass that sees the site moves its read cursor past
        # every row it has read, and the rows here are 15 minutes back: a row imported after such a pass would
        # sit behind the cursor and never be read. A pass while there is no site reads nothing and moves nothing.
        self._await_partitions({moment for moment, _ in rows})
        lines = [line for _, line in rows]
        imported = skipped = out_of_range = failed = 0
        error_lines: list[int] = []
        for start in range(0, len(lines), IMPORT_LINES):
            chunk = lines[start:start + IMPORT_LINES]
            reply = self._api().call("POST", "/api/import", raw=b"\n".join(chunk) + b"\n",
                                     content_type="application/x-ndjson")
            imported += reply["imported"]
            skipped += reply["skipped"]
            out_of_range += reply["out_of_range"]
            failed += reply["errors"]
            error_lines.extend(reply["error_lines"][:5])
        if failed or out_of_range:
            raise LearningError(f"导入训练记录没有全部成功：{failed} 行无法读取（行号 {error_lines[:5]}），"
                                f"{out_of_range} 行超出保留期")
        self.log(f"学习段：导入训练记录 {imported} 条（重复跳过 {skipped} 条）")
        self._api().call("POST", "/api/sites", {"spec": base_spec}, expect=(201,))
        self._await_startup_pass()
        candidates = self._api().call("GET", f"{self.site_path}/objects/bootstrap")["candidates"]
        picked = [item for item in candidates if _is_picked(item)]
        self.bootstrap = [_candidate_doc(item) for item in picked]
        self.bootstrap_unpicked = [{**_candidate_doc(item), "note": item.get("note"), "conflict": item.get("conflict")}
                                   for item in candidates if not _is_picked(item)]
        items = [(item["key"], item["kind"], item.get("name") or item["kind"]) for item in picked]
        written = self._write_entries(items, {}, "学习段第 0 轮：确认控制台预选的冷启动候选")
        self.log(f"学习段：第 0 轮 冷启动候选 {len(candidates)} 条，预选确认 {len(picked)} 条（写入 {written} 项），"
                 f"未预选 {len(self.bootstrap_unpicked)} 条")

    def _await_partitions(self, moments: set[int]) -> None:
        """The decision log has one partition per UTC day, created by the control's first maintenance pass at
        start-up, which runs while the first requests arrive. An import line whose day has no partition is
        refused, so this waits until every day of the rows has one."""
        needed = {moment // DAY_MILLIS for moment in moments}
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        while True:
            storage = self._api().call("GET", "/api/system")["storage"]
            covered = {item["from_millis"] // DAY_MILLIS for item in storage["partitions"]
                       if item["from_millis"] is not None}
            if needed <= covered:
                return
            if time.monotonic() > deadline:
                raise LearningError(f"控制台 {START_TIMEOUT_SECONDS:.0f} 秒内没有建好 {len(needed - covered)} 个日分区")
            time.sleep(0.1)

    def _await_startup_pass(self) -> None:
        """The first process of the stage may run its start-up pass while the site is being created. The pass
        either lists the site, and then starts a run within a moment, or it does not. Waits for such a run to
        show, up to STARTUP_GRACE_SECONDS, and then for every run to finish: a process is stopped only between
        runs, since an unfinished run blocks the site's learning for 30 minutes."""
        deadline = time.monotonic() + STARTUP_GRACE_SECONDS
        while time.monotonic() < deadline:
            if self._api().call("GET", f"{self.site_path}/objects/runs?limit=1")["runs"]:
                break
            time.sleep(0.1)
        self._settle()

    def _write_entries(self, items: list[tuple[str, str, str]], names: dict[str, str], note: str) -> int:
        saved = self._api().call("GET", self.site_path)
        spec, written = _with_entries(saved["spec"], items, names)
        if written:
            self._api().call("PUT", self.site_path,
                             {"spec": spec, "expected_version": saved["version"], "note": note})
        return written

    def learn(self, number: int) -> tuple[dict[str, Any], dict[str, Any]]:
        """Restarts the control, which runs one learning pass, and reads the object map it leaves."""
        after = self._settle() if self.control is not None else 0
        self.stop()
        self.start(f"round-{number}")
        run_row = self._wait_run(after)
        snapshot = self._api().call("GET", f"{self.site_path}/objects")
        self.last_events = snapshot["events"]
        return _round_doc(number, run_row, snapshot), snapshot

    def confirm(self, number: int, snapshot: dict[str, Any]) -> int:
        """Confirms what the pass proposed, as the console does: the class of each proposed position, then
        the tier and accepts-public judgements. Returns how many confirmations changed the configuration."""
        names = {item["id"]: item["name"] for item in snapshot["classes"]}
        items: list[tuple[str, str, str]] = []
        for row in snapshot["slots"]:
            if row["state"] != "proposed" or row["class"] is None or row["dismissed"]:
                continue
            mark = ("entry", row["key"], row["class"])
            if mark in self.confirmed:
                continue
            self.confirmed.add(mark)
            items.append((row["key"], row["class"], names.get(row["class"], row["class"])))
        written = self._write_entries(items, names, f"学习段第 {number} 轮：原样确认类别提议") if items else 0
        judged = 0
        for item in snapshot["judgements"]:
            body = _judgement_body(item)
            mark = ("judgement", item["id"], json.dumps(body, sort_keys=True))
            if mark in self.confirmed:
                continue
            self.confirmed.add(mark)
            self._api().call("POST", f"{self.site_path}/objects/slots/{quote(item['id'], safe='')}/judgement/confirm",
                             body, expect=(200, 204))
            judged += 1
        self.log(f"学习段：第 {number} 轮 类别提议 {len(items)} 条（写入 {written} 项），"
                 f"档位与接受公共来源提议 {len(snapshot['judgements'])} 条（确认 {judged} 条）")
        return written + judged

    def converge(self) -> list[dict[str, Any]]:
        """Rounds until two in a row confirm nothing, then one more restart for stability. At most MAX_ROUNDS."""
        rounds: list[dict[str, Any]] = []
        quiet = 0
        while len(rounds) < MAX_ROUNDS:
            doc, snapshot = self.learn(len(rounds) + 1)
            rounds.append(doc)
            quiet = quiet + 1 if self.confirm(doc["round"], snapshot) == 0 else 0
            if quiet >= QUIET_ROUNDS:
                if len(rounds) < MAX_ROUNDS:
                    stability, _ = self.learn(len(rounds) + 1)
                    rounds.append(stability)
                    self.log(f"学习段：第 {stability['round']} 轮 稳定性核对，不确认任何内容")
                break
        return rounds

    def final_spec(self) -> dict[str, Any]:
        return self._api().call("GET", self.site_path)["spec"]


# ---------------------------------------------------------------- command line

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Learn the object map from training decisions (plan 5.1).")
    parser.add_argument("--decisions", type=Path, required=True, help="decisions.jsonl of the training traffic")
    parser.add_argument("--out", type=Path, required=True, help="directory for learned.json and the logs")
    parser.add_argument("--truth", type=Path, default=None, help="truth.json, to check the identity positions")
    arguments = parser.parse_args(argv)
    try:
        truth = load_truth(arguments.truth) if arguments.truth else None
        base = site_spec("none", labkit.free_port(), mode=TRAINING_MODE)
        result = run(arguments.decisions, base, truth, arguments.out)
    except (LearningError, OSError, ValueError) as error:
        print(f"学习段失败：{error}", file=sys.stderr)
        return 2
    if result["status"] == "skip":
        print(f"学习段未执行：{result['why']}")
        return 0
    print(f"学习段完成：{result['learned_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

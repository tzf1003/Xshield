"""The protection-effectiveness lab (plan 5.1): the training segment, the protection segment and the report.

    python3 scripts/measure_effectiveness.py [lab] [--mode quick|full] [--seed N] [--only X,Y] [--out DIR]
                                             [--jev ideal|live|record|replay]

Training: the clinic origin and the benign journeys of plan 4.2, through one edge in observation mode, with the ideal
model of fake_jev.py. Protection: the attack probes, the benign text and the regression cases (plan 4.3 to 4.5) through
one edge in enforcement mode, on a site without an object map and a site with one, plus a site with a per-session Jev
budget and one in observation mode for P1-5. Every site has an origin of its own, so the state of one site cannot
change what another site is given.

The learning segment (batch 5, effectiveness.learning) runs between the training and the protection segments when
PostgreSQL is available. The object map it learns from the training decisions becomes a third protection site,
clinic-learned, which gets the journeys and the probes of the object-map configurations. Without PostgreSQL, or when
the module cannot be imported, the report says the segment did not run and why, and no learned column appears.

The full mode (--mode full, batch 7, plan 5.2) has 48 doctors and the whole corpus, and adds: the convergence cost (L4)
over 3, 6, 12 and 24 users; the anti-pollution measure (L5), a learning over the training traffic with attack sessions
mixed in, whose search-then-delete position must not learn to accept public sources (a gate); the deletions in the order
of the day, whose public search result must learn public at high (a gate); the observation against the enforcement
(P6), the same protection batch on a fresh observation-mode site and on a fresh enforcement site, each on an edge of its
own; the consequence of the pollution for the protection (batch 10: clinic-polluted and clinic-polluted-set, each probed
like clinic-learned and compared with it probe by probe); a
regression case with a session table that overflows (b11-session-eviction, its own gateway); and the whole run a
second time, in a folder of its own, whose deterministic part must be equal. It needs PostgreSQL and the ideal model,
and it is refused with exit status 2 otherwise. The full group of the baseline file is its own.

The quick run compares with the quick group of tests/security-lab/effectiveness-baseline.json (plan 8): a missing
group fails the run, and the run's learning problems are checked against tests/security-lab/effectiveness-known-gaps.json
(known_gaps.py). --update-baseline writes the group of the mode it ran in, after the run passed every gate and no number
went down; it is refused with --only (part of the probes) and with a real Jev (the baseline is for the ideal model).

`--jev live` points the protection segment at the real Jev named by XSHIELD_JEV_ENDPOINT, with the key from
XSHIELD_JEV_API_KEY, and repeats every scored request three times. A missing endpoint or key is an error: the run
never falls back to the scripted model. The training stays on the ideal model, because its records are the learning's
input. The key is never written to a file, and it is redacted from the edge logs.

`--jev record` does the same against the real Jev and keeps every reply in jev-recording.jsonl in the output folder
(jev_relay.py). `--jev replay` reads the committed recording (recordings/quick.jsonl) and needs neither an endpoint nor
a key: it sends nothing, and a request without a recorded reply gets UNKNOWN and is counted in the report.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import importlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import labkit
from clinic_origin import DEFAULT_SEED, QUICK_DOCTORS, ClinicOrigin, site_spec
from clinic_traffic import Evidence, run_training
from fake_jev import FakeJev

from . import full, jev_relay, probes, regressions
from .cli import KNOWN_GAPS_PATH, _commit
from .contracts import (
    ContractError, baseline_group, dump_json, load_baseline, load_known_gaps, write_baseline,
)
from .report import render_markdown, render_terminal, report_document
from .score import (
    CONSEQUENCE,
    CONSEQUENCE_FIELD,
    CONSISTENCY_ENFORCE_GROUP,
    CONSISTENCY_GROUP,
    POLLUTED_SET_SITE,
    POLLUTED_SITE,
    baseline_values,
    confidence_scan,
    learning_metrics,
    score,
)

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "target" / "effectiveness" / "latest"
BASELINE_PATH = ROOT / "tests" / "security-lab" / "effectiveness-baseline.json"
LIVE_ENDPOINT_VARIABLE = "XSHIELD_JEV_ENDPOINT"
LIVE_KEY_VARIABLE = "XSHIELD_JEV_API_KEY"
LIVE_REPEATS = 3
RECORDING_NAME = "jev-recording.jsonl"  # the record mode writes it into the output folder
SOURCE_TEXT = {"ideal": "理想模型", "live": "真实 Jev", "record": "真实 Jev（录制）", "replay": "录制回放"}
JOURNEY_USERS, JOURNEY_LOGINS = 2, 1  # the benign journeys inside the protection segment: a small sample
FULL_ONLY_SKIP = "完整模式专用（--mode full），快速模式没有计算"
EVICTION_SKIP = "完整模式专用：会话表填满需要两万多次登录，快速模式不跑（b11-session-eviction）"
PAGE_PROBE_SKIP = "只在真实 Jev（--jev live、record、replay）下发送：理想模型比较不了没有类别的页码位置"
TRAIN_SITE = "clinic-none"
SITE_NONE, SITE_TRUTH = "clinic-none", "clinic-truth"
SITE_LIMIT = "clinic-truth-limit"
SITE_OBSERVE = "clinic-truth-observe"
SITE_LEARNED = "clinic-learned"  # the learned object map (batch 5), when the learning stage ran
SITE_EVICT = regressions.SITE_EVICT  # full mode only: the session table that overflows
# full mode only: the two halves of P6, each from a fresh origin, on an edge that hosts that site alone
SITE_P6_ENFORCE, SITE_P6_OBSERVE = "clinic-p6-enforce", "clinic-p6-observe"
# full mode only (batch 10): the learned mapping of the polluted training, as it is, and with each open position set by hand
SITE_POLLUTED, SITE_POLLUTED_SET = POLLUTED_SITE, POLLUTED_SET_SITE
JOURNEY_SITES = (SITE_NONE, SITE_TRUTH)  # the journeys and the probe families run on the two object-map configurations

Live = tuple[str, str]  # the real Jev's endpoint and key, both from the environment


@dataclass(frozen=True)
class Options:
    seed: int = DEFAULT_SEED
    mode: str = "quick"  # quick or full (plan 5.2)
    users: int = QUICK_DOCTORS
    logins: int = 4
    only: frozenset[str] = frozenset()
    out: Path = DEFAULT_OUT
    jev: str = "ideal"  # ideal, live, record or replay
    update_baseline: bool = False
    baseline: Path = BASELINE_PATH
    known_gaps: Path = KNOWN_GAPS_PATH

    @property
    def full(self) -> bool:
        return self.mode == "full"


def run(args: argparse.Namespace) -> int:
    """The `lab` subcommand: refuses what is not allowed, reads the settings of the chosen Jev, and runs."""
    if args.keep:
        return _not_built("--keep 要的控制台随学习段进来（批次 5）")
    only = frozenset(name.strip() for name in args.only.split(",") if name.strip())
    if args.update_baseline and only:
        return _not_built("--update-baseline 不能和 --only 同用：只跑了一部分探针，写下的数字不完整")
    if args.update_baseline and args.jev != "ideal":
        return _not_built("--update-baseline 只写理想模型下的基线")
    if args.mode == "full" and args.jev != "ideal":
        return _not_built("完整模式只用理想模型（--jev ideal），真实 Jev 的完整模式还没有估过调用次数")
    if args.mode == "full":
        problem = _database_problem()
        if problem is not None:
            return _not_built(f"完整模式需要 PostgreSQL（学习段）：{problem}")
    live: Live | None = None
    if args.jev in ("live", "record"):
        live = _live_settings(args.jev)
        if live is None:
            return 2
    options = Options(seed=args.seed, mode=args.mode, users=full.FULL_DOCTORS if args.mode == "full" else QUICK_DOCTORS,
                      only=only, out=args.out, jev=args.jev, update_baseline=args.update_baseline)
    return execute(options, live=live)


def _not_built(what: str) -> int:
    print(f"{what}，没有运行任何内容", file=sys.stderr)
    return 2


def _database_problem() -> str | None:
    """Why the learning stage cannot run here, or None. The full mode needs it, so it is checked before anything runs."""
    try:
        learning = importlib.import_module(".learning", __package__)
    except ImportError as error:
        return f"effectiveness.learning 导入失败：{error}"
    return learning.unavailable_reason()


def _live_settings(mode: str) -> Live | None:
    endpoint = os.environ.get(LIVE_ENDPOINT_VARIABLE, "").strip()
    key = os.environ.get(LIVE_KEY_VARIABLE, "").strip()
    if not endpoint or not key:
        print(f"error: --jev {mode} 需要环境变量 {LIVE_ENDPOINT_VARIABLE} 和 {LIVE_KEY_VARIABLE}；"
              "没有就报错退出，不退回模拟 Jev", file=sys.stderr)
        return None
    return endpoint, key


def _recording_incomplete(relay: jev_relay.JevRelay | None) -> bool:
    """True, with a message on stderr, when a record got a reply it could not keep (see jev_relay), whether the run
    finished or an error cut it short."""
    if relay is None or not relay.failures:
        return False
    print(f"error: 录制不完整：{relay.failures} 次调用没有得到可用的应答（或应答里带有密钥），"
          "录制文件不能用于回放，不要入库", file=sys.stderr)
    return True


def execute(options: Options, *, live: Live | None = None) -> int:
    """One run of the lab. The full mode runs the whole measurement a second time, in a folder of its own, and the
    deterministic part of the two reports must be equal (batch 7, the two-pass gate)."""
    started = time.monotonic()
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = options.out
    secrets: tuple[str, ...] = (live[1],) if live else ()
    try:
        relay = _open_relay(options, live, out)  # a replay reads its recording now, before any work starts
    except (jev_relay.RelayError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    try:
        out.mkdir(parents=True, exist_ok=True)
        labkit.build_edge()
        result, extra = _measure(options, live, relay, out, secrets)
        if options.full:
            second, second_extra = _measure(options, None, None, out / "second-pass", ())
            differing = full.differences(full.comparable(result), full.comparable(second))
            result["gates"].append(full.two_pass_gate(differing))
            result["gates"].append(full.consistency_gate(result["metrics"].get("P6")))
            result["gates"].append(full.natural_order_gate(result.get("natural_order")))
            result["gates"].append(full.polluted_delete_gate(result.get("pollution")))
            result["gates"].extend(full.consequence_gates(result["metrics"].get("L5")))
            result["passed"] = all(gate["ok"] is not False for gate in result["gates"])
            extra["two_pass"] = {"differing": differing, "seconds": [extra["seconds"], second_extra["seconds"]]}
        meta = {
            "commit": _commit(), "mode": options.mode, "jev": options.jev, "seed": options.seed,
            "started": stamp, "seconds": round(time.monotonic() - started, 3), "unsent": extra["unsent"],
            "jev_relay": relay.summary() if relay is not None else None,
            "timings": extra["timings"], "two_pass": extra.get("two_pass"),
        }
        dump_json(out / "report.json", report_document(result, meta))
        (out / "report.md").write_text(render_markdown(result, meta), encoding="utf-8")
        print(render_terminal(result, meta))
        print(f"报告：{out / 'report.md'}")
        if _recording_incomplete(relay):
            return 2
        if options.update_baseline:
            return _update_baseline(options, result, meta)
        return 0 if result["passed"] else 1
    except ContractError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        _recording_incomplete(relay)  # a run cut short by an error still says that its recording is incomplete
        return 2
    finally:
        if relay is not None:
            relay.stop()


def _measure(options: Options, live: Live | None, relay: jev_relay.JevRelay | None, out: Path,
             secrets: tuple[str, ...]) -> tuple[dict[str, Any], dict[str, Any]]:
    """One measurement: the segments and the score. Returns the result and what the report adds to its meta."""
    started = time.monotonic()
    real = options.jev != "ideal"
    out.mkdir(parents=True, exist_ok=True)
    ideal = FakeJev(attack_texts=probes.attack_texts())
    ideal.start()
    try:
        train_rows, train_records, truth, train_spec = _training(options, ideal, out, secrets)
        _say(f"训练段：{len(train_rows)} 个请求，观察模式，无对象表，理想模型")
        learning = _learning(train_spec, truth, out)
        _say("学习段：完成，学到的配置作为 clinic-learned 进入防护段" if learning["status"] == "ok"
             else f"学习段：SKIP（{learning['why']}）")
        extras: dict[str, Any] = {}
        polluted: dict[str, Any] | None = None  # the polluted mapping and its set variant (batch 10), full mode only
        if options.full:
            if learning["status"] != "ok":
                raise RuntimeError(f"完整模式的学习段没有执行：{learning['why']}")
            extras, polluted = _full_learning(options, ideal, truth, train_records, learning, out, secrets)
        protect_rows, protect_records, unsent, timings = _protection(options, ideal, live, relay, out, secrets,
                                                                     learning, polluted)
        _say(f"防护段：{len(protect_rows)} 个计分请求，{SOURCE_TEXT[options.jev]}")
        observations = [*train_rows, *protect_rows]
        decisions = [*train_records, *protect_records]
        _write_inputs(out, observations, decisions, truth)
        # The baseline is for the ideal model, and for a run that sends every probe (--only sends some of them).
        # A missing group fails the gate, unless this run is the one that writes it (--update-baseline).
        compared = not real and not options.only
        document = load_baseline(options.baseline) if compared and options.baseline.exists() else None
        group = baseline_group(document, options.mode) if compared else None
        result = score(observations, decisions, truth=truth, learned=_learned_document(learning),
                       baseline=group, gap_entries=_gap_entries(options),
                       check_gaps=not options.only,
                       require_baseline=compared and group is None and not options.update_baseline,
                       training=train_records)
        _mark_unrun(result, real=real, learning_why=learning["why"], full_mode=options.full)
        result.update(extras)
        if "pollution" in result:  # the consequence is read beside the pollution measure in report.json (batch 10)
            result["pollution"]["consequence"] = result["metrics"].get("L5")
        if real:  # the scan needs a real model's probabilities; the ideal model's are fixed (plan 10, batch 9)
            result["confidence_scan"] = confidence_scan(protect_rows, protect_records)
    finally:
        ideal.stop()
    return result, {"unsent": unsent, "timings": timings, "seconds": round(time.monotonic() - started, 3)}


def _update_baseline(options: Options, result: dict[str, Any], meta: dict[str, Any]) -> int:
    """Writes the group of the mode, when the run passed every gate and no number went down (plan 10, --update-baseline)."""
    if not result["passed"]:
        print("error: 门槛未通过，没有写基线（失败的门槛见报告）", file=sys.stderr)
        return 1
    if result["baseline"]["regressions"]:
        names = "、".join(item["name"] for item in result["baseline"]["regressions"])
        print(f"error: 有指标比基线差（{names}），没有写基线", file=sys.stderr)
        return 1
    group = {"seed": options.seed, "commit": meta["commit"], "values": baseline_values(result["metrics"])}
    write_baseline(options.baseline, options.mode, group)
    print(f"基线已写入：{options.baseline}（{options.mode} 组，提交 {meta['commit']}）")
    return 0


def _say(message: str) -> None:
    print(message, flush=True)


def _open_relay(options: Options, live: Live | None, out: Path) -> jev_relay.JevRelay | None:
    """The relay of the record and replay modes, None for the others. A record uses the real endpoint and key that
    run() read; a replay reads its recording here, so a missing or empty one stops the run before anything starts."""
    if options.jev == jev_relay.RECORD:
        if live is None:
            raise RuntimeError("--jev record 需要真实 Jev 的地址和密钥")
        return jev_relay.JevRelay(jev_relay.RECORD, recording=out / RECORDING_NAME, endpoint=live[0], key=live[1])
    if options.jev == jev_relay.REPLAY:
        return jev_relay.JevRelay(jev_relay.REPLAY, recording=jev_relay.DEFAULT_RECORDING)
    return None


# Training segment ---------------------------------------------------------------------------------------

def _training(options: Options, ideal: FakeJev, out: Path, secrets: tuple[str, ...], *,
              attackers: int = 0, natural_order: bool = False) -> tuple[list[dict[str, Any]], list[dict[str, Any]],
                                                                        dict[str, Any], dict[str, Any]]:
    """The training rows, their decision records, the origin's truth, and the site configuration they ran on. The
    attackers are attack sessions mixed in (the anti-pollution run); the rest is the same traffic as always.
    `natural_order` is the report-only variant of the full mode (see run_training)."""
    out.mkdir(parents=True, exist_ok=True)
    origin = ClinicOrigin(seed=options.seed, doctors=options.users)
    origin.start()
    try:
        train_spec = _spec(origin, TRAIN_SITE, "none", "observe")
        sites = _write_sites(out / "sites-train.json", [train_spec])
        edge = labkit.start_edge(sites, ideal.url, out / "decisions-train.jsonl")
        try:
            def send(host: str, method: str, target: str, **options_: Any) -> labkit.Sent:
                return labkit.exchange(edge, origin.was_served, host, method, target, **options_)

            rows = run_training(send, origin, options.seed, options.users, options.logins, config="none",
                                mode="observe", evidence=Evidence(), full=options.full, attackers=attackers,
                                natural_order=natural_order)
        finally:
            records = _finish_edge(edge, out, "train", secrets)
        _write_jsonl(out / "observations-train.jsonl", rows)  # the edge already wrote decisions-train.jsonl
        return rows, records, origin.truth(), train_spec
    finally:
        origin.stop()


# Full mode: L4 and L5 -----------------------------------------------------------------------------------

def _full_learning(options: Options, ideal: FakeJev, truth: dict[str, Any], train_records: list[dict[str, Any]],
                   learning: Mapping[str, Any], out: Path, secrets: tuple[str, ...]) -> tuple[
                       dict[str, Any], dict[str, Any]]:
    """L4 (plan 3.2): the learning over 3, 6, 12 and 24 users, each on a site of its own, next to the run's own 48.
    L5: the learning over the run's training traffic with attack sessions mixed in, ten in a hundred of all sessions.
    Each run keeps its files in a folder of its own. Returns the measures for the report, and the polluted mapping's two
    configurations for the protection segment: as it is, and with each open position set by hand (batch 10)."""
    clean = learning_metrics(truth, _learned_document(learning), train_records)
    points: list[tuple[int, dict[str, Any]]] = []
    for users in full.CONVERGENCE_USERS:
        point_options = dataclasses.replace(options, users=users)
        point_out = out / f"convergence-{users}"
        _, records, point_truth, point_spec = _training(point_options, ideal, point_out, secrets)
        point_learning = _learning(point_spec, point_truth, point_out)
        if point_learning["status"] != "ok":
            raise RuntimeError(f"收敛段（{users} 个用户）的学习段没有执行：{point_learning['why']}")
        points.append((users, learning_metrics(point_truth, _learned_document(point_learning), records)))
        _say(f"收敛段：{users} 个用户的学习段完成")
    points.append((options.users, clean))

    benign_sessions = options.users * options.logins
    attackers = full.attacker_count(benign_sessions)
    pollution_out = out / "pollution"
    polluted_rows, polluted_records, polluted_truth, polluted_spec = _training(options, ideal, pollution_out, secrets,
                                                                              attackers=attackers)
    polluted_learning = _learning(polluted_spec, polluted_truth, pollution_out)
    if polluted_learning["status"] != "ok":
        raise RuntimeError(f"抗污染段的学习段没有执行：{polluted_learning['why']}")
    polluted_doc = _learned_document(polluted_learning)
    polluted = learning_metrics(polluted_truth, polluted_doc, polluted_records)
    _say(f"抗污染段：混入 {attackers} 个攻击会话后的学习段完成")
    # The polluted mapping as it is, and the same with every position the rules left open set by hand (batch 10). A
    # learned file from before batch 10 has no public_shares, and reads as none.
    shares = polluted_doc.get("public_shares", [])
    try:
        set_spec = full.set_public_positions(polluted_learning["final_spec"], shares)
    except ValueError as error:
        raise RuntimeError(f"抗污染段的防护后果没有执行：{error}") from error
    polluted_plan = {"spec": polluted_learning["final_spec"], "set_spec": set_spec}
    # The attack requests by category, with what the observation run did with each (plan 3.2, L5): the outcome in the
    # polluted run's own records, the same records the learning read.
    outcomes = {record["request_id"]: record["outcome"] for record in polluted_records}
    requests = full.attack_requests(polluted_rows, outcomes)
    # The natural-order variant (plan 10, batch 7): report only. Its public agreement and learned tier are read beside the
    # ordered run's.
    natural_out = out / "natural-order"
    _, natural_records, natural_truth, natural_spec = _training(options, ideal, natural_out, secrets, natural_order=True)
    natural_learning = _learning(natural_spec, natural_truth, natural_out)
    if natural_learning["status"] != "ok":
        raise RuntimeError(f"自然顺序变体的学习段没有执行：{natural_learning['why']}")
    natural = learning_metrics(natural_truth, _learned_document(natural_learning), natural_records)
    _say("自然顺序变体：删除穿插在搜索之间的学习段完成")
    measures = {
        "convergence": full.convergence(points),
        "pollution": full.pollution(clean, polluted, attackers=attackers, benign_sessions=benign_sessions,
                                    attack_requests=requests, set_shares=shares),
        "natural_order": full.natural_order(_learned_document(learning), _learned_document(natural_learning),
                                            ordered_metrics=clean, natural_metrics=natural),
    }
    return measures, polluted_plan


# Protection segment -------------------------------------------------------------------------------------

def _protection(options: Options, ideal: FakeJev, live: Live | None, relay: jev_relay.JevRelay | None, out: Path,
                secrets: tuple[str, ...], learning: Mapping[str, Any],
                polluted: Mapping[str, Any] | None = None) -> tuple[
                    list[dict[str, Any]], list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    """The scored rows and decision records of the protection segment, the payloads that were not sent at the path
    point in one run (the same in every run and on every journey site), and what the probes measured about the run.

    A real Jev repeats the whole segment LIVE_REPEATS times (plan 6). Each repeat gets origins and edges of its own:
    the probes write to the origins, and a repeat that found the first one's writes would not measure the same thing.
    """
    real = options.jev != "ideal"
    repeats = LIVE_REPEATS if real else 1
    jev_url, jev_key = _jev_target(ideal, live, relay)
    if relay is not None:
        relay.start()  # execute stops it, once the edges of every repeat have stopped
    pool = probes.Pool()
    rows: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    unsent: dict[str, int] = {}
    timings: dict[str, Any] = {}
    for run_no in range(1, repeats + 1):
        tag = "" if repeats == 1 else f"-r{run_no}"
        run_rows, run_records, run_unsent, run_timings = _protection_run(
            options, ideal, real, jev_url, jev_key, out, tag, secrets, learning, pool, run_no, polluted)
        rows.extend(run_rows)
        records.extend(run_records)
        if run_no == 1:
            unsent = run_unsent
        timings.update(run_timings)
    return rows, records, unsent, timings


def _protection_run(options: Options, ideal: FakeJev, real: bool, jev_url: str, jev_key: str, out: Path, tag: str,
                    secrets: tuple[str, ...], learning: Mapping[str, Any], pool: probes.Pool,
                    run_no: int, polluted: Mapping[str, Any] | None = None) -> tuple[
                        list[dict[str, Any]], list[dict[str, Any]], dict[str, int], dict[str, Any]]:
    """One pass over the protection sites, on origins and edges that start empty. `polluted` holds the two configurations of
    the anti-pollution consequence (batch 10); None outside the full mode."""
    learned_spec = learning["final_spec"]  # None when the learning stage did not run
    names = [SITE_NONE, SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE]
    if learned_spec:
        names.append(SITE_LEARNED)
    if options.full:
        names += [SITE_EVICT, SITE_P6_ENFORCE, SITE_P6_OBSERVE]
    if polluted is not None:
        names += [SITE_POLLUTED, SITE_POLLUTED_SET]
    origins = {name: ClinicOrigin(seed=options.seed, doctors=options.users) for name in names}
    for origin in origins.values():
        origin.start()
    rows: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    unsent: dict[str, int] = {}
    timings: dict[str, Any] = {}
    edges: list[tuple[labkit.Edge, str]] = []  # started edges, stopped and read in reverse order at the end
    attacks, benign = probes.attacks(full=options.full), probes.benign(full=options.full)
    try:
        protect_sites = [_spec(origins[SITE_NONE], SITE_NONE, "none", "enforce"),
                         _spec(origins[SITE_TRUTH], SITE_TRUTH, "truth", "enforce"),
                         _limit_spec(origins[SITE_LIMIT])]
        if learned_spec:
            protect_sites.append(_learned_spec(learned_spec, origins[SITE_LEARNED]))
        if polluted is not None:
            protect_sites.append(_learned_spec(polluted["spec"], origins[SITE_POLLUTED], SITE_POLLUTED))
            protect_sites.append(_learned_spec(polluted["set_spec"], origins[SITE_POLLUTED_SET], SITE_POLLUTED_SET))
        edge_p = labkit.start_edge(_write_sites(out / f"sites-protect{tag}.json", protect_sites), jev_url,
                                   out / f"decisions-protect{tag}.jsonl", jev_key=jev_key)
        edges.append((edge_p, f"protect{tag}"))
        observe_spec = _spec(origins[SITE_OBSERVE], SITE_OBSERVE, "truth", "observe")
        edge_o = labkit.start_edge(_write_sites(out / f"sites-observe{tag}.json", [observe_spec]), jev_url,
                                   out / f"decisions-observe{tag}.jsonl", jev_key=jev_key)
        edges.append((edge_o, f"observe{tag}"))
        p6_plan: dict[str, tuple[labkit.Edge, str]] = {}
        if options.full:
            # P6 (plan 3.3): each half of the batch gets a fresh origin and an edge that hosts that site alone, so the two
            # start alike and no other site's state reaches either of them.
            for name, mode in ((SITE_P6_ENFORCE, "enforce"), (SITE_P6_OBSERVE, "observe")):
                spec = _spec(origins[name], name, "truth", mode)
                edge = labkit.start_edge(_write_sites(out / f"sites-{name}{tag}.json", [spec]), jev_url,
                                         out / f"decisions-{name}{tag}.jsonl", jev_key=jev_key)
                edges.append((edge, f"{name}{tag}"))
                p6_plan[name] = (edge, mode)
        plan: dict[str, tuple[labkit.Edge, str, str]] = {
            SITE_NONE: (edge_p, "none", "enforce"),
            SITE_TRUTH: (edge_p, "truth", "enforce"),
            SITE_LIMIT: (edge_p, "truth", "enforce"),
            SITE_OBSERVE: (edge_o, "truth", "observe"),
        }
        if learned_spec:
            plan[SITE_LEARNED] = (edge_p, "learned", "enforce")
        if options.full:
            evict_spec = _spec(origins[SITE_EVICT], SITE_EVICT, "truth", "enforce")
            edge_e = labkit.start_edge(_write_sites(out / f"sites-evict{tag}.json", [evict_spec]), jev_url,
                                       out / f"decisions-evict{tag}.jsonl", jev_key=jev_key)
            edges.append((edge_e, f"evict{tag}"))
            plan[SITE_EVICT] = (edge_e, "truth", "enforce")
        probers = {name: _prober(edge, origins, name, config, mode, pool, ideal, real, run_no, options)
                   for name, (edge, config, mode) in plan.items()}
        p6_probers = {name: _prober(edge, origins, name, "truth", mode, pool, ideal, real, run_no, options)
                      for name, (edge, mode) in p6_plan.items()}
        # The anti-pollution consequence (batch 10): the two polluted sites share the learned site's edge, and get its journey
        # and its probes. They get no regression case, so they are not in `probers`.
        consequence_plan: dict[str, tuple[labkit.Edge, str, str]] = {}
        if polluted is not None:
            consequence_plan = {SITE_POLLUTED: (edge_p, "polluted", "enforce"),
                                SITE_POLLUTED_SET: (edge_p, "polluted-set", "enforce")}
        consequence_probers = {name: _prober(edge, origins, name, config, mode, pool, ideal, real, run_no, options)
                               for name, (edge, config, mode) in consequence_plan.items()}
        for name in JOURNEY_SITES + ((SITE_LEARNED,) if learned_spec else ()):
            prober = probers[name]
            prober.rows.extend(_journey(prober, options.seed, full=options.full))
            probes.run_site(prober, attacks, benign)
        for prober in consequence_probers.values():  # right after the learned site, on the same edge (batch 10)
            prober.rows.extend(_journey(prober, options.seed, full=options.full))
            probes.run_site(prober, attacks, benign)
            for row in prober.rows:  # kept apart from every other metric; score.py compares them with the learned site
                row.update({CONSEQUENCE_FIELD: CONSEQUENCE, "counterpart": SITE_LEARNED})
        unsent = dict(probers[JOURNEY_SITES[0]].unsent)
        regressions.run_all(probers, only=options.only, full=options.full)
        if options.full:
            # P6 (plan 3.3): the same protection batch on both halves, each after the same journey, whose rows are not
            # scored. The enforcement half is the counterpart the observation rows are compared with, so its rows are kept
            # apart from every other metric, and only P6 reads them.
            for name, prober in p6_probers.items():
                _journey(prober, options.seed, full=True)
                first = len(prober.rows)
                probes.run_site(prober, attacks, benign)
                group = CONSISTENCY_GROUP if name == SITE_P6_OBSERVE else CONSISTENCY_ENFORCE_GROUP
                for row in prober.rows[first:]:
                    row.update(group=group, category=group, counterpart=SITE_P6_ENFORCE)
        for prober in (*probers.values(), *p6_probers.values(), *consequence_probers.values()):
            rows.extend(prober.rows)
            timings.update(prober.notes)
    finally:
        for edge, name in reversed(edges):
            records.extend(_finish_edge(edge, out, name, secrets))
        for origin in origins.values():
            origin.stop()
    return rows, records, unsent, timings


def _jev_target(ideal: FakeJev, live: Live | None, relay: jev_relay.JevRelay | None) -> tuple[str, str]:
    """The URL the edges call as their Jev, and the key they send. A record sends the real key through the relay,
    a replay sends the lab's key, which nothing checks, and the other modes name the endpoint themselves."""
    if relay is not None:
        return relay.url, (live[1] if live else labkit.LAB_JEV_KEY)
    if live is not None:
        return live
    return ideal.url, labkit.LAB_JEV_KEY


def _prober(edge: labkit.Edge, origins: Mapping[str, ClinicOrigin], name: str, config: str, mode: str,
            pool: probes.Pool, ideal: FakeJev, real: bool, run_no: int, options: Options) -> probes.Prober:
    site = probes.Site(name=name, config=config, mode=mode, origin=origins[name])
    return probes.Prober(edge, site, pool, jev=None if real else ideal, run=run_no, only=options.only)


def _journey(prober: probes.Prober, seed: int, *, full: bool = False) -> list[dict[str, Any]]:
    """A few benign journeys of plan 4.2 on one site, enforced. Their rows are benign rows, not training rows. The
    journey goes to the prober's own site, whatever its name is (the observation-mode site is not named after its
    configuration)."""
    origin = prober.site.origin

    def send(host: str, method: str, target: str, **options: Any) -> labkit.Sent:
        return labkit.exchange(prober.edge, origin.was_served, prober.site.host, method, target, **options)

    rows = run_training(send, origin, seed, JOURNEY_USERS, JOURNEY_LOGINS, config=prober.site.config,
                        mode="enforce", evidence=Evidence(), full=full)
    for row in rows:
        if row["expect"] == "allow":  # the rows that expect a block (the administrator search) are not benign
            row["group"] = "benign"
        row["run"] = prober.run
    return rows


# Learning segment ---------------------------------------------------------------------------------------

def _learning(train_spec: dict[str, Any], truth: dict[str, Any], out: Path) -> dict[str, Any]:
    """The learning stage over the training decisions (batch 5). A module that cannot be imported is a skip, with the
    import error as the reason; otherwise the module decides, and it skips when PostgreSQL is not available."""
    try:
        learning = importlib.import_module(".learning", __package__)
    except ImportError as error:
        return {"status": "skip", "why": f"effectiveness.learning 导入失败：{error}", "learned_path": None,
                "final_spec": None}
    (out / "learning").mkdir(parents=True, exist_ok=True)
    return learning.run(out / "decisions-train.jsonl", train_spec, truth, out / "learning", log=_say)


def _learned_document(learning_result: Mapping[str, Any]) -> dict[str, Any] | None:
    """learned.json as the scorer reads it, or None when the learning stage did not run."""
    if learning_result["status"] != "ok":
        return None
    return json.loads(Path(learning_result["learned_path"]).read_text(encoding="utf-8"))


def _learned_spec(final_spec: Mapping[str, Any], origin: ClinicOrigin, name: str = SITE_LEARNED) -> dict[str, Any]:
    """The configuration the learning stage saved, under the site's own name (the learned site's by default), host, origin
    and mode (enforce). The rest of it is kept as the control saved it."""
    spec = copy.deepcopy(dict(final_spec))
    spec["name"] = name
    spec["hosts"] = [f"{name}.lab"]
    spec["origin"] = f"http://127.0.0.1:{origin.port}"
    spec["mode"] = "enforce"
    return spec


# Sites, edges and files ---------------------------------------------------------------------------------

def _spec(origin: ClinicOrigin, name: str, config: str, mode: str) -> dict[str, Any]:
    """The site of plan 3.3 under the lab's own name and host (site_spec names it after the configuration)."""
    spec = site_spec(config, origin.port, mode=mode)
    spec["name"] = name
    spec["hosts"] = [f"{name}.lab"]
    return spec


def _limit_spec(origin: ClinicOrigin) -> dict[str, Any]:
    """A site whose session may spend two Jev calls a minute, and which lets traffic through when Jev is down
    (the P0-2 case, plan 4.5). Only that case runs on it."""
    spec = _spec(origin, SITE_LIMIT, "truth", "enforce")
    spec["on_jev_unavailable"] = "allow"
    spec["advanced"]["session_calls_per_minute"] = 2
    return spec


def _write_sites(path: Path, specs: Sequence[Mapping[str, Any]]) -> Path:
    path.write_text(json.dumps(list(specs), ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _finish_edge(edge: labkit.Edge, out: Path, name: str, secrets: tuple[str, ...]) -> list[dict[str, Any]]:
    """Stops an edge and returns its decision records. Its stderr goes to edge-<name>.log, without any secret."""
    edge.stop()
    with edge.lock:
        records = list(edge.records)
        stderr = list(edge.stderr)
    text = "\n".join(stderr)
    for secret in secrets:
        text = text.replace(secret, "<redacted>")
    (out / f"edge-{name}.log").write_text(text + "\n", encoding="utf-8")
    return records


def _gap_entries(options: Options) -> list[dict[str, Any]]:
    """The learning known-gap list. A missing file is an empty list, so every learning problem then counts."""
    return load_known_gaps(options.known_gaps) if options.known_gaps.exists() else []


def _write_inputs(out: Path, observations: Sequence[Mapping[str, Any]],
                  decisions: Sequence[Mapping[str, Any]], truth: Mapping[str, Any]) -> None:
    _write_jsonl(out / "observations.jsonl", observations)
    _write_jsonl(out / "decisions.jsonl", decisions)
    dump_json(out / "truth.json", truth)


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as sink:
        for row in rows:
            sink.write(json.dumps(row, ensure_ascii=False) + "\n")


def _mark_unrun(result: dict[str, Any], *, real: bool, learning_why: str, full_mode: bool) -> None:
    """The scorer names the segments it could not compute; this run gives the reason of each, and names the probe
    that only a real Jev sends. The learning reason is the one the learning stage returned. The full mode's measures
    (L4, L5, and P6 from its consistency rows) are either computed here or named as not run in the quick mode."""
    for item in result["skipped"]:
        if item["section"] == "学习段":
            item["why"] = learning_why
    result["skipped"] = [item for item in result["skipped"] if item["section"] != "L4、L5"]
    if not full_mode:
        result["skipped"].append({"section": "L4、L5、P6、防护后果", "why": FULL_ONLY_SKIP})
        result["skipped"].append({"section": "b11-session-eviction", "why": EVICTION_SKIP})
    if not real:
        result["skipped"].append({"section": "idor_cross_class/page-as-prescription", "why": PAGE_PROBE_SKIP})

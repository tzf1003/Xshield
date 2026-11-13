"""The protection-effectiveness lab (plan 5.1): the training segment, the protection segment and the report.

    python3 scripts/measure_effectiveness.py [lab] [--seed N] [--only X,Y] [--out DIR] [--jev ideal|live|record|replay]

Training: the clinic origin and the benign journeys of plan 4.2, through one edge in observation mode, with the ideal
model of fake_jev.py. Protection: the attack probes, the benign text and the regression cases (plan 4.3 to 4.5) through
one edge in enforcement mode, on a site without an object map and a site with one, plus a site with a per-session Jev
budget and one in observation mode for P1-5. Every site has an origin of its own, so the state of one site cannot
change what another site is given.

The learning segment (batch 5, effectiveness.learning) runs between the training and the protection segments when
PostgreSQL is available. The object map it learns from the training decisions becomes a third protection site,
clinic-learned, which gets the journeys and the probes of the object-map configurations. Without PostgreSQL, or when
the module cannot be imported, the report says the segment did not run and why, and no learned column appears. The
full mode (batch 7) is refused with exit status 2, as is --keep (the
console comes with the learning segment).

The quick run compares with the quick group of tests/security-lab/effectiveness-baseline.json (plan 8): a missing
group fails the run, and the run's learning problems are checked against tests/security-lab/effectiveness-known-gaps.json
(known_gaps.py). --update-baseline writes the quick group, after the run passed every gate and no number went down;
it is refused with --only (part of the probes) and with a real Jev (the baseline is for the ideal model).

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

from . import jev_relay, probes, regressions
from .cli import KNOWN_GAPS_PATH, _commit
from .contracts import (
    ContractError, baseline_group, dump_json, load_baseline, load_known_gaps, write_baseline,
)
from .report import render_markdown, render_terminal, report_document
from .score import baseline_values, confidence_scan, score

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "target" / "effectiveness" / "latest"
BASELINE_PATH = ROOT / "tests" / "security-lab" / "effectiveness-baseline.json"
BASELINE_MODE = "quick"  # the group this run reads and writes; the full group comes with batch 7
LIVE_ENDPOINT_VARIABLE = "XSHIELD_JEV_ENDPOINT"
LIVE_KEY_VARIABLE = "XSHIELD_JEV_API_KEY"
LIVE_REPEATS = 3
RECORDING_NAME = "jev-recording.jsonl"  # the record mode writes it into the output folder
SOURCE_TEXT = {"ideal": "理想模型", "live": "真实 Jev", "record": "真实 Jev（录制）", "replay": "录制回放"}
JOURNEY_USERS, JOURNEY_LOGINS = 2, 1  # the benign journeys inside the protection segment: a small sample
FULL_SKIP = "完整模式专用（批次 7），本次没有计算"
PAGE_PROBE_SKIP = "只在真实 Jev（--jev live、record、replay）下发送：理想模型比较不了没有类别的页码位置"
TRAIN_SITE = "clinic-none"
SITE_NONE, SITE_TRUTH = "clinic-none", "clinic-truth"
SITE_LIMIT = "clinic-truth-limit"
SITE_OBSERVE = "clinic-truth-observe"
SITE_LEARNED = "clinic-learned"  # the learned object map (batch 5), when the learning stage ran
JOURNEY_SITES = (SITE_NONE, SITE_TRUTH)  # the journeys and the probe families run on the two object-map configurations

Live = tuple[str, str]  # the real Jev's endpoint and key, both from the environment


@dataclass(frozen=True)
class Options:
    seed: int = DEFAULT_SEED
    users: int = QUICK_DOCTORS
    logins: int = 4
    only: frozenset[str] = frozenset()
    out: Path = DEFAULT_OUT
    jev: str = "ideal"  # ideal, live, record or replay
    update_baseline: bool = False
    baseline: Path = BASELINE_PATH
    known_gaps: Path = KNOWN_GAPS_PATH


def run(args: argparse.Namespace) -> int:
    """The `lab` subcommand: refuses the modes that are not built, reads the settings of the chosen Jev, and runs."""
    if args.mode != "quick":
        return _not_built("完整模式（--mode full）是批次 7")
    if args.keep:
        return _not_built("--keep 要的控制台随学习段进来（批次 5）")
    only = frozenset(name.strip() for name in args.only.split(",") if name.strip())
    if args.update_baseline and only:
        return _not_built("--update-baseline 不能和 --only 同用：只跑了一部分探针，写下的数字不完整")
    if args.update_baseline and args.jev != "ideal":
        return _not_built("--update-baseline 只写理想模型下的基线")
    live: Live | None = None
    if args.jev in ("live", "record"):
        live = _live_settings(args.jev)
        if live is None:
            return 2
    return execute(Options(seed=args.seed, only=only, out=args.out, jev=args.jev,
                           update_baseline=args.update_baseline), live=live)


def _not_built(what: str) -> int:
    print(f"{what}，没有运行任何内容", file=sys.stderr)
    return 2


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
    started = time.monotonic()
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = options.out
    real = options.jev != "ideal"
    secrets: tuple[str, ...] = (live[1],) if live else ()
    try:
        relay = _open_relay(options, live, out)  # a replay reads its recording now, before any work starts
    except (jev_relay.RelayError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    ideal = FakeJev(attack_texts=probes.attack_texts())
    ideal.start()
    try:
        out.mkdir(parents=True, exist_ok=True)
        labkit.build_edge()
        train_rows, train_records, truth, train_spec = _training(options, ideal, out, secrets)
        _say(f"训练段：{len(train_rows)} 个请求，观察模式，无对象表，理想模型")
        learning = _learning(train_spec, truth, out)
        _say("学习段：完成，学到的配置作为 clinic-learned 进入防护段" if learning["status"] == "ok"
             else f"学习段：SKIP（{learning['why']}）")
        protect_rows, protect_records, unsent = _protection(options, ideal, live, relay, out, secrets, learning)
        _say(f"防护段：{len(protect_rows)} 个计分请求，{SOURCE_TEXT[options.jev]}")
        observations = [*train_rows, *protect_rows]
        decisions = [*train_records, *protect_records]
        _write_inputs(out, observations, decisions, truth)
        # The baseline is for the ideal model, and for a run that sends every probe (--only sends some of them).
        # A missing group fails the gate, unless this run is the one that writes it (--update-baseline).
        compared = not real and not options.only
        document = load_baseline(options.baseline) if compared and options.baseline.exists() else None
        group = baseline_group(document, BASELINE_MODE) if compared else None
        result = score(observations, decisions, truth=truth, learned=_learned_document(learning),
                       baseline=group, gap_entries=_gap_entries(options),
                       check_gaps=not options.only,
                       require_baseline=compared and group is None and not options.update_baseline,
                       training=train_records)
        _mark_unrun(result, real=real, learning_why=learning["why"])
        if real:  # the scan needs a real model's probabilities; the ideal model's are fixed (plan 10, batch 9)
            result["confidence_scan"] = confidence_scan(protect_rows, protect_records)
        meta = {
            "commit": _commit(), "mode": "quick", "jev": options.jev, "seed": options.seed,
            "started": stamp, "seconds": round(time.monotonic() - started, 3), "unsent": unsent,
            "jev_relay": relay.summary() if relay is not None else None,
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
        ideal.stop()
        if relay is not None:
            relay.stop()


def _gap_entries(options: Options) -> list[dict[str, Any]]:
    """The learning known-gap list. A missing file is an empty list, so every learning problem then counts."""
    return load_known_gaps(options.known_gaps) if options.known_gaps.exists() else []


def _update_baseline(options: Options, result: dict[str, Any], meta: dict[str, Any]) -> int:
    """Writes the quick group, when the run passed every gate and no number went down (plan 10, --update-baseline)."""
    if not result["passed"]:
        print("error: 门槛未通过，没有写基线（失败的门槛见报告）", file=sys.stderr)
        return 1
    if result["baseline"]["regressions"]:
        names = "、".join(item["name"] for item in result["baseline"]["regressions"])
        print(f"error: 有指标比基线差（{names}），没有写基线", file=sys.stderr)
        return 1
    group = {"seed": options.seed, "commit": meta["commit"], "values": baseline_values(result["metrics"])}
    write_baseline(options.baseline, BASELINE_MODE, group)
    print(f"基线已写入：{options.baseline}（{BASELINE_MODE} 组，提交 {meta['commit']}）")
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

def _training(options: Options, ideal: FakeJev, out: Path, secrets: tuple[str, ...]) -> tuple[
        list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """The training rows, their decision records, the origin's truth, and the site configuration they ran on."""
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
                                mode="observe", evidence=Evidence())
        finally:
            records = _finish_edge(edge, out, "train", secrets)
        _write_jsonl(out / "observations-train.jsonl", rows)  # the edge already wrote decisions-train.jsonl
        return rows, records, origin.truth(), train_spec
    finally:
        origin.stop()


# Protection segment -------------------------------------------------------------------------------------

def _protection(options: Options, ideal: FakeJev, live: Live | None, relay: jev_relay.JevRelay | None, out: Path,
                secrets: tuple[str, ...], learning: Mapping[str, Any]) -> tuple[
                    list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """The scored rows and decision records of the protection segment, and the payloads that were not sent at the
    path point in one run (the same in every run and on every journey site).

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
    for run_no in range(1, repeats + 1):
        tag = "" if repeats == 1 else f"-r{run_no}"
        run_rows, run_records, run_unsent = _protection_run(options, ideal, real, jev_url, jev_key, out, tag, secrets,
                                                            learning, pool, run_no)
        rows.extend(run_rows)
        records.extend(run_records)
        if run_no == 1:
            unsent = run_unsent
    return rows, records, unsent


def _protection_run(options: Options, ideal: FakeJev, real: bool, jev_url: str, jev_key: str, out: Path, tag: str,
                    secrets: tuple[str, ...], learning: Mapping[str, Any], pool: probes.Pool,
                    run_no: int) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """One pass over the protection sites, on origins and edges that start empty."""
    learned_spec = learning["final_spec"]  # None when the learning stage did not run
    names = (SITE_NONE, SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE) + ((SITE_LEARNED,) if learned_spec else ())
    origins = {name: ClinicOrigin(seed=options.seed, doctors=options.users) for name in names}
    for origin in origins.values():
        origin.start()
    rows: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    unsent: dict[str, int] = {}
    try:
        protect_sites = [_spec(origins[SITE_NONE], SITE_NONE, "none", "enforce"),
                         _spec(origins[SITE_TRUTH], SITE_TRUTH, "truth", "enforce"),
                         _limit_spec(origins[SITE_LIMIT])]
        if learned_spec:
            protect_sites.append(_learned_spec(learned_spec, origins[SITE_LEARNED]))
        observe_sites = [_spec(origins[SITE_OBSERVE], SITE_OBSERVE, "truth", "observe")]
        edge_p = labkit.start_edge(_write_sites(out / f"sites-protect{tag}.json", protect_sites), jev_url,
                                   out / f"decisions-protect{tag}.jsonl", jev_key=jev_key)
        try:
            edge_o = labkit.start_edge(_write_sites(out / f"sites-observe{tag}.json", observe_sites), jev_url,
                                       out / f"decisions-observe{tag}.jsonl", jev_key=jev_key)
            try:
                probers = {
                    SITE_NONE: _prober(edge_p, origins, SITE_NONE, "none", "enforce", pool, ideal, real, run_no, options),
                    SITE_TRUTH: _prober(edge_p, origins, SITE_TRUTH, "truth", "enforce", pool, ideal, real, run_no,
                                        options),
                    SITE_LIMIT: _prober(edge_p, origins, SITE_LIMIT, "truth", "enforce", pool, ideal, real, run_no,
                                        options),
                    SITE_OBSERVE: _prober(edge_o, origins, SITE_OBSERVE, "truth", "observe", pool, ideal, real, run_no,
                                          options),
                }
                if learned_spec:
                    probers[SITE_LEARNED] = _prober(edge_p, origins, SITE_LEARNED, "learned", "enforce", pool, ideal,
                                                    real, run_no, options)
                attacks, benign = probes.quick_attacks(), probes.quick_benign()
                for name in JOURNEY_SITES + ((SITE_LEARNED,) if learned_spec else ()):
                    prober = probers[name]
                    prober.rows.extend(_journey(prober, options.seed))
                    probes.run_site(prober, attacks, benign)
                unsent = dict(probers[JOURNEY_SITES[0]].unsent)
                regressions.run_all(probers, only=options.only)
                for prober in probers.values():
                    rows.extend(prober.rows)
            finally:
                records.extend(_finish_edge(edge_o, out, f"observe{tag}", secrets))
        finally:
            records.extend(_finish_edge(edge_p, out, f"protect{tag}", secrets))
    finally:
        for origin in origins.values():
            origin.stop()
    return rows, records, unsent


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


def _journey(prober: probes.Prober, seed: int) -> list[dict[str, Any]]:
    """A few benign journeys of plan 4.2 on one site, enforced. Their rows are benign rows, not training rows."""
    origin = prober.site.origin

    def send(host: str, method: str, target: str, **options: Any) -> labkit.Sent:
        return labkit.exchange(prober.edge, origin.was_served, host, method, target, **options)

    rows = run_training(send, origin, seed, JOURNEY_USERS, JOURNEY_LOGINS, config=prober.site.config,
                        mode="enforce", evidence=Evidence())
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


def _learned_spec(final_spec: Mapping[str, Any], origin: ClinicOrigin) -> dict[str, Any]:
    """The configuration the learning stage saved, under the learned site's own name, host, origin and mode (enforce).
    The rest of it is kept as the control saved it."""
    spec = copy.deepcopy(dict(final_spec))
    spec["name"] = SITE_LEARNED
    spec["hosts"] = [f"{SITE_LEARNED}.lab"]
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


def _write_inputs(out: Path, observations: Sequence[Mapping[str, Any]],
                  decisions: Sequence[Mapping[str, Any]], truth: Mapping[str, Any]) -> None:
    _write_jsonl(out / "observations.jsonl", observations)
    _write_jsonl(out / "decisions.jsonl", decisions)
    dump_json(out / "truth.json", truth)


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as sink:
        for row in rows:
            sink.write(json.dumps(row, ensure_ascii=False) + "\n")


def _mark_unrun(result: dict[str, Any], *, real: bool, learning_why: str) -> None:
    """The scorer names the segments it could not compute; this run gives the reason of each, and names the probe
    that only a real Jev sends. The learning reason is the one the learning stage returned."""
    for item in result["skipped"]:
        if item["section"] == "学习段":
            item["why"] = learning_why
        elif item["section"].startswith("P6"):
            item["why"] = FULL_SKIP
    if not real:
        result["skipped"].append({"section": "idor_cross_class/page-as-prescription", "why": PAGE_PROBE_SKIP})

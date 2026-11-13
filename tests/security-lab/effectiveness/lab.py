"""The protection-effectiveness lab (plan 5.1): the training segment, the protection segment and the report.

    python3 scripts/measure_effectiveness.py [lab] [--seed N] [--only X,Y] [--out DIR] [--jev ideal|live]

Training: the clinic origin and the benign journeys of plan 4.2, through one edge in observation mode, with the ideal
model of fake_jev.py. Protection: the attack probes, the benign text and the regression cases (plan 4.3 to 4.5) through
one edge in enforcement mode, on a site without an object map and a site with one, plus a site with a per-session Jev
budget and one in observation mode for P1-5. Every site has an origin of its own, so the state of one site cannot
change what another site is given.

The learning segment (batch 5, effectiveness.learning) runs between the training and the protection segments when
PostgreSQL is available. The object map it learns from the training decisions becomes a third protection site,
clinic-learned, which gets the journeys and the probes of the object-map configurations. Without PostgreSQL, or when
the module cannot be imported, the report says the segment did not run and why, and no learned column appears. The
full mode (batch 7) and the record and replay modes (batch 9) are refused with exit status 2, as is --keep (the
console comes with the learning segment) and --update-baseline (the baseline file comes with batch 8).

`--jev live` points the protection segment at the real Jev named by XSHIELD_JEV_ENDPOINT, with the key from
XSHIELD_JEV_API_KEY, and repeats every scored request three times. A missing endpoint or key is an error: the run
never falls back to the scripted model. The training stays on the ideal model, because its records are the learning's
input. The key is never written to a file, and it is redacted from the edge logs.
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

from . import probes, regressions
from .cli import _commit
from .contracts import dump_json
from .report import render_markdown, render_terminal, report_document
from .score import score

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "target" / "effectiveness" / "latest"
LIVE_ENDPOINT_VARIABLE = "XSHIELD_JEV_ENDPOINT"
LIVE_KEY_VARIABLE = "XSHIELD_JEV_API_KEY"
LIVE_REPEATS = 3
JOURNEY_USERS, JOURNEY_LOGINS = 2, 1  # the benign journeys inside the protection segment: a small sample
FULL_SKIP = "完整模式专用（批次 7），本次没有计算"
PAGE_PROBE_SKIP = "只在 --jev live 下发送：理想模型比较不了没有类别的页码位置，快速和完整模式不发"
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


def run(args: argparse.Namespace) -> int:
    """The `lab` subcommand: refuses the modes that are not built, reads the live settings, and runs."""
    if args.mode != "quick":
        return _not_built("完整模式（--mode full）是批次 7")
    if args.jev in ("record", "replay"):
        return _not_built(f"--jev {args.jev} 是批次 9")
    if args.keep:
        return _not_built("--keep 要的控制台随学习段进来（批次 5）")
    if args.update_baseline:
        return _not_built("--update-baseline 要的基线文件在批次 8 建立")
    live: Live | None = None
    if args.jev == "live":
        live = _live_settings()
        if live is None:
            return 2
    only = frozenset(name.strip() for name in args.only.split(",") if name.strip())
    return execute(Options(seed=args.seed, only=only, out=args.out), live=live)


def _not_built(what: str) -> int:
    print(f"{what}，没有运行任何内容", file=sys.stderr)
    return 2


def _live_settings() -> Live | None:
    endpoint = os.environ.get(LIVE_ENDPOINT_VARIABLE, "").strip()
    key = os.environ.get(LIVE_KEY_VARIABLE, "").strip()
    if not endpoint or not key:
        print(f"error: --jev live 需要环境变量 {LIVE_ENDPOINT_VARIABLE} 和 {LIVE_KEY_VARIABLE}；"
              "没有就报错退出，不退回模拟 Jev", file=sys.stderr)
        return None
    return endpoint, key


def execute(options: Options, *, live: Live | None = None) -> int:
    started = time.monotonic()
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = options.out
    out.mkdir(parents=True, exist_ok=True)
    secrets: tuple[str, ...] = (live[1],) if live else ()
    ideal = FakeJev(attack_texts=probes.attack_texts())
    ideal.start()
    try:
        labkit.build_edge()
        train_rows, train_records, truth, train_spec = _training(options, ideal, out, secrets)
        _say(f"训练段：{len(train_rows)} 个请求，观察模式，无对象表，理想模型")
        learning = _learning(train_spec, truth, out)
        _say("学习段：完成，学到的配置作为 clinic-learned 进入防护段" if learning["status"] == "ok"
             else f"学习段：SKIP（{learning['why']}）")
        protect_rows, protect_records, unsent = _protection(options, ideal, live, out, secrets, learning)
        _say(f"防护段：{len(protect_rows)} 个计分请求，{'真实 Jev' if live else '理想模型'}")
        observations = [*train_rows, *protect_rows]
        decisions = [*train_records, *protect_records]
        _write_inputs(out, observations, decisions, truth)
        result = score(observations, decisions, truth=truth, learned=_learned_document(learning))
        _mark_unrun(result, live=live is not None, learning_why=learning["why"])
        meta = {
            "commit": _commit(), "mode": "quick", "jev": "live" if live else "ideal", "seed": options.seed,
            "started": stamp, "seconds": round(time.monotonic() - started, 3), "unsent": unsent,
        }
        dump_json(out / "report.json", report_document(result, meta))
        (out / "report.md").write_text(render_markdown(result, meta), encoding="utf-8")
        print(render_terminal(result, meta))
        print(f"报告：{out / 'report.md'}")
        return 0 if result["passed"] else 1
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    finally:
        ideal.stop()


def _say(message: str) -> None:
    print(message, flush=True)


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

def _protection(options: Options, ideal: FakeJev, live: Live | None, out: Path, secrets: tuple[str, ...],
                learning: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """The scored rows and decision records of the protection segment, and the payloads that were not sent at the
    path point in one run (the same in every run and on every journey site)."""
    unsent: dict[str, int] = {}
    repeats = LIVE_REPEATS if live else 1
    jev_url, jev_key = live if live else (ideal.url, labkit.LAB_JEV_KEY)
    learned_spec = learning["final_spec"]  # None when the learning stage did not run
    names = (SITE_NONE, SITE_TRUTH, SITE_LIMIT, SITE_OBSERVE) + ((SITE_LEARNED,) if learned_spec else ())
    origins = {name: ClinicOrigin(seed=options.seed, doctors=options.users) for name in names}
    for origin in origins.values():
        origin.start()
    rows: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    try:
        protect_sites = [_spec(origins[SITE_NONE], SITE_NONE, "none", "enforce"),
                         _spec(origins[SITE_TRUTH], SITE_TRUTH, "truth", "enforce"),
                         _limit_spec(origins[SITE_LIMIT])]
        if learned_spec:
            protect_sites.append(_learned_spec(learned_spec, origins[SITE_LEARNED]))
        observe_sites = [_spec(origins[SITE_OBSERVE], SITE_OBSERVE, "truth", "observe")]
        edge_p = labkit.start_edge(_write_sites(out / "sites-protect.json", protect_sites), jev_url,
                                   out / "decisions-protect.jsonl", jev_key=jev_key)
        try:
            edge_o = labkit.start_edge(_write_sites(out / "sites-observe.json", observe_sites), jev_url,
                                       out / "decisions-observe.jsonl", jev_key=jev_key)
            try:
                pool = probes.Pool()
                attacks, benign = probes.quick_attacks(), probes.quick_benign()
                for run_no in range(1, repeats + 1):
                    probers = {
                        SITE_NONE: _prober(edge_p, origins, SITE_NONE, "none", "enforce", pool, ideal, live,
                                           run_no, options),
                        SITE_TRUTH: _prober(edge_p, origins, SITE_TRUTH, "truth", "enforce", pool, ideal, live,
                                            run_no, options),
                        SITE_LIMIT: _prober(edge_p, origins, SITE_LIMIT, "truth", "enforce", pool, ideal, live,
                                            run_no, options),
                        SITE_OBSERVE: _prober(edge_o, origins, SITE_OBSERVE, "truth", "observe", pool, ideal,
                                              live, run_no, options),
                    }
                    if learned_spec:
                        probers[SITE_LEARNED] = _prober(edge_p, origins, SITE_LEARNED, "learned", "enforce", pool,
                                                        ideal, live, run_no, options)
                    for name in JOURNEY_SITES + ((SITE_LEARNED,) if learned_spec else ()):
                        prober = probers[name]
                        prober.rows.extend(_journey(prober, options.seed))
                        probes.run_site(prober, attacks, benign)
                    if run_no == 1:
                        unsent = dict(probers[JOURNEY_SITES[0]].unsent)
                    regressions.run_all(probers, only=options.only)
                    for prober in probers.values():
                        rows.extend(prober.rows)
            finally:
                records.extend(_finish_edge(edge_o, out, "observe", secrets))
        finally:
            records.extend(_finish_edge(edge_p, out, "protect", secrets))
    finally:
        for origin in origins.values():
            origin.stop()
    return rows, records, unsent


def _prober(edge: labkit.Edge, origins: Mapping[str, ClinicOrigin], name: str, config: str, mode: str,
            pool: probes.Pool, ideal: FakeJev, live: Live | None, run_no: int,
            options: Options) -> probes.Prober:
    site = probes.Site(name=name, config=config, mode=mode, origin=origins[name])
    return probes.Prober(edge, site, pool, jev=None if live else ideal, run=run_no, only=options.only)


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


def _mark_unrun(result: dict[str, Any], *, live: bool, learning_why: str) -> None:
    """The scorer names the segments it could not compute; this run gives the reason of each, and names the probe
    that only the live Jev sends. The learning reason is the one the learning stage returned."""
    for item in result["skipped"]:
        if item["section"] == "学习段":
            item["why"] = learning_why
        elif item["section"].startswith("P6"):
            item["why"] = FULL_SKIP
    if not live:
        result["skipped"].append({"section": "idor_cross_class/page-as-prescription", "why": PAGE_PROBE_SKIP})

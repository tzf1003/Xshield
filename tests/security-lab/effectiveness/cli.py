"""Command line of the effectiveness measurement. scripts/measure_effectiveness.py calls main().

    measure_effectiveness.py [lab] [--mode quick|full] [--jev ideal|live|record|replay]
                             [--seed N] [--only X,Y] [--out DIR] [--keep] [--update-baseline]
    measure_effectiveness.py site (--decisions FILE | --control URL --site NAME)
                             --suite-results DIR_OR_ZIP [--truth FILE] [--objects FILE] [--out DIR]
    measure_effectiveness.py score --observations FILE --decisions FILE
                             [--truth FILE] [--learned FILE] [--baseline FILE] [--known-gaps FILE]
                             [--training FILE] [--out DIR]

Without a subcommand the command is `lab`. `lab` (effectiveness.lab) runs the training, learning and
protection segments; `--mode full` adds the full mode of batch 7 (full.py), which needs PostgreSQL and the ideal model.
`--jev record` and `--jev replay` (batch 9) use the relay of jev_relay.py. `--keep` is not built yet and exits 2.
`site` (effectiveness.site) reads the suite output and the decision records and sends no traffic.

Exit status: 0 when every gate passes (a gate with no data does not fail), 1 when a gate
fails, 2 for a usage or environment error.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import (
    ContractError, baseline_group, dump_json, load_baseline, load_decisions, load_known_gaps, load_learned,
    load_observations, load_truth,
)
from .report import render_markdown, render_terminal, report_document
from .score import score

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUT = ROOT / "target" / "effectiveness" / "latest"
KNOWN_GAPS_PATH = ROOT / "tests" / "security-lab" / "effectiveness-known-gaps.json"
SUBCOMMANDS = ("lab", "site", "score")
PASSWORD_ENV = "XSHIELD_CONSOLE_PASSWORD"
PASSWORD_FLAGS = frozenset({"--password", "--pass", "--passwd", "--pwd"})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/measure_effectiveness.py",
        description="防护有效性度量。不带子命令时等同于 lab。",
    )
    commands = parser.add_subparsers(dest="command", metavar="{lab,site,score}")

    lab = commands.add_parser("lab", help="靶场：训练段、学习段和防护段；--mode full 为完整模式（需要 PostgreSQL）")
    lab.add_argument("--mode", choices=("quick", "full"), default="quick",
                     help="quick：快速模式（默认）；full：完整模式，48 个医生、全部语料，并多跑 L4、L5、P6，整套跑两遍")
    lab.add_argument("--jev", choices=("ideal", "live", "record", "replay"), default="ideal")
    lab.add_argument("--seed", type=int, default=20261113)
    lab.add_argument("--only", default="", help="只跑这些类别或用例，逗号分隔（不与基线比较）")
    lab.add_argument("--out", type=Path, default=DEFAULT_OUT)
    lab.add_argument("--keep", action="store_true", help="跑完不关进程，打印控制台地址")
    lab.add_argument("--update-baseline", action="store_true", help="把本次指标写回基线文件")

    site = commands.add_parser("site", help="真实站点：读套件输出与判定记录，不发流量")
    site.add_argument("--decisions", type=Path, help="判定记录文件（控制台导出或网关文件模式输出）")
    site.add_argument("--control", help="控制台地址，由脚本登录后取判定记录")
    site.add_argument("--site", help="--control 下的站点名")
    site.add_argument("--suite-results", type=Path, required=True, help="套件输出目录或 zip")
    site.add_argument("--truth", type=Path, help="位置真值文件")
    site.add_argument("--objects", type=Path, help="对象表导出文件")
    site.add_argument("--out", type=Path, default=DEFAULT_OUT)

    score_parser = commands.add_parser("score", help="只给四个文件计分，不发流量")
    score_parser.add_argument("--observations", type=Path, required=True)
    score_parser.add_argument("--decisions", type=Path, required=True)
    score_parser.add_argument("--truth", type=Path)
    score_parser.add_argument("--learned", type=Path)
    score_parser.add_argument("--baseline", type=Path, help="基线文件；不给就不做基线比较")
    score_parser.add_argument("--known-gaps", type=Path, default=KNOWN_GAPS_PATH,
                              help="学习的已知缺口清单，默认与 lab 相同的仓库文件；文件不存在时清单为空")
    score_parser.add_argument("--training", type=Path,
                              help="训练段的判定记录（lab 输出目录里的 decisions-train.jsonl）；不给就按全部判定记录算原因标签")
    score_parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Checked before argparse, which would echo an unknown option's value in its usage error.
    if any(arg.split("=", 1)[0] in PASSWORD_FLAGS for arg in raw):
        print(f"error: 口令不能通过命令行传入，请设置环境变量 {PASSWORD_ENV}", file=sys.stderr)
        return 2
    if not raw or (raw[0] not in SUBCOMMANDS and raw[0] not in ("-h", "--help")):
        raw.insert(0, "lab")
    parser = build_parser()
    try:
        args = parser.parse_args(raw)
    except SystemExit as exit_request:  # argparse reports usage errors by exiting with 2
        return int(exit_request.code or 0)
    if args.command is None:
        parser.print_help()
        return 2
    if args.command == "site" and args.decisions is None and not (args.control and args.site):
        print("error: site 需要 --decisions，或同时给 --control 和 --site", file=sys.stderr)
        return 2
    if args.command == "score":
        return _run_score(args)
    return _delegate(args.command, args)


def _delegate(command: str, args: argparse.Namespace) -> int:
    module_name = f"effectiveness.{command}"
    if importlib.util.find_spec(module_name) is None:
        print(f"{command}：尚未实现（{module_name} 不存在），没有运行任何内容", file=sys.stderr)
        return 2
    module = importlib.import_module(module_name)
    return int(module.run(args))


def _commit() -> str:
    try:
        done = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "未知"
    value = done.stdout.strip()
    return value if done.returncode == 0 and value else "未知"


def _run_score(args: argparse.Namespace) -> int:
    started = time.monotonic()
    try:
        observations = load_observations(args.observations)
        decisions = load_decisions(args.decisions)
        truth = load_truth(args.truth) if args.truth else None
        learned = load_learned(args.learned) if args.learned else None
        baseline = baseline_group(load_baseline(args.baseline), "quick") if args.baseline else None
        gap_entries = load_known_gaps(args.known_gaps) if args.known_gaps.exists() else []
        training = load_decisions(args.training) if args.training else None
    except (ContractError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    result: dict[str, Any] = score(observations, decisions, truth=truth, learned=learned, baseline=baseline,
                                   gap_entries=gap_entries, training=training)
    meta: dict[str, Any] = {
        "commit": _commit(),
        "mode": "score",
        "jev": "未指定（按理想模型口径计分）",
        "note": ("原因标签按训练段的判定记录计算" if training is not None
                 else "原因标签按全部判定记录计算（未给 --training，防护段的拒绝可能被标成“被拒绝记录挡住”）"),
        "seed": truth["seed"] if truth else None,
        "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seconds": round(time.monotonic() - started, 3),
    }
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    dump_json(out / "report.json", report_document(result, meta))
    (out / "report.md").write_text(render_markdown(result, meta), encoding="utf-8")
    sources = {"observations.jsonl": args.observations, "decisions.jsonl": args.decisions,
               "truth.json": args.truth, "learned.json": args.learned}
    for name, source in sources.items():
        if source is None:
            continue
        target = out / name
        if source.resolve() != target.resolve():
            shutil.copyfile(source, target)

    print(render_terminal(result, meta))
    print(f"报告：{out / 'report.md'}")
    return 0 if result["passed"] else 1

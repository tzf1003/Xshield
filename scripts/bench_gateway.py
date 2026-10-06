#!/usr/bin/env python3
"""Baseline latency of the edge in front of a trivial origin (docs/21 section 21.1).

The budget in docs/21 is "no-model request path: P95 added latency <= 15 ms". This
script measures the part of that budget the edge owns on one machine: the same
GET sent straight to a stub origin and through the real release edge, at several
concurrency levels, with a high-resolution timer around every request (Apache's
`ab` only reports whole milliseconds, which hides sub-millisecond overhead).

What it does and does not measure
  * target "origin"  : the stub origin directly (the floor: client + stub cost)
  * target "edge"    : a PUBLIC route through the edge. Each request still passes
                       admission, the durable-audit barrier (a journal append that
                       must be durable before the origin is contacted) and the
                       terminal audit event, so the difference to "origin" is the
                       edge's added latency including its audit cost.
  * target "denied"  : an unknown path the edge refuses itself (no origin call),
                       which still writes its audit events.
  It does NOT measure identity (PostgreSQL), request/response crypto, the sensor,
  TLS, large bodies, ClickHouse publication or any model. Numbers from a laptop
  that is doing other work are an indication, not a result: run it on a quiet
  machine, read the spread (p50 vs p99) and keep the printed environment lines
  with any number you quote.

Needs: cargo, python3. Build output goes under CARGO_TARGET_DIR, which must be
set (the script refuses an in-repo default so a release build never lands on the
system disk by accident). The journal and logs live in a scratch directory under
--scratch (default: TMPDIR) and are removed on exit; the journal is capped at
256 MiB.

  CARGO_TARGET_DIR=/Volumes/XshieldBuild/target-release scripts/bench_gateway.py
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import platform
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BODY = json.dumps({"ok": True, "padding": "x" * 40}).encode()


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args: object) -> None:
        return


class OriginServer(ThreadingHTTPServer):
    # The default listen backlog is 5: sixteen clients opening upstream connections
    # at once would overflow it and show up as 502s that belong to the stub.
    request_queue_size = 512
    daemon_threads = True


def serve_origin(port: int) -> None:
    OriginServer(("127.0.0.1", port), Origin).serve_forever()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(port: int, seconds: float = 20.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise SystemExit(f"nothing listens on 127.0.0.1:{port}")


def percentile(sorted_ns: list[int], fraction: float) -> float:
    """Nearest-rank percentile in milliseconds."""
    index = min(len(sorted_ns) - 1, max(0, int(round(fraction * len(sorted_ns) + 0.5)) - 1))
    return sorted_ns[index] / 1e6


def drive(port: int, path: str, concurrency: int, seconds: float) -> tuple[list[int], dict[int, int]]:
    """Closed-loop load: every worker keeps one connection and sends back to back."""
    latencies: list[list[int]] = [[] for _ in range(concurrency)]
    statuses: list[dict[int, int]] = [{} for _ in range(concurrency)]
    stop_at = time.monotonic() + seconds

    def worker(slot: int) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        while time.monotonic() < stop_at:
            started = time.perf_counter_ns()
            try:
                connection.request("GET", path)
                response = connection.getresponse()
                response.read()
                code = response.status
            except (OSError, http.client.HTTPException):
                connection.close()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                code = 0
            latencies[slot].append(time.perf_counter_ns() - started)
            statuses[slot][code] = statuses[slot].get(code, 0) + 1
        connection.close()

    threads = [threading.Thread(target=worker, args=(slot,)) for slot in range(concurrency)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    merged: dict[int, int] = {}
    for counts in statuses:
        for code, count in counts.items():
            merged[code] = merged.get(code, 0) + count
    return sorted(value for chunk in latencies for value in chunk), merged


def edge_config(directory: Path, edge_port: int, origin_port: int) -> Path:
    audit = directory / "audit"
    audit.mkdir(mode=0o700)
    config = {
        "listen": f"127.0.0.1:{edge_port}",
        "origin": {"address": f"127.0.0.1:{origin_port}", "server_name": "bench.local", "tls": False},
        "tenant_id": "tenant_bench",
        "site_id": "site_bench",
        "policy_revision": "bench-r1",
        "audit": {
            "directory": str(audit),
            "key_id": "journal-bench-r1",
            "producer_id": "edge-bench",
            "max_bytes": 268_435_456,
            "high_watermark_bytes": 201_326_592,
            "segment_max_bytes": 8_388_608,
        },
        # The default site rate limit (1000 requests/s) would turn a benchmark
        # into a measurement of the limiter, so lift it to the largest allowed.
        "site_policy": {"limits": {"requests_per_second": 1_000_000, "burst": 2_000_000}},
        "operations": [
            {"operation_id": "bench.read", "method": "GET", "path": "/bench", "admission": "PUBLIC"}
        ],
    }
    path = directory / "gateway.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    return path


def describe_machine() -> list[str]:
    lines = [f"- {platform.platform()} on {platform.machine()}, python {platform.python_version()}"]
    for command in (["sysctl", "-n", "machdep.cpu.brand_string"], ["sysctl", "-n", "hw.ncpu"]):
        try:
            lines.append("- " + subprocess.run(command, capture_output=True, text=True, check=True).stdout.strip())
        except (OSError, subprocess.CalledProcessError):
            pass
    try:
        load = os.getloadavg()
        lines.append(f"- load average before the run: {load[0]:.2f} {load[1]:.2f} {load[2]:.2f} (a quiet machine is below ~1)")
    except OSError:
        pass
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=float, default=10.0, help="load time per target and concurrency (default 10)")
    parser.add_argument("--concurrency", default="1,8", help="comma separated closed-loop client counts (default 1,8)")
    parser.add_argument("--scratch", default=os.environ.get("TMPDIR", "/tmp"), help="where the journal and logs go")
    parser.add_argument("--no-build", action="store_true", help="use the existing binary")
    parser.add_argument("--profile", choices=("release", "debug"), default="release",
                        help="release for numbers; debug only to smoke-test the script itself")
    parser.add_argument("--keep", action="store_true", help="keep the scratch directory (edge.log) and print its path")
    parser.add_argument("--origin-port", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.origin_port:
        serve_origin(args.origin_port)
        return 0
    target_dir = os.environ.get("CARGO_TARGET_DIR")
    if not target_dir or Path(target_dir).resolve().is_relative_to(ROOT):
        print("error: set CARGO_TARGET_DIR to a directory outside the repository (a large volume)", file=sys.stderr)
        return 2
    binary = Path(target_dir) / args.profile / "xshield-gateway"
    if not args.no_build:
        subprocess.run(
            ["cargo", "build", *(["--release"] if args.profile == "release" else []), "-p", "xshield-gateway", "--locked"],
            cwd=ROOT,
            check=True,
            env={**os.environ, "CARGO_INCREMENTAL": "0"},
        )
    if not binary.exists():
        print(f"error: {binary} does not exist", file=sys.stderr)
        return 2

    scratch = Path(tempfile.mkdtemp(prefix="xshield-bench-", dir=args.scratch))
    scratch.chmod(0o700)
    origin_port, edge_port = free_port(), free_port()
    children: list[subprocess.Popen[bytes]] = []
    try:
        children.append(subprocess.Popen([sys.executable, __file__, "--origin-port", str(origin_port)]))
        wait_for(origin_port)
        config = edge_config(scratch, edge_port, origin_port)
        edge_log = (scratch / "edge.log").open("wb")
        children.append(
            subprocess.Popen(
                [str(binary)],
                env={
                    **os.environ,
                    "XSHIELD_CONFIG": str(config),
                    "XSHIELD_JOURNAL_KEY_HEX": secrets.token_hex(32),
                },
                stdout=edge_log,
                stderr=subprocess.STDOUT,
            )
        )
        wait_for(edge_port)

        print("## Environment")
        print("\n".join(describe_machine()))
        print(f"- binary: {binary} ({binary.stat().st_size // 1024} KiB), {args.seconds:g} s per row, closed loop, one keep-alive connection per client")
        print()
        targets = [("origin", origin_port, "/bench"), ("edge", edge_port, "/bench"), ("denied", edge_port, "/denied")]
        for _name, port, path in targets:  # warm-up: connections, page cache, JIT-less but cold paths
            drive(port, path, 2, 1.0)
        rows: dict[tuple[str, int], tuple[float, float, float, float, float, int, dict[int, int]]] = {}
        for clients in (int(part) for part in args.concurrency.split(",")):
            for name, port, path in targets:
                latencies, statuses = drive(port, path, clients, args.seconds)
                total = len(latencies)
                rows[(name, clients)] = (
                    total / args.seconds,
                    percentile(latencies, 0.50),
                    percentile(latencies, 0.95),
                    percentile(latencies, 0.99),
                    latencies[-1] / 1e6,
                    total,
                    statuses,
                )
        print("## Latency (ms) and throughput")
        print()
        print("| target | clients | requests | req/s | p50 | p95 | p99 | max | statuses |")
        print("|---|---:|---:|---:|---:|---:|---:|---:|---|")
        for (name, clients), (rate, p50, p95, p99, worst, total, statuses) in rows.items():
            counts = ", ".join(f"{code or 'error'}:{count}" for code, count in sorted(statuses.items()))
            print(f"| {name} | {clients} | {total} | {rate:,.0f} | {p50:.3f} | {p95:.3f} | {p99:.3f} | {worst:.3f} | {counts} |")
        print()
        print("## Added by the edge (edge minus origin, ms)")
        print()
        print("| clients | p50 | p95 | p99 |")
        print("|---:|---:|---:|---:|")
        for clients in sorted({clients for _name, clients in rows}):
            origin, edge = rows[("origin", clients)], rows[("edge", clients)]
            print(f"| {clients} | {edge[1] - origin[1]:.3f} | {edge[2] - origin[2]:.3f} | {edge[3] - origin[3]:.3f} |")
        print()
        print("Budget (docs/21): added P95 <= 15 ms for the no-model path. This table is one machine's")
        print("indication, not a verified result; see the script header for what is not measured.")
        bad = [key for key, value in rows.items() if key[0] != "denied" and set(value[6]) != {200}]
        if bad:
            print(f"warning: non-200 answers for {bad}; the numbers above include error responses", file=sys.stderr)
            return 1
        return 0
    finally:
        for child in children:
            if child.poll() is None:
                child.send_signal(signal.SIGKILL)
        for child in children:
            child.wait()
        if args.keep:
            print(f"scratch kept: {scratch}", file=sys.stderr)
        else:
            shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Raw durable-append latency of a directory's volume (docs/21 section 21.7).

The edge's no-model latency is dominated by the journal's durable sync (13.9),
so before reading `bench_gateway.py` numbers on a machine, measure what one
sync costs there: append a block the size of one audit batch, `fdatasync`
(`F_FULLFSYNC` on macOS, as `File::sync_data` does), repeat, and print the
latency distribution. Comparing two volumes (an NVMe disk and a tmpfs, say)
tells how much of the edge's added latency is the storage.

  scripts/bench_fsync.py /var/lib/xshield /dev/shm
"""
from __future__ import annotations

import argparse
import os
import platform
import sys
import tempfile
import time
from pathlib import Path


def durable_sync(fd: int) -> None:
    if sys.platform == "darwin":
        import fcntl

        fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
    else:
        os.fdatasync(fd)


def percentile(sorted_ns: list[int], fraction: float) -> float:
    index = min(len(sorted_ns) - 1, max(0, int(round(fraction * len(sorted_ns) + 0.5)) - 1))
    return sorted_ns[index] / 1e6


def measure(directory: Path, count: int, block: int) -> list[int]:
    payload = os.urandom(block)
    fd, name = tempfile.mkstemp(prefix="xshield-fsync-", dir=directory)
    try:
        latencies = []
        for _ in range(count):
            started = time.perf_counter_ns()
            os.write(fd, payload)
            durable_sync(fd)
            latencies.append(time.perf_counter_ns() - started)
        return sorted(latencies)
    finally:
        os.close(fd)
        os.unlink(name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directories", nargs="+", type=Path)
    parser.add_argument("--count", type=int, default=2000, help="appends per directory (default 2000)")
    parser.add_argument("--block", type=int, default=2600, help="bytes per append (default 2600, one audit batch)")
    args = parser.parse_args()
    print(f"- {platform.platform()}, {os.cpu_count()} CPUs, load average {os.getloadavg()[0]:.2f}")
    print(f"- {args.count} appends of {args.block} bytes, each followed by a durable sync")
    print()
    print("| directory | syncs/s | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |")
    print("|---|---:|---:|---:|---:|---:|")
    for directory in args.directories:
        latencies = measure(directory, args.count, args.block)
        rate = len(latencies) / (sum(latencies) / 1e9)
        print(f"| {directory} | {rate:,.0f} | {percentile(latencies, 0.50):.3f} | {percentile(latencies, 0.95):.3f} "
              f"| {percentile(latencies, 0.99):.3f} | {latencies[-1] / 1e6:.3f} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())

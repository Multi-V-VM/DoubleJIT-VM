#!/usr/bin/env python3
"""Measure a standalone actor executable with reproducible warmup and trials."""

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--runs", type=int, default=15)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or args.command[0] != "--" or len(args.command) == 1:
        parser.error("provide the executable after --")
    command = args.command[1:]

    for _ in range(args.warmup):
        subprocess.run(command, check=True)

    samples_ns = []
    for _ in range(args.runs):
        started = time.perf_counter_ns()
        subprocess.run(command, check=True)
        samples_ns.append(time.perf_counter_ns() - started)

    result = {
        "command": command,
        "warmup_runs": args.warmup,
        "measured_runs": args.runs,
        "samples_ns": samples_ns,
        "median_ns": int(statistics.median(samples_ns)),
        "mean_ns": int(statistics.mean(samples_ns)),
        "min_ns": min(samples_ns),
        "max_ns": max(samples_ns),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

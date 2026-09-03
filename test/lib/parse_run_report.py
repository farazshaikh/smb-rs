#!/usr/bin/env python3
"""Parse a smb-testsuite RunReport JSON into CSV rows for the system suite.

Emits `name,category,status,duration_ms,note` rows (no header) to stdout,
one per case in `cases[]` (id -> name, message -> note).

Usage: parse_run_report.py [path/to/run.json]   # defaults to the newest
                                                  # report under test/data/runs
       parse_run_report.py ... | update_status.py system
"""
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_DIR = REPO_ROOT / "test" / "data" / "runs"


def latest_report() -> Path:
    reports = sorted(RUNS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not reports:
        sys.exit(f"no run reports found under {RUNS_DIR}")
    return reports[-1]


def main() -> None:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else latest_report()
    report = json.loads(path.read_text())

    writer = csv.writer(sys.stdout)
    for case in report["cases"]:
        writer.writerow([
            case["id"],
            case["category"],
            case["status"],
            case["duration_ms"],
            case["message"],
        ])


if __name__ == "__main__":
    main()

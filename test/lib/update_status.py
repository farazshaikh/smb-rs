#!/usr/bin/env python3
"""Upsert one suite's rows into test_status.csv.

Reads new rows for SUITE from stdin as CSV columns `name,category,status,
duration_ms,note` (no header), stamps each with the current timestamp and git
commit, drops any existing rows for SUITE, and appends the new ones. Rows for
other suites are left untouched.

Usage: parse_*.py ... | update_status.py <suite>
"""
import csv
import datetime
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = REPO_ROOT / "test_status.csv"
FIELDS = ["suite", "name", "category", "status", "duration_ms", "timestamp", "commit", "note"]


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def load_existing() -> list[dict]:
    if not CSV_PATH.exists():
        return []
    with open(CSV_PATH, newline="") as f:
        return list(csv.DictReader(f))


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: update_status.py <suite> < new-rows.csv")
    suite = sys.argv[1]

    commit = git_commit()
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

    new_rows = [
        {
            "suite": suite,
            "name": name,
            "category": category,
            "status": status,
            "duration_ms": duration_ms,
            "timestamp": now,
            "commit": commit,
            "note": note,
        }
        for name, category, status, duration_ms, note in csv.reader(sys.stdin)
    ]

    rows = [r for r in load_existing() if r["suite"] != suite] + new_rows
    rows.sort(key=lambda r: (r["suite"], r["name"]))

    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"update_status: {suite}: {len(new_rows)} row(s) written -> {CSV_PATH}")


if __name__ == "__main__":
    main()

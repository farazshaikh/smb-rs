#!/usr/bin/env python3
"""Merge test results from all three suites into the dashboard CSV.

Sources (any subset may be supplied):
  --trx <file>          VSTest .trx  -> suite=protocol
  --cargo <file>        `cargo test` stdout -> suite=unit
  --conformance <file>  smb-testrunner stdout -> suite=system

Output schema: suite,name,category,status,duration_ms,timestamp
"""
import argparse
import csv
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def git_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True).strip()
    except Exception:
        return ""


def protocol_rows(path):
    tree = ET.parse(path)
    root = tree.getroot()
    class_by_test = {}
    for unit in root.findall(".//t:TestDefinitions/t:UnitTest", NS):
        method = unit.find("t:TestMethod", NS)
        if method is not None and unit.get("id"):
            class_by_test[unit.get("id")] = method.get("className", "")
    rows = []
    for result in root.findall(".//t:Results/t:UnitTestResult", NS):
        class_name = class_by_test.get(result.get("testId", ""), "")
        rows.append({
            "suite": "protocol",
            "name": result.get("testName", "").rsplit(".", 1)[-1],
            "category": class_name.rsplit(".", 1)[-1] or "Unknown",
            "status": _trx_status(result.get("outcome")),
            "duration_ms": _hms_ms(result.get("duration")),
            "timestamp": result.get("startTime", ""),
        })
    return rows


def _trx_status(outcome):
    o = (outcome or "").lower()
    return {"passed": "pass", "failed": "fail"}.get(o, "skip")


def _hms_ms(text):
    if not text:
        return 0
    try:
        h, m, s = text.split(":")
        return int((int(h) * 3600 + int(m) * 60 + float(s)) * 1000)
    except ValueError:
        return 0


def _protocol_category(name):
    stem = name[4:] if name.startswith("BVT_") else name
    return stem.split("_", 1)[0] or "Unknown"


def protocol_list_rows(path):
    """Seed every protocol test as `unknown` from a `--list-tests` dump."""
    rows, ts = [], now_iso()
    with open(path, errors="replace") as f:
        for line in f:
            name = line.strip()
            if not name or " " in name or not name[0].isalpha():
                continue
            rows.append({
                "suite": "protocol",
                "name": name,
                "category": _protocol_category(name),
                "status": "unknown",
                "duration_ms": 0,
                "timestamp": ts,
            })
    return rows


# `test <path>::<name> ... ok|FAILED|ignored`
CARGO_RE = re.compile(r"^test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)")
CARGO_CRATE_RE = re.compile(r"Running\s+\S+\s+.*deps/([A-Za-z0-9_]+)-[0-9a-f]+")


def unit_rows(path):
    rows, crate = [], "workspace"
    ts = now_iso()
    with open(path, errors="replace") as f:
        for line in f:
            crate_match = CARGO_CRATE_RE.search(line)
            if crate_match:
                crate = crate_match.group(1)
                continue
            m = CARGO_RE.match(line.strip())
            if not m:
                continue
            status = {"ok": "pass", "FAILED": "fail", "ignored": "skip"}[m.group(2)]
            rows.append({
                "suite": "unit",
                "name": m.group(1),
                "category": crate,
                "status": status,
                "duration_ms": 0,
                "timestamp": ts,
            })
    return rows


# `  PASS security.query_descriptor    97 ms`
CONF_RE = re.compile(r"^\s*(PASS|FAIL|SKIP|ERROR)\s+(\S+)\s+(?:(\d+)\s*ms)?")


def system_rows(path):
    rows, ts = [], now_iso()
    with open(path, errors="replace") as f:
        for line in f:
            m = CONF_RE.match(line)
            if not m:
                continue
            name = m.group(2)
            rows.append({
                "suite": "system",
                "name": name,
                "category": name.split(".", 1)[0],
                "status": {"PASS": "pass", "FAIL": "fail", "ERROR": "fail",
                           "SKIP": "skip"}[m.group(1)],
                "duration_ms": int(m.group(3) or 0),
                "timestamp": ts,
            })
    return rows


def load_base(path):
    """Load an existing CSV keyed by (suite, name) so prior results survive an
    incremental sweep that only re-ran a subset of tests."""
    base = {}
    if not path or not os.path.exists(path):
        return base
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            r["duration_ms"] = int(r.get("duration_ms") or 0)
            r.setdefault("commit", "")
            base[(r["suite"], r["name"])] = r
    return base


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", help="existing CSV to preserve (incremental sweep)")
    ap.add_argument("--trx")
    ap.add_argument("--protocol-list")
    ap.add_argument("--cargo")
    ap.add_argument("--conformance")
    ap.add_argument("--commit", default=git_commit(),
                    help="changeset to stamp on newly passing tests (default: git HEAD)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    # Start from prior results, seed any unseen protocol tests as unknown, then
    # overlay freshly produced outcomes (last write wins).
    base = load_base(args.base)
    merged = dict(base)
    if args.protocol_list:
        for r in protocol_list_rows(args.protocol_list):
            merged.setdefault((r["suite"], r["name"]), r)
    for r in (protocol_rows(args.trx) if args.trx else []):
        merged[(r["suite"], r["name"])] = r
    for r in (unit_rows(args.cargo) if args.cargo else []):
        merged[(r["suite"], r["name"])] = r
    for r in (system_rows(args.conformance) if args.conformance else []):
        merged[(r["suite"], r["name"])] = r

    stamp_commits(merged, base, args.commit)

    rows = sorted(merged.values(), key=lambda r: (r["suite"], r["category"], r["name"]))
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["suite", "name", "category", "status",
                           "duration_ms", "timestamp", "commit"])
        w.writeheader()
        w.writerows(rows)

    by_suite = {}
    for r in rows:
        by_suite.setdefault(r["suite"], []).append(r["status"])
    print(f"wrote {len(rows)} rows to {args.out}")
    for suite, statuses in sorted(by_suite.items()):
        p = statuses.count("pass")
        print(f"  {suite:9} {p}/{len(statuses)} passed")


def stamp_commits(merged, base, commit):
    """Record the changeset each test passed at: keep a prior pass's commit,
    stamp a newly passing test with the current changeset, clear non-passes."""
    for key, r in merged.items():
        if r.get("status") != "pass":
            r["commit"] = ""
            continue
        prev = base.get(key)
        if prev and prev.get("status") == "pass" and prev.get("commit"):
            r["commit"] = prev["commit"]
        elif not r.get("commit"):
            r["commit"] = commit


if __name__ == "__main__":
    main()

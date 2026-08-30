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
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trx")
    ap.add_argument("--protocol-list")
    ap.add_argument("--cargo")
    ap.add_argument("--conformance")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = []
    if args.trx:
        rows += protocol_rows(args.trx)
    elif args.protocol_list:
        rows += protocol_list_rows(args.protocol_list)
    if args.cargo:
        rows += unit_rows(args.cargo)
    if args.conformance:
        rows += system_rows(args.conformance)

    rows.sort(key=lambda r: (r["suite"], r["category"], r["name"]))
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["suite", "name", "category", "status", "duration_ms", "timestamp"])
        w.writeheader()
        w.writerows(rows)

    by_suite = {}
    for r in rows:
        by_suite.setdefault(r["suite"], []).append(r["status"])
    print(f"wrote {len(rows)} rows to {args.out}")
    for suite, statuses in sorted(by_suite.items()):
        p = statuses.count("pass")
        print(f"  {suite:9} {p}/{len(statuses)} passed")


if __name__ == "__main__":
    main()

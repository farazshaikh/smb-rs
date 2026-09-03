#!/usr/bin/env python3
"""Parse `cargo test --workspace` text output into CSV rows for the unit suite.

Tracks which test binary ("Running ... (target/.../deps/NAME-hash)" or
"Doc-tests NAME") each `test <path> ... <outcome>` line belongs to, and emits
`name,category,status,duration_ms,note` rows (no header) to stdout, where
`category` is the binary/crate slug (e.g. `smb_proto_smb2`, `conformance`).
Default cargo test output carries no per-test duration, so duration_ms is 0.

Usage: cargo test --workspace 2>&1 | tee log; parse_cargo_test.py log | update_status.py unit
"""
import csv
import re
import sys

RUNNING_RE = re.compile(r"^\s*Running .*deps[/\\]([A-Za-z0-9_]+)-[0-9a-f]+\)?\s*$")
DOCTEST_RE = re.compile(r"^\s*Doc-tests\s+(\S+)\s*$")
TEST_RE = re.compile(r"^test\s+(\S+)\s+\.\.\.\s+(ok|FAILED|ignored)\b")

STATUS_MAP = {"ok": "pass", "FAILED": "fail", "ignored": "skip"}


def parse(lines: list[str]) -> list[tuple[str, str, str, str, str]]:
    rows = []
    binary = "unknown"
    for line in lines:
        if m := RUNNING_RE.match(line):
            binary = m.group(1)
        elif m := DOCTEST_RE.match(line):
            binary = m.group(1)
        elif m := TEST_RE.match(line):
            name, outcome = m.group(1), m.group(2)
            rows.append((name, binary, STATUS_MAP[outcome], "0", ""))
    return rows


def main() -> None:
    text = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    rows = parse(text.splitlines())
    writer = csv.writer(sys.stdout)
    writer.writerows(rows)


if __name__ == "__main__":
    main()

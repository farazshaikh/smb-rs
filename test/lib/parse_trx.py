#!/usr/bin/env python3
"""Parse an MSTest TRX file (dotnet test's `trx` logger) into CSV rows for the
protocol suite.

Emits `name,category,status,duration_ms,note` rows (no header) to stdout.
`category` is the test class's last namespace segment (e.g. `AppInstanceIdBasic`
from `Microsoft.Protocols.TestSuites.FileServer.AppInstanceIdBasic`), matching
Microsoft's WindowsProtocolTestSuites test-suite grouping.

Usage: parse_trx.py path/to/result.trx | update_status.py protocol
"""
import csv
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}

OUTCOME_MAP = {
    "passed": "pass",
    "failed": "fail",
    "timeout": "fail",
    "aborted": "fail",
    "notexecuted": "skip",
    "inconclusive": "skip",
}

DURATION_RE = re.compile(r"^(\d+):(\d+):(\d+)(?:\.(\d+))?$")


def duration_ms(raw: str) -> int:
    m = DURATION_RE.match(raw or "")
    if not m:
        return 0
    h, mnt, s, frac = m.groups()
    total_ms = (int(h) * 3600 + int(mnt) * 60 + int(s)) * 1000
    if frac:
        total_ms += int((frac + "000")[:3])
    return total_ms


def class_name_of(unit_test: ET.Element) -> str:
    method = unit_test.find("t:TestMethod", NS)
    class_name = method.get("className") if method is not None else ""
    return class_name.rsplit(".", 1)[-1] if class_name else "unknown"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: parse_trx.py <result.trx>")
    root = ET.parse(Path(sys.argv[1])).getroot()

    class_by_test_id = {
        unit_test.get("id"): class_name_of(unit_test)
        for unit_test in root.findall(".//t:TestDefinitions/t:UnitTest", NS)
    }

    writer = csv.writer(sys.stdout)
    for result in root.findall(".//t:Results/t:UnitTestResult", NS):
        message_el = result.find("t:Output/t:ErrorInfo/t:Message", NS)
        writer.writerow([
            result.get("testName"),
            class_by_test_id.get(result.get("testId"), "unknown"),
            OUTCOME_MAP.get((result.get("outcome") or "").lower(), "unknown"),
            duration_ms(result.get("duration")),
            (message_el.text or "").strip() if message_el is not None else "",
        ])


if __name__ == "__main__":
    main()

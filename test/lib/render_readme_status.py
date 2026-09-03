#!/usr/bin/env python3
"""Render a snapshot of test_status.csv into README.md, between the
<!-- TEST_STATUS_START/END --> markers, mirroring what smb-server-test-dashboard
serves live. Run standalone or via test/runtest.sh after any suite run.
"""
import csv
import datetime
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CSV_PATH = REPO_ROOT / "test_status.csv"
README_PATH = REPO_ROOT / "README.md"
START = "<!-- TEST_STATUS_START -->"
END = "<!-- TEST_STATUS_END -->"

SUITE_INFO = {
    "protocol": "Microsoft's official MS-SMB2 Server Test Suite (Windows Protocol Test Suites)",
    "system": "End-to-end interop tests driving a live server through the Python `smbprotocol` client",
    "unit": "In-process Rust unit & integration tests (`cargo test --workspace`)",
}
SUITE_ORDER = ["protocol", "system", "unit"]


def normalize(status: str) -> str:
    s = status.strip().lower()
    if s in ("pass", "passed", "ok"):
        return "pass"
    if s in ("fail", "failed", "error"):
        return "fail"
    if s in ("skip", "skipped", "notexecuted", "ignored"):
        return "skip"
    return "unknown"


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    except Exception:
        return ""


def summarize(rows: list[dict]) -> dict:
    by_suite: dict[str, dict[str, int]] = {}
    for row in rows:
        s = by_suite.setdefault(row["suite"], {"pass": 0, "fail": 0, "skip": 0, "unknown": 0, "total": 0})
        s[normalize(row["status"])] += 1
        s["total"] += 1
    return by_suite


def pass_rate(s: dict) -> float:
    ran = s["total"] - s["skip"]
    return 100.0 * s["pass"] / ran if ran else 0.0


def render(by_suite: dict, commit: str, now: str) -> str:
    overall = {"pass": 0, "fail": 0, "skip": 0, "unknown": 0, "total": 0}
    for s in by_suite.values():
        for k in overall:
            overall[k] += s[k]

    lines = [START, ""]
    lines.append(
        f"**{overall['total']} tests · {overall['pass']} passed · {overall['fail']} failed · "
        f"{overall['skip']} skipped · {pass_rate(overall):.1f}% pass rate** "
        f"(commit `{commit}`, {now})"
    )
    lines.append("")
    lines.append("| Suite | What it runs | Passed | Failed | Skipped | Total |")
    lines.append("|---|---|---|---|---|---|")
    for name in SUITE_ORDER:
        s = by_suite.get(name)
        if not s:
            continue
        lines.append(
            f"| **{name}** | {SUITE_INFO[name]} | {s['pass']} | {s['fail']} | {s['skip']} | {s['total']} |"
        )
    lines.append("")
    lines.append(
        "Generated from [`test_status.csv`](test_status.csv) by "
        "[`test/lib/render_readme_status.py`](test/lib/render_readme_status.py) "
        "after a test run. Live view: `smb-server-test-dashboard` (see "
        "[test/README.md](test/README.md))."
    )
    lines.append("")
    lines.append(END)
    return "\n".join(lines)


def main() -> None:
    rows = list(csv.DictReader(open(CSV_PATH)))
    by_suite = summarize(rows)
    commit = git_commit()
    now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d")
    block = render(by_suite, commit, now)

    text = README_PATH.read_text()
    start_i = text.index(START)
    end_i = text.index(END) + len(END)
    new_text = text[:start_i] + block + text[end_i:]
    README_PATH.write_text(new_text)
    print(f"render_readme_status: wrote summary for {sum(s['total'] for s in by_suite.values())} tests -> {README_PATH}")


if __name__ == "__main__":
    main()

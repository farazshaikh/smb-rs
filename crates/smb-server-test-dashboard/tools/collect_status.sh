#!/usr/bin/env bash
# Regenerate the dashboard CSV from all three test suites.
#
#   collect_status.sh [--trx <file>] [--out <csv>] [--sut-port <n>]
#
# Runs the Rust unit tests and the smbprotocol conformance (system) suite, and
# folds in a protocol .trx if one is supplied, then writes the merged CSV that
# smb-server-test-dashboard serves.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tools="$repo_root/crates/smb-server-test-dashboard/tools"

trx=""
out="$repo_root/test_status.csv"
sut_port=4452
share="/tmp/smb-ct-share"
python="/tmp/smbtest_venv/bin/python"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trx) trx="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --sut-port) sut_port="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

cd "$repo_root"
cargo build -p smb-server --bin rustsmb -q
cargo build -p smb-server-testsuite --bin smb-testrunner -q

echo "== unit tests =="
cargo test --workspace 2>&1 | tee /tmp/cargo_tests.txt >/dev/null || true

echo "== system (conformance) tests =="
./target/debug/rustsmb -p "$sut_port" -s "public=$share" -u faraz:pass --log warn >/dev/null 2>&1 &
srv=$!
sleep 2
./target/debug/smb-testrunner --host 127.0.0.1 --port "$sut_port" \
  --user faraz --pass pass --python "$python" >/tmp/conf.txt 2>&1 || true
kill "$srv" 2>/dev/null || true

args=(--cargo /tmp/cargo_tests.txt --conformance /tmp/conf.txt --out "$out")
[[ -n "$trx" ]] && args+=(--trx "$trx")

echo "== merge =="
python3 "$tools/collect_status.py" "${args[@]}"

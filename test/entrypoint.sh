#!/usr/bin/env bash
# Entrypoint for the smb-server-rs conformance image: starts the server, runs the
# suite, records results to $DATA_DIR, and exits non-zero on any failure.
set -euo pipefail

PORT="${PORT:-4450}"
DATA_DIR="${DATA_DIR:-/work/test/data}"
SHARE_DIR="${SHARE_DIR:-/tmp/smb-server-rs-share}"
PYTHON="${SMB_TEST_PYTHON:-python3}"
DRIVER="${SMB_TEST_DRIVER:-/work/test/driver/smb_driver.py}"

mkdir -p "$SHARE_DIR" "$DATA_DIR"

# The runner starts rustsmb itself, waits for it to bind, runs every case,
# writes the per-run JSON + CSV history + aggregate results.json, then stops
# the server. Extra args (e.g. --filter Create, --no-fail) pass straight through.
exec smb-testrunner \
    --start-server \
    --server-bin /usr/local/bin/rustsmb \
    --port "$PORT" \
    --share-dir "$SHARE_DIR" \
    --record \
    --data-dir "$DATA_DIR" \
    --python "$PYTHON" \
    --driver "$DRIVER" \
    "$@"

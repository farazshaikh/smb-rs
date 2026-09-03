#!/usr/bin/env bash
# Orchestrates the three smb-server-rs test suites (unit/system/protocol): verifies a
# live server before any suite that needs one, runs the suite, folds results
# into test_status.csv, and refreshes the README summary.
#
# Usage:
#   test/runtest.sh                        # run every suite
#   test/runtest.sh --suite unit           # run one suite (unit|system|protocol|all)
#   test/runtest.sh --setup                # install/patch prerequisites, no test run
#   test/runtest.sh --setup --suite protocol
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$REPO_ROOT/test/lib"
BIN_DIR="$REPO_ROOT/target/debug"
PYTHON="${SMB_TEST_PYTHON:-python3}"

SYSTEM_PORT=4450
PROTOCOL_PORT=4452
SPAWNED_PID=""

log() { echo "[runtest] $*"; }
die() { echo "[runtest] error: $*" >&2; exit 1; }

# ---- server lifecycle ------------------------------------------------------

wait_for_port() {
    local host="$1" port="$2" timeout="${3:-15}"
    local deadline=$(( $(date +%s) + timeout ))
    while (( $(date +%s) < deadline )); do
        if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
            exec 3>&- 3<&- 2>/dev/null || true
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Ensures a rustsmb server is reachable on $port before tests run: reuses one
# already listening there, else starts one from $BIN_DIR/rustsmb (extra args
# forwarded) and records its pid in SPAWNED_PID so only what we started gets
# stopped afterward.
ensure_server() {
    local port="$1"; shift
    if wait_for_port 127.0.0.1 "$port" 1; then
        log "server already up on :$port"
        return 0
    fi
    log "starting rustsmb on :$port"
    "$BIN_DIR/rustsmb" -p "$port" --log warn "$@" &
    SPAWNED_PID=$!
    wait_for_port 127.0.0.1 "$port" 15 || die "rustsmb did not come up on :$port within 15s"
    log "server up on :$port (pid $SPAWNED_PID)"
}

stop_spawned_server() {
    [[ -n "$SPAWNED_PID" ]] || return 0
    kill "$SPAWNED_PID" 2>/dev/null || true
    wait "$SPAWNED_PID" 2>/dev/null || true
    SPAWNED_PID=""
}
trap stop_spawned_server EXIT

# ---- setup ------------------------------------------------------------------

setup_unit() {
    log "unit: building workspace"
    cargo build --workspace
}

setup_system() {
    log "system: building server + testsuite"
    cargo build -p smb-server -p smb-server-testsuite
    "$PYTHON" -c "import smbprotocol" 2>/dev/null \
        || { log "system: installing smbprotocol"; "$PYTHON" -m pip install --user smbprotocol; }
}

setup_protocol() {
    if ! command -v dotnet >/dev/null 2>&1; then
        log "protocol: dotnet SDK not found -- install it, then re-run --setup --suite protocol"
        log "protocol:   sudo apt install dotnet-sdk-8.0   (or) sudo snap install dotnet-sdk"
        return 1
    fi
    log "protocol: building server"
    cargo build -p smb-server
    log "protocol: patching test/wpts for a local SUT"
    "$PYTHON" "$LIB/setup_protocol.py"
    log "protocol: building MS-SMB2 test suite"
    dotnet build "$REPO_ROOT/test/wpts/TestSuites/FileServer/src/SMB2/TestSuite/MS-SMB2_ServerTestSuite.csproj"
}

# ---- run --------------------------------------------------------------------

run_unit() {
    log "unit: cargo test --workspace"
    local out; out="$(mktemp)"
    local status=0
    cargo test --workspace --no-fail-fast > >(tee "$out") 2>&1 || status=$?
    "$PYTHON" "$LIB/parse_cargo_test.py" "$out" | "$PYTHON" "$LIB/update_status.py" unit
    rm -f "$out"
    return "$status"
}

run_system() {
    log "system: smb-testrunner"
    local share_dir; share_dir="$(mktemp -d)"
    ensure_server "$SYSTEM_PORT" -s "public=$share_dir" -u "faraz:pass"
    local status=0
    "$BIN_DIR/smb-testrunner" \
        --host 127.0.0.1 --port "$SYSTEM_PORT" --user faraz --pass pass --share public \
        --python "$PYTHON" --record --data-dir "$REPO_ROOT/test/data" || status=$?
    stop_spawned_server
    "$PYTHON" "$LIB/parse_run_report.py" | "$PYTHON" "$LIB/update_status.py" system
    return "$status"
}

run_protocol() {
    if ! command -v dotnet >/dev/null 2>&1; then
        log "protocol: dotnet SDK not found -- run 'test/runtest.sh --setup --suite protocol' after installing it"
        return 1
    fi
    log "protocol: dotnet test (MS-SMB2 Server Test Suite)"
    local share_dir; share_dir="$(mktemp -d)"
    ensure_server "$PROTOCOL_PORT" \
        -s "SMBBasic=$share_dir" -s "SMBEncrypted=$share_dir" -s "SMBCompressed=$share_dir" \
        --encrypt-share SMBEncrypted --compress-share SMBCompressed \
        -u "Administrator:Password01!" -u "nonadmin:Password01!" -u "Guest:Password01!"
    local results_dir; results_dir="$(mktemp -d)"
    local status=0
    SMB2_SUT_PORT="$PROTOCOL_PORT" dotnet test \
        "$REPO_ROOT/test/wpts/TestSuites/FileServer/src/SMB2/TestSuite/MS-SMB2_ServerTestSuite.csproj" \
        --logger "trx;LogFileName=result.trx" --results-directory "$results_dir" || status=$?
    stop_spawned_server
    "$PYTHON" "$LIB/parse_trx.py" "$results_dir/result.trx" | "$PYTHON" "$LIB/update_status.py" protocol
    return "$status"
}

# ---- dispatch ---------------------------------------------------------------

usage() {
    cat <<'EOF'
Usage: test/runtest.sh [--setup] [--suite unit|system|protocol|all]

  (no flags)            run every suite
  --suite <name>        run (or, with --setup, set up) only that suite
  --setup               install/patch prerequisites for the selected suite(s)
                        (default: all) and exit without running tests
EOF
}

suite="all"
do_setup=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --setup) do_setup=true; shift ;;
        --suite) suite="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

case "$suite" in
    unit|system|protocol|all) ;;
    *) die "unknown --suite '$suite' (want unit|system|protocol|all)" ;;
esac

suites=(unit system protocol)
[[ "$suite" == "all" ]] || suites=("$suite")

exit_code=0

if $do_setup; then
    for s in "${suites[@]}"; do
        "setup_$s" || exit_code=1
    done
    exit "$exit_code"
fi

for s in "${suites[@]}"; do
    "run_$s" || exit_code=1
done

"$PYTHON" "$LIB/render_readme_status.py"
exit "$exit_code"

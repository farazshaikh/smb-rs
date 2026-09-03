# smb-rs conformance & interoperability test suite

A Rust integration-test harness that exercises the `rustsmb` server and tracks
pass/fail and performance metrics across runs. The **test plan** mirrors the
category structure of Microsoft's
[WindowsProtocolTestSuites](https://github.com/microsoft/WindowsProtocolTestSuites)
**FileServer** family ([MS-SMB2], [MS-FSCC], [MS-FSA], [MS-DFSC], [MS-SWN]) —
we use that suite as the reference catalog of what to cover, and implement the
checks as native Rust tests.

## Suites

Three independent suites feed one status file, [`../test_status.csv`](../test_status.csv):

| Suite | What it is | Needs a live server |
|---|---|---|
| `unit` | `cargo test --workspace` — in-process Rust tests | no |
| `system` | this crate's harness (`smb-testrunner`), driven by the Python `smbprotocol` client below | yes |
| `protocol` | Microsoft's official MS-SMB2 Server Test Suite, vendored as the [`wpts`](wpts) submodule | yes |

`../test/runtest.sh` runs them:

```sh
test/runtest.sh --setup                       # install/patch prerequisites (all suites)
test/runtest.sh --setup --suite protocol      # just one suite's prerequisites

test/runtest.sh                               # run every suite
test/runtest.sh --suite unit                  # run one suite (unit|system|protocol|all)
```

It verifies a server is up before any suite that needs one (starting `rustsmb`
itself and health-checking the port if nothing is already listening), runs the
suite, upserts that suite's rows in `test_status.csv` via `test/lib/update_status.py`,
and regenerates the summary embedded in the top-level [README.md](../README.md).

The `protocol` suite needs the [.NET SDK](https://dotnet.microsoft.com/download)
(`dotnet test`); `--setup --suite protocol` also idempotently patches the
submodule so it can point at a local, non-privileged-port SUT instead of a
Windows box on port 445 (see `test/lib/setup_protocol.py`) — that patch lives
in `test/wpts`'s own working tree (a separate git checkout), not in this repo.

## How it fits together

```
test/
├── driver/smb_driver.py     JSON-in/JSON-out SMB actuator (uses `smbprotocol`)
├── Dockerfile               builds the workspace + runs the suite
├── entrypoint.sh            container entrypoint (start server, run, record)
└── data/                    committed results + static history UI
    ├── index.html, app.js   zero-dependency viewer (open directly, no server)
    ├── results.json         aggregate the UI reads (regenerated each run)
    ├── summary.csv          one row per run
    ├── history.csv          one row per (run, case)
    └── runs/<run_id>.json   full per-run report

crates/smb-testsuite/        the Rust harness
├── src/lib.rs               endpoint, driver wrapper, case model, runner
├── src/cases.rs             the case registry (the test plan, in code)
├── src/recorder.rs          JSON/CSV persistence + aggregate
├── src/bin/run.rs           `smb-testrunner` (automated + interactive CLI)
└── tests/conformance.rs     `cargo test` entry (one test per category)
```

Assertions live in Rust; the actual SMB traffic is produced by the Python
`smbprotocol` driver, invoked once per call with a JSON list of operations.

## Running

### Interactive — `cargo test`

Point the tests at a running server (they skip cleanly if `SMB_TEST_HOST` is
unset, so `cargo test --workspace` stays green without one):

```sh
./target/debug/rustsmb -p 4450 -s public=/tmp/share -u faraz:pass &
SMB_TEST_HOST=127.0.0.1 SMB_TEST_PORT=4450 \
SMB_TEST_USER=faraz SMB_TEST_PASS=pass SMB_TEST_SHARE=public \
SMB_TEST_PYTHON=/path/to/python-with-smbprotocol \
cargo test -p smb-testsuite
```

### Automated — `smb-testrunner`

Starts the server itself, runs every case, and records a run under `test/data/`:

```sh
cargo build -p smb-server -p smb-testsuite
./target/debug/smb-testrunner --start-server --port 4450 --record \
    --python /path/to/python-with-smbprotocol
./target/debug/smb-testrunner --list           # list cases
./target/debug/smb-testrunner --filter Create   # run one category
```

### Docker

```sh
docker build -f test/Dockerfile -t smb-rs-test .
docker run --rm --security-opt seccomp=unconfined \
    -v "$PWD/test/data:/work/test/data" smb-rs-test
```

> `--security-opt seccomp=unconfined` is required because the server uses
> `io_uring`, which Docker's default seccomp profile restricts.

### Viewing history

Open `test/data/index.html` in a browser (directly, or via any static file
server). It renders `results.json`: summary cards, a pass-rate sparkline across
runs, per-category breakdown, the latest run's cases, and the full run history.

## Metrics recorded per run

- Per-case status (`pass`/`fail`/`skip`/`error`) and duration.
- Suite totals and pass rate, tracked across runs for trends.
- Git commit, server version, host, timestamp.
- Throughput-relevant metrics (e.g. bytes moved by the large-MTU case).

Results are written as CSV + JSON under `test/data/` (`summary.csv` carries the
git commit per run, so a revision's results are greppable). The commit column
keys results to the revision under test.

## Test plan (category catalog)

Mapped to the MS FileServer/MS-SMB2 test categories. `implemented` = a Rust
case exists; `planned` = catalogued for a future harness iteration.

| Category | MS-SMB2 ref | Coverage | Status |
|---|---|---|---|
| Negotiate | §2.2.3/4 | dialects 2.0.2/2.1.0/3.1.1, default negotiation | implemented |
| Session | §2.2.5, MS-NLMP | NTLM auth, signed session | implemented |
| Encryption | §2.2.41, §3.3.5.16 | AES transform roundtrip | implemented |
| TreeConnect | §2.2.9/10 | connect to share | implemented |
| Create | §2.2.13 | create/overwrite_if/open-missing/dir open | implemented |
| ReadWrite | §2.2.19/21 | small, offset, 256 KiB large-MTU (crc-verified) | implemented |
| Directory | §2.2.33/34 | enumeration, wildcard pattern | implemented |
| Ioctl/FSCTL | §2.2.31 | validate-negotiate, query-network-interface | implemented |
| QueryInfo | §2.2.37, MS-FSCC §2.4 | standard, all, network-open | implemented |
| SetInfo | §2.2.39, MS-FSCC §2.4 | set-EOF, rename, delete disposition | implemented |
| Locking | §2.2.26/27 | exclusive conflict + unlock roundtrip | implemented |
| Streams (ADS) | MS-FSCC §2.6 | named-stream read/write + enumeration | implemented |
| Security | MS-FSCC §2.4.6 | query owner/group/DACL descriptor | implemented |
| Oplock/Lease | §2.2.23/24 | grant + break | planned |
| DurableHandle | §2.2.13.2 | grant → reconnect | planned |
| ChangeNotify | §2.2.35/36 | recursive + non-recursive notify | planned |
| Compound | §3.3.5.2 | chained requests | planned |
| SetInfo security | MS-FSCC §2.4.6 | set SD | planned |
| Signing policy | §3.3.5.2.3 | require-signing enforcement | planned |

Adding a case is a single entry in `crates/smb-testsuite/src/cases.rs`; the
runner, `cargo test`, recorder, and UI pick it up automatically.

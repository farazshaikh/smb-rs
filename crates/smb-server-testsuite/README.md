# smb-server-testsuite

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Conformance/interoperability test harness for the server — the `system`
suite in the project's three-suite test model (alongside `unit` and the
vendored `protocol` suite; see [test/README.md](../../test/README.md)).
Assertions live here in Rust; the actual SMB traffic is produced by a small
Python `smbprotocol` driver (`test/driver/smb_driver.py`) invoked once per
call, so test cases stay idiomatic Rust while reusing a mature client.

Two entry points share one case registry (`cases.rs`): `cargo test -p
smb-server-testsuite` for interactive runs against an already-running server, and
the `smb-testrunner` binary for automated runs that start the server, run
every case, and record results under `test/data/`. This crate has no path
dependency on any other workspace crate — it drives the server over the
network, the same way a real client would.

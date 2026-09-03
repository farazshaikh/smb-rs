# smb-server-test-dashboard

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

A tiny, dependency-free HTTP server that serves MS-SMB2 test results. It
reads `test_status.csv` (the source of truth for pass/fail state, kept
current by [test/runtest.sh](../../test/runtest.sh)), exposes a small REST
API over it, and serves a static single-page dashboard rendering per-suite
pass/fail/skip counts and history.

Listens on the SMB port plus one by default, so it sits next to the server
under test. Standalone — no path dependency on any other workspace crate;
it only reads the CSV file.

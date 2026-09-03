# smb-server

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

The `rustsmb` server binary: CLI argument parsing, the async accept loop,
SMB1/SMB2 request dispatch, session/tree/handle state, and observability
(tracing + Prometheus metrics). This is where every other crate in the
workspace comes together — `smb-server-proto`/`smb-server-proto-smb1`/`smb-server-proto-smb2`
for wire codecs, `smb-server-transport` for framing, `smb-server-vfs`/`smb-server-backend-posix`
for storage, `smb-server-auth` for authentication, and `smb-server-handle-store` for
durable handles.

Runs fully async on `io_uring` via a `tokio_uring` current-thread runtime —
see the top-level [README](../../README.md) for the full concurrency model
and feature set.

# smb-server-transport

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Async SMB message transport abstraction. A `Transport` trait moves complete
SMB frames (the bytes between NBSS headers, i.e. starting at the `\xFFSMB`
or `\xFESMB` magic) over some network or in-memory channel, so the server's
dispatch loop can be exercised without real sockets.

Implementations: `tcp` (RFC 1002 NBSS-over-TCP framing, io_uring-backed) and
`mem` (in-process, used by tests and the transport crate's own test suite).
`smb-server` depends on this crate for all network I/O; it has no
dependency on any other workspace crate.

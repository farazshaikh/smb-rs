# smb-server-backend-posix

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Default storage backend mapping the `smb-server-vfs` interface onto POSIX file
semantics. The data path (open/read/write/fsync) and mutating directory
operations (mkdir/rmdir/rename/unlink) run on **io_uring** via
`tokio_uring::fs` — non-blocking, zero-copy, completion-based. Read-only
metadata and directory enumeration use `std::fs`, since Linux has no async
`getdents`/`statx` fast path.

All client paths are resolved inside the configured share root — `..`
traversal and absolute components are refused, and existing entries are
matched case-insensitively to emulate Windows semantics. Depends on
`smb-server-proto` and `smb-server-vfs`; `smb-server` links it as the (currently only)
storage backend.

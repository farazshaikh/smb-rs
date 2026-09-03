# smb-server-proto

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Dialect-neutral SMB protocol primitives shared by every SMB dialect: the
`Wire` codec trait used by all on-wire structures, explicit-endian integer
readers, NT status codes, FILETIME conversion, and the byte-buffer helpers
that implement SMB's string and alignment rules.

This is the foundation crate the rest of the workspace builds on —
`smb-server-proto-smb1`, `smb-server-proto-smb2`, `smb-server-proto-smb3`, `smb-server-vfs`, `smb-server-auth`
and `smb-server` all depend on it directly. It has no dependency on any
other crate in the workspace.

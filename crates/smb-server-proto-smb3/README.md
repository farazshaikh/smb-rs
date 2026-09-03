# smb-server-proto-smb3

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Reserved placeholder for SMB3-only wire transforms that don't belong in
`smb-server-proto-smb2`, should the SMB3 surface ever grow enough to warrant
splitting out on its own.

Today SMB3's encryption transform and compression already live directly in
`smb-server-proto-smb2` (see its `commands`/`compress`/`negotiate` modules), so this
crate is currently an unused scaffold: a workspace member that nothing else
depends on. Treat it as reserved namespace, not working code, until a
concrete SMB3-only feature needs it.

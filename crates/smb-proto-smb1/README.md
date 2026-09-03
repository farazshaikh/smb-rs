# smb-proto-smb1

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

SMB1 ([MS-SMB]/[MS-CIFS]) wire structures: the SMB header and response/AndX
assembly, `NT_CREATE_ANDX`, `READ_ANDX`/`WRITE_ANDX`, the TRANS2 subcommand
family (`FIND_*`, `QUERY_FS`, `QUERY`/`SET_PATH`/`FILE`), and legacy
core/LANMAN-era commands (`MKDIR`/`RMDIR`/`CHECKDIR`, `DELETE`, `RENAME`,
`QUERY`/`SET_INFORMATION`).

Built on `smb-proto`'s codec trait and value types; holds no VFS or
networking logic of its own, only the SMB1 wire format. `smb-server` links
this crate to decode and encode every SMB1 request and response it serves.

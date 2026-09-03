# smb-server-proto-smb2

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

SMB2/SMB3 wire structures ([MS-SMB2]): the 64-byte header, `NEGOTIATE` (all
dialects plus negotiate contexts), `SESSION_SETUP`, `TREE_CONNECT`,
`CREATE`/`READ`/`WRITE`/`CLOSE`/`FLUSH`, directory/query/set information
levels, `CHANGE_NOTIFY`, compound-request framing, and today's SMB3
additions — the encryption transform header and compression (LZNT1, LZ77,
Pattern_V1).

Depends on `smb-server-proto` for shared primitives and on `smb-server-vfs` for the
neutral operation types it encodes to and from the wire. `smb-server` links
this crate for every SMB2/SMB3 request it serves.

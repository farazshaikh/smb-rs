# smb-server-vfs

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Dialect-neutral virtual filesystem interface. Protocol dispatchers
(SMB1/SMB2) translate incoming commands into the operations of the `Vfs`
trait; storage backends implement those operations. This is the seam that
keeps information-level encoding, access-mask mapping and NTSTATUS
translation entirely inside the protocol layers and out of storage
backends, so SMB1 and SMB2 drive the same backend and stay behaviourally
identical.

Depends on `smb-server-proto` for shared value types. `smb-server-proto-smb2` and
`smb-server-backend-posix` both depend on it — the former to describe operations
neutrally, the latter to implement them against POSIX filesystems.

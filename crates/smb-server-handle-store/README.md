# smb-server-handle-store

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Pluggable store for durable and persistent SMB handles ([MS-SMB2] §3.3.1.10)
— state that lets a client reclaim an open file across a disconnect (or, for
replicated backends, a server node failover) via `DH2C`. One async
`HandleStore` trait keeps the server code backend-agnostic:

- `MemStore` — in-process, non-durable (single node, dev/tests).
- `RedbStore` (feature `redb-backend`, default) — embedded durable KV;
  survives a process restart on one node.
- Replicated backends (openraft/etcd) can plug in behind the same trait for
  multi-node continuous availability, without touching SMB protocol code.

Only handle *lifecycle* state lives here (open/close/reclaim/lock), never
the file data path — values stay small and writes are infrequent.
`smb-server` depends on this crate to back its durable-handle support.

# smb-csp

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

Crypto service provider: one stable API surface (MD4, HMAC-MD5/SHA256,
AES-GCM/CCM, RC4, SHA-256) behind two interchangeable backends selected at
compile time —

- **`lib`** (default) — maintained [RustCrypto](https://github.com/RustCrypto)
  crates, with hardware acceleration (AES-NI et al.) where available; the
  production choice.
- **`handrolled`** — the bundled from-scratch implementations. Zero external
  dependencies, useful for auditing or constrained builds.

The two backends are mutually exclusive (selecting both, or neither, is a
compile error) and must produce byte-identical output; both are exercised
against the same test vectors. `smb-auth` depends on this crate for every
cryptographic primitive it needs; nothing in this crate depends on the rest
of the workspace.

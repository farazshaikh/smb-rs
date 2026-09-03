# smb-server-auth

This is part of the [smb-server-rs](https://github.com/farazshaikh/smb-server-rs)
project: a pure-Rust, high-performance SMB1/2/3 server implementation.

## About

SMB authentication primitives: [MS-NLMP] NTLMSSP message construction and
parsing, the minimal SPNEGO DER wrapping used during extended-security
session setup, and NTLMv1/v2 challenge/response verification. Dialect
independent — SMB1 extended security and SMB2 session setup both speak
SPNEGO + NTLMSSP through this crate.

Cryptographic primitives (MD4, HMAC-MD5, HMAC-SHA256) are delegated to
`smb-server-csp` rather than implemented here. `smb-server` depends on this crate
for every session setup it handles.

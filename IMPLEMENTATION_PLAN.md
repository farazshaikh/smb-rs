# smb-rs Implementation Plan

## Legend
- ✅ DONE — implemented, tested, verified
- 🔨 IN PROGRESS — code written but has known issues
- ⬜ TODO — not started

---

## Phase 0: Foundation

- ✅ Cargo workspace (7 crates, modular, independently testable)
- ✅ `deny(missing_docs)`, `forbid(unsafe_code)` on all crates
- ✅ Explicit-endian reads (`from_le_bytes` / `to_le_bytes`)
- ✅ Zero-copy decode trait (`Wire` with `'de` lifetime borrows)
- ✅ Async transport abstraction (`Transport` trait, tokio)
- ✅ VFS abstraction trait (`Vfs` with async methods)
- ✅ POSIX backend (`PosixVfs`: path containment, wildcards, case-insensitive)
- ✅ Crypto primitives (MD4, MD5, HMAC-MD5, DES — RFC vectors pass)

## Phase 1: SMB1 ([MS-SMB] + [MS-CIFS])

### Transport and Framing
- ✅ NBSS framing over TCP (RFC 1002)
- ✅ Session request / keepalive handling
- ✅ Multi-protocol upgrade detection (\xFESMB marker in negotiate)

### Negotiation
- ✅ Dialect list parsing and selection (NT LM 0.12)
- ✅ Byte-packed WC=17 response (ChallengeLength inside words)
- ✅ Capability negotiation
- ✅ Server GUID for extended security

### Authentication
- ✅ Non-extended security (challenge/response legacy passwords)
- ✅ Extended security (SPNEGO NegTokenInit/Targ + NTLMSSP type1/2/3)
- ✅ NTLMv2 proof verification
- ✅ NTLMv1 DES fallback
- ✅ Guest mapping
- ✅ LOGON_FAILURE on bad credentials

### Sessions and Trees
- ✅ SESSION_SETUP_ANDX (WC=13 legacy + WC=12 extended)
- ✅ UID allocation in response header
- ✅ TREE_CONNECT_ANDX (share resolution, IPC$ virtual share)
- ✅ TID allocation in response header
- ✅ TREE_DISCONNECT
- ✅ LOGOFF_ANDX

### File Operations
- ✅ NT_CREATE_ANDX (all dispositions, dirs, delete-on-close, root-relative)
- ✅ READ_ANDX (64-bit offset support)
- ✅ WRITE_ANDX (both wire variants, 64-bit offset support)
- ✅ CLOSE (with optional mtime update)
- ✅ FLUSH (single handle and all)
- ✅ SEEK
- ✅ LOCKING_ANDX (accepted, unenforced)

### Directory Operations
- ✅ CREATE_DIRECTORY (MKDIR)
- ✅ DELETE_DIRECTORY (RMDIR)
- ✅ CHECK_DIRECTORY
- ✅ DELETE (exact file and wildcard patterns)
- ✅ RENAME
- ✅ NT_RENAME (level 1 = rename)

### Information Queries
- ✅ TRANS2_QUERY_FS_INFO (volume, size, device, attribute levels)
- ✅ TRANS2_FIND_FIRST2 (levels 0x102 0x103 0x104 0x105 DOS standard)
- ✅ TRANS2_FIND_NEXT2 (SID continuation)
- ✅ TRANS2_QUERY_PATH_INFORMATION (pass-through levels)
- ✅ TRANS2_QUERY_FILE_INFORMATION (by FID)
- ✅ TRANS2_SET_FILE_INFORMATION (disposition alloc EOF basic rename)
- ✅ TRANS2_SET_PATH_INFORMATION
- ✅ Composite getattr level 0x107 (92-byte form matching smbd)
- 🔨 FIND_FIRST2 level 0x104 name parse regression (smbclient ls)

### Legacy Commands
- ✅ QUERY_INFORMATION
- ✅ SET_INFORMATION
- ✅ QUERY_INFORMATION_DISK
- ✅ PROCESS_EXIT
- ✅ ECHO
- ✅ NT_CANCEL

### Protocol Details
- ✅ AndX chaining
- ✅ Unicode/OEM string encoding per client capabilities
- ✅ DOS error fallback when CAP_STATUS32 not negotiated
- ✅ Path containment (no .. escape from share root)
- ✅ Case-insensitive file resolution

## Phase 2: SMB2 ([MS-SMB2])

### Transport
- ✅ Per-frame dialect routing (\xFE magic routes to SMB2 loop)

### Negotiate
- ✅ NEGOTIATE request parsing
- ✅ NEGOTIATE response building
- ✅ Dialect selection (2.0.2 2.1.0)
- ✅ Capabilities advertisement
- ✅ Client GUID echo
- ✅ Security mode negotiation

### Session Management
- ✅ SESSION_SETUP both legs (SPNEGO/NTLMSSP reuse)
- ✅ Session ID allocation (u64)
- ✅ Session flags (guest bit)
- ✅ LOGOFF handler

### Tree Connect
- ✅ TREE_CONNECT basic share resolution
- ✅ TREE_DISCONNECT
- ⬜ Share capabilities in response

### File Operations
- ✅ CREATE (dispositions, dirs, delete-on-close)
- ✅ READ
- ✅ WRITE
- ✅ CLOSE (post-close attrs)
- ✅ FLUSH
- ✅ LOCK (accepted unenforced)

### Directory and Info
- ✅ FIND (QUERY_DIRECTORY, classes 1/2/3/12/37/38, continuation state)
- ✅ QUERY_INFO (file + fs levels)
- ✅ SET_INFO (basic/eof/alloc/disposition/rename)
- ✅ IOCTL (VALIDATE_NEGOTIATE_INFO echo, LMR_REQ_RESILIENCY)
- ✅ Compound request/response chaining (8-byte aligned NextCommand)

### Signing ([MS-SMB2] §3.2.5.3, dialects < 3.0)
- ✅ NTLMv2 session key derivation (SessionBaseKey + RC4 key exchange)
- ✅ HMAC-SHA256 response signatures mirrored from signed requests
- ✅ Crypto additions: SHA-256, HMAC-SHA256, RC4 (FIPS/RFC vectors green)

## Phase 3: SMB3 ([MS-SMB2] 3.0+)

- ✅ Dialects 3.0 / 3.0.2 / 3.1.1 selection
- ✅ Negotiate contexts: PREAUTH_INTEGRITY_CAPABILITIES (SHA-512 + salt),
  ENCRYPTION_CAPABILITIES (single chosen cipher), SIGNING_CAPABILITIES
  (AES-128-CMAC)
- ✅ Signing keys: KDF counter-mode HMAC-SHA256 ("SMB2AESCMAC"/"SmbSign" for
  3.0+, "SMBSigningKey"/preauth-hash for 3.1.1); raw session key for 2.x
- ✅ AES-CMAC-AES128 signatures for 3.x (HMAC-SHA256 for 2.x)
- ✅ Pre-auth integrity hash (SHA-512 over negotiate/session-setup frames)
- 🔨 Encryption transform (AES-GCM/CCM): cipher negotiated but transform not
  applied; clients that do not request encryption work normally
- ⬜ Multichannel support

### Crypto additions — now via `smb-csp` crate
- Crypto service provider (`crates/smb-csp`) with two compile-time backends:
  * `lib` (default): RustCrypto crates (md4/md5/sha2/hmac/des/aes/cmac/rc4),
    hardware-accelerated AES where available
  * `handrolled`: bundled from-scratch implementations (zero external deps)
- Both backends pass the same FIPS/RFC/interop vector suite; NTLMv1 DES key
  expansion fixed to match impacket/OpenSSL ground truth

## Known Regressions
- 🔨 FIND_FIRST2 level 0x104 entry name parse (smbclient ls shows empty names)

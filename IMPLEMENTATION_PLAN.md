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
- ⬜ NEGOTIATE request parsing
- ⬜ NEGOTIATE response building
- ⬜ Dialect selection (2.0.2 2.1.0)
- ⬜ Capabilities advertisement
- ⬜ Client GUID echo
- ⬜ Security mode negotiation

### Session Management
- ✅ SESSION_SETUP both legs (SPNEGO/NTLMSSP reuse)
- ✅ Session ID allocation (u64)
- ✅ Session flags (guest bit)
- ⬜ LOGOFF handler

### Tree Connect
- ✅ TREE_CONNECT basic share resolution
- ✅ TREE_DISCONNECT
- ⬜ Share capabilities in response

### File Operations
- ⬜ CREATE
- ⬜ READ
- ⬜ WRITE
- ⬜ CLOSE
- ⬜ FLUSH
- ⬜ LOCK

### Directory and Info
- ⬜ FIND (directory enumeration)
- ⬜ QUERY_INFO
- ⬜ SET_INFO

## Phase 3: SMB3 ([MS-SMB2] 3.0+)

- ⬜ Negotiate contexts (pre-auth integrity, encryption)
- ⬜ AES-CCM / AES-GCM encryption
- ⬜ HMAC-SHA256 signing
- ⬜ Pre-auth integrity hash (SHA-512)
- ⬜ Multichannel support

## Known Regressions
- 🔨 FIND_FIRST2 level 0x104 entry name parse (smbclient ls shows empty names)

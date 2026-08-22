# rustsmb

An SMB1 (Server Message Block Version 1.0) file server written in pure Rust —
zero external dependencies, implementing the wire protocol from the public
[MS-SMB] / [MS-CIFS] specifications (Microsoft Open Specifications).

Verified interoperable with two independent open-source SMB1 clients:
- **smbclient** (Samba 4.x, NT1 dialect)
- **impacket** `SMB` client (Python)
- Linux kernel CIFS (`mount -t cifs -o vers=1.0`) should also work

## Build & run

```sh
cargo build --release
./target/release/rustsmb [--port 4450] [--share name=path]... [--user name:pass]...
```

Defaults: port 4450, share `public` = current directory, no users
(guest/anonymous access allowed).

Examples:

```sh
# guest-accessible share
rustsmb --port 4450 --share public=/srv/files

# user-mode: NTLMv2 challenge/response verification
rustsmb -p 4450 -s public=/srv/files -u alice:wonderland -u bob:builder
```

Connect:

```sh
smbclient //127.0.0.1/public -p 4450 -U alice%secret123 \
  --option='client min protocol=NT1' --option='client max protocol=NT1'
```

(NT1 is required; modern Samba builds disable SMB1 by default.)

## Protocol surface implemented

| Area | Details |
|---|---|
| Transport | NBSS framing over TCP (RFC 1002), session request/keepalive |
| Negotiate | `NT LM 0.12`, byte-packed response, capability negotiation |
| Sessions | `SESSION_SETUP_ANDX` extended security (SPNEGO + NTLMSSP), full NTLMv2 proof verification (MD4/HMAC-MD5/DES in pure Rust), anonymous/guest mapping, logon failure |
| Trees | `TREE_CONNECT_ANDX`, `TREE_DISCONNECT`, IPC$ handling |
| Files | `NT_CREATE_ANDX` (all dispositions, dirs, delete-on-close, root-relative opens), `READ_ANDX`, `WRITE_ANDX` (incl. Impacket WC=14 variant), `CLOSE`, `FLUSH`, `SEEK`, `LOCKING_ANDX`, legacy byte-range locks |
| Directories | `CREATE_DIRECTORY`, `DELETE_DIRECTORY`, `CHECK_DIRECTORY`, wildcard `DELETE`, `RENAME`, `NT_RENAME` |
| Info | TRANS2 `FIND_FIRST2`/`FIND_NEXT2` (levels 0x102–0x105 + DOS standard), `QUERY_FS_INFO` (volume/size/device/attribute), `QUERY_PATH/FILE_INFORMATION` incl. pass-through levels (basic/standard/internal/ea/access/name/alloc/eof/all/streams), attribute composite (0x107) |
| Set info | disposition (delete), allocation, EOF truncate, timestamps, rename-by-handle (0x100A), path variants |
| Legacy | MKDIR/RMDIR/CHECKDIR, DELETE, RENAME, QUERY/SET_INFORMATION, QUERY_INFORMATION_DISK, SEEK, ECHO, PROCESS_EXIT |
| Errors | NT status codes with DOS fallback mapping |

AndX chaining is parsed on requests and generated on responses.

## Layout

```
src/
├── main.rs      CLI, TCP listener, share/user config
├── nbss.rs      RFC 1002 framing
├── smb.rs       constants, header codec, NTSTATUS, FILETIME, string I/O
├── message.rs   request parsing, AndX-aware response assembly
├── dispatch.rs  connection loop, command routing, session gating
├── handlers.rs  negotiate / session setup / tree connect / echo / …
├── files.rs     create, read, write, close, flush, seek, locks
├── dirops.rs    legacy directory & file commands
├── trans2.rs    FIND_*, QUERY_*/SET_* information levels
├── ntlm.rs      MS-NLMP type1/2/3 + minimal SPNEGO DER
├── crypto.rs    MD4, MD5, HMAC-MD5, DES (for NTLMv1/LM)
└── state.rs     shares, sessions, handles, search contexts
```

## Security notes

This is an interoperability/reference implementation. It enforces share-root
containment (no `..` escape), optional per-user authentication via NTLMv2,
and maps unauthenticated clients to guest only when no user DB is configured.
It does not implement SMB signing, encryption, oplock negotiation, or SMB2/3.
Run it on trusted networks only.

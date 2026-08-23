<p align="center">
  <img src="assets/logo.jpg" alt="smb-rs logo" width="600"/>
</p>

<h1 align="center">smb-rs</h1>

<p align="center">
  <strong>An SMB1/SMB2/SMB3 file server written in pure Rust.</strong>
</p>

---

`smb-rs` is a from-scratch implementation of the SMB Version 1.0 wire protocol,
built directly against the public [MS-SMB] and [MS-CIFS] specifications
(Microsoft Open Specifications). It serves files and directories over the
network to standard SMB clients, with real challenge/response authentication
(NTLMv2) implemented by hand — MD4, MD5, HMAC-MD5 and DES live in ~460 lines
of `src/crypto.rs`.

> **Why?** To demonstrate that an interoperable SMB endpoint can be built as a
> single small binary with no third-party crates, and to serve as a readable
> map of how SMB1 actually works on the wire.

---

## What it does

- Serves any number of **shares**, each mapped to a directory on disk
- Full **file I/O**: create/open/read/write/truncate/close with all six
  NT create dispositions
- **Directory enumeration** with wildcard patterns (`*`, `?`) and multiple
  find-information levels
- **File metadata**: attributes, timestamps, sizes — query *and* set
- Deletes, renames (incl. rename-by-handle), mkdir/rmdir
- **Authentication**: user-mode NTLMv2 challenge/response verification, or
  open guest/anonymous mode
- Multi-client: one thread per TCP connection

Verified interoperable against:

| Client | Status |
|---|---|
| [Samba](https://www.samba.org/) `smbclient` 4.x (NT LM 0.12 dialect) | ✅ full suite |
| [Impacket](https://github.com/fortra/impacket) Python client | ✅ full suite |
| Linux kernel CIFS (`mount -t cifs -o vers=1.0`) | expected to work |

## What it does *not* do

No SMB2/3, no signing/encryption, no oplock granting, no named pipes /
DCERPC over `IPC$`, no byte-range lock enforcement, no ACLs. Unsupported
requests are rejected cleanly with proper NT status codes. Treat it as an
interoperability/reference implementation for trusted networks — not as a
production file server.

---

## Requirements

- Rust 1.70+ (`rustup` or your distribution's package manager) — nothing else.
  The crate has **zero dependencies**; even the crypto is built in.
- A client for testing: `smbclient`, impacket, Windows/macOS explorer, …

Note: modern Samba tools ship with SMB1 disabled. When testing with
`smbclient`, force the dialect (see below).

## Compiling

```sh
git clone https://github.com/farazshaikh/smb-rs.git
cd smb-rs
cargo build --release        # → target/release/rustsmb
```

That's it. No network access needed after checkout (there are no crates to
download), and the release binary is fully static-in-purpose: drop it anywhere.

Debug build with logging-friendly symbols:

```sh
cargo build                  # → target/debug/rustsmb
```

## Running

```
rustsmb [--port N] [--share name=path]... [--user name:password]...
```

| Option | Meaning | Default |
|---|---|---|
| `--port`, `-p` | TCP port to listen on (SMB is 445; use ≥1024 unprivileged) | `4450` |
| `--share`, `-s` | Publish a share: `name=/path`. Repeatable. | `public=<cwd>` |
| `--user`, `-u` | Add a user account: `name=password`. Repeatable. | none (guest mode) |

Behaviour notes:

- With **no `--user`** options the server runs in guest mode — anyone may
  connect and read/write.
- With **one or more `--user`** options only those logins succeed; unknown
  users are rejected. Clients that authenticate without credentials are mapped
  to guest *only if* no users are configured.

Examples:

```sh
# Guest-readable/writable share on the default port
./target/release/rustsmb -p 4450 -s public=$HOME/public

# Two shares, two accounts
./target/release/rustsmb -p 4450 \
    -s media=/srv/media -s scratch=/tmp/scratch \
    -u alice:wonderland -u bob:builder
```

## Connecting

### smbclient (Samba)

Modern Samba builds ship with SMB1 disabled, so force the NT1 dialect:

```sh
smbclient //127.0.0.1/public -p 4450 -U alice%secret123 \
    --option='client min protocol=NT1' --option='client max protocol=NT1'
smb: \> ls
smb: \> put somefile.txt
smb: \> get somefile.txt
```

Guest session: add `-N` instead of `-U`.

### Impacket (Python)

```python
from impacket.smb import SMB
s = SMB('*SMBSERVER', '127.0.0.1', sess_port=4450)
s.login('alice', 'secret123')
tid = s.tree_connect_andx('\\\\RUSTSMB\\public')
fid = s.nt_create_andx(tid, '\\hello.txt')
print(bytes(s.read_andx(tid, fid, offset=0, max_size=100)))
```

### Linux kernel CIFS

```sh
sudo mount -t cifs //127.0.0.1/public /mnt -o vers=1.0,user=alice,port=4450
```

### Windows / macOS

Map a drive in Explorer (`\\host\share`) — SMB1 must be enabled on the client
(legacy feature, disabled by default on current Windows).

## Protocol coverage

| Area | Implemented |
|---|---|
| Transport | NBSS framing over TCP (RFC 1002), session request / keepalive |
| Negotiate | `NT LM 0.12`, capability negotiation, server GUID |
| Sessions | Extended security (SPNEGO NegTokenInit/Targ + NTLMSSP type1/2/3), NTLMv2 proof verification, anonymous/guest mapping, `LOGOFF_ANDX` |
| Trees | `TREE_CONNECT_ANDX`, `TREE_DISCONNECT`, `IPC$` handling |
| Files | `NT_CREATE_ANDX` (all dispositions, directories, delete-on-close, root-relative opens), `READ_ANDX`, `WRITE_ANDX`, `CLOSE`, `FLUSH`, `SEEK`, `LOCKING_ANDX` (accepted) |
| Directories | `CREATE_DIRECTORY`, `DELETE_DIRECTORY`, `CHECK_DIRECTORY`, wildcard `DELETE`, `RENAME`, `NT_RENAME` |
| Enumeration | TRANS2 `FIND_FIRST2` / `FIND_NEXT2` — levels `0x102`, `0x103`, `0x104`, `0x105`, DOS standard; unicode *and* OEM name encoding |
| Queries | `QUERY_FS_INFO` (volume / size / device / attribute), path & file information incl. pass-through levels: basic, standard, internal, EA, access, name, allocation, EOF, disposition, all-info, streams, attribute-composite (0x107) |
| Set info | Disposition (delete), allocation, EOF truncate, basic timestamps, rename-by-handle (pass-through), path variants |
| Legacy | MKDIR/RMDIR/CHECKDIR, DELETE, RENAME, QUERY/SET_INFORMATION, QUERY_INFORMATION_DISK, ECHO, PROCESS_EXIT |
| Errors | NT status codes with automatic DOS error mapping for old clients |
| Chaining | AndX requests parsed and responses chained |

## Source layout

```
src/
├── main.rs      CLI parsing, TCP listener, share/user configuration
├── nbss.rs      RFC 1002 NetBIOS session-service framing
├── smb.rs       Constants, SMB header codec, NTSTATUS codes, FILETIME,
│                byte reader/writer with Unicode/OEM string handling
├── message.rs   Request parsing (incl. AndX chains), response assembly
├── dispatch.rs  Per-connection loop, session gating, command routing
├── handlers.rs  NEGOTIATE, SESSION_SETUP, TREE_CONNECT, ECHO, …
├── files.rs     NT_CREATE_ANDX, READ/WRITE_ANDX, CLOSE, FLUSH, SEEK, locks
├── dirops.rs    Legacy directory/file commands (MKDIR, RMDIR, DELETE, …)
├── trans2.rs    FIND_*, QUERY_*/SET_* information levels
├── ntlm.rs      MS-NLMP type1/type2/type3 messages + minimal SPNEGO DER
├── crypto.rs    MD4, MD5, HMAC-MD5, DES — for NTLMv2/v1 verification
└── state.rs     Shares, sessions, tree connects, open handles, searches
```

## Design notes

- **Zero dependencies**: everything from NBSS framing to DES is hand-written;
  `Cargo.toml` declares no crates, so builds are hermetic and fast.
- **Byte-level fidelity**: several fields that other implementations get wrong
  are handled strictly here — the byte-packed NEGOTIATE words, Unicode string
  parity padding relative to the SMB header start, per-message WordCount/BC
  layouts, and both WRITE_ANDX WC=14 variants found in the wild.
- **State model**: UIDs → sessions, TIDs → tree connects, FIDs → open handles,
  plus per-connection directory-search contexts; each connection is isolated
  on its own thread with its own state.
- **Path safety**: every client-supplied path is normalised and resolved inside
  the share root; `..` traversal and absolute escapes are refused.

## Security considerations

This project exists to demonstrate protocol interoperability. Before exposing
it beyond localhost be aware: there is no SMB signing or encryption, sharing
modes and byte-range locks are accepted but not enforced, and the auth model is
single-factor. Run it on trusted networks.

## References

- [MS-SMB]: Server Message Block (SMB) Protocol Version 1.0 Extensions
- [MS-CIFS]: Common Internet File System Protocol
- [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
- RFC 1002 (NetBIOS service), RFC 4178 (SPNEGO)

<p align="center">
  <img src="assets/logo.jpg" alt="smb-rs logo" width="600"/>
</p>

<h1 align="center">smb-rs</h1>

<p align="center">
  <strong>An SMB1 / SMB2 / SMB3 file server written in Rust.</strong>
</p>

---

`smb-rs` is a from-scratch implementation of the SMB family of protocols,
built directly against the public Microsoft Open Specifications — [MS-CIFS],
[MS-SMB], [MS-SMB2] and [MS-NLMP]. It serves files and directories over the
network to standard clients (`smbclient`, Windows Explorer, macOS, the Linux
kernel CIFS upcall) with real NTLMv2 challenge/response authentication,
message signing on every dialect, and SMB 3.x negotiate contexts including
pre-authentication integrity.

It is organised as a focused cargo workspace (protocol codecs, transport,
VFS abstraction, POSIX backend, auth, crypto service provider, server) so
each layer stays readable and independently testable.

> **Why?** A readable, layered map of how SMB actually works on the wire —
> that is also a working file server.

---

## Feature highlights

| Area | What you get |
|---|---|
| **Dialects** | NT LM 0.12 (SMB1) · 2.0.2 · 2.1.0 · 3.0 · 3.0.2 · **3.1.1** |
| **Auth** | NTLMv2 verification, NTLMv1 fallback, RC4 key exchange, guest/anonymous mapping, multi-user DB |
| **Signing** | HMAC-SHA256 (SMB 2.x) and AES-CMAC (SMB 3.x) — responses signed, verified by Samba clients |
| **Pre-auth integrity** | SHA-512 chaining over all NEGOTIATE/SESSION_SETUP frames (3.1.1) |
| **File I/O** | Create/open (all six dispositions), read, write, close, flush, truncate, delete-on-close |
| **Directories** | Wildcard enumeration across six find-information levels, mkdir/rmdir, rename incl. rename-by-handle |
| **Info levels** | Query/set for file & filesystem classes ([MS-FSCC]) |
| **IOCTLs** | `VALIDATE_NEGOTIATE_INFO`, `LMR_REQ_RESILIENCY` |
| **Compounding** | Multi-request frames handled with 8-byte-aligned chained replies |
| **Observability** | `tracing` structured logs (EnvFilter) + Prometheus metrics endpoint |

Verified interoperable against:

| Client | Dialects exercised | Status |
|---|---|---|
| Samba `smbclient` 4.x | NT1 · SMB2 · SMB3 (guest *and* authenticated+signed) | ✅ full suite |
| Impacket `SMB` / `SMB3` classes | 2.1 + 3.x flows | ✅ full suite |

## Status — what works today, and what's next

Working end-to-end today: negotiation (all dialects above), session setup
with SPNEGO/NTLMSSP (both legs), tree connects, create/open, read, write,
close, flush, byte-range lock *parsing*, directory enumeration with
continuation, query/set information, delete/rename/mkdir/rmdir, echo,
logoff/tree-disconnect, compound frames, and message signing.

Known gaps (tracked in detail in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)'s **Feature Matrix**):
the SMB3 encryption transform is negotiated but not yet applied to traffic,
byte-range locks are accepted but not enforced, there are no
oplocks/leases/durable handles, no CHANGE_NOTIFY yet, and IPC$ serves no
named pipes (share enumeration via srvsvc is on the roadmap). Unsupported
requests are rejected cleanly with proper NT status codes.

Run it on trusted networks; treat it as an interoperability/reference
implementation that is steadily growing production features.

---

## Building

```sh
git clone https://github.com/farazshaikh/smb-rs.git
cd smb-rs
cargo build --release --workspace   # → target/release/rustsmb
```

### Crypto backend selection

Cryptography lives in the [`crates/smb-csp`](crates/smb-csp) service-provider
crate behind one API surface with two compile-time backends:

| Backend | Build command | Notes |
|---|---|---|
| `lib` (**default**) | `cargo build --release --workspace` | Maintained RustCrypto crates (`sha2`, `aes`, `cmac`, `hmac`, `des`, `rc4`, `md4`, `md-5`) — hardware-accelerated AES where available |
| `handrolled` | `cargo build --release --workspace --no-default-features --features handrolled` | Bundled from-scratch implementations; zero external dependencies |

Both backends must satisfy the same FIPS/RFC/interop vector suite
(enforced by tests inside `smb-csp`).

## Running

```
rustsmb [OPTIONS]
```

| Option | Meaning | Default |
|---|---|---|
| `-p, --port` | TCP listen port (SMB tradition is 445) | `4450` |
| `-s, --share NAME=PATH` | Publish a share (repeatable) | `public=<cwd>` |
| `-u, --user USER:PASSWORD` | Add an account (repeatable) | none → guest mode |
| `--log FILTER` | `tracing` EnvFilter (`RUST_LOG` overrides) | `info` |
| `--metrics-bind ADDR` | Serve Prometheus at `http://ADDR/metrics` | off |
| `--require-signing` | Reject unsigned traffic from authenticated sessions | off |

Examples:

```sh
# Guest-readable/writable share
./target/release/rustsmb -p 4450 -s public=$HOME/public

# Two shares, two accounts, metrics on
./target/release/rustsmb -p 4450 \
    -s media=/srv/media -s scratch=/tmp/scratch \
    -u alice:wonderland -u bob:builder \
    --metrics-bind 127.0.0.1:9449
```

With **no `--user`** options the server runs in guest mode. With one or more,
only those logins succeed; unauthenticated clients map to guest only when no
users are configured.

## Connecting

### smbclient — modern dialects (default build)

```sh
smbclient //127.0.0.1/public -p 4450 -U alice%secret123 \
    --option='client min protocol=SMB2' --option='client max protocol=SMB3'
smb: \> ls
smb: \> get hello.txt
```

Guest session: add `-N` instead of `-U`. Legacy SMB1: force
`min/max protocol=NT1`.

### Impacket (Python)

```python
from impacket.smb3 import SMB3
s = SMB3('*SMBSERVER', '127.0.0.1', sess_port=4450)
s.login('', '', '')
tid = s.tree_connect_andx('\\\\RUSTSMB\\public')
fid = s.nt_create_andx(tid, '\\hello.txt')
print(bytes(s.read_andx(tid, fid, offset=0, max_size=100)))
```

### Linux kernel CIFS / Windows / macOS

```sh
sudo mount -t cifs //127.0.0.1/public /mnt -o vers=3.0,user=alice,port=4450
```

Windows/macOS: map `\\host\share` in Explorer.

## Observability

* **Logs**: `tracing` structured events. Filter with `RUST_LOG`
  (e.g. `RUST_LOG=rustsmb=debug`) or `--log`; per-frame debug records carry
  cmd/mid/session/tree ids.
* **Metrics**: scrape `http://ADDR/metrics` when `--metrics-bind` is set.
  Counters/gauges/histograms include:

  ```
  smb_nbss_frames_total        smb_responses_total
  smb_bytes_read_total         smb_bytes_written_total
  smb_creates_total            smb_closes_total
  smb_tcons_total              smb_logoffs_total
  smb_auth_total{outcome}      smb_sessions_active
  smb_trees_active             smb_frame_duration_us (quantiles)
  ```

## Workspace layout

```
crates/
├── smb-proto/        Shared value types: NTSTATUS, FILETIME, attributes,
│                     wire reader/writer
├── smb-transport/    RFC 1002 NBSS-over-TCP framing
├── smb-proto-smb1/   SMB1 codecs: header, AndX, TRANS2 find/query/set…
├── smb-proto-smb2/   SMB2/SMB3 codecs: header, CREATE/READ/WRITE…,
│                     FSCC info encoders, negotiate contexts
├── smb-proto-smb3/   Reserved for SMB3-only transforms (encryption)
├── smb-auth/         NTLMSSP messages, SPNEGO DER wrapping, credential
│                     verification (delegates primitives to smb-csp)
├── smb-csp/          Crypto service provider — RustCrypto crates by
│                     default, bundled implementations behind a feature
├── smb-vfs/          Dialect-neutral VFS trait
├── smb-backend-posix/ POSIX backend: containment, wildcards, case folding
└── smb-server/       rustsmb binary: CLI, dispatch loops (SMB1+SMB2),
                       sessions/trees/handles state, observability
```

## Design notes

- **Layered by spec**: protocol crates only translate wire ↔ neutral types;
  handlers speak to a VFS abstraction, so SMB1 and SMB2 drive the same
  storage backend and stay behaviourally identical.
- **Spec-named field offsets**: every wire struct documents its section and
  uses named offsets instead of magic numbers.
- **Byte-level fidelity**: the fiddly parts other implementations get wrong
  are handled strictly — byte-packed NEGOTIATE words, Unicode parity padding
  relative to the SMB1 header, both WRITE_ANDX variants found in the wild,
  absolute buffer offsets and StructureSize conventions in SMB2, TreeId
  stamping, chained NextCommand assembly.
- **Path safety**: client paths are resolved inside the share root; `..`
  traversal and absolute escapes are refused.
- **Honest status tracking**: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md)
  carries a per-feature matrix (spec section, status, unit/system tests,
  benchmarking, logging, metrics) that is kept current.

## Security considerations

Single-factor auth (NTLM), no ACL enforcement, byte-range locks accepted but
not enforced, and SMB3 encryption is negotiated but not yet applied to
traffic. Fine for labs and trusted networks; harden before exposing more
widely. See the Feature Matrix for exactly where the edges are.

## References

- [MS-CIFS]: Common Internet File System Protocol
- [MS-SMB]: SMB Protocol Version 1.0 Extensions
- [MS-SMB2]: SMB 2.0 and 3.x Protocols
- [MS-NLMP]: NT LAN Manager Authentication Protocol
- [MS-FSCC]: File System Control Codes
- RFC 1002 (NetBIOS service), RFC 4178 (SPNEGO), RFC 4493 (AES-CMAC),
  NIST SP800-108 (KDF), FIPS 180-4 (SHA-2), FIPS 197 (AES)

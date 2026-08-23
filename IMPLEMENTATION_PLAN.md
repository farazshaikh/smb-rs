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
- ✅ FIND_FIRST2 entry encoding (chain terminator, 0x102 layout — fixed)

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
- ✅ Compound request/response chains (8-byte aligned NextCommand)
- ⬜ Credit accounting / multi-credit large R/W
- ⬜ Async processing (STATUS_PENDING) + CANCEL
- ✅ Compound request/response chains
- ⬜ Credit accounting / multi-credit large R/W
- ⬜ Async processing (STATUS_PENDING) + CANCEL

### Negotiate
- ✅ NEGOTIATE request parsing (incl. 3.1.1 context layout)
- ✅ NEGOTIATE response building (contexts for 3.1.1)
- ✅ Dialect selection (2.0.2 – 3.1.1)
- ✅ Wildcard-probe (invalid-status) reply
- ✅ Capabilities advertisement
- ✅ Client GUID echo
- ✅ Security mode negotiation

### Session Management
- ✅ SESSION_SETUP both legs (SPNEGO/NTLMSSP reuse)
- ✅ Session ID allocation (u64)
- ✅ Session flags (guest bit)
- ✅ LOGOFF handler

### Tree Connect
- ✅ TREE_CONNECT / TREE_DISCONNECT (+ new TreeId stamped into header)
- ✅ ShareType/flags/caps/MaximalAccess in response

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

---

## Feature Matrix (live tracker)

Legend — status: `complete` / `in_progress` / `planned`.
Columns: **unittest** = cargo unit/vector tests; **systemtest** = real-client
harness; **benchmarking** = measured throughput/latency; **logging** =
diagnostic output today; **metric** = runtime counter/gauge. Metrics are
*planned* until a metrics module lands.

### Transport & framing ([MS-SMB2] §2.1, RFC 1001/1002)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| NBSS framing over TCP :445 | RFC 1002 §5.2 | complete | — | smbclient all dialects | — | conn span + disconnect debug (tracing) | nbss_frames_total ✅ |
| Multi-protocol upgrade (\xFESMB in SMB1 negotiate) | [MS-CIFS] §2.2.4.52 + [MS-SMB2] §3.2.4.2 | complete | — | impacket SMB class fallback | — | upgrade line | — |
| Compound request/response chains | [MS-SMB2] §3.3.5.2 | complete | — (todo: parser fuzz) | smbd parallel_read path | — | tracing::debug per frame | compounded_msgs_total ✅ |
| Credit accounting (grant/charge, multi-credit) | [MS-SMB2] §3.3.1.1 | planned | charge calc unit tests | large-file copy ≥64 KiB chunks | large-R/W MB/s | credits granted per resp | credits_granted |
| Large MTU (>64 KiB single R/W) | §2.2.3.1.1 CAP_LARGE_MTU | planned | — | dd through mount | bulk MB/s | — | max_rw_seen |
| Async processing (STATUS_PENDING, async id) | §2.2.1.1, §3.3.4.2 | planned | state-machine tests | notify long-poll | — | pending count | async_pending |
| CANCEL | §2.2.30 | planned | — | ctrl-c mid-read | — | cancel received | cancels_total |
| NetBIOS 139 + datagram browsing | RFC 1001/1002 | planned | — | Windows Network browse | — | — | — |

### Negotiation ([MS-SMB2] §2.2.3)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| Dialect selection 2.0.2–3.1.1 (incl. 3.1.1 context layout) | §2.2.3.1.1 | complete | dialect-layout parse test | per-dialect client runs | — | info: listening/dialect | negotiated_dialect (todo) |
| Wildcard-probe (invalid-status) reply | §3.3.5.3 | complete | raw probe script | smbclient SMB2-only connect | — | — | probes_answered |
| Negotiate contexts parse/build (preauth, encryption, signing) | §2.2.3.1.2 | complete | context walk test | SMB3 handshake | — | RUSTSMB_DEBUG | ctx_types_seen |
| Pre-auth integrity hash (SHA-512 chaining) | §3.3.4.1.1 | complete | sha512 vectors | signed SMB3 session | — | — | preauth_updates |
| Salt generation per connection | §2.2.3.1.2 | complete | — | — | — | — | — |
| Capabilities advertisement | §2.2.3.2.5 | complete | — | validate-negotiate echo | — | — | — |
| Compression capability (LZNT1/PATTERN_V1) | §2.2.3.1.2 ctx 0x0003 | planned | roundtrip vectors | compressed xfer ratio | compress MB/s | algo chosen | comp_ratio |

### Sessions & authentication ([MS-SMB2] §2.2.5, [MS-NLMP])

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| SESSION_SETUP both legs (SPNEGO NegTokenInit/Targ) | §2.2.5, [MS-SPNGO] | complete | setup codec offset test | samba + impacket logons | — | trace: token type/len | setups_total (todo) |
| NTLMv2 proof verification | [MS-NLMP] §3.3.2 | complete | golden vs impacket | alice%pass login | — | info: session established | auth_total{outcome} ✅, sessions_active ✅ |
| NTLMv1 fallback (DES responses) | [MS-NLMP] §3.3.1 | complete | OpenSSL ground-truth vector | legacy client login (todo) | — | — | — |
| RC4 key exchange (EncryptedRandomSessionKey) | [MS-NLMP] §3.2.5.1.2 | complete | rc4 vectors | signed traffic accepted | — | — | key_exchanges_total |
| Guest / null-session mapping | §3.3.5.5 | complete | — | guest% logins | — | info: session established | sessions_active ✅ |
| User database (`-u user:pass`) | local policy | complete | — | wrong-pass → LOGON_FAILURE | — | — | — |
| Anonymous handling | §2.2.5.1 Flags bit | complete | — | empty-creds login | — | — | — |
| LOGOFF | §2.2.7 | complete | — | impacket logoff | — | counter on logoff | logoffs_total ✅ |
| Kerberos / other SPNEGO mechs | [MS-KILE] | planned | — | domain join (n/a standalone) | — | — | — |

### Signing & encryption ([MS-SMB2] §3.2.5.3, §2.2.41)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| HMAC-SHA256 signatures (2.x) | §3.2.5.3.1 | complete | rfc4231 vectors | samba verifies our sigs | 2.1 GB/s (sha2 crate) | bad-sig line | sig_verify_fail |
| AES-CMAC signatures (3.x) + SIGNING_CAPABILITIES ctx | §2.2.3.1.2, §3.2.5.3.1 | complete | rfc4493 vectors | SMB3 signed session | 1.6 GB/s (AES-NI) | — | — |
| Signing-key KDF (CTR-HMAC-SHA256, dialect labels) | §3.1.4.1 | complete | python cross-check vector | keys accepted by samba | — | derived-once assert | — |
| Preauth-hash-bound 3.1.1 signing key | §3.3.5.2.1 | complete | — | SMB3 auth works | — | — | — |
| Encryption transform AES-GCM/CCM (TF header §2.2.41) | §3.3.5.16 | in_progress | AEAD roundtrip tests (todo) | smbclient --encrypt (todo) | target >500 MB/s | enc on/off per msg | enc_bytes_total |
| Cipher key derivation (C2S/S2C labels + preauth ctx) | §3.1.4.1 | planned (w/ transform) | kdf vectors | encrypted session | — | — | — |
| Require-signing server policy (--require-signing) / require-encryption | §3.3.5.2.3 | in_progress | gate unit test (todo) | unsigned client rejected (todo) | — | rejects logged + counted | rejects_total ✅ |

### Tree connects & shares ([MS-SMB2] §2.2.9–§2.2.11)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| TREE_CONNECT / DISCONNECT + TreeId stamping | §2.2.9–11 | complete | tcon codec test | all client runs | — | debug: tree connected | tcons_total ✅, trees_active ✅ |
| Share resolution, BAD_NETWORK_NAME | §3.3.5.7 | complete | — | typo-share test | — | — | — |
| ShareType/flags/caps/MaximalAccess response | §2.2.10.2 | complete | body-size test | — | — | — | — |
| Virtual IPC$ share | §3.3.5.7 | complete | — | tcon ipc$ | — | — | — |
| DFS referrals | §2.2.31.1 | planned | — | dfs client | — | — | referrals_served |

### File operations ([MS-SMB2] §2.2.13–§2.2.28)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| CREATE (all dispositions, dirs, delete-on-close, root) | §2.2.13/14 | complete | create codec test | get/put battery | — | debug: create (both dialects) | creates_total ✅ |
| READ (DataOffset abs, 1 MiB clamp) | §2.2.19 | complete | read codec test | get battery | — | trace: read | bytes_read_total ✅ |
| WRITE | §2.2.21 | complete | write codec test | put battery | — | trace: write | bytes_written_total ✅ |
| CLOSE (+post-close attrs) | §2.2.15/16 | complete | — | del-on-close flow | — | counter on close | closes_total ✅ |
| FLUSH | §2.2.17 | complete | — | — | — | — | flushes_total |
| LOCK byte-range (enforced) | §2.2.26/27 | in_progress | conflict-matrix tests (todo) | two-client lock race (todo) | — | — | locks_active |
| Sharing-mode conflict detection | §3.3.5.10 | planned | sharing matrix tests | two opens same file | — | violation line | sharing_violations |
| Oplocks v1/v2 + break notification | [MS-SMB] §2.2.4.50, §2.2.24 | planned | break state machine | two-client cache race | oplock latency | break sent lines | breaks_sent |
| Leases v2/v3 (directory leases) | §2.2.23.2 | planned | lease table tests | explorer dir cache | — | lease key lines | leases_active |
| Durable / persistent handles | §2.2.13.2.4–6 | planned | reconnect test | network-blip resume | — | — | durables_held |
| Server-side COPYCHUNK (ODX offload) | §2.2.31.6 | planned | — | windows copy offload | effective MB/s | — | offload_bytes |
| ZERO_DATA / SET_SPARSE | §2.2.31.12/14 | planned | — | fallocate check | — | — | zeroed_bytes |

### Directories ([MS-SMB2] §2.2.33–§2.2.36)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| QUERY_DIRECTORY classes 1/2/3/12/37/38 | §2.2.33/34, [MS-FSCC] §2.4 | complete | entry-chain decode tests | ls + impacket list | entries/s (todo) | — | dirs_scanned |
| Continuation queue + RESTART/REOPEN/SCAN flags | §3.3.5.24 | complete | restart-flag unit test | multi-page ls | — | — | enum_restarts |
| RETURN_SINGLE_ENTRY | §2.2.33.1 | complete | — | — | — | — | — |
| Resume-by-index (INDEX_SPECIFIED) | §2.2.33.1 | planned | index resume tests | huge-dir page walk | — | — | — |
| 8.3 short-name generation/matching | [MS-FSCC] §2.1.5 | planned | name-gen tests | dos-style lookup | — | — | — |
| CHANGE_NOTIFY (recursive/non-recursive) | §2.2.35/36 | planned | filter map tests | touch → notify wait | — | notify fire lines | notifies_sent |
| DOS wildcard matcher (* ?) | [MS-CIFS] §2.2.8.1 | complete | wildcard unit tests | patterned ls | — | — | — |

### Information levels & metadata ([MS-FSCC])

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| QUERY_INFO file levels (basic/standard/internal/ea/access/name/mode/alignment/all/position/network-open/attr-tag) | §2.2.37/38, [MS-FSCC] §2.4 | complete | ALL-info alignment test | fstat-driven gets | — | — | qinfo_by_class |
| QUERY_INFO FS levels (volume/size/device/attr/full-size) | [MS-FSCC] §2.5 | complete | fs encode test | df via smbclient | — | — | — |
| FileAllInformation 8-byte embedded-struct alignment | [MS-FSCC] §2.4.1 | complete | size+offset asserts | size reported correctly | — | — | — |
| SET_INFO basic/eof/allocation/disposition/rename/position | §2.2.39/40 | complete | SetOp decode tests | rename/truncate flows | — | — | sets_total |
| Security descriptors (query/set SECURITY) | [MS-FSCC] §2.4.6 | planned | SD parse tests | acl view/edit | — | — | sd_ops |
| Quota query/set | [MS-FSCC] §2.4.14 | planned | — | — | — | — | — |
| Alternate data streams (enumerate/read/write) | [MS-FSCC] §2.6 | planned | stream VFS tests | ads copy | — | — | streams_io |
| Case-insensitive resolution + path containment | backend | complete | posix resolve tests | case-twiddled opens | — | — | — |

### IOCTLs / FSCTL ([MS-SMB2] §2.2.31)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| FSCTL_VALIDATE_NEGOTIATE_INFO echo | §3.3.5.15 | complete | input-length guard | authenticated SMB3 tcon | — | — | validate_negotiates |
| FSCTL_LMR_REQ_RESILIENCY ack | §2.2.31.10 | complete | — | resilient-open clients | — | — | — |
| FSCTL_PIPE_WAIT | §2.2.31.2 | planned (stub ack only) | pipe-wait test | — | — | — | — |
| FSCTL_DFS_GET_REFERRALS | §2.2.31.1 | planned | — | dfs client | — | — | — |
| FSCTL_SRV_REQUEST_RESUME_KEY | §2.2.31.4 | planned | resume-key tests | odx prerequisite | — | — | — |
| FSCTL_COPYCHUNK(_WRITE) | §2.2.31.6/7 | planned | chunk-limit tests | server-side copy | effective copy MB/s | — | copychunk_bytes |

### IPC$ / named pipes ([MS-SMB2] §2.1.2.1, [MS-SRVS])

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| Pipe create/read/write over IPC$ (srvsvc, lanman) | §2.1.2.1 | planned | pipe frame tests | smbclient -L | — | pipe open/close | pipe_msgs_total |
| srvsvc NetShareEnum (share enumeration) | [MS-SRVS] §3.1.4.10 | planned | share-list NDR tests | smbclient -L / net view | — | enum served | enums_served |
| RPC bind/transact over named pipes ([MS-RPCE]) | [MS-RPCE] §2 | planned | bind ack tests | — | — | — | — |

### Ergonomics

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| clap-derive CLI (-p/-s/-u/--log/--metrics-bind/--require-signing) | n/a | complete | — | --help render + flags used in battery | — | startup banner | — |
| Observability wiring (tracing subscriber + prometheus recorder) | n/a | complete | — | scraped /metrics live | histogram overhead µs-level | EnvFilter via RUST_LOG or --log | see metrics rows above |

### Robustness & QA

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| Malformed-frame fuzzing of parsers | n/a | planned | cargo-fuzz targets | fuzz-run soak | — | crash reports | fuzz_corpus_size |
| Cross-client concurrency stress (two writers, lock races) | n/a | planned | — | stress script | ops/s | — | concurrent_sessions |
| Windows-client soak | n/a | planned | — | win11 vm battery | — | — | — |
| Structured tracing (EnvFilter, per-frame debug spans) | n/a | complete | — | RUSTSMB_LOG/--log verified | — | `tracing` fmt subscriber; RUSTSMB_LOG overrides | — |
| Metrics export (prometheus at --metrics-bind) | n/a | complete | — | scraped during battery | scrape latency negligible | recorder install line | frames/bytes/creates/auth/sessions/trees + latency histogram |
| Criterion benches (sign/encrypt/find throughput) | n/a | planned | — | — | criterion baselines | — | — |

## Known Regressions

- None currently open. Historical: the FIND_FIRST2 chain terminator and the
  bundled NTLMv1 DES key schedule were both fixed (see Feature Matrix and
  session_summary_003).

> The **Feature Matrix** above is the live tracker for remaining work; the
> phase lists are historical records of what landed when.

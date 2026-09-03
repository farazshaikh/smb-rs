# smb-server-rs Implementation Plan

## Legend
- ✅ DONE — implemented, tested, verified
- 🔨 IN PROGRESS — code written but has known issues
- ⬜ TODO — not started

---

## Phase 0: Foundation

- ✅ Cargo workspace (10 crates, modular, independently testable)
- ✅ `deny(missing_docs)`, `forbid(unsafe_code)` on all crates
- ✅ Explicit-endian reads (`from_le_bytes` / `to_le_bytes`)
- ✅ Zero-copy decode trait (`Wire` with `'de` lifetime borrows)
- ✅ Async transport abstraction (`Transport` trait, tokio)
- ✅ VFS abstraction trait (`Vfs` with async methods)
- ✅ POSIX backend (`PosixVfs`: path containment, wildcards, case-insensitive)
- ✅ Crypto service provider (`smb-csp`): RustCrypto crates by default,
  bundled hand-rolled implementations behind `handrolled` feature;
  both pass the same FIPS/RFC/interop vector suite

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
- ✅ Pre-auth integrity hash (SHA-512 over negotiate/session-setup frames,
  both directions — request and response each re-seed the chain:
  `state = SHA512(prev_state || msg)`, starting from zeros(64))
- ✅ Encryption transform (AES-GCM/CCM): full sealed sessions green against
  smbclient `--client-protection=encrypt` on 3.1.1 + 3.0.2 (ls/put/get/rm).
  Fixes landed: TYPE2 advertises KEY_EXCH, mechListMIC = bare MechTypes
  SEQUENCE with seq 0, TF tag read from the Signature field (detached),
  0xFD transform frames routed to SMB2 dispatch. Open nits: encrypt +
  require-signing combo rejects smbclient (client does not sign inside
  encryption); CCM live path untested
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
| Credit accounting (grant/charge, multi-credit) | [MS-SMB2] §3.3.1.1 | complete | charge calc unit tests | large-file copy ≥64 KiB chunks ✅ | large-R/W MB/s | credits granted per resp | credits_granted |
| Large MTU (>64 KiB single R/W) | §2.2.3.1.1 CAP_LARGE_MTU | complete | NBSS 24-bit length codec round-trip ✅ | 256 KiB single-op R/W (smbprotocol) ✅ | bulk MB/s | — | max_rw_seen |
| Async processing (STATUS_PENDING, async id) | §2.2.1.1, §3.3.4.2 | complete | async-frame + inotify watch/cancel tests | smbprotocol notify over encryption ✅ | — | pending gauge | async_pending ✅ |
| CANCEL | §2.2.30 | complete | cancel-stops-watch test | ctrl-c mid-read | — | cancel received | cancels_total ✅ |
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
| Compression capability (LZNT1/PATTERN_V1) | §2.2.3.1.2 ctx 0x0003 | complete | codec round-trip + negotiate tests | raw-socket negotiate + transform ECHO ✅ | — | algo chosen | via lznt1 crate |
| Multichannel capability + interface discovery | §2.2.31.4, §3.3.5.15.4 | complete | interface-list encode test | smbprotocol FSCTL_QUERY_NETWORK_INTERFACE_INFO ✅ | — | — | CAP_MULTI_CHANNEL |
| Session binding (multichannel) | §3.3.5.5.2 | complete | session-table bind/forget test | — (needs multi-NIC client) | — | — | shared SessionTable |

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
| Preauth-hash-bound 3.1.1 signing key | §3.3.5.2.1 | complete | — | SMB3 auth works; chain verified byte-exact vs smbclient (LD_PRELOAD gnutls trace) | — | — | — |
| mechListMIC (SPNEGO accept-complete, [MS-NLMP] §3.4.6) | RFC 4178 §4.2.2 | complete | — | smbclient --client-protection=encrypt session setup green | — | debug: sk/mech/mic inputs | — |
| Encryption transform AES-GCM/CCM (TF header §2.2.41) | §3.3.5.16 | complete | csp AEAD roundtrip+tamper+NIST ✅ | smbclient --client-protection=encrypt green on 3.1.1 + 3.0.2 (ls/put/get/rm); open: encrypt+require-signing combo, CCM live | target >500 MB/s | enc on/off per msg | enc_bytes_total |
| Cipher key derivation (C2S/S2C labels + preauth ctx) | §3.1.4.1 | complete | kdf vectors | encrypted tree-connect/read/write round-trips | — | — | — |
| Compression transform + COMPRESSION_CAPABILITIES ctx (LZNT1/Pattern_V1) | §2.2.42, §2.2.3.1.3 | complete | codec round-trip + negotiate tests | raw-socket negotiate ctx + \xFCSMB ECHO decompress ✅ | — | — | via lznt1 crate |
| Require-signing server policy (--require-signing) / require-encryption | §3.3.5.2.3 | complete | sign/verify round-trip test | unsigned client rejected; signed verified | — | rejects logged + counted | rejects_total ✅ |

### Tree connects & shares ([MS-SMB2] §2.2.9–§2.2.11)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| TREE_CONNECT / DISCONNECT + TreeId stamping | §2.2.9–11 | complete | tcon codec test | all client runs | — | debug: tree connected | tcons_total ✅, trees_active ✅ |
| Share resolution, BAD_NETWORK_NAME | §3.3.5.7 | complete | — | typo-share test | — | — | — |
| ShareType/flags/caps/MaximalAccess response | §2.2.10.2 | complete | body-size test | — | — | — | — |
| Virtual IPC$ share | §3.3.5.7 | complete | — | tcon ipc$ | — | — | — |
| DFS referrals | §2.2.31.1 | complete | — | non-DFS reject (STATUS_NOT_FOUND) | — | — | — |

### File operations ([MS-SMB2] §2.2.13–§2.2.28)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| CREATE (all dispositions, dirs, delete-on-close, root) | §2.2.13/14 | complete | create codec test | get/put battery | — | debug: create (both dialects) | creates_total ✅ |
| READ (DataOffset abs, 1 MiB clamp) | §2.2.19 | complete | read codec test | get battery | — | trace: read | bytes_read_total ✅ |
| WRITE | §2.2.21 | complete | write codec test | put battery | — | trace: write | bytes_written_total ✅ |
| CLOSE (+post-close attrs) | §2.2.15/16 | complete | — | del-on-close flow | — | counter on close | closes_total ✅ |
| FLUSH | §2.2.17 | complete | — | — | — | — | flushes_total |
| LOCK byte-range (enforced) | §2.2.26/27 | complete | conflict-matrix unit tests + lock-parse tests | two-client lock race (smbprotocol) ✅ | — | — | locks_granted ✅ |
| Sharing-mode conflict detection | §3.3.5.10 | complete | share-mode matrix unit tests | two opens same file (smbprotocol) ✅ | — | violation line | sharing_violations ✅ |
| Oplocks (exclusive) + break notification | [MS-SMB2] §2.2.23/24 | complete | grant+break integration test + codec tests | smbprotocol grant ✅ (break: server test) | oplock latency | break sent lines | oplock_breaks_total ✅ |
| Leases v2/v3 (file leases) | §2.2.23.2 | complete | lease codec tests + grant/break integration tests | smbprotocol lease grant ✅ (break: server test) | — | lease grant/break lines | leases_granted_total ✅ |
| Durable / persistent handles | §2.2.13.2.3–6 | complete | durable grant/reconnect + codec tests | smbprotocol DH2Q grant→drop→DH2C reconnect ✅ | — | — | durables_granted_total ✅ |
| Server-side COPYCHUNK (ODX offload) | §2.2.31.6 | complete | copychunk copy + limits integration tests | resume-key→copychunk between two handles | effective MB/s | copychunk debug | copychunk_bytes ✅ |
| ZERO_DATA / SET_SPARSE | §2.2.31.12/14 | complete | zero_range integration test | punches/zeros a range | — | — | zeroed_bytes ✅ |

### Directories ([MS-SMB2] §2.2.33–§2.2.36)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| QUERY_DIRECTORY classes 1/2/3/12/37/38 | §2.2.33/34, [MS-FSCC] §2.4 | complete | entry-chain decode tests | ls + impacket list | entries/s (todo) | — | dirs_scanned |
| Continuation queue + RESTART/REOPEN/SCAN flags | §3.3.5.24 | complete | restart-flag unit test | multi-page ls | — | — | enum_restarts |
| RETURN_SINGLE_ENTRY | §2.2.33.1 | complete | — | — | — | — | — |
| Resume-by-index (INDEX_SPECIFIED) | §2.2.33.1 | complete | file_index parse test | index-resumed page walk | — | — | — |
| 8.3 short-name generation/matching | [MS-FSCC] §2.1.5 | complete (generation) | short-name gen tests | ShortName in BOTH_DIRECTORY listing ✅ | — | — | — |
| CHANGE_NOTIFY (recursive/non-recursive) | §2.2.35/36 | complete | parse/build + inotify watch + recursive-subdir tests | smbprotocol watch→create→notify over encryption ✅ | — | notify fire lines | notifies_sent ✅ |
| DOS wildcard matcher (* ?) | [MS-CIFS] §2.2.8.1 | complete | wildcard unit tests | patterned ls | — | — | — |

### Information levels & metadata ([MS-FSCC])

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| QUERY_INFO file levels (basic/standard/internal/ea/access/name/mode/alignment/all/position/network-open/attr-tag) | §2.2.37/38, [MS-FSCC] §2.4 | complete | ALL-info alignment test | fstat-driven gets | — | — | qinfo_by_class |
| QUERY_INFO FS levels (volume/size/device/attr/full-size) | [MS-FSCC] §2.5 | complete | fs encode test | df via smbclient | — | — | — |
| FileAllInformation 8-byte embedded-struct alignment | [MS-FSCC] §2.4.1 | complete | size+offset asserts | size reported correctly | — | — | — |
| SET_INFO basic/eof/allocation/disposition/rename/position | §2.2.39/40 | complete | SetOp decode tests | rename/truncate flows | — | — | sets_total |
| Security descriptors (query/set SECURITY) | [MS-FSCC] §2.4.6 | complete | SD build/filter + query/set round-trip tests | smbprotocol query→set→query ✅ | — | — | via win-sd crate |
| Quota query/set | [MS-FSCC] §2.4.14 | complete | — | STATUS_INVALID_DEVICE_REQUEST (quotas not enabled) | — | — | — |
| Alternate data streams (enumerate/read/write) | [MS-FSCC] §2.6 | complete | stream_info codec + backend round-trip tests | smbprotocol ADS write/read + FileStreamInformation enum ✅ | — | — | xattr-backed |
| Case-insensitive resolution + path containment | backend | complete | posix resolve tests | case-twiddled opens | — | — | — |

### IOCTLs / FSCTL ([MS-SMB2] §2.2.31)

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| FSCTL_VALIDATE_NEGOTIATE_INFO echo | §3.3.5.15 | complete | input-length guard | authenticated SMB3 tcon | — | — | validate_negotiates |
| FSCTL_LMR_REQ_RESILIENCY ack | §2.2.31.10 | complete | — | resilient-open clients | — | — | — |
| FSCTL_PIPE_WAIT | §2.2.31.2 | complete | — | immediate success (pipes always available) | — | — | — |
| FSCTL_DFS_GET_REFERRALS | §2.2.31.1 | complete | — | STATUS_NOT_FOUND (non-DFS) | — | — | — |
| FSCTL_SRV_REQUEST_RESUME_KEY | §2.2.31.4 | complete | resume-key response test | odx source key | — | — | — |
| FSCTL_COPYCHUNK(_WRITE) | §2.2.31.6/7 | complete | copychunk parse + copy + chunk-limit tests | server-side copy | effective copy MB/s | — | copychunk_bytes ✅ |

### IPC$ / named pipes ([MS-SMB2] §2.1.2.1, [MS-SRVS])

| feature | specsection | status | unittest | systemtest | benchmarking | logging | metric |
|---|---|---|---|---|---|---|---|
| Pipe create/read/write over IPC$ (srvsvc, lanman) | §2.1.2.1 | complete | pipe open/write/read/close tests | impacket + smbclient -L | — | pipe opened/write/read debug | pipe_writes/reads_total |
| srvsvc NetShareEnum (share enumeration) | [MS-SRVS] §3.1.4.10 | complete | NDR round-trip decode unit tests | smbclient -L ✅ (dynamic encoder, `ms-ndr` crate) | — | debug: opnum/resp len | enums_served |
| RPC bind/transact over named pipes ([MS-RPCE]) | [MS-RPCE] §2 | complete | bind ack + auth3 + frag reassembly tests | impacket DCERPC bind+request ✓ | — | — | pipe_msgs_total |

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


---

## Milestones (execution order for remaining work)

Ordered cut-lines over the Feature Matrix above.

### M1 — Windows-usable ✅ COMPLETE
All items resolved:
- ✅ Encryption transform: encrypt green on 3.1.1 + 3.0.2 + CCM (RUSTSMB_CIPHER=ccm);
  encrypt+require-signing combo fixed via AEAD-integrity exemption
- ✅ srvsvc NetShareEnum over IPC$ named pipes: `smbclient -L` works (encrypted +
  plaintext); dynamic NDR encoder built on the `ms-ndr` crate (no template replay) —
  marshals any share set with correct deferred-string layout, verified live
- ✅ Credit accounting: lenient spend/refund tracking; multi-credit large R/W verified
  (16 MB encrypted round-trip); Large-MTU advertised for ≥2.1.0; NBSS 3-byte length fixed
- ✅ Regressions triaged: SMB2(2.02) tree-connect fixed (VNI caps echo + cipher gate);
  NT1 confirmed working server-side (smbclient ≥4.11 disables NT1 client-side)
- ✅ FSCTL_PIPE_TRANSACT ctl code corrected; IOCTL response StructureSize = 49;
  VALIDATE_NEGOTIATE_INFO echoes advertised caps/dialect exactly

### M1 residual polish (non-blocking)
- ✅ srvsvc dynamic NDR encoder: adopted the `ms-ndr` primitive crate for referent
  ids, alignment and conformant-varying wstrings; `smbclient -L` enumerates a
  dynamic share set (public/docs/IPC$) live, round-trip unit tests green
- ✅ Throughput: 64 MB encrypted PUT ~403 MB/s, GET ~291 MB/s (loopback, AES-GCM)
- ⬜ impacket-based integration tests as CI regression suite (M2 item)

### M2 — Real-server semantics

**Architectural crux — async send path (must land first).** The dispatch loop
is synchronous `recv → process → single send`; the transport is `&mut`-owned by
the serve loop so nothing can push an unsolicited/interim frame. Every M2
feature needs this (STATUS_PENDING interim, oplock/lease breaks, CHANGE_NOTIFY
completion, lock-wait wakeups). `TcpTransport::recv` uses `read_exact` and is
**not** cancel-safe, so a `select!`-drop approach would corrupt the stream — the
fix is to **split** the transport into read/write halves with a dedicated writer
task draining an outbound `mpsc`. Background tasks and handlers hold a
`Sender<Vec<u8>>`; async requests get an `AsyncId` ([MS-SMB2] §3.3.4.2) tracked
in a per-connection `async_id → CancellationToken` map; CANCEL cancels the
pending op and returns STATUS_CANCELLED on the original.

- **M2.1 Async/PENDING + CHANGE_NOTIFY** (item 4): split-transport writer + async
  tracking, then CHANGE_NOTIFY ([MS-SMB2] §2.2.35/36) via `inotify`; fix CANCEL
  to signal pending ops. Metrics `async_pending`, `notifies_sent`.
  Status: **done and live-validated** — interim STATUS_PENDING then signed/sealed
  async final, non-recursive inotify watcher, CANCEL wired. Verified end-to-end
  over an **encrypted** `smbprotocol` session (watch → create file → notification
  received → clean teardown, exit 0), plus proto unit tests and real-OS inotify
  integration tests. Interop fixes landed to get there: (a) derive cipher keys
  whenever a cipher is negotiated — not only under `--encrypt` — so the server
  can decrypt client-initiated sealed traffic, and seal replies to sealed
  requests; (b) TREE_DISCONNECT/LOGOFF/ECHO/FLUSH/LOCK response bodies were 2
  bytes but must be 4 (StructureSize + Reserved) — strict clients failed to
  unpack; (c) TREE_DISCONNECT is now idempotent; (d) LOGOFF no longer zeroes the
  session id before its (sealed) response is built. Remaining: recursive
  `SMB2_WATCH_TREE`; completed async ops leave a dead cancel-map entry until
  disconnect. Fixed alongside: `smbclient get` no longer fails its getattrib —
  a relative share root (`./share`) double-prefixed on stat-by-stored-path;
  the POSIX backend now canonicalizes its root to absolute.
- **M2.2 Byte-range lock enforcement** (item 6): per-open lock table + conflict
  matrix; STATUS_LOCK_NOT_GRANTED / async wait; sharing-violation on CREATE.
  Status: **done** — server-wide `LockManager` (keyed by path, owned by
  session+file id) with exclusive/shared conflict matrix; FAIL_IMMEDIATELY →
  STATUS_LOCK_NOT_GRANTED, blocking locks wait async and complete when the
  conflict clears; locks released on close/logoff/disconnect. Sharing-violation
  on CREATE via a server-wide `ShareModeTable` ([MS-FSA] §2.1.5.1). Fixed two
  pre-existing `LockReq` parse bugs (element offset BODY+24 not BODY+48; flags
  UNLOCK=0x4 / FAIL_IMMEDIATELY=0x10) exposed once locks were enforced. Unit
  tests (lock + share-mode matrices, lock parse) + live smbprotocol two-client
  lock-conflict and sharing-violation checks. Metrics `locks_granted`,
  `sharing_violations`.
- **M2.3 Oplocks v1/v2 + leases v2/v3** (item 5): parse lease create-contexts;
  lease table; unsolicited break notifications (needs M2.1) + break-ack.
  Status: **done.** Exclusive oplocks granted to the
  sole opener (server-wide OplockTable); a contending open breaks the holder
  with a signed/sealed unsolicited OPLOCK_BREAK notification via the async
  writer and gets no oplock; OPLOCK_BREAK acks handled; oplocks released on
  close/logoff/disconnect. Leases: CREATE `RqLs` create-context parse/build
  (v1 32-byte + v2 52-byte), a server-wide `LeaseTable` keyed by path, RWH
  granted to the sole opener, a contending open with a different lease key
  gets an unsolicited LEASE_BREAK downgrading the holder to RH (ack dispatched
  by StructureSize 36 on the shared OPLOCK_BREAK command), same-key reopen
  shares state without breaking, leases released on close/logoff/disconnect.
  Unit codec + grant/break integration tests; live smbprotocol lease grant
  verified (0x07 RWH). Simplifications (documented in `state.rs`): a single
  primary holder is tracked per path and leases/oplocks are arbitrated
  independently. Metric `leases_granted_total`, `lease_breaks_total`.

- **M2.4 FSCTL batch** (item 7, independent/synchronous): SRV_REQUEST_RESUME_KEY
  + COPYCHUNK(_WRITE) pair; SET_SPARSE + SET_ZERO_DATA via `fallocate` punch-hole.
  Status: **done** — resume-key registry, chunked server-side copy with
  [MS-SMB2] §3.3.5.15.6 limits enforcement, SET_SPARSE accepted, SET_ZERO_DATA
  zeros a range (VFS `zero_range`, default writes zeros). Proto codec unit tests
  + server integration tests (copy between handles, limits rejection, zero range);
  smbclient/smbprotocol regressions still green. Metrics `copychunk_bytes`,
  `zeroed_bytes`.

Sequencing: M2.1 first (unblocks all) → M2.4 in parallel (independent) →
M2.2 (needs async wait) → M2.3 (needs async breaks). Cross-cutting: extend the
`Vfs` trait with inotify-watch and `fallocate`/punch-hole/sparse methods;
background tasks must stop when the connection drops; land the impacket CI
regression suite alongside M2.1.

4. Async/PENDING scaffolding → CHANGE_NOTIFY via inotify → CANCEL.
5. Oplocks v1/v2 + leases v2/v3 with break notifications.
6. Byte-range lock enforcement + sharing-violation detection.
7. FSCTL batch: SRV_REQUEST_RESUME_KEY, COPYCHUNK, ZERO_DATA/SET_SPARSE.

### M3 — Completeness & hardening

Close the remaining practical [MS-SMB2] / [MS-FSCC] surface a standalone
Windows/macOS/Linux client exercises. Prefer existing crates for marshalling
(`ms-ndr`, `windows-acl`/`sddl` parsing where viable) and crypto (`RustCrypto`
suites already vendored via `smb-csp`) over hand-rolled codecs.

8. **Metadata/VFS completeness**
   - Security descriptors: QUERY/SET_INFO `SECURITY` ([MS-FSCC] §2.4.6,
     [MS-DTYP] §2.4.6 SECURITY_DESCRIPTOR). Marshal via a self-describing
     `SECURITY_DESCRIPTOR`/`ACL`/`SID` codec; expose owner/group/DACL in VFS.
   - Alternate data streams: enumerate/read/write ([MS-FSCC] §2.6); VFS stream
     handles backed by a naming convention or xattrs.
   - Quota query/set ([MS-FSCC] §2.4.14) — report-only stubs acceptable first.
   - 8.3 short-name generation/matching ([MS-FSCC] §2.1.5).
   - QUERY_DIRECTORY resume-by-index `INDEX_SPECIFIED` (§2.2.33.1).
9. **Compression** — SMB3 compression capability (LZNT1 / PATTERN_V1) via the
   `SMB2_COMPRESSION_CAPABILITIES` negotiate context + compressed transform
   (§2.2.42). Use an existing LZNT1 crate if one exists; else a reviewed impl.
10. **Advanced handles/connections**
    - Durable / persistent handles (§2.2.13.2.3–6, DH2Q/DH2C create contexts).
    - Multichannel + session binding (SMB2_SESSION_FLAG_BINDING).
    - DFS referrals + `FSCTL_DFS_GET_REFERRALS` (§2.2.31.1) referral response.
    - `FSCTL_PIPE_WAIT` real wait (currently a stub ack).
11. **QA / hardening** (no protocol code)
    - cargo-fuzz parser targets, cross-client concurrency stress harness,
      Windows-client soak, criterion benches wired into CI.

### M4 — Interop conformance vs Microsoft WindowsProtocolTestSuites

The remaining protocol work is driven by **passing Microsoft's real MS-SMB2
FileServer test suite** (286 test methods, 113 tagged BVT), not a home-grown
proxy. Toolchain is proven: the suite builds on **.NET 8 / Linux** (0 errors),
so every fix is measured against Microsoft's own tests.

12. **Stand up the harness (baseline).** Build the MS-SMB2 suite; write a
    workgroup `ptfconfig` (SUT = rustsmb) with shares `SMBBasic`,
    `SMBEncrypted`, `SMBCompressed`; provide a minimal SUT control adapter;
    run the `Bvt` category → record a real `X/113` baseline and bucket the
    failures.
13. **Infra-light feature buckets** (no domain/cluster; each raises the score):
    - Exact `NTSTATUS` codes — `UnexpectedFields` (31) + `UnexpectedContext` (16).
    - Compression `LZ77` / `LZ77+Huffman` / chained ([MS-SMB2] §2.2.42) — (34).
    - Lease v2 + directory leasing ([MS-SMB2] §2.2.23.2, §3.3.4.7) — (18).
    - Replay detection (channel-sequence, `SMB2_FLAGS_REPLAY_OPERATION`) — (20).
    - Multichannel real alt-channel bind ([MS-SMB2] §3.3.5.15.4) — (10).
    - Persistent-handle single-node reclaim — (19); **store foundation done**.
14. **Iterate.** Re-run the suite after each bucket; keep a per-revision score.

### M5 — Continuous availability & Witness (multi-node)

15. **Pluggable handle store** — async `HandleStore` trait + `MemStore` +
    `RedbStore` (embedded, durable across restart), wired into the server's
    durable-handle path (`--handle-store mem|redb`). ✅ **COMPLETE**
    (`smb-handle-store` crate; grant→`put`, DH2C→atomic `take`, sweep).
16. **Replicated backend** — `openraft` (or etcd via `etcd-client`) backend
    behind the same trait for multi-node handle/lock/session state.
17. **Shared-storage VFS** — a backend both nodes serve identical bytes from,
    so a reclaim on node B resumes node A's handle.
18. **Witness protocol** ([MS-SWN]) — RPC service on `\pipe\witness`
    (`WitnessrGetInterfaceList/Register/AsyncNotify/UnRegister`) reusing the
    srvsvc RPC plumbing, plus a notification engine driven by store
    owner-changes; advertise `SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY`.

### M6 — Optional companion specs

Separate MS specs most single-node servers never ship; tracked for completeness.

19. **SMB Direct / RDMA** ([MS-SMBD]) — RDMA transport + SMBDirect framing;
    needs RDMA-capable NICs and a Rust RDMA binding.
20. **Full DFS namespace server** ([MS-DFSC]) — namespace hosting beyond the
    M3 referral-response path.
21. **RSVD / SQOS / FSRVP** — shared-VHD, storage-QoS, and VSS-snapshot RPC
    services (Hyper-V / Windows-cluster niche).



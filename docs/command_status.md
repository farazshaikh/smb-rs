# Command implementation status

Per-command coverage for `smb-rs`, keyed to the on-the-wire opcodes in
[MS-SMB2] and [MS-CIFS]/[MS-SMB]. This is a command-level view; the granular
per-feature tracker (tests, benchmarks, metrics) lives in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

Legend: **done** = implemented and exercised against real clients ·
**partial** = handled with documented limits · **planned** = not yet
implemented.

## SMB2 / SMB3 commands ([MS-SMB2] §2.2)

SMB3 (dialects 3.0 / 3.0.2 / 3.1.1) adds **no new command opcodes** — it
reuses the SMB2 command set below. Its features ride on existing commands via
new negotiate contexts (preauth, encryption, compression, signing), create
contexts (lease v2/v3, durable v2), FSCTLs (validate-negotiate,
query-network-interface), and the `\xFD` encryption / `\xFC` compression
transform headers (transport-layer framings, not commands).

All 19 SMB2 command opcodes are dispatched.

| Opcode | Command | Spec | Status | Notes |
|---|---|---|---|---|
| 0x00 | NEGOTIATE | §2.2.3/4 | done | Dialects 2.0.2–3.1.1, negotiate contexts (preauth, encryption, signing, compression), wildcard probe |
| 0x01 | SESSION_SETUP | §2.2.5/6 | done | Both SPNEGO legs, NTLMv2/v1, RC4 key exchange, session binding, mechListMIC |
| 0x02 | LOGOFF | §2.2.7/8 | done | Tears down session + tables |
| 0x03 | TREE_CONNECT | §2.2.9/10 | done | Share resolution, IPC$, MaximalAccess, BAD_NETWORK_NAME |
| 0x04 | TREE_DISCONNECT | §2.2.11/12 | done | |
| 0x05 | CREATE | §2.2.13/14 | done | All six dispositions, dirs, delete-on-close, create contexts (lease, durable) |
| 0x06 | CLOSE | §2.2.15/16 | done | Post-close attributes |
| 0x07 | FLUSH | §2.2.17/18 | done | |
| 0x08 | READ | §2.2.19/20 | done | Absolute DataOffset, large-MTU (>64 KiB) multi-credit |
| 0x09 | WRITE | §2.2.21/22 | done | Large-MTU multi-credit |
| 0x0A | LOCK | §2.2.26/27 | done | Byte-range locks **enforced** (conflict matrix); async blocking waits |
| 0x0B | IOCTL | §2.2.31/32 | done | FSCTL subset below |
| 0x0C | CANCEL | §2.2.30 | done | Cancels async CHANGE_NOTIFY / blocking LOCK |
| 0x0D | ECHO | §2.2.28/29 | done | |
| 0x0E | QUERY_DIRECTORY | §2.2.33/34 | done | Info classes 1/2/3/12/37/38, restart/resume-by-index, single-entry |
| 0x0F | CHANGE_NOTIFY | §2.2.35/36 | done | Recursive + non-recursive, inotify-backed, cancelable |
| 0x10 | QUERY_INFO | §2.2.37/38 | done | File + FS classes, security descriptors, streams, quota (rejected) |
| 0x11 | SET_INFO | §2.2.39/40 | done | basic/eof/allocation/disposition/rename/position, security, streams |
| 0x12 | OPLOCK_BREAK | §2.2.23/24 | done | Exclusive oplocks + leases (v2/v3), break notification/ack |

### FSCTL / IOCTL codes ([MS-SMB2] §2.2.31)

| Control code | FSCTL | Spec | Status | Notes |
|---|---|---|---|---|
| 0x00140204 | VALIDATE_NEGOTIATE_INFO | §3.3.5.15 | done | Echoes negotiated caps/GUID/mode/dialect |
| 0x001401D4 | LMR_REQUEST_RESILIENCY | §2.2.31.10 | done | Acknowledged |
| 0x0011C017 | PIPE_TRANSACT | §2.2.31 | done | DCERPC over named pipes |
| 0x00110018 | PIPE_WAIT | §2.2.31.2 | done | Immediate success (pipes always instantiable) |
| 0x00140078 | SRV_REQUEST_RESUME_KEY | §2.2.31.4 | done | Server-side copy source key |
| 0x001440F2 | SRV_COPYCHUNK | §2.2.31.6 | done | ODX offload copy |
| 0x001480F2 | SRV_COPYCHUNK_WRITE | §2.2.31.7 | done | ODX offload copy |
| 0x000900C4 | SET_SPARSE | §2.2.31 | done | Accepted (Linux files implicitly sparse) |
| 0x000980C8 | SET_ZERO_DATA | [MS-FSCC] §2.3.79 | done | Punches / zeros a range |
| 0x00060194 | DFS_GET_REFERRALS | §2.2.31.1 | done | STATUS_NOT_FOUND (standalone, non-DFS) |
| 0x001401FC | QUERY_NETWORK_INTERFACE_INFO | §3.3.5.15.4 | done | Multichannel interface discovery |
| other | — | — | planned | Answered STATUS_NOT_IMPLEMENTED |

## SMB1 / CIFS commands ([MS-CIFS], [MS-SMB])

SMB1 is supported for negotiation and legacy access, including in-band
upgrade to SMB2 via the `\xFESMB` multi-protocol negotiate.

| Opcode | Command | Status | Notes |
|---|---|---|---|
| 0x72 | SMB_COM_NEGOTIATE | done | Advertises NT LM 0.12 and the SMB2 wildcard |
| 0x73 | SMB_COM_SESSION_SETUP_ANDX | done | NTLMSSP / SPNEGO |
| 0x74 | SMB_COM_LOGOFF_ANDX | done | |
| 0x75 | SMB_COM_TREE_CONNECT_ANDX | done | |
| 0x71 | SMB_COM_TREE_DISCONNECT | done | |
| 0xA2 | SMB_COM_NT_CREATE_ANDX | done | |
| 0x2E | SMB_COM_READ_ANDX | done | |
| 0x2F | SMB_COM_WRITE_ANDX | done | Both wire variants |
| 0x04 | SMB_COM_CLOSE | done | |
| 0x05 | SMB_COM_FLUSH | done | |
| 0x12 | SMB_COM_SEEK | done | |
| 0x24 | SMB_COM_LOCKING_ANDX | done | |
| 0x0C | SMB_COM_LOCK_BYTE_RANGE | done | |
| 0x0D | SMB_COM_UNLOCK_BYTE_RANGE | done | |
| 0x00 | SMB_COM_CREATE_DIRECTORY | done | |
| 0x01 | SMB_COM_DELETE_DIRECTORY | done | |
| 0x10 | SMB_COM_CHECK_DIRECTORY | done | |
| 0x06 | SMB_COM_DELETE | done | |
| 0x07 | SMB_COM_RENAME | done | |
| 0xA5 | SMB_COM_NT_RENAME | done | |
| 0x08 | SMB_COM_QUERY_INFORMATION | done | Legacy path info |
| 0x09 | SMB_COM_SET_INFORMATION | done | Legacy path info |
| 0x80 | SMB_COM_QUERY_INFORMATION_DISK | done | |
| 0x11 | SMB_COM_PROCESS_EXIT | done | |
| 0xA4 | SMB_COM_NT_CANCEL | done | |
| 0x26 | SMB_COM_ECHO | done | |
| 0x32 | SMB_COM_TRANSACTION2 | done | Subcommands below |

### TRANSACTION2 subcommands ([MS-CIFS] §2.2.6)

| Subcode | Subcommand | Status |
|---|---|---|
| 0x01 | TRANS2_FIND_FIRST2 | done |
| 0x02 | TRANS2_FIND_NEXT2 | done |
| 0x03 | TRANS2_QUERY_FS_INFORMATION | done |
| 0x04 | TRANS2_SET_FS_INFORMATION | done |
| 0x05 | TRANS2_QUERY_PATH_INFORMATION | done |
| 0x06 | TRANS2_SET_PATH_INFORMATION | done |
| 0x07 | TRANS2_QUERY_FILE_INFORMATION | done |
| 0x08 | TRANS2_SET_FILE_INFORMATION | done |

## Not implemented

These sit outside the core `[MS-SMB2]` request set (see the roadmap in the
[README](../README.md)):

- NetBIOS :139 session service + datagram browsing (RFC 1001/1002)
- Kerberos / non-NTLM SPNEGO mechanisms ([MS-KILE])
- RDMA transport / SMB Direct ([MS-SMBD])
- Witness protocol ([MS-SWN]) and continuous availability
- Full DFS namespace referrals ([MS-DFSC]) beyond the clean non-DFS reject

//! SMB2 command request/response codecs ([MS-SMB2] §2.2.13–§2.2.39).
//!
//! Every structure maps directly to its spec section (noted per item).
//! Buffer fields (`NameOffset`, `DataOffset`, …) are absolute offsets from
//! the frame start, so parsers take the **complete frame** including the
//! 64-byte header.

/// Byte offset where each request body begins.
pub const BODY: usize = 64;



/// SMB2 file identifier (16 bytes, replaces SMB1's 16-bit FID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub [u8; 16]);

impl FileId {
    /// All-zero file identifier.
    pub const ZERO: FileId = FileId([0u8; 16]);
}

fn g16(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}
fn g32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}
fn g64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

// ---------------- CREATE (§2.2.13 / §2.2.14) ----------------

/// CREATE request fixed-part offsets.
#[allow(dead_code)]
mod create_off {
    use super::BODY;

    /// StructureSize (=57).
    pub const STRUCT: usize = BODY;
    /// RequestedOplockLevel (1 byte, after the 1-byte SecurityFlags).
    pub const OPLOCK_LEVEL: usize = BODY + 3;
    /// SecurityFlags(1) RequestedOplockLevel(1) BulkSecurity(4) — skip to:
    /// ImpersonationLevel.
    pub const IMPERSONATION: usize = BODY + 8;
    /// SmbCreateFlags.
    pub const CREATE_FLAGS: usize = BODY + 16;
    /// DesiredAccess.
    pub const DESIRED_ACCESS: usize = BODY + 24;
    /// FileAttributes.
    pub const ATTRIBUTES: usize = BODY + 28;
    /// ShareAccess.
    pub const SHARE_ACCESS: usize = BODY + 32;
    /// CreateDisposition.
    pub const DISPOSITION: usize = BODY + 36;
    /// CreateOptions.
    pub const OPTIONS: usize = BODY + 40;
    /// NameOffset (absolute).
    pub const NAME_OFFSET: usize = BODY + 44;
    /// NameLength.
    pub const NAME_LENGTH: usize = BODY + 46;
    /// CreateContextsOffset.
    pub const CTX_OFFSET: usize = BODY + 48;
    /// CreateContextsLength.
    pub const CTX_LENGTH: usize = BODY + 52;
    /// Fixed part size (56 bytes).
    pub const FIXED_END: usize = BODY + 56;
}

/// CREATE request body (§2.2.13).
#[derive(Debug)]
pub struct CreateReq {
    /// Desired access mask.
    pub desired_access: u32,
    /// File attributes for new files.
    pub attrs: u32,
    /// Share access flags.
    pub share_access: u32,
    /// NT create disposition (SUPERSEDE/OPEN/CREATE/OPEN_IF/OVERWRITE/OVERWRITE_IF).
    pub disposition: u32,
    /// Create options (DIRECTORY_FILE, DELETE_ON_CLOSE, …).
    pub options: u32,
    /// Object name relative to share root (empty = share root itself).
    pub name: String,
    /// RequestedOplockLevel ([MS-SMB2] §2.2.13, [`oplock`]).
    pub oplock_level: u8,
    /// Parsed `RqLs` lease create-context, if the client requested a lease.
    pub lease: Option<LeaseReq>,
    /// Parsed durable-handle request/reconnect intent, if any.
    pub durable: Option<DurableReq>,
}

/// Durable-handle intent parsed from a CREATE's create-context chain
/// ([MS-SMB2] §2.2.13.2.3/§2.2.13.2.4/§2.2.13.2.11/§2.2.13.2.12).
#[derive(Debug, Clone, Copy)]
pub enum DurableReq {
    /// `DHnQ` v1 durable-handle request.
    RequestV1,
    /// `DH2Q` v2 durable-handle request.
    RequestV2 {
        /// Requested handle timeout in milliseconds (0 = server default).
        timeout: u32,
        /// Durable-handle flags (e.g. [`durable::FLAG_PERSISTENT`]).
        flags: u32,
        /// Client create-guid identifying the handle across reconnects.
        create_guid: [u8; 16],
    },
    /// `DHnC` v1 reconnect carrying the persistent handle id.
    ReconnectV1 {
        /// Persistent id (original FileId) to reclaim.
        file_id: [u8; 16],
    },
    /// `DH2C` v2 reconnect carrying the persistent id and create-guid.
    ReconnectV2 {
        /// Persistent id (original FileId) to reclaim.
        file_id: [u8; 16],
        /// Client create-guid that must match the preserved handle.
        create_guid: [u8; 16],
    },
}

/// Durable-handle create-context name tags ([MS-SMB2] §2.2.13.2).
pub mod durable {
    /// `SMB2_CREATE_DURABLE_HANDLE_REQUEST`.
    pub const REQ_V1: &[u8] = b"DHnQ";
    /// `SMB2_CREATE_DURABLE_HANDLE_RECONNECT`.
    pub const RECONNECT_V1: &[u8] = b"DHnC";
    /// `SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2`.
    pub const REQ_V2: &[u8] = b"DH2Q";
    /// `SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2`.
    pub const RECONNECT_V2: &[u8] = b"DH2C";
    /// Persistent-handle flag (`SMB2_DHANDLE_FLAG_PERSISTENT`).
    pub const FLAG_PERSISTENT: u32 = 0x0000_0002;
}

/// Walk a CREATE create-context chain, invoking `f(name, data)` for each entry.
fn walk_create_contexts(frame: &[u8], ctx_off: usize, ctx_len: usize, mut f: impl FnMut(&[u8], &[u8])) {
    if ctx_len == 0 || ctx_off < BODY {
        return;
    }
    let mut pos = ctx_off;
    let end = (ctx_off + ctx_len).min(frame.len());
    loop {
        if pos + 16 > end {
            return;
        }
        let next = g32(frame, pos) as usize;
        let name_off = g16(frame, pos + 4) as usize;
        let name_len = g16(frame, pos + 6) as usize;
        let data_off = g16(frame, pos + 10) as usize;
        let data_len = g32(frame, pos + 12) as usize;
        if let (Some(name), Some(data)) = (
            frame.get(pos + name_off..pos + name_off + name_len),
            frame.get(pos + data_off..(pos + data_off + data_len).min(frame.len())),
        ) {
            f(name, data);
        }
        if next == 0 {
            return;
        }
        pos += next;
    }
}

/// Parse durable-handle intent from a CREATE's create-context chain.
fn parse_durable_context(frame: &[u8], ctx_off: usize, ctx_len: usize) -> Option<DurableReq> {
    let mut found = None;
    walk_create_contexts(frame, ctx_off, ctx_len, |name, data| {
        let parsed = if name == durable::REQ_V2 && data.len() >= 32 {
            Some(DurableReq::RequestV2 {
                timeout: u32::from_le_bytes(data[0..4].try_into().unwrap()),
                flags: u32::from_le_bytes(data[4..8].try_into().unwrap()),
                create_guid: data[16..32].try_into().unwrap(),
            })
        } else if name == durable::RECONNECT_V2 && data.len() >= 32 {
            Some(DurableReq::ReconnectV2 {
                file_id: data[0..16].try_into().unwrap(),
                create_guid: data[16..32].try_into().unwrap(),
            })
        } else if name == durable::RECONNECT_V1 && data.len() >= 16 {
            Some(DurableReq::ReconnectV1 { file_id: data[0..16].try_into().unwrap() })
        } else if name == durable::REQ_V1 {
            Some(DurableReq::RequestV1)
        } else {
            None
        };
        if parsed.is_some() {
            found = parsed;
        }
    });
    found
}

/// Encode the `DH2Q` v2 durable-handle response data ([MS-SMB2] §2.2.14.2.11).
pub fn durable_v2_resp_data(timeout: u32, flags: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(8);
    d.extend_from_slice(&timeout.to_le_bytes());
    d.extend_from_slice(&flags.to_le_bytes());
    d
}

/// Encode the `DHnQ` v1 durable-handle response data ([MS-SMB2] §2.2.14.2.3):
/// 8 reserved bytes.
pub fn durable_v1_resp_data() -> Vec<u8> {
    vec![0u8; 8]
}

/// Requested lease from an `SMB2_CREATE_REQUEST_LEASE`(`_V2`) context
/// ([MS-SMB2] §2.2.13.2.8 / §2.2.13.2.10).
#[derive(Debug, Clone, Copy)]
pub struct LeaseReq {
    /// Client-chosen lease key identifying the shared caching state.
    pub key: [u8; 16],
    /// Requested lease state ([`lease`] caching bits).
    pub state: u32,
    /// Lease flags.
    pub flags: u32,
    /// Parent lease key (v2 only; zero otherwise).
    pub parent_key: [u8; 16],
    /// Lease epoch (v2 only; zero otherwise).
    pub epoch: u16,
    /// True when the context was the v2 (52-byte) form.
    pub v2: bool,
}

impl LeaseReq {
    /// Parse the lease context data blob (32 bytes v1, 52 bytes v2).
    fn parse_data(d: &[u8]) -> Option<LeaseReq> {
        if d.len() < 32 {
            return None;
        }
        let v2 = d.len() >= 52;
        Some(LeaseReq {
            key: d.get(0..16)?.try_into().ok()?,
            state: u32::from_le_bytes(d.get(16..20)?.try_into().ok()?),
            flags: u32::from_le_bytes(d.get(20..24)?.try_into().ok()?),
            parent_key: if v2 {
                d.get(32..48)?.try_into().ok()?
            } else {
                [0u8; 16]
            },
            epoch: if v2 {
                u16::from_le_bytes(d.get(48..50)?.try_into().ok()?)
            } else {
                0
            },
            v2,
        })
    }
}

/// Locate the `RqLs` lease context in a CREATE request's create-context chain
/// ([MS-SMB2] §2.2.13.2) and parse it.
fn parse_lease_context(frame: &[u8], ctx_off: usize, ctx_len: usize) -> Option<LeaseReq> {
    if ctx_len == 0 || ctx_off < BODY {
        return None;
    }
    let mut pos = ctx_off;
    let end = (ctx_off + ctx_len).min(frame.len());
    loop {
        if pos + 16 > end {
            return None;
        }
        let next = g32(frame, pos) as usize;
        let name_off = g16(frame, pos + 4) as usize;
        let name_len = g16(frame, pos + 6) as usize;
        let data_off = g16(frame, pos + 10) as usize;
        let data_len = g32(frame, pos + 12) as usize;
        let name = frame.get(pos + name_off..pos + name_off + name_len);
        if name == Some(lease::CONTEXT_NAME) {
            let data = frame.get(pos + data_off..(pos + data_off + data_len).min(frame.len()))?;
            return LeaseReq::parse_data(data);
        }
        if next == 0 {
            return None;
        }
        pos += next;
    }
}

impl CreateReq {
    /// Parse from the complete frame; `None` on malformed input.
    pub fn parse(frame: &[u8]) -> Option<CreateReq> {
        if frame.len() < create_off::FIXED_END || g16(frame, create_off::STRUCT) != 57 {
            return None;
        }
        let name_off = g16(frame, create_off::NAME_OFFSET) as usize;
        let name_len = g16(frame, create_off::NAME_LENGTH) as usize;
        let raw = if name_len > 0 && name_off >= BODY {
            frame.get(name_off..(name_off + name_len).min(frame.len()))?
        } else {
            &[]
        };
        // UTF-16LE name, strip null terminator.
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
            .take_while(|&u| u != 0)
            .collect();
        let ctx_off = g32(frame, create_off::CTX_OFFSET) as usize;
        let ctx_len = g32(frame, create_off::CTX_LENGTH) as usize;
        Some(CreateReq {
            desired_access: g32(frame, create_off::DESIRED_ACCESS),
            attrs: g32(frame, create_off::ATTRIBUTES),
            share_access: g32(frame, create_off::SHARE_ACCESS),
            disposition: g32(frame, create_off::DISPOSITION),
            options: g32(frame, create_off::OPTIONS),
            name: String::from_utf16_lossy(&units),
            oplock_level: *frame.get(create_off::OPLOCK_LEVEL).unwrap_or(&0),
            lease: parse_lease_context(frame, ctx_off, ctx_len),
            durable: parse_durable_context(frame, ctx_off, ctx_len),
        })
    }
}

/// Oplock levels ([MS-SMB2] §2.2.13 / §2.2.14).
pub mod oplock {
    /// No oplock.
    pub const NONE: u8 = 0x00;
    /// Level II (shared, read caching).
    pub const LEVEL_II: u8 = 0x01;
    /// Exclusive.
    pub const EXCLUSIVE: u8 = 0x08;
    /// Batch.
    pub const BATCH: u8 = 0x09;
    /// A lease is requested instead of an oplock.
    pub const LEASE: u8 = 0xFF;
}

/// Lease caching-state bits and constants ([MS-SMB2] §2.2.13.2.8).
pub mod lease {
    /// No caching.
    pub const NONE: u32 = 0x00;
    /// Read caching.
    pub const READ_CACHING: u32 = 0x01;
    /// Handle caching.
    pub const HANDLE_CACHING: u32 = 0x02;
    /// Write caching.
    pub const WRITE_CACHING: u32 = 0x04;
    /// Read + handle (the level a write-caching lease breaks down to).
    pub const RH: u32 = READ_CACHING | HANDLE_CACHING;
    /// Read + write + handle (full lease).
    pub const RWH: u32 = READ_CACHING | WRITE_CACHING | HANDLE_CACHING;
    /// Create-context tag for `SMB2_CREATE_REQUEST_LEASE`.
    pub const CONTEXT_NAME: &[u8] = b"RqLs";
    /// Break-notification flag demanding a lease-break acknowledgement.
    pub const BREAK_FLAG_ACK_REQUIRED: u32 = 0x01;
}


/// Granted lease returned in a CREATE response `RqLs` context.
#[derive(Debug, Clone, Copy)]
pub struct LeaseResp {
    /// Lease key echoed back to the client.
    pub key: [u8; 16],
    /// Granted lease state ([`lease`] bits).
    pub state: u32,
    /// Lease flags.
    pub flags: u32,
    /// Lease epoch (v2 only).
    pub epoch: u16,
    /// Emit the v2 (52-byte) form.
    pub v2: bool,
}

/// Encode just the lease structure ([MS-SMB2] §2.2.14.2.10/§2.2.14.2.11 data)
/// for a granted lease, without the create-context wrapper.
pub fn lease_context_data(l: &LeaseResp) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&l.key); // LeaseKey
    c.extend_from_slice(&l.state.to_le_bytes()); // LeaseState
    c.extend_from_slice(&l.flags.to_le_bytes()); // LeaseFlags
    c.extend_from_slice(&0u64.to_le_bytes()); // LeaseDuration
    if l.v2 {
        c.extend_from_slice(&[0u8; 16]); // ParentLeaseKey
        c.extend_from_slice(&l.epoch.to_le_bytes()); // Epoch
        c.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    }
    c
}

/// Encode a chain of CREATE-response create-contexts ([MS-SMB2] §2.2.13.2)
/// from `(name, data)` pairs, wiring `NextEntryOffset` links and keeping each
/// entry 8-byte aligned. Returns an empty buffer for no entries.
pub fn encode_create_contexts(entries: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (name, data)) in entries.iter().enumerate() {
        let start = out.len();
        let data_off = (16 + name.len()).next_multiple_of(8);
        out.extend_from_slice(&0u32.to_le_bytes()); // Next (patched below)
        out.extend_from_slice(&16u16.to_le_bytes()); // NameOffset
        out.extend_from_slice(&(name.len() as u16).to_le_bytes()); // NameLength
        out.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        let doff = if data.is_empty() { 0 } else { data_off as u16 };
        out.extend_from_slice(&doff.to_le_bytes()); // DataOffset
        out.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
        out.extend_from_slice(name);
        while out.len() - start < data_off {
            out.push(0);
        }
        out.extend_from_slice(data);
        if i + 1 < entries.len() {
            // Pad to an 8-byte boundary so the next entry (and Next link) align.
            while (out.len() - start) % 8 != 0 {
                out.push(0);
            }
            let next = (out.len() - start) as u32;
            out[start..start + 4].copy_from_slice(&next.to_le_bytes());
        }
    }
    out
}

/// Build CREATE response body (§2.2.14.1).
///
/// Fixed part is 88 bytes; the FileId sits after `Reserved2` at offset 64.
/// `contexts` is a pre-chained create-context blob (see
/// [`encode_create_contexts`]); when non-empty the context offset/length
/// fields point at it (offset is header-relative).
#[allow(clippy::too_many_arguments)]
pub fn build_create_resp(
    file_id: FileId,
    action: u32,
    times: [u64; 4],
    attrs: u32,
    alloc: u64,
    eof: u64,
    is_dir: bool,
    oplock: u8,
    contexts: &[u8],
) -> Vec<u8> {
    let _ = is_dir;
    // Contexts follow the 88-byte fixed body, at header-relative offset 152.
    let (ctx_off, ctx_len) = if contexts.is_empty() {
        (0u32, 0u32)
    } else {
        ((BODY + 88) as u32, contexts.len() as u32)
    };
    let mut b = Vec::with_capacity(88 + contexts.len());
    b.extend_from_slice(&89u16.to_le_bytes()); // StructureSize @0
    b.push(oplock); // OplockLevel @2
    b.push(0); // Flags @3
    b.extend_from_slice(&action.to_le_bytes()); // CreateAction @4
    for t in &times {
        b.extend_from_slice(&t.to_le_bytes());
    } // Creation/Access/Write/Change @8..40
    b.extend_from_slice(&alloc.to_le_bytes()); // AllocationSize @40
    b.extend_from_slice(&eof.to_le_bytes()); // EndOfFile @48
    b.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes @56
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2 @60
    b.extend_from_slice(&file_id.0); // FileId @64..80
    b.extend_from_slice(&ctx_off.to_le_bytes()); // CreateContextsOffset @80
    b.extend_from_slice(&ctx_len.to_le_bytes()); // CreateContextsLength @84
    debug_assert_eq!(b.len(), 88);
    b.extend_from_slice(contexts);
    b
}


/// Build an OPLOCK_BREAK notification body ([MS-SMB2] §2.2.23.1): a 24-byte
/// structure telling the holder to break its oplock down to `new_level`.
pub fn build_oplock_break(file_id: FileId, new_level: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.extend_from_slice(&24u16.to_le_bytes()); // StructureSize
    b.push(new_level); // OplockLevel
    b.push(0); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    b.extend_from_slice(&file_id.0); // FileId
    b
}

/// OPLOCK_BREAK acknowledgement/response body ([MS-SMB2] §2.2.24.2), echoing
/// the level the holder settled on.
pub fn build_oplock_break_resp(file_id: FileId, level: u8) -> Vec<u8> {
    build_oplock_break(file_id, level)
}

/// Parsed OPLOCK_BREAK acknowledgement ([MS-SMB2] §2.2.24.1).
#[derive(Debug)]
pub struct OplockBreakAck {
    /// Level the client has broken to.
    pub level: u8,
    /// Handle being acknowledged.
    pub file_id: FileId,
}

impl OplockBreakAck {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<OplockBreakAck> {
        if frame.len() < BODY + 24 || g16(frame, BODY) != 24 {
            return None;
        }
        Some(OplockBreakAck {
            level: *frame.get(BODY + 2)?,
            file_id: FileId(frame.get(BODY + 8..BODY + 24)?.try_into().ok()?),
        })
    }
}

/// Build a LEASE_BREAK notification body ([MS-SMB2] §2.2.23.2): a 44-byte
/// structure asking the holder of `key` to drop from `current` to `new` state.
pub fn build_lease_break(key: [u8; 16], current: u32, new: u32, epoch: u16, flags: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(44);
    b.extend_from_slice(&44u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&epoch.to_le_bytes()); // NewEpoch
    b.extend_from_slice(&flags.to_le_bytes()); // Flags
    b.extend_from_slice(&key); // LeaseKey
    b.extend_from_slice(&current.to_le_bytes()); // CurrentLeaseState
    b.extend_from_slice(&new.to_le_bytes()); // NewLeaseState
    b.extend_from_slice(&0u32.to_le_bytes()); // BreakReason
    b.extend_from_slice(&0u32.to_le_bytes()); // AccessMaskHint
    b.extend_from_slice(&0u32.to_le_bytes()); // ShareMaskHint
    debug_assert_eq!(b.len(), 44);
    b
}

/// LEASE_BREAK response body ([MS-SMB2] §2.2.24.2): a 36-byte structure echoing
/// the state the holder settled on.
pub fn build_lease_break_resp(key: [u8; 16], state: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(36);
    b.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // Flags
    b.extend_from_slice(&key); // LeaseKey
    b.extend_from_slice(&state.to_le_bytes()); // LeaseState
    b.extend_from_slice(&0u64.to_le_bytes()); // LeaseDuration
    debug_assert_eq!(b.len(), 36);
    b
}

/// Parsed LEASE_BREAK acknowledgement ([MS-SMB2] §2.2.24.1), distinguished from
/// an oplock-break ack by its StructureSize of 36.
#[derive(Debug)]
pub struct LeaseBreakAck {
    /// Lease key being acknowledged.
    pub key: [u8; 16],
    /// State the client has broken to.
    pub state: u32,
}

impl LeaseBreakAck {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<LeaseBreakAck> {
        if frame.len() < BODY + 36 || g16(frame, BODY) != 36 {
            return None;
        }
        Some(LeaseBreakAck {
            key: frame.get(BODY + 8..BODY + 24)?.try_into().ok()?,
            state: g32(frame, BODY + 24),
        })
    }
}


// ---------------- READ (§2.2.19 / §2.2.19.1) ----------------

/// READ request fixed-part offsets.
#[allow(dead_code)]
mod read_off {
    use super::BODY;

    /// StructureSize (=49).
    pub const STRUCT: usize = BODY;
    /// Padding(1) Reserved(1) then Length.
    pub const LENGTH: usize = BODY + 4;
    /// Offset (64-bit file position).
    pub const OFFSET: usize = BODY + 8;
    /// FileId.
    pub const FILE_ID: usize = BODY + 16;
    /// MinimumCount.
    pub const MIN_COUNT: usize = BODY + 32;
    /// Channel.
    pub const CHANNEL: usize = BODY + 36;
    /// RemainingBytes.
    pub const REMAINING: usize = BODY + 40;
}

/// READ request body (§2.2.19).
#[derive(Debug)]
pub struct ReadReq {
    /// Number of bytes to read.
    pub length: u32,
    /// Absolute file offset.
    pub offset: u64,
    /// Target file identifier.
    pub file_id: FileId,
    /// Bytes the client will accept below Length before a short read.
    #[allow(dead_code)]
    pub min_count: u32,
}

impl ReadReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<ReadReq> {
        if frame.len() < read_off::STRUCT + 48 || g16(frame, read_off::STRUCT) != 49 {
            return None;
        }
        Some(ReadReq {
            length: g32(frame, read_off::LENGTH),
            offset: g64(frame, read_off::OFFSET),
            file_id: FileId(frame.get(read_off::FILE_ID..read_off::FILE_ID + 16)?.try_into().ok()?),
            min_count: g32(frame, read_off::MIN_COUNT),
        })
    }
}

/// READ response body (§2.2.19.1); DataOffset is absolute from frame start
/// (64+16=80), 8-byte aligned.
pub fn build_read_resp(data: &[u8]) -> Vec<u8> {
    const DATA_OFF: usize = 80usize;
    let mut b = Vec::with_capacity(DATA_OFF - BODY + data.len());
    b.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
    b.push(DATA_OFF as u8); // DataOffset (absolute from header start)
    b.push(0); // Reserved
    b.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
    b.extend_from_slice(&0u32.to_le_bytes()); // DataRemaining
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    while BODY + b.len() < DATA_OFF {
        b.push(0);
    }
    b.extend_from_slice(data);
    b
}

// ---------------- WRITE (§2.2.21 / §2.2.21.1) ----------------

/// WRITE request fixed-part offsets.
#[allow(dead_code)]
mod write_off {
    use super::BODY;

    /// StructureSize (=49).
    pub const STRUCT: usize = BODY;
    /// DataOffset (absolute from frame start).
    pub const DATA_OFFSET: usize = BODY + 2;
    /// Length of the data payload.
    pub const LENGTH: usize = BODY + 4;
    /// Offset (64-bit file position).
    pub const OFFSET: usize = BODY + 8;
    /// FileId.
    pub const FILE_ID: usize = BODY + 16;
    /// Channel.
    pub const CHANNEL: usize = BODY + 32;
    /// RemainingBytes.
    pub const REMAINING: usize = BODY + 36;
    /// WriteChannelInfoOffset.
    pub const CH_INFO_OFFSET: usize = BODY + 40;
    /// WriteChannelInfoLength.
    pub const CH_INFO_LENGTH: usize = BODY + 42;
}

/// WRITE request body (§2.2.21).
#[derive(Debug)]
pub struct WriteReq {
    /// Absolute write offset.
    pub offset: u64,
    /// Target file identifier.
    pub file_id: FileId,
    /// Data to write.
    pub payload: Vec<u8>,
}

impl WriteReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<WriteReq> {
        if frame.len() < write_off::STRUCT + 48 || g16(frame, write_off::STRUCT) != 49 {
            return None;
        }
        let dlen = g32(frame, write_off::LENGTH) as usize;
        let doff = g16(frame, write_off::DATA_OFFSET) as usize;
        let payload = if dlen > 0 && doff >= BODY {
            frame.get(doff..(doff + dlen).min(frame.len()))?.to_vec()
        } else {
            Vec::new()
        };
        Some(WriteReq {
            offset: g64(frame, write_off::OFFSET),
            file_id: FileId(frame.get(write_off::FILE_ID..write_off::FILE_ID + 16)?.try_into().ok()?),
            payload,
        })
    }
}

/// WRITE response body (§2.2.21.1).
pub fn build_write_resp(written: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&written.to_le_bytes()); // Count
    b.extend_from_slice(&0u32.to_le_bytes()); // Remaining
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
    debug_assert_eq!(b.len(), 16);
    b
}

// ---------------- CLOSE (§2.2.15 / §2.2.15.1) ----------------

/// CLOSE request fixed-part offsets.
mod close_off {
    use super::BODY;

    /// StructureSize (=24).
    pub const STRUCT: usize = BODY;
    /// Flags.
    pub const FLAGS: usize = BODY + 2;
    /// FileId.
    pub const FILE_ID: usize = BODY + 8;
}

/// CLOSE request body (§2.2.15).
#[derive(Debug)]
pub struct CloseReq {
    /// True when the client wants post-close attributes in the reply.
    pub query_attrs: bool,
    /// Handle to close.
    pub file_id: FileId,
}

impl CloseReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<CloseReq> {
        if frame.len() < close_off::STRUCT + 24 || g16(frame, close_off::STRUCT) != 24 {
            return None;
        }
        Some(CloseReq {
            query_attrs: g16(frame, close_off::FLAGS) & 0x0001 != 0,
            file_id: FileId(frame.get(close_off::FILE_ID..close_off::FILE_ID + 16)?.try_into().ok()?),
        })
    }
}

/// CLOSE response body (§2.2.15.1).
pub fn build_close_resp(times: [u64; 4], alloc: u64, eof: u64, attrs: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(60);
    b.extend_from_slice(&60u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Flags
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    for t in &times {
        b.extend_from_slice(&t.to_le_bytes());
    }
    b.extend_from_slice(&alloc.to_le_bytes());
    b.extend_from_slice(&eof.to_le_bytes());
    b.extend_from_slice(&attrs.to_le_bytes());
    debug_assert_eq!(b.len(), 60);
    b
}

// ---------------- FLUSH (§2.2.17 / §2.2.17.1) ----------------

/// FLUSH request body (§2.2.17): StructureSize(2)=24 Reserved(2) FileId(16).
#[derive(Debug)]
pub struct FlushReq {
    /// Handle to flush.
    pub file_id: FileId,
}

impl FlushReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<FlushReq> {
        if frame.len() < BODY + 20 || g16(frame, BODY) != 24 {
            return None;
        }
        Some(FlushReq { file_id: FileId(frame.get(BODY + 4..BODY + 20)?.try_into().ok()?) })
    }
}

/// FLUSH response body (§2.2.17.1): StructureSize=4 only.
pub fn build_flush_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b
}

// ---------------- QUERY_DIRECTORY (§2.2.33 / §2.2.34) ----------------

/// QUERY_DIRECTORY request fixed-part offsets.
#[allow(dead_code)]
mod qdir_off {
    use super::BODY;

    /// StructureSize (=33).
    pub const STRUCT: usize = BODY;
    /// FileInformationClass.
    pub const CLASS: usize = BODY + 2;
    /// Flags.
    pub const FLAGS: usize = BODY + 3;
    /// FileIndex.
    pub const FILE_INDEX: usize = BODY + 4;
    /// FileId of the open directory handle.
    pub const FILE_ID: usize = BODY + 8;
    /// FileNameOffset (absolute).
    pub const NAME_OFFSET: usize = BODY + 24;
    /// FileNameLength.
    pub const NAME_LENGTH: usize = BODY + 26;
    /// Fixed part size (32 bytes).
    pub const FIXED_END: usize = BODY + 32;
}

/// FIND flags (§2.2.33.1).
pub mod find_flags {
    /// Restart the enumeration from the beginning.
    pub const RESTART_SCANS: u8 = 0x01;
    /// Return one entry at most.
    pub const RETURN_SINGLE_ENTRY: u8 = 0x02;
    /// Rescan directory contents (may duplicate).
    pub const SCAN: u8 = 0x04;
    /// FileIndex field carries meaning.
    pub const INDEX_SPECIFIED: u8 = 0x08;
    /// Re-open the search.
    pub const REOPEN: u8 = 0x10;
}

/// QUERY_DIRECTORY request body (§2.2.33).
#[derive(Debug)]
pub struct QueryDirReq {
    /// FileInformationClass requested.
    pub class: u8,
    /// FIND flags byte.
    pub flags: u8,
    /// Resume index (meaningful only when `INDEX_SPECIFIED` is set).
    pub file_index: u32,
    /// Directory handle.
    pub file_id: FileId,
    /// Search pattern (empty when continuing an enumeration).
    pub pattern: String,
}

impl QueryDirReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<QueryDirReq> {
        if frame.len() < qdir_off::FIXED_END || g16(frame, qdir_off::STRUCT) != 33 {
            return None;
        }
        let off = g16(frame, qdir_off::NAME_OFFSET) as usize;
        let len = g16(frame, qdir_off::NAME_LENGTH) as usize;
        let raw = if len > 0 && off >= BODY {
            frame.get(off..(off + len).min(frame.len()))?
        } else {
            &[]
        };
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
            .collect();
        Some(QueryDirReq {
            class: *frame.get(qdir_off::CLASS)?,
            flags: *frame.get(qdir_off::FLAGS)?,
            file_index: g32(frame, qdir_off::FILE_INDEX),
            file_id: FileId(frame.get(qdir_off::FILE_ID..qdir_off::FILE_ID + 16)?.try_into().ok()?),
            pattern: String::from_utf16_lossy(&units),
        })
    }
}

/// QUERY_DIRECTORY / QUERY_INFO response body (§2.2.34.1 / §2.2.38.1):
/// StructureSize=9 followed by the output buffer 8-byte aligned.
pub fn build_info_resp(buffer: &[u8]) -> Vec<u8> {
    const BUF_OFF: usize = BODY + 8; // StructureSize(2)+Offset(2)+Length(4)
    let mut b = Vec::with_capacity(BUF_OFF - BODY + buffer.len());
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&(BUF_OFF as u16).to_le_bytes()); // OutputBufferOffset
    b.extend_from_slice(&(buffer.len() as u32).to_le_bytes()); // OutputBufferLength
    while (BODY + b.len()) % 8 != 0 || BODY + b.len() < BUF_OFF {
        b.push(0);
    }
    b.extend_from_slice(buffer);
    b
}

// ---------------- QUERY_INFO (§2.2.37 / §2.2.38) ----------------

/// QUERY_INFO request fixed-part offsets.
#[allow(dead_code)]
mod qinfo_off {
    use super::BODY;

    /// StructureSize (=41).
    pub const STRUCT: usize = BODY;
    /// InfoType.
    pub const INFO_TYPE: usize = BODY + 2;
    /// FileInfoClass.
    pub const CLASS: usize = BODY + 3;
    /// OutputBufferLength.
    pub const OUTPUT_LEN: usize = BODY + 4;
    /// InputBufferOffset (absolute).
    pub const INPUT_OFFSET: usize = BODY + 8;
    /// InputBufferLength.
    pub const INPUT_LENGTH: usize = BODY + 12;
    /// AdditionalInformation.
    pub const ADDITIONAL: usize = BODY + 16;
    /// Flags.
    pub const FLAGS: usize = BODY + 20;
    /// FileId.
    pub const FILE_ID: usize = BODY + 24;
    /// Fixed part size (40 bytes).
    pub const FIXED_END: usize = BODY + 40;
}

/// QUERY_INFO InfoType values (§2.2.37.1).
pub mod info_type {
    /// File information (FileInformationClass based).
    pub const FILE: u8 = 0x01;
    /// File system information.
    pub const FS: u8 = 0x02;
    /// Security information (SDS).
    pub const SECURITY: u8 = 0x03;
    /// Quota information.
    pub const QUOTA: u8 = 0x04;
}

/// QUERY_INFO request body (§2.2.37).
#[derive(Debug)]
pub struct QueryInfoReq {
    /// InfoType byte.
    pub info_type: u8,
    /// FileInformationClass / FsInformationClass.
    pub class: u8,
    /// Maximum bytes the client accepts in the output buffer.
    pub output_len: u32,
    /// AdditionalInformation (SECURITY_INFORMATION mask for SECURITY queries).
    pub additional: u32,
    /// Target handle (FILE info type only).
    pub file_id: FileId,
    /// Raw input buffer (rename source path etc.), may be empty.
    pub input: Vec<u8>,
}

impl QueryInfoReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<QueryInfoReq> {
        if frame.len() < qinfo_off::FIXED_END || g16(frame, qinfo_off::STRUCT) != 41 {
            return None;
        }
        let off = g16(frame, qinfo_off::INPUT_OFFSET) as usize;
        let len = g32(frame, qinfo_off::INPUT_LENGTH) as usize;
        let input = if len > 0 && off >= BODY {
            frame.get(off..(off + len).min(frame.len()))?.to_vec()
        } else {
            Vec::new()
        };
        Some(QueryInfoReq {
            info_type: *frame.get(qinfo_off::INFO_TYPE)?,
            class: *frame.get(qinfo_off::CLASS)?,
            output_len: g32(frame, qinfo_off::OUTPUT_LEN),
            additional: g32(frame, qinfo_off::ADDITIONAL),
            file_id: FileId(frame.get(qinfo_off::FILE_ID..qinfo_off::FILE_ID + 16)?.try_into().ok()?),
            input,
        })
    }
}

// ---------------- SET_INFO (§2.2.39 / §2.2.40) ----------------

/// SET_INFO request fixed-part offsets.
#[allow(dead_code)]
mod sinfo_off {
    use super::BODY;

    /// StructureSize (=33).
    pub const STRUCT: usize = BODY;
    /// InfoType.
    pub const INFO_TYPE: usize = BODY + 2;
    /// FileInfoClass.
    pub const CLASS: usize = BODY + 3;
    /// BufferLength.
    pub const BUFFER_LEN: usize = BODY + 4;
    /// BufferOffset (absolute).
    pub const BUFFER_OFFSET: usize = BODY + 8;
    /// AdditionalInformation.
    pub const ADDITIONAL: usize = BODY + 12;
    /// FileId.
    pub const FILE_ID: usize = BODY + 16;
    /// Fixed part size (32 bytes).
    pub const FIXED_END: usize = BODY + 32;
}

/// SET_INFO request body (§2.2.39).
#[derive(Debug)]
pub struct SetInfoReq {
    /// InfoType byte.
    pub info_type: u8,
    /// File/Fs information class.
    pub class: u8,
    /// AdditionalInformation (SECURITY_INFORMATION mask for SECURITY sets).
    pub additional: u32,
    /// Target handle.
    pub file_id: FileId,
    /// Raw info-class payload buffer.
    pub buffer: Vec<u8>,
}

impl SetInfoReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<SetInfoReq> {
        if frame.len() < sinfo_off::FIXED_END || g16(frame, sinfo_off::STRUCT) != 33 {
            return None;
        }
        let off = g16(frame, sinfo_off::BUFFER_OFFSET) as usize;
        let len = g32(frame, sinfo_off::BUFFER_LEN) as usize;
        let buffer = if len > 0 && off >= BODY {
            frame.get(off..(off + len).min(frame.len()))?.to_vec()
        } else {
            Vec::new()
        };
        Some(SetInfoReq {
            info_type: *frame.get(sinfo_off::INFO_TYPE)?,
            class: *frame.get(sinfo_off::CLASS)?,
            additional: g32(frame, sinfo_off::ADDITIONAL),
            file_id: FileId(frame.get(sinfo_off::FILE_ID..sinfo_off::FILE_ID + 16)?.try_into().ok()?),
            buffer,
        })
    }
}

/// SET_INFO response body (§2.2.40): StructureSize=2 only.
pub fn build_set_info_resp() -> Vec<u8> {
    2u16.to_le_bytes().to_vec()
}

// ---------------- TREE_CONNECT / DISCONNECT / LOGOFF ----------------

/// TREE_CONNECT response body (§2.2.10.2): 16-byte fixed part, no buffer.
pub fn build_tree_connect_resp(share_type: u8) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&16u16.to_le_bytes()); // StructureSize
    b.push(share_type); // ShareType: 0x01 disk
    b.push(0); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // ShareFlags
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0x001F_01FFu32.to_le_bytes()); // MaximalAccess
    debug_assert_eq!(b.len(), 16);
    b
}

/// TREE_DISCONNECT response body (§2.2.11): StructureSize=4 then 2-byte
/// Reserved — the whole structure is 4 bytes.
pub fn build_tree_disconnect_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b
}

/// LOGOFF response body (§2.2.8): StructureSize=4 then 2-byte Reserved.
pub fn build_logoff_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b
}

/// ECHO response body (§2.2.29): StructureSize=4 then 2-byte Reserved.
pub fn build_echo_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b
}

/// TREE_CONNECT request fixed-part offsets (§2.2.9).
pub mod tcon_off {
    /// StructureSize (=9).
    pub const STRUCT: usize = super::BODY;
    /// PathOffset (absolute).
    pub const PATH_OFFSET: usize = super::BODY + 4;
    /// PathLength.
    pub const PATH_LENGTH: usize = super::BODY + 6;
}

/// Share types advertised in TREE_CONNECT responses (§2.2.10.1).
pub mod share_type {
    /// Disk share.
    pub const DISK: u8 = 0x01;
    /// Named pipe share.
    pub const PIPE: u8 = 0x02;
    /// Printer share.
    pub const PRINT: u8 = 0x03;
}

/// Capability bits advertised by the server (§2.2.9.2.1 / §2.2.10.2).
pub mod caps {
    use crate::consts;
    /// Distributed file system.
    pub const DFS: u32 = consts::CAP_DFS;
    /// Large MTU (multi-credit) support.
    pub const LARGE_MTU: u32 = consts::CAP_LARGE_MTU;
    /// Leasing support.
    pub const LEASING: u32 = 0x0000_0008;
}

/// Lock vector entry (§2.2.26.1).
#[derive(Debug)]
pub struct LockElem {
    /// Byte range start.
    pub offset: u64,
    /// Byte range length.
    pub length: u64,
    /// Shared lock.
    pub shared: bool,
    /// Exclusive lock.
    pub exclusive: bool,
    /// Unlock operation.
    pub unlock: bool,
    /// Fail immediately instead of blocking.
    pub fail_immediately: bool,
}

/// LOCK request (§2.2.26). The 24-byte header (StructureSize, LockCount,
/// LockSequence, FileId) is followed by `LockCount` 24-byte lock elements;
/// StructureSize is fixed at 48 (header + one element) per the SMB2 convention.
#[derive(Debug)]
pub struct LockReq {
    /// Locked handle.
    pub file_id: FileId,
    /// One entry per locked/unlocked range.
    pub locks: Vec<LockElem>,
}

impl LockReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<LockReq> {
        if frame.len() < BODY + 48 || g16(frame, BODY) != 48 {
            return None;
        }
        let count = g16(frame, BODY + 2) as usize;
        let fid = FileId(frame.get(BODY + 8..BODY + 24)?.try_into().ok()?);
        let mut locks = Vec::with_capacity(count.min(1024));
        for i in 0..count {
            // Lock elements begin right after the 24-byte header.
            let base = BODY + 24 + i * 24;
            let e = frame.get(base..base + 24)?;
            // Flags is a 32-bit field at offset 16 ([MS-SMB2] §2.2.26.1):
            // SHARED 0x1, EXCLUSIVE 0x2, UNLOCK 0x4, FAIL_IMMEDIATELY 0x10.
            let flags = g32(e, 16);
            locks.push(LockElem {
                offset: g64(e, 0),
                length: g64(e, 8),
                shared: flags & 0x01 != 0,
                exclusive: flags & 0x02 != 0,
                unlock: flags & 0x04 != 0,
                fail_immediately: flags & 0x10 != 0,
            });
        }
        Some(LockReq { file_id: fid, locks })
    }
}

/// LOCK response body (§2.2.27): StructureSize=4.
pub fn build_lock_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(4);
    b.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b
}

// ---------------- CHANGE_NOTIFY (§2.2.35 / §2.2.36) ----------------

/// CHANGE_NOTIFY completion-filter bits ([MS-SMB2] §2.2.35, [MS-FSCC] §2.7.1).
pub mod notify_filter {
    /// Renames, additions or deletions of a file name.
    pub const FILE_NAME: u32 = 0x0000_0001;
    /// Renames, additions or deletions of a directory name.
    pub const DIR_NAME: u32 = 0x0000_0002;
    /// Attribute changes.
    pub const ATTRIBUTES: u32 = 0x0000_0004;
    /// Size changes.
    pub const SIZE: u32 = 0x0000_0008;
    /// Last-write timestamp changes.
    pub const LAST_WRITE: u32 = 0x0000_0010;
    /// Last-access timestamp changes.
    pub const LAST_ACCESS: u32 = 0x0000_0020;
    /// Creation timestamp changes.
    pub const CREATION: u32 = 0x0000_0040;
    /// Extended-attribute changes.
    pub const EA: u32 = 0x0000_0080;
    /// Named-stream add/rename/delete.
    pub const STREAM_NAME: u32 = 0x0000_0200;
    /// Named-stream size changes.
    pub const STREAM_SIZE: u32 = 0x0000_0400;
    /// Named-stream writes.
    pub const STREAM_WRITE: u32 = 0x0000_0800;
}

/// FILE_NOTIFY_INFORMATION action codes ([MS-FSCC] §2.7.1).
pub mod notify_action {
    /// A file was added to the directory.
    pub const ADDED: u32 = 0x0000_0001;
    /// A file was removed from the directory.
    pub const REMOVED: u32 = 0x0000_0002;
    /// A file was modified (size, attributes, timestamps).
    pub const MODIFIED: u32 = 0x0000_0003;
    /// The old name of a renamed file.
    pub const RENAMED_OLD_NAME: u32 = 0x0000_0004;
    /// The new name of a renamed file.
    pub const RENAMED_NEW_NAME: u32 = 0x0000_0005;
}

/// SMB2_WATCH_TREE — recurse into subdirectories ([MS-SMB2] §2.2.35).
pub const WATCH_TREE: u16 = 0x0001;

/// CHANGE_NOTIFY request (§2.2.35).
#[derive(Debug)]
pub struct ChangeNotifyReq {
    /// Watched directory handle.
    pub file_id: FileId,
    /// Watch the whole subtree rather than just the directory.
    pub watch_tree: bool,
    /// Maximum bytes of FILE_NOTIFY_INFORMATION the client will accept.
    pub output_len: u32,
    /// Completion filter selecting which changes fire ([`notify_filter`]).
    pub filter: u32,
}

impl ChangeNotifyReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<ChangeNotifyReq> {
        if frame.len() < BODY + 32 || g16(frame, BODY) != 32 {
            return None;
        }
        Some(ChangeNotifyReq {
            file_id: FileId(frame.get(BODY + 8..BODY + 24)?.try_into().ok()?),
            watch_tree: g16(frame, BODY + 2) & WATCH_TREE != 0,
            output_len: g32(frame, BODY + 4),
            filter: g32(frame, BODY + 24),
        })
    }
}

/// Build a FILE_NOTIFY_INFORMATION list ([MS-FSCC] §2.7.1) from `(action,
/// name)` pairs. Names are directory-relative, UTF-16LE, no terminator; each
/// record is 4-byte aligned and chained through `NextEntryOffset`.
pub fn build_file_notify_information(entries: &[(u32, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, (action, name)) in entries.iter().enumerate() {
        let rec = out.len();
        let name16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        out.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched)
        out.extend_from_slice(&action.to_le_bytes());
        out.extend_from_slice(&(name16.len() as u32).to_le_bytes());
        out.extend_from_slice(&name16);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        if i + 1 < entries.len() {
            let next = (out.len() - rec) as u32;
            out[rec..rec + 4].copy_from_slice(&next.to_le_bytes());
        }
    }
    out
}

/// CHANGE_NOTIFY response body (§2.2.36): StructureSize=9, then the
/// FILE_NOTIFY_INFORMATION buffer at offset 72 from the header start.
pub fn build_change_notify_resp(buffer: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + buffer.len());
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&72u16.to_le_bytes()); // OutputBufferOffset (64 + 8)
    b.extend_from_slice(&(buffer.len() as u32).to_le_bytes());
    b.extend_from_slice(buffer);
    b
}

// ---------------- IOCTL (§2.2.31 / §2.2.32) ----------------

/// IOCTL request fixed-part offsets.
mod ioctl_off {
    use super::BODY;
    /// StructureSize (=57).
    pub const STRUCT: usize = BODY;
    /// CtlCode.
    pub const CTL_CODE: usize = BODY + 4;
    /// FileId.
    pub const FILE_ID: usize = BODY + 8;
    /// InputBufferOffset (absolute).
    pub const INPUT_OFFSET: usize = BODY + 24;
    /// InputBufferLength.
    pub const INPUT_COUNT: usize = BODY + 28;
    /// MaxInputResponse.
    pub const MAX_INPUT: usize = BODY + 32;
    /// OutputBufferOffset (absolute).
    pub const OUTPUT_OFFSET: usize = BODY + 36;
    /// OutputBufferLength.
    pub const OUTPUT_COUNT: usize = BODY + 40;
    /// MaxOutputResponse.
    pub const MAX_OUTPUT: usize = BODY + 44;
    /// Flags.
    pub const FLAGS: usize = BODY + 48;
}

/// FSCTL codes used by clients during share access ([MS-SMB2] §2.2.31).
pub mod fsctl {
    /// FSCTL_DFS_GET_REFERRALS ([MS-SMB2] §2.2.31.1).
    pub const DFS_GET_REFERRALS: u32 = 0x0006_0194;
    /// FSCTL_PIPE_WAIT ([MS-SMB2] §2.2.31.2):
    /// CTL_CODE(FILE_DEVICE_NAMED_PIPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS).
    pub const PIPE_WAIT: u32 = 0x0011_0018;
    /// FSCTL_QUERY_NETWORK_INTERFACE_INFO ([MS-SMB2] §2.2.31.4) — multichannel
    /// interface discovery.
    pub const QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
    /// FSCTL_SRV_REQUEST_RESUME_KEY.
    pub const SRV_REQUEST_RESUME_KEY: u32 = 0x0014_0078;
    /// FSCTL_SRV_COPYCHUNK — server-side copy ([MS-SMB2] §2.2.31.1).
    pub const SRV_COPYCHUNK: u32 = 0x0014_40F2;
    /// FSCTL_SRV_COPYCHUNK_WRITE — server-side copy, write handle.
    pub const SRV_COPYCHUNK_WRITE: u32 = 0x0014_80F2;
    /// FSCTL_SET_SPARSE ([MS-FSCC] §2.3.67).
    pub const SET_SPARSE: u32 = 0x0009_00C4;
    /// FSCTL_SET_ZERO_DATA ([MS-FSCC] §2.3.79) — punch a zero range.
    pub const SET_ZERO_DATA: u32 = 0x0009_80C8;
    /// FSCTL_LMR_REQ_RESILIENCY.
    pub const LMR_REQUEST_RESILIENCY: u32 = 0x0014_01D4;
    /// FSCTL_PIPE_TRANSACT ([MS-SMB2] §2.2.31.10 "Transact named pipe"):
    /// DCERPC PDUs tunnelled through the IOCTL input/output buffers.
    pub const PIPE_TRANSACT: u32 = 0x0011_C017;
    /// FSCTL_VALIDATE_NEGOTIATE_INFO.
    pub const VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
}

/// IOCTL request body (§2.2.31).
#[derive(Debug)]
pub struct IoctlReq {
    /// Control code.
    pub ctl_code: u32,
    /// Target handle (may be all-FF for special files).
    pub file_id: FileId,
    /// Raw input buffer.
    pub input: Vec<u8>,
    /// Bytes the client accepts as output.
    pub max_output: u32,
    /// True when this is a filesystem device request (Flags bit 1 clear).
    #[allow(dead_code)]
    pub is_fsctl: bool,
}

impl IoctlReq {
    /// Parse from the complete frame.
    pub fn parse(frame: &[u8]) -> Option<IoctlReq> {
        if frame.len() < ioctl_off::FLAGS + 8 || g16(frame, ioctl_off::STRUCT) != 57 {
            return None;
        }
        let ioff = g32(frame, ioctl_off::INPUT_OFFSET) as usize;
        let icnt = g32(frame, ioctl_off::INPUT_COUNT) as usize;
        let input = if icnt > 0 && ioff >= BODY {
            frame.get(ioff..(ioff + icnt).min(frame.len()))?.to_vec()
        } else {
            Vec::new()
        };
        Some(IoctlReq {
            ctl_code: g32(frame, ioctl_off::CTL_CODE),
            file_id: FileId(
                frame.get(ioctl_off::FILE_ID..ioctl_off::FILE_ID + 16)?.try_into().ok()?,
            ),
            input,
            max_output: g32(frame, ioctl_off::MAX_OUTPUT),
            is_fsctl: g32(frame, ioctl_off::FLAGS) & 0x1 == 0,
        })
    }
}

/// Build an IOCTL response body (§2.2.32.1). Fixed part is 48 bytes;
/// StructureSize mirrors smbd (49); `output` lands 8-byte aligned after it.
pub fn build_ioctl_resp(file_id: FileId, ctl_code: u32, output: &[u8]) -> Vec<u8> {
    const FIXED: usize = 48;
    let mut b = Vec::with_capacity(FIXED + output.len());
    b.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&ctl_code.to_le_bytes());
    b.extend_from_slice(&file_id.0);
    b.extend_from_slice(&0u32.to_le_bytes()); // InputOffset (none)
    b.extend_from_slice(&0u32.to_le_bytes()); // InputCount
    let out_off = BODY + FIXED;
    b.extend_from_slice(&(out_off as u32).to_le_bytes()); // OutputOffset
    b.extend_from_slice(&(output.len() as u32).to_le_bytes()); // OutputCount
    b.extend_from_slice(&0u32.to_le_bytes()); // Flags
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    while (BODY + b.len()) % 8 != 0 || BODY + b.len() < out_off {
        b.push(0);
    }
    b.extend_from_slice(output);
    debug_assert_eq!(b.len(), FIXED + output.len());
    b
}

// ---------------- Server-side copy ([MS-SMB2] §2.2.31.1 / §2.2.32.1) ----------

/// Server-side copy limits ([MS-SMB2] §3.3.5.15.6).
pub mod copychunk_limits {
    /// Maximum chunks per request.
    pub const MAX_CHUNKS: u32 = 16;
    /// Maximum bytes per chunk (1 MiB).
    pub const MAX_CHUNK_SIZE: u32 = 1_048_576;
    /// Maximum total bytes per request (16 MiB).
    pub const MAX_TOTAL_SIZE: u32 = 16_777_216;
}

/// One SRV_COPYCHUNK entry ([MS-SMB2] §2.2.31.1).
#[derive(Debug, Clone, Copy)]
pub struct CopyChunk {
    /// Byte offset in the source file.
    pub source_offset: u64,
    /// Byte offset in the target file.
    pub target_offset: u64,
    /// Number of bytes to copy.
    pub length: u32,
}

/// Parsed SRV_COPYCHUNK_COPY request ([MS-SMB2] §2.2.31.1): a 24-byte source
/// resume key followed by a chunk list.
#[derive(Debug)]
pub struct CopyChunkCopy {
    /// Resume key identifying the source open ([`build_resume_key_resp`]).
    pub source_key: [u8; 24],
    /// Copy operations to perform.
    pub chunks: Vec<CopyChunk>,
}

impl CopyChunkCopy {
    /// Parse from the IOCTL input buffer.
    pub fn parse(input: &[u8]) -> Option<CopyChunkCopy> {
        if input.len() < 32 {
            return None;
        }
        let source_key: [u8; 24] = input[0..24].try_into().ok()?;
        let chunk_count = g32(input, 24) as usize;
        // Reserved at [28..32].
        let mut chunks = Vec::with_capacity(chunk_count.min(64));
        for i in 0..chunk_count {
            let base = 32 + i * 24;
            let e = input.get(base..base + 24)?;
            chunks.push(CopyChunk {
                source_offset: g64(e, 0),
                target_offset: g64(e, 8),
                length: g32(e, 16),
            });
        }
        Some(CopyChunkCopy { source_key, chunks })
    }
}

/// Build the SRV_REQUESTED_RESUME_KEY response ([MS-SMB2] §2.2.32.3): the
/// 24-byte key then a zero ContextLength.
pub fn build_resume_key_resp(key: &[u8; 24]) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(key);
    b.extend_from_slice(&0u32.to_le_bytes()); // ContextLength
    b.extend_from_slice(&0u32.to_le_bytes()); // Context (empty, padded)
    b
}

/// Build the SRV_COPYCHUNK_RESPONSE ([MS-SMB2] §2.2.32.1). On success it
/// reports chunks/bytes written; on a limits violation the caller sends it
/// with STATUS_INVALID_PARAMETER carrying the server's maximums.
pub fn build_copychunk_resp(chunks_written: u32, chunk_bytes_written: u32, total_bytes_written: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(12);
    b.extend_from_slice(&chunks_written.to_le_bytes());
    b.extend_from_slice(&chunk_bytes_written.to_le_bytes());
    b.extend_from_slice(&total_bytes_written.to_le_bytes());
    b
}

/// Parse FILE_ZERO_DATA_INFORMATION ([MS-FSCC] §2.3.79): `(FileOffset,
/// BeyondFinalZero)`. The zeroed range is `[FileOffset, BeyondFinalZero)`.
pub fn parse_zero_data(input: &[u8]) -> Option<(u64, u64)> {
    if input.len() < 16 {
        return None;
    }
    Some((g64(input, 0), g64(input, 8)))
}

// ---------------- Encryption transform header ([MS-SMB2] §2.2.41) ----------------

/// Transform-header field offsets.
pub mod tf_off {
    /// ProtocolId = `\xFD 'S' 'M' 'B'`.
    pub const PROTOCOL_ID: usize = 0;
    /// AEAD tag (16 bytes) — zeroed inside the AAD region.
    pub const SIGNATURE: usize = 4;
    /// Nonce (16 bytes; GCM consumes 12, CCM 11, remainder zeroed).
    pub const NONCE: usize = 20;
    /// OriginalMessageSize.
    pub const MSG_SIZE: usize = 36;
    /// Reserved.
    pub const RESERVED: usize = 40;
    /// Flags (bit 0 = SMB2_TF_FLAGS_ENCRYPTED).
    pub const FLAGS: usize = 42;
    /// SessionId.
    pub const SESSION_ID: usize = 44;
    /// Fixed header size.
    pub const HDR_SIZE: usize = 52;
}

/// `\xFD 'S' 'M' 'B'` — transform-frame magic.
pub const TF_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];
/// SMB2_TF_FLAGS_ENCRYPTED.
pub const TF_FLAGS_ENCRYPTED: u16 = 0x0001;

/// Parsed transform header ([MS-SMB2] §2.2.41).
#[derive(Debug)]
pub struct TransformHdr {
    /// OriginalMessageSize — length of the plaintext SMB2 message.
    pub original_len: usize,
    /// SessionId the message belongs to.
    pub session_id: u64,
    /// Flags word (ENCRYPTED bit).
    pub flags: u16,
}

impl TransformHdr {
    /// Parse the 52-byte header from the start of `frame`; verifies magic.
    pub fn parse(frame: &[u8]) -> Option<TransformHdr> {
        if frame.len() < tf_off::HDR_SIZE || frame[..4] != TF_MAGIC {
            return None;
        }
        Some(TransformHdr {
            original_len: g32(frame, tf_off::MSG_SIZE) as usize,
            session_id: g64(frame, tf_off::SESSION_ID),
            flags: g16(frame, tf_off::FLAGS),
        })
    }

    /// Additional-authenticated-data view: header bytes from Nonce to the
    /// end ([MS-SMB2] §3.1.4.2 — everything after the 16-byte Nonce field,
    /// with Signature excluded because it precedes the Nonce).
    pub fn aad<'a>(&self, frame: &'a [u8]) -> &'a [u8] {
        &frame[tf_off::NONCE..tf_off::HDR_SIZE]
    }

}


/// Build the 52-byte transform header with a zeroed Signature field
/// (the AEAD tag is copied in after sealing).
#[allow(clippy::too_many_arguments)]
pub fn build_transform(
    session_id: u64,
    nonce: &[u8; 16],
    original_len: usize,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(tf_off::HDR_SIZE);
    t.extend_from_slice(&TF_MAGIC);
    t.extend_from_slice(&[0u8; 16]); // Signature (tag lands here)
    t.extend_from_slice(nonce);
    t.extend_from_slice(&(original_len as u32).to_le_bytes());
    t.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    t.extend_from_slice(&TF_FLAGS_ENCRYPTED.to_le_bytes()); // Flags
    t.extend_from_slice(&session_id.to_le_bytes());
    debug_assert_eq!(t.len(), tf_off::HDR_SIZE);
    t
}

#[cfg(test)]
mod change_notify_tests {
    use super::*;

    fn change_notify_request(file_id: [u8; 16], watch_tree: bool, filter: u32) -> Vec<u8> {
        let mut f = vec![0u8; BODY + 32];
        f[BODY..BODY + 2].copy_from_slice(&32u16.to_le_bytes()); // StructureSize
        let flags: u16 = if watch_tree { WATCH_TREE } else { 0 };
        f[BODY + 2..BODY + 4].copy_from_slice(&flags.to_le_bytes());
        f[BODY + 4..BODY + 8].copy_from_slice(&65536u32.to_le_bytes()); // OutputBufferLength
        f[BODY + 8..BODY + 24].copy_from_slice(&file_id);
        f[BODY + 24..BODY + 28].copy_from_slice(&filter.to_le_bytes());
        f
    }

    #[test]
    fn parses_change_notify_request() {
        let fid = [7u8; 16];
        let frame = change_notify_request(fid, true, notify_filter::FILE_NAME | notify_filter::LAST_WRITE);
        let req = ChangeNotifyReq::parse(&frame).expect("parse");
        assert_eq!(req.file_id.0, fid);
        assert!(req.watch_tree);
        assert_eq!(req.output_len, 65536);
        assert_eq!(req.filter, notify_filter::FILE_NAME | notify_filter::LAST_WRITE);
    }

    #[test]
    fn rejects_wrong_structure_size() {
        let mut frame = change_notify_request([0u8; 16], false, 0);
        frame[BODY..BODY + 2].copy_from_slice(&31u16.to_le_bytes());
        assert!(ChangeNotifyReq::parse(&frame).is_none());
    }

    #[test]
    fn single_notify_record_is_self_terminating() {
        let buf = build_file_notify_information(&[(notify_action::ADDED, "new.txt")]);
        // NextEntryOffset = 0 (last), Action = ADDED, FileNameLength = 14 bytes.
        assert_eq!(&buf[0..4], &0u32.to_le_bytes());
        assert_eq!(&buf[4..8], &notify_action::ADDED.to_le_bytes());
        assert_eq!(&buf[8..12], &14u32.to_le_bytes());
        assert_eq!(&buf[12..26], &"new.txt".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>()[..]);
        assert_eq!(buf.len() % 4, 0);
    }

    #[test]
    fn chained_notify_records_link_via_next_offset() {
        let buf = build_file_notify_information(&[
            (notify_action::ADDED, "a.txt"),
            (notify_action::REMOVED, "b.txt"),
        ]);
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_ne!(next, 0, "first record must point to the second");
        assert_eq!(next % 4, 0, "records are 4-byte aligned");
        assert_eq!(&buf[next..next + 4], &0u32.to_le_bytes(), "second record terminates");
        assert_eq!(&buf[next + 4..next + 8], &notify_action::REMOVED.to_le_bytes());
    }

    #[test]
    fn change_notify_response_header_offsets() {
        let notify = build_file_notify_information(&[(notify_action::MODIFIED, "x")]);
        let body = build_change_notify_resp(&notify);
        assert_eq!(&body[0..2], &9u16.to_le_bytes(), "StructureSize");
        assert_eq!(&body[2..4], &72u16.to_le_bytes(), "OutputBufferOffset");
        assert_eq!(&body[4..8], &(notify.len() as u32).to_le_bytes(), "OutputBufferLength");
        assert_eq!(&body[8..], &notify[..]);
    }

    /// Fixed-size response bodies whose SMB2 StructureSize is 4 must be a full
    /// 4 bytes on the wire (StructureSize + 2-byte Reserved); a 2-byte body
    /// makes strict clients fail to unpack the Reserved field.
    #[test]
    fn fixed_four_byte_responses_carry_reserved() {
        for (name, body) in [
            ("tree_disconnect", build_tree_disconnect_resp()),
            ("logoff", build_logoff_resp()),
            ("echo", build_echo_resp()),
            ("flush", build_flush_resp()),
            ("lock", build_lock_resp()),
        ] {
            assert_eq!(body.len(), 4, "{name} response must be 4 bytes");
            assert_eq!(&body[0..2], &4u16.to_le_bytes(), "{name} StructureSize=4");
            assert_eq!(&body[2..4], &0u16.to_le_bytes(), "{name} Reserved=0");
        }
    }
}

#[cfg(test)]
mod fsctl_tests {
    use super::*;

    #[test]
    fn parses_copychunk_copy() {
        let key = [0xABu8; 24];
        let mut input = Vec::new();
        input.extend_from_slice(&key);
        input.extend_from_slice(&2u32.to_le_bytes()); // ChunkCount
        input.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        for (so, to, len) in [(0u64, 100u64, 10u32), (10, 110, 20)] {
            input.extend_from_slice(&so.to_le_bytes());
            input.extend_from_slice(&to.to_le_bytes());
            input.extend_from_slice(&len.to_le_bytes());
            input.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        }
        let cc = CopyChunkCopy::parse(&input).expect("parse");
        assert_eq!(cc.source_key, key);
        assert_eq!(cc.chunks.len(), 2);
        assert_eq!(cc.chunks[1].source_offset, 10);
        assert_eq!(cc.chunks[1].target_offset, 110);
        assert_eq!(cc.chunks[1].length, 20);
    }

    #[test]
    fn copychunk_response_fields() {
        let r = build_copychunk_resp(3, 0, 999);
        assert_eq!(&r[0..4], &3u32.to_le_bytes(), "ChunksWritten");
        assert_eq!(&r[4..8], &0u32.to_le_bytes(), "ChunkBytesWritten");
        assert_eq!(&r[8..12], &999u32.to_le_bytes(), "TotalBytesWritten");
    }

    #[test]
    fn resume_key_response_carries_key() {
        let key = [7u8; 24];
        let r = build_resume_key_resp(&key);
        assert_eq!(&r[0..24], &key);
        assert_eq!(&r[24..28], &0u32.to_le_bytes(), "ContextLength=0");
    }

    #[test]
    fn parses_zero_data_range() {
        let mut input = Vec::new();
        input.extend_from_slice(&4096u64.to_le_bytes());
        input.extend_from_slice(&8192u64.to_le_bytes());
        assert_eq!(parse_zero_data(&input), Some((4096, 8192)));
        assert!(parse_zero_data(&input[..8]).is_none());
    }
}

#[cfg(test)]
mod lock_tests {
    use super::*;

    fn lock_request(file_id: [u8; 16], elems: &[(u64, u64, u32)]) -> Vec<u8> {
        let mut f = vec![0u8; BODY];
        f.extend_from_slice(&48u16.to_le_bytes()); // StructureSize
        f.extend_from_slice(&(elems.len() as u16).to_le_bytes()); // LockCount
        f.extend_from_slice(&0u32.to_le_bytes()); // LockSequence
        f.extend_from_slice(&file_id); // FileId (BODY+8..BODY+24)
        for &(off, len, flags) in elems {
            f.extend_from_slice(&off.to_le_bytes());
            f.extend_from_slice(&len.to_le_bytes());
            f.extend_from_slice(&flags.to_le_bytes());
            f.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        }
        f
    }

    #[test]
    fn parses_lock_elements_at_correct_offset() {
        // Elements start at BODY+24 (24-byte header), not BODY+48.
        let fid = [9u8; 16];
        let frame = lock_request(fid, &[(0, 10, 0x02 | 0x10)]); // EXCLUSIVE|FAIL_IMMEDIATELY
        let req = LockReq::parse(&frame).expect("parse");
        assert_eq!(req.file_id.0, fid);
        assert_eq!(req.locks.len(), 1);
        assert_eq!(req.locks[0].offset, 0);
        assert_eq!(req.locks[0].length, 10);
        assert!(req.locks[0].exclusive);
        assert!(req.locks[0].fail_immediately);
        assert!(!req.locks[0].unlock);
    }

    #[test]
    fn parses_unlock_and_shared_flags() {
        let frame = lock_request([0u8; 16], &[(5, 5, 0x01), (5, 5, 0x04)]); // SHARED, UNLOCK
        let req = LockReq::parse(&frame).expect("parse");
        assert_eq!(req.locks.len(), 2);
        assert!(req.locks[0].shared && !req.locks[0].unlock);
        assert!(req.locks[1].unlock && !req.locks[1].shared);
    }
}

#[cfg(test)]
mod oplock_codec_tests {
    use super::*;

    #[test]
    fn create_response_carries_oplock_level() {
        let body = build_create_resp(FileId([1; 16]), 1, [0; 4], 0, 0, 0, false, oplock::EXCLUSIVE, &[]);
        assert_eq!(body[2], oplock::EXCLUSIVE, "OplockLevel @2");
        assert_eq!(&body[80..84], &0u32.to_le_bytes(), "no contexts");
    }

    #[test]
    fn oplock_break_notification_shape() {
        let brk = build_oplock_break(FileId([9; 16]), oplock::NONE);
        assert_eq!(brk.len(), 24);
        assert_eq!(&brk[0..2], &24u16.to_le_bytes(), "StructureSize");
        assert_eq!(brk[2], oplock::NONE, "OplockLevel");
        assert_eq!(&brk[8..24], &[9u8; 16], "FileId");
    }

    #[test]
    fn parses_oplock_break_ack() {
        let mut frame = vec![0u8; BODY];
        frame.extend_from_slice(&build_oplock_break(FileId([7; 16]), oplock::LEVEL_II));
        let ack = OplockBreakAck::parse(&frame).expect("parse");
        assert_eq!(ack.level, oplock::LEVEL_II);
        assert_eq!(ack.file_id.0, [7; 16]);
    }
}

#[cfg(test)]
mod lease_codec_tests {
    use super::*;

    /// Wrap a lease data blob in a `RqLs` create-context inside a full CREATE
    /// request frame and confirm the parser recovers it.
    fn create_with_lease(key: [u8; 16], state: u32, v2: bool) -> Vec<u8> {
        let data_len = if v2 { 52usize } else { 32 };
        let mut ctx = Vec::new();
        ctx.extend_from_slice(&0u32.to_le_bytes()); // Next
        ctx.extend_from_slice(&16u16.to_le_bytes()); // NameOffset
        ctx.extend_from_slice(&4u16.to_le_bytes()); // NameLength
        ctx.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        ctx.extend_from_slice(&24u16.to_le_bytes()); // DataOffset
        ctx.extend_from_slice(&(data_len as u32).to_le_bytes()); // DataLength
        ctx.extend_from_slice(lease::CONTEXT_NAME);
        ctx.extend_from_slice(&[0u8; 4]); // pad to 24
        ctx.extend_from_slice(&key);
        ctx.extend_from_slice(&state.to_le_bytes());
        ctx.extend_from_slice(&0u32.to_le_bytes()); // flags
        ctx.extend_from_slice(&0u64.to_le_bytes()); // duration
        if v2 {
            ctx.extend_from_slice(&[0u8; 16]); // parent key
            ctx.extend_from_slice(&7u16.to_le_bytes()); // epoch
            ctx.extend_from_slice(&0u16.to_le_bytes()); // reserved
        }

        let mut f = vec![0u8; BODY];
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        body[3] = oplock::LEASE; // RequestedOplockLevel
        let ctx_off = BODY + 56;
        body[48..52].copy_from_slice(&(ctx_off as u32).to_le_bytes()); // CTX offset
        body[52..56].copy_from_slice(&(ctx.len() as u32).to_le_bytes()); // CTX length
        f.extend_from_slice(&body);
        f.extend_from_slice(&ctx);
        f
    }

    #[test]
    fn parses_lease_v1_context() {
        let frame = create_with_lease([0x11; 16], lease::RWH, false);
        let req = CreateReq::parse(&frame).expect("parse");
        let l = req.lease.expect("lease context present");
        assert_eq!(l.key, [0x11; 16]);
        assert_eq!(l.state, lease::RWH);
        assert!(!l.v2);
    }

    #[test]
    fn parses_lease_v2_context() {
        let frame = create_with_lease([0x22; 16], lease::RH, true);
        let l = CreateReq::parse(&frame).unwrap().lease.expect("lease");
        assert!(l.v2);
        assert_eq!(l.epoch, 7);
        assert_eq!(l.state, lease::RH);
    }

    #[test]
    fn create_response_appends_lease_context() {
        let grant = LeaseResp { key: [0x33; 16], state: lease::RH, flags: 0, epoch: 1, v2: true };
        let ctx = encode_create_contexts(&[(lease::CONTEXT_NAME, lease_context_data(&grant))]);
        let body = build_create_resp(FileId([1; 16]), 1, [0; 4], 0, 0, 0, false, oplock::LEASE, &ctx);
        assert_eq!(body[2], oplock::LEASE, "OplockLevel = lease");
        let off = u32::from_le_bytes(body[80..84].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(body[84..88].try_into().unwrap()) as usize;
        assert_eq!(off, BODY + 88, "context offset header-relative");
        assert_eq!(len, 24 + 52, "v2 context length");
        // Context sits right after the 88-byte fixed part; name tag "RqLs".
        assert_eq!(&body[88 + 16..88 + 20], lease::CONTEXT_NAME);
    }

    #[test]
    fn parses_durable_v2_request_and_reconnect() {
        // Build a DH2Q request context and confirm the guid/timeout parse.
        let mut data = Vec::new();
        data.extend_from_slice(&5000u32.to_le_bytes()); // Timeout
        data.extend_from_slice(&durable::FLAG_PERSISTENT.to_le_bytes()); // Flags
        data.extend_from_slice(&[0u8; 8]); // Reserved
        data.extend_from_slice(&[0xAB; 16]); // CreateGuid
        let ctx = encode_create_contexts(&[(durable::REQ_V2, data)]);
        let mut frame = vec![0u8; BODY];
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        let ctx_off = BODY + 56;
        body[48..52].copy_from_slice(&(ctx_off as u32).to_le_bytes());
        body[52..56].copy_from_slice(&(ctx.len() as u32).to_le_bytes());
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&ctx);
        match CreateReq::parse(&frame).unwrap().durable.expect("durable") {
            DurableReq::RequestV2 { timeout, flags, create_guid } => {
                assert_eq!(timeout, 5000);
                assert_eq!(flags, durable::FLAG_PERSISTENT);
                assert_eq!(create_guid, [0xAB; 16]);
            }
            other => panic!("expected RequestV2, got {other:?}"),
        }
    }

    #[test]
    fn lease_break_notification_shape() {
        let brk = build_lease_break([9; 16], lease::RWH, lease::RH, 2, lease::BREAK_FLAG_ACK_REQUIRED);
        assert_eq!(brk.len(), 44);
        assert_eq!(&brk[0..2], &44u16.to_le_bytes(), "StructureSize");
        assert_eq!(&brk[8..24], &[9u8; 16], "LeaseKey");
        assert_eq!(u32::from_le_bytes(brk[24..28].try_into().unwrap()), lease::RWH, "Current");
        assert_eq!(u32::from_le_bytes(brk[28..32].try_into().unwrap()), lease::RH, "New");
    }

    #[test]
    fn parses_lease_break_ack() {
        let mut frame = vec![0u8; BODY];
        frame.extend_from_slice(&build_lease_break_resp([7; 16], lease::RH));
        let ack = LeaseBreakAck::parse(&frame).expect("parse");
        assert_eq!(ack.key, [7; 16]);
        assert_eq!(ack.state, lease::RH);
    }
}


#[cfg(test)]
mod query_dir_tests {
    use super::*;

    #[test]
    fn parses_resume_file_index() {
        let mut f = vec![0u8; 64];
        let mut body = vec![0u8; 32];
        body[0..2].copy_from_slice(&33u16.to_le_bytes()); // StructureSize
        body[3] = find_flags::INDEX_SPECIFIED; // Flags
        body[4..8].copy_from_slice(&7u32.to_le_bytes()); // FileIndex
        f.extend_from_slice(&body);
        let req = QueryDirReq::parse(&f).expect("parse");
        assert_eq!(req.file_index, 7, "resume index parsed");
        assert_eq!(req.flags & find_flags::INDEX_SPECIFIED, find_flags::INDEX_SPECIFIED);
    }
}

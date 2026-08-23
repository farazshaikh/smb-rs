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
        Some(CreateReq {
            desired_access: g32(frame, create_off::DESIRED_ACCESS),
            attrs: g32(frame, create_off::ATTRIBUTES),
            share_access: g32(frame, create_off::SHARE_ACCESS),
            disposition: g32(frame, create_off::DISPOSITION),
            options: g32(frame, create_off::OPTIONS),
            name: String::from_utf16_lossy(&units),
        })
    }
}

/// Build CREATE response body (§2.2.14.1).
///
/// Fixed part is 88 bytes; the FileId sits after `Reserved2` at offset 64.
#[allow(clippy::too_many_arguments)]
pub fn build_create_resp(
    file_id: FileId,
    action: u32,
    times: [u64; 4],
    attrs: u32,
    alloc: u64,
    eof: u64,
    is_dir: bool,
) -> Vec<u8> {
    let _ = is_dir;
    let mut b = Vec::with_capacity(88);
    b.extend_from_slice(&89u16.to_le_bytes()); // StructureSize @0
    b.push(0); // OplockLevel @2
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
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset @80
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength @84
    debug_assert_eq!(b.len(), 88);
    b
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
    4u16.to_le_bytes().to_vec()
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

/// TREE_DISCONNECT response body (§2.2.11.2): StructureSize=4.
pub fn build_tree_disconnect_resp() -> Vec<u8> {
    4u16.to_le_bytes().to_vec()
}

/// LOGOFF response body (§2.2.7.2): StructureSize=4.
pub fn build_logoff_resp() -> Vec<u8> {
    4u16.to_le_bytes().to_vec()
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

/// LOCK request (§2.2.26) — parsed but unenforced, mirroring SMB1 LOCKING_ANDX.
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
            let base = BODY + 48 + i * 24;
            let e = frame.get(base..base + 24)?;
            locks.push(LockElem {
                offset: g64(e, 0),
                length: g64(e, 8),
                shared: e[16] & 0x01 != 0,
                exclusive: e[16] & 0x02 != 0,
                unlock: e[16] & 0x08 != 0,
                fail_immediately: e[17] & 0x02 != 0,
            });
        }
        Some(LockReq { file_id: fid, locks })
    }
}

/// LOCK response body (§2.2.27): StructureSize=4.
pub fn build_lock_resp() -> Vec<u8> {
    4u16.to_le_bytes().to_vec()
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
    /// FSCTL_DFS_GET_REFERRALS.
    pub const DFS_GET_REFERRALS: u32 = 0x0006_0194;
    /// FSCTL_PIPE_WAIT.
    pub const PIPE_WAIT: u32 = 0x0011_0098;
    /// FSCTL_SRV_REQUEST_RESUME_KEY.
    pub const SRV_REQUEST_RESUME_KEY: u32 = 0x0014_0078;
    /// FSCTL_LMR_REQ_RESILIENCY.
    pub const LMR_REQUEST_RESILIENCY: u32 = 0x0014_01D4;
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

/// Build an IOCTL response body (§2.2.32.1). Fixed part is 48 bytes
/// (StructureSize 49); `output` lands 8-byte aligned after it.
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

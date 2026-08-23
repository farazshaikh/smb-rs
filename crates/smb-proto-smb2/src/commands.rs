//! SMB2 command request/response codecs.
//!
//! Each structure maps directly to [MS-SMB2] sections as noted.

use crate::consts;

/// SMB2 file identifier (16 bytes, replaces SMB1's 16-bit FID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId(pub [u8; 16]);

impl FileId {
    /// All-zero file identifier.
    pub const ZERO: FileId = FileId([0u8; 16]);
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
    /// Object name relative to share root.
    pub name: String,
}

impl CreateReq {
    /// Parse from bytes following the 64-byte header.
    pub fn parse(b: &[u8]) -> Option<CreateReq> {
        if b.len() < 56 || g16(b, 0) != 57 { return None; }
        let desired_access = g32(b, 24);
        let attrs = g32(b, 28);
        let share_access = g32(b, 32);
        let disposition = g32(b, 36);
        let options = g32(b, 40);
        let name_off = g16(b, 44) as usize;
        let name_len = g16(b, 46) as usize;
        let raw = b.get(name_off..name_off + name_len)?;
        // UTF-16LE name, strip null terminator
        let units: Vec<u16> = raw.chunks_exact(2)
            .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
            .take_while(|&u| u != 0)
            .collect();
        Some(CreateReq {
            desired_access,
            attrs,
            share_access,
            disposition,
            options,
            name: String::from_utf16_lossy(&units),
        })
    }
}

/// Build CREATE response body (§2.2.13.1).
#[allow(clippy::too_many_arguments)]
pub fn build_create_resp(
    file_id: &[u8; 16],
    action: u32,
    times: [u64; 4],
    attrs: u32,
    alloc: u64,
    eof: u64,
    is_dir: bool,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(88);
    b.extend_from_slice(&89u16.to_le_bytes()); // StructureSize
    b.push(0); // OplockLevel
    b.push(0); // Reserved
    b.extend_from_slice(file_id); // FileId (16B)
    b.extend_from_slice(&action.to_le_bytes()); // CreateAction
    for t in &times { b.extend_from_slice(&t.to_le_bytes()); }
    b.extend_from_slice(&alloc.to_le_bytes());
    b.extend_from_slice(&eof.to_le_bytes());
    b.extend_from_slice(&attrs.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
    b
}

/// READ request body (§2.2.19).
#[derive(Debug)]
pub struct ReadReq {
    /// Number of bytes to read.
    pub length: u32,
    /// Absolute file offset.
    pub offset: u64,
    /// Target file identifier.
    pub file_id: [u8; 16],
}

impl ReadReq {
    /// Parse a READ request body.
    pub fn parse(b: &[u8]) -> Option<ReadReq> {
        if b.len() < 48 || g16(b, 0) != 49 { return None; }
        Some(ReadReq {
            length: g32(b, 4),
            offset: g64(b, 8),
            file_id: b.get(16..32)?.try_into().ok()?,
        })
    }
}

/// Build READ response body (§2.2.19.1). Data at offset 64+16=80.
pub fn build_read_resp(data: &[u8], hdr_len: usize) -> Vec<u8> {
    let data_off: usize = hdr_len + 16; // StructureSize(2)+DataOffset(1)+Reserved(1)+Len(4)+Remaining(4)+Resv(4) = 16
    let mut b = Vec::with_capacity(data_off - hdr_len + data.len());
    b.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
    b.push((data_off - hdr_len) as u8); // DataOffset (from start of header)
    b.push(0); // Reserved
    b.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
    b.extend_from_slice(&0u32.to_le_bytes()); // DataRemaining
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    while (hdr_len + b.len()) % 8 != 0 { b.push(0); } // align data
    b.extend_from_slice(data);
    b
}

/// WRITE request body (§2.2.21).
#[derive(Debug)]
pub struct WriteReq {
    /// Absolute write offset.
    pub offset: u64,
    /// Target file identifier.
    pub file_id: [u8; 16],
    /// Data to write.
    pub payload: Vec<u8>,
}

impl WriteReq {
    /// Parse a WRITE request body.
    pub fn parse(b: &[u8]) -> Option<WriteReq> {
        if b.len() < 48 || g16(b, 0) != 49 { return None; }
        let dlen = g32(b, 4);
        let offset = g64(b, 8);
        let fid: [u8; 16] = b.get(16..32)?.try_into().ok()?;
        let doff = g16(b, 32) as usize;
        if doff as usize + dlen as usize > b.len() { return None; }
        Some(WriteReq {
            offset, file_id: fid,
            payload: b.get(doff..(doff + dlen as usize)).unwrap_or(&[]).to_vec(),
        })
    }
}

/// Build WRITE response body (§2.2.21.1).
pub fn build_write_resp(written: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&written.to_le_bytes()); // Count
    b.extend_from_slice(&0u32.to_le_bytes()); // Remaining
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
    b
}

/// CLOSE request body (§2.2.15).
#[derive(Debug)]
pub struct CloseReq {
    /// Handle to close.
    pub file_id: [u8; 16],
}

impl CloseReq {
    /// Parse a CLOSE request body.
    pub fn parse(b: &[u8]) -> Option<CloseReq> {
        if b.len() < 24 || g16(b, 0) != 24 { return None; }
        Some(CloseReq { file_id: b.get(16..32)?.try_into().ok()? })
    }
}

/// Build CLOSE response body (§2.2.15.1).
pub fn build_close_resp(times: [u64; 4], alloc: u64, eof: u64, attrs: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(60);
    b.extend_from_slice(&60u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Flags
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    for t in &times { b.extend_from_slice(&t.to_le_bytes()); }
    b.extend_from_slice(&alloc.to_le_bytes());
    b.extend_from_slice(&eof.to_le_bytes());
    b.extend_from_slice(&attrs.to_le_bytes());
    b
}

fn g16(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0)
}
fn g32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}
fn g64(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())).unwrap_or(0)
}

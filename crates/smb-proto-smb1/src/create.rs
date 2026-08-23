//! `SMB_COM_NT_CREATE_ANDX` ([MS-SMB] §2.2.4.9).

use smb_proto::buf::Reader;

use crate::session_setup::BodyError;

impl From<smb_proto::error::ProtoError> for BodyError {
    fn from(_: smb_proto::error::ProtoError) -> Self {
        BodyError::TooShort
    }
}

/// Parsed client request ([MS-SMB] §2.2.4.9.1, WC=24).
#[derive(Debug)]
pub struct NtCreateReq {
    /// Name length in bytes (includes the NUL for Unicode names).
    pub name_len: usize,
    /// FID of a directory to open relative paths against (0 = share root).
    pub root_fid: u32,
    /// Desired access mask (generic + specific bits).
    pub desired_access: u32,
    /// Extended file attributes for newly created objects.
    pub ext_attrs: u32,
    /// Create disposition (`SUPERSEDE`..`OVERWRITE_IF`).
    pub disposition: u32,
    /// Create options (DIRECTORY_FILE, DELETE_ON_CLOSE, …).
    pub create_options: u32,
    /// Object name (decoded; empty = open the share root itself).
    pub name: String,
}

fn u16le(w: &[u8], off: usize) -> u16 {
    w.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

fn u32le(w: &[u8], off: usize) -> u32 {
    w.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

impl NtCreateReq {
    /// Parse the WC=24 request. `data_base` is the absolute frame offset of
    /// the data area so Unicode parity is honoured when the client pads
    /// before the name.
    pub fn parse(
        words: &[u8],
        data: &[u8],
        unicode: bool,
        bc_off_abs: usize,
    ) -> Result<Self, BodyError> {
        use super::session_setup::BodyError;
        if words.len() < 48 || data.is_empty() {
            return Err(BodyError::TooShort);
        }
        let name_len = u16le(words, 5) as usize;
        let root_fid = u32le(words, 11);
        let desired_access = u32le(words, 15);
        let ext_attrs = u32le(words, 27);
        let disposition = u32le(words, 35);
        let create_options = u32le(words, 39);

        // Skip one pad byte when the data area starts at an odd offset.
        let mut start = 0;
        if bc_off_abs % 2 != 0 && !data.is_empty() {
            start = 1;
        }
        let mut rd = Reader::new(data, start);
        let raw_len = name_len.min(data.len().saturating_sub(start));
        let raw = rd.take(raw_len)?.to_vec();
        let name = decode_name(&raw, unicode);

        Ok(NtCreateReq {
            name_len,
            root_fid,
            desired_access,
            ext_attrs,
            disposition,
            create_options,
            name,
        })
    }
}

/// Decode a create-name blob honouring the Unicode flag.
fn decode_name(raw: &[u8], unicode: bool) -> String {
    if unicode {
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned()
    }
}

/// Build the WC=34 success response ([MS-SMB] §2.2.4.9.2): oplock level,
/// FID, create action, four FILETIMEs, attributes, allocation/EOF sizes.
#[allow(clippy::too_many_arguments)]
pub fn build_response(
    fid: u16,
    action: u32,
    times: [smb_proto::types::FileTime; 4],
    attrs: u32,
    alloc: u64,
    eof: u64,
    is_dir: bool,
) -> Vec<u8> {
    let mut params = Vec::with_capacity(68);
    params.push(0xFF); // terminal AndX
    params.push(0);
    params.extend_from_slice(&0u16.to_le_bytes());
    params.push(0); // OplockLevel: none granted
    params.extend_from_slice(&fid.to_le_bytes());
    params.extend_from_slice(&action.to_le_bytes());
    for t in &times {
        params.extend_from_slice(&t.0.to_le_bytes());
    }
    params.extend_from_slice(&attrs.to_le_bytes());
    params.extend_from_slice(&alloc.to_le_bytes());
    params.extend_from_slice(&eof.to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes()); // FileType: disk
    params.extend_from_slice(&0u16.to_le_bytes()); // DeviceState
    params.push(if is_dir { 1 } else { 0 }); // Directory flag
    params
}

/// Map an I/O error kind onto an NT status for create paths.
pub fn map_create_err(e: &std::io::Error) -> smb_proto::types::Status {
    use smb_proto::types::Status;
    match e.kind() {
        std::io::ErrorKind::NotFound => Status::OBJECT_NAME_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => Status::ACCESS_DENIED,
        std::io::ErrorKind::AlreadyExists => Status::OBJECT_NAME_COLLISION,
        _ => Status::UNSUCCESSFUL,
    }
}

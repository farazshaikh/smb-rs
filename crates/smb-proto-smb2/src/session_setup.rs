//! SESSION_SETUP ([MS-SMB2] §2.2.5).


/// Byte offset of each §2.2.5.1 field within the request body.
///
/// Note `Flags` and `SecurityMode` are single-byte fields ([MS-SMB2]
/// §2.2.5.1). Fixed part totals 24 bytes.
#[allow(dead_code)]
mod req_off {
    /// StructureSize (=25).
    pub const STRUCT: usize = 0;
    /// Flags (1 byte).
    pub const FLAGS: usize = 2;
    /// SecurityMode (1 byte).
    pub const SECURITY_MODE: usize = 3;
    /// Capabilities.
    pub const CAPABILITIES: usize = 4;
    /// Channel.
    pub const CHANNEL: usize = 8;
    /// SecurityBufferOffset (absolute, from frame start).
    pub const BLOB_OFFSET: usize = 12;
    /// SecurityBufferLength.
    pub const BLOB_LENGTH: usize = 14;
    /// PrevSessionId.
    pub const PREV_SESSION_ID: usize = 16;
    /// Fixed part size before the variable buffer.
    pub const FIXED_END: usize = 24;
}

fn g16(b: &[u8], o: usize) -> u16 {
    match b.get(o..o + 2) {
        Some(s) => u16::from_le_bytes([s[0], s[1]]),
        None => 0,
    }
}

/// Parsed SESSION_SETUP request (§2.2.5.1).
#[derive(Debug)]
pub struct Request {
    /// Security mode requested by client.
    pub security_mode: u16,
    /// Client capabilities word.
    pub capabilities: u32,
    /// Previous session id for reauthentication (usually 0).
    pub prev_session_id: u64,
    /// SPNEGO/NTLMSSP token bytes.
    pub blob: Vec<u8>,
}

impl Request {
    /// Parse from the full frame (header included): buffer fields are
    /// addressed absolutely per §2.2.5.1.
    pub fn parse(frame: &[u8]) -> Option<Request> {
        const HDR: usize = 64;
        let b = frame.get(HDR..)?;
        if g16(b, req_off::STRUCT) != 25 && g16(b, req_off::STRUCT) != 24 {
            return None;
        }
        let blob_off = g16(b, req_off::BLOB_OFFSET) as usize;
        let blob_len = g16(b, req_off::BLOB_LENGTH) as usize;
        // Fall back to "blob follows the fixed part" when the client sent a
        // zero offset with a non-empty trailing buffer.
        let (start, end) = if blob_off >= HDR {
            (blob_off, blob_off.saturating_add(blob_len))
        } else {
            (HDR + req_off::FIXED_END, frame.len())
        };
        let blob = frame.get(start..end.min(frame.len())).unwrap_or(&[]).to_vec();
        Some(Request {
            security_mode: *b.get(req_off::SECURITY_MODE).unwrap_or(&0) as u16,
            capabilities: u32::from_le_bytes(
                b.get(req_off::CAPABILITIES..req_off::CAPABILITIES + 4)
                    .map(|s| s.try_into().unwrap())
                    .unwrap_or([0; 4]),
            ),
            prev_session_id: u64::from_le_bytes(
                b.get(req_off::PREV_SESSION_ID..req_off::PREV_SESSION_ID + 8)
                    .map(|s| s.try_into().unwrap())
                    .unwrap_or([0; 8]),
            ),
            blob,
        })
    }
}

/// Build a SESSION_SETUP response body (§2.2.5.2).
///
/// `session_flags`: 0x01 guest, 0x02 null session. The security buffer
/// directly follows the 8-byte fixed body, i.e. offset 64+8=72 from the
/// frame start.
pub fn build_response(session_flags: u16, blob: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + blob.len());
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&session_flags.to_le_bytes());
    b.extend_from_slice(&(72u16).to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&(blob.len() as u16).to_le_bytes());
    b.extend_from_slice(blob);
    b
}

/// Commands (§2.2.1.2).
pub mod cmd {
        /// Negotiate command.
    pub const NEGOTIATE: u16 = 0;
        /// Session Setup command.
    pub const SESSION_SETUP: u16 = 1;
        /// Logoff command.
    pub const LOGOFF: u16 = 2;
        /// Tree Connect command.
    pub const TREE_CONNECT: u16 = 3;
        /// Tree Disconnect command.
    pub const TREE_DISCONNECT: u16 = 4;
        /// Create command.
    pub const CREATE: u16 = 5;
        /// Close command.
    pub const CLOSE: u16 = 6;
        /// Flush command.
    pub const FLUSH: u16 = 7;
        /// Read command.
    pub const READ: u16 = 8;
        /// Write command.
    pub const WRITE: u16 = 9;
        /// Lock command.
    pub const LOCK: u16 = 10;
        /// Ioctl command.
    pub const IOCTL: u16 = 11;
        /// Cancel command.
    pub const CANCEL: u16 = 12;
        /// Echo command.
    pub const ECHO: u16 = 13;
        /// Query Directory command.
    pub const QUERY_DIRECTORY: u16 = 14;
        /// Change Notify command.
    pub const CHANGE_NOTIFY: u16 = 15;
        /// Query Info command.
    pub const QUERY_INFO: u16 = 16;
        /// Set Info command.
    pub const SET_INFO: u16 = 17;
}

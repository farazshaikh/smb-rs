//! SESSION_SETUP ([MS-SMB2] §2.2.5).

use smb_proto::types::Status;

use crate::negotiate;

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
    /// SPNEGO/NTLMSSP token bytes.
    pub blob: Vec<u8>,
}

impl Request {
    /// Parse from body; `prev_session_id` at fixed offset when present.
    pub fn parse(b: &[u8]) -> Option<Request> {
        let ss = g16(b, 0);
        if ss != 25 && ss != 24 {
            return None;
        }
        Some(Request {
            security_mode: g16(b, 6),
            blob: b.get(24..).unwrap_or(&[]).to_vec(),
        })
    }
}

/// Build a SESSION_SETUP response body (§2.2.5.2).
///
/// `session_flags`: 0x01 guest, 0x02 null session.
pub fn build_response(
    session_flags: u16,
    blob: &[u8],
    hdr_len: usize,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(9 + blob.len());
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&session_flags.to_le_bytes());
    b.extend_from_slice(&((hdr_len + 72) as u16).to_le_bytes()); // SecurityBufferOffset
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

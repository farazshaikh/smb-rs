//! SMB2 wire structures ([MS-SMB2]).
//!
//! Pass-2 scaffold. Planned modules against the spec stored at
//! `docs/protocol/smb2_3/MS-SMB2.pdf`:
//! - header: 64-byte SMB2 header (§2.2.1)
//! - negotiate: §2.2.3 (dialects 2.0.2/2.1.0/3.x, capabilities, contexts)
//! - session: SESSION_SETUP §2.2.5, LOGOFF §2.2.7
//! - tree: TREE_CONNECT/CONNECTX/DISCONNECT §2.2.9–2.2.11
//! - create/read/write/close/flush: §2.2.13–2.2.17
//! - find/query/set info/dir: §2.2.33–2.2.37
//! - credits: credit grant/charge accounting (§3.3.1.1)
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

/// SMB2 header magic `\xFESMB`.
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

pub mod commands;
pub mod compress;
pub mod consts;
pub mod info;
pub mod negotiate;
pub mod session_setup;

/// Known SMB2/3 dialect numbers (§2.2.3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// 2.0.2
    V202,
    /// 2.1.0
    V210,
    /// 3.0
    V300,
    /// 3.0.2
    V302,
    /// 3.1.1
    V311,
}

impl Dialect {
    /// Wire dialect revision number.
    pub fn rev(self) -> u16 {
        match self {
            Dialect::V202 => 0x0202,
            Dialect::V210 => 0x0210,
            Dialect::V300 => 0x0300,
            Dialect::V302 => 0x0302,
            Dialect::V311 => 0x0311,
        }
    }
}

/// Fixed 64-byte SMB2 header (§2.2.1) — decoded view.
#[derive(Debug, Clone)]
pub struct Header2 {
    /// Credit charge (SMB3.1.1) / structure size.
    pub credit_charge: u16,
    /// Status.
    pub status: u32,
    /// Command code (§2.2.1.2).
    pub command: u16,
    /// Credits granted by server.
    pub credits: u16,
    /// Header flags.
    pub flags: u32,
    /// Next command chain offset (compounding).
    pub next_command: u32,
    /// Message identifier.
    pub message_id: u64,
    /// Tree identifier (0 when not tree-bound).
    pub tree_id: u32,
    /// Session identifier.
    pub session_id: u64,
    /// Signature / dedupe tag.
    pub signature: [u8; 16],
}

impl Header2 {
    /// Parse the 64-byte header from `buf`; `None` on bad magic/size.
    pub fn parse(buf: &[u8]) -> Option<Header2> {
        if buf.len() < 64 || buf[0..4] != SMB2_MAGIC {
            return None;
        }
        Some(Header2 {
            credit_charge: u16::from_le_bytes(buf[6..8].try_into().ok()?),
            status: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            command: u16::from_le_bytes(buf[12..14].try_into().ok()?),
            credits: u16::from_le_bytes(buf[14..16].try_into().ok()?),
            flags: u32::from_le_bytes(buf[16..20].try_into().ok()?),
            next_command: u32::from_le_bytes(buf[20..24].try_into().ok()?),
            message_id: u64::from_le_bytes(buf[24..32].try_into().ok()?),
            // ProcessId/Reserved occupies 32..36; TreeId 36..40; SessionId
            // spans 40..48 ([MS-SMB2] §2.2.1).
            tree_id: u32::from_le_bytes(buf[36..40].try_into().ok()?),
            session_id: u64::from_le_bytes(buf[40..48].try_into().ok()?),
            signature: buf[48..64].try_into().ok()?,
        })
    }

    /// True when the response flag (bit 0) is set.
    pub fn is_response(&self) -> bool {
        self.flags & 0x0000_0001 != 0
    }

    /// True when the signed flag (bit 2) is set.
    pub fn is_signed(&self) -> bool {
        self.flags & 0x0000_0008 != 0
    }

    /// True when the async flag is set: `Flags & SMB2_FLAGS_ASYNC_COMMAND`
    /// (0x00000002, [MS-SMB2] §2.2.1.2).
    pub fn is_async(&self) -> bool {
        self.flags & 0x0000_0002 != 0
    }
}

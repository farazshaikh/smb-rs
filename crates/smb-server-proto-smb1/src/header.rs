//! SMB header codec ([MS-SMB] §2.2.3.1, base layout [MS-CIFS] §2.2.1.1) and
//! AndX-aware response assembly.

use smb_server_proto::types::Status;

pub use crate::consts::{flags, flags2};

/// The 32-byte SMB header shared by every message.
#[derive(Debug, Clone)]
pub struct Header {
    /// Command opcode.
    pub command: u8,
    /// NT status (or DOS error packed into 4 bytes).
    pub status: Status,
    /// Flags byte.
    pub flags: u8,
    /// Flags2 word.
    pub flags2: u16,
    /// High half of the multiplexed PID.
    pub pid_high: u16,
    /// Tree identifier.
    pub tid: u16,
    /// Process identifier (low half).
    pub pid: u16,
    /// User identifier.
    pub uid: u16,
    /// Multiplex identifier.
    pub mid: u16,
}

/// Size of the fixed SMB header.
pub const HDR_LEN: usize = 32;

/// Magic bytes `\xFFSMB`.
pub const SMB_MAGIC: [u8; 4] = [0xFF, b'S', b'M', b'B'];

/// Parse a header from the start of `buf`; returns the header plus the
/// WordCount offset (always [`HDR_LEN`]). `None` on bad magic/size.
pub fn parse_header(buf: &[u8]) -> Option<(Header, usize)> {
    if buf.len() < HDR_LEN + 1 || buf[0..4] != SMB_MAGIC {
        return None;
    }
    let hdr = Header {
        command: buf[4],
        status: Status(u32::from_le_bytes(buf[5..9].try_into().ok()?)),
        flags: buf[9],
        flags2: u16::from_le_bytes(buf[10..12].try_into().ok()?),
        pid_high: u16::from_le_bytes(buf[12..14].try_into().ok()?),
        tid: u16::from_le_bytes(buf[24..26].try_into().ok()?),
        pid: u16::from_le_bytes(buf[26..28].try_into().ok()?),
        uid: u16::from_le_bytes(buf[28..30].try_into().ok()?),
        mid: u16::from_le_bytes(buf[30..32].try_into().ok()?),
    };
    Some((hdr, HDR_LEN))
}

/// One response body (parameter words + data block). A complete frame carries
/// a header plus one body; AndX chains carry several bodies whose parameter
/// blocks open with AndXCommand/AndXOffset links.
#[derive(Debug, Clone)]
pub struct RespBody {
    /// Command this body responds to.
    pub command: u8,
    /// Parameter words (even length; AndX fields live at bytes 0–3).
    pub params: Vec<u8>,
    /// Data block following ByteCount.
    pub bytes: Vec<u8>,
    /// Overrides the response header TID (tree connect returns a fresh TID).
    pub tid_override: Option<u16>,
    /// Overrides the response header UID (session setup returns a fresh UID).
    pub uid_override: Option<u16>,
}

impl RespBody {
    /// Build a body without ID overrides.
    pub fn new(command: u8, params: Vec<u8>, bytes: Vec<u8>) -> Self {
        RespBody { command, params, bytes, tid_override: None, uid_override: None }
    }
}

fn is_andx_capable(cmd: u8) -> bool {
    matches!(
        cmd,
        crate::consts::COM_SESSION_SETUP_ANDX
            | crate::consts::COM_TREE_CONNECT_ANDX
            | crate::consts::COM_READ_ANDX
            | crate::consts::COM_WRITE_ANDX
            | crate::consts::COM_LOGOFF_ANDX
            | crate::consts::COM_LOCKING_ANDX
            | crate::consts::COM_NT_CREATE_ANDX
    )
}

/// Assemble a complete SMB frame echoing `req_hdr`, carrying `status` and the
/// given bodies, wiring AndX offsets between them.
///
/// An empty `bodies` list produces a bare error frame for the request's own
/// command so header-only rejections still reach the client.
pub fn build_response(req_hdr: &Header, status: Status, mut bodies: Vec<RespBody>) -> Vec<u8> {
    if bodies.is_empty() {
        bodies.push(RespBody::new(req_hdr.command, Vec::new(), Vec::new()));
    }

    // Terminal AndX bodies: AndXCommand=0xFF, AndXOffset=0 (as real servers).
    for i in 0..bodies.len() {
        if is_andx_capable(bodies[i].command)
            && bodies[i].params.len() >= 4
            && i + 1 >= bodies.len()
        {
            bodies[i].params[0] = 0xFF;
            bodies[i].params[1] = 0;
            bodies[i].params[2..4].copy_from_slice(&0u16.to_le_bytes());
        }
    }

    let mut out = Vec::with_capacity(HDR_LEN + 64);
    out.extend_from_slice(&SMB_MAGIC);
    out.push(bodies[0].command);
    if req_hdr.flags2 & flags2::NT_STATUS != 0 {
        out.extend_from_slice(&status.raw().to_le_bytes());
    } else {
        let (class, code) = status.to_dos();
        out.extend_from_slice(&[code, 0, class, 0]);
    }
    out.push(flags::RESPONSE | (req_hdr.flags & flags::CASE_SENSITIVE));
    let mut flags2 = req_hdr.flags2 & (flags2::UNICODE | flags2::LONG_NAMES | flags2::NT_STATUS);
    flags2 |= flags2::LONG_NAMES;
    out.extend_from_slice(&flags2.to_le_bytes());
    out.extend_from_slice(&req_hdr.pid_high.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]); // signature — signing unsupported
    out.extend_from_slice(&[0u8; 2]); // reserved
    out.extend_from_slice(&bodies[0].tid_override.unwrap_or(req_hdr.tid).to_le_bytes());
    out.extend_from_slice(&req_hdr.pid.to_le_bytes());
    out.extend_from_slice(&bodies[0].uid_override.unwrap_or(req_hdr.uid).to_le_bytes());
    out.extend_from_slice(&req_hdr.mid.to_le_bytes());

    for (i, body) in bodies.iter().enumerate() {
        let body_start = out.len();
        debug_assert!(body.params.len() % 2 == 0);
        out.push((body.params.len() / 2) as u8);
        out.extend_from_slice(&body.params);
        out.extend_from_slice(&(body.bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&body.bytes);

        if is_andx_capable(body.command) && body.params.len() >= 4 {
            match bodies.get(i + 1) {
                Some(next) => {
                    let next_off = out.len();
                    out[body_start + 1] = next.command;
                    out[body_start + 2] = 0;
                    out[body_start + 3..body_start + 5]
                        .copy_from_slice(&(next_off as u16).to_le_bytes());
                }
                None => {
                    // Terminal: 0xFF/0/0 already patched above.
                    let end = out.len() as u16;
                    out[body_start + 3..body_start + 5].copy_from_slice(&end.to_le_bytes());
                    out[body_start + 1] = 0xFF;
                }
            }
        }
    }
    out
}

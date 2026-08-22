// SMB message parsing and response assembly, including AndX chaining.

pub use crate::smb::*;

pub const HDR_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct SmbHeader {
    pub command: u8,
    pub status: Status,
    pub flags: u8,
    pub flags2: u16,
    pub pid_high: u16,
    pub tid: u16,
    pub pid: u16,
    pub uid: u16,
    pub mid: u16,
}

pub struct Request<'a> {
    pub hdr: SmbHeader,
    /// Full message buffer (header + params + bytes).
    pub buf: &'a [u8],
    /// Offset of WordCount byte.
    pub wc_off: usize,
    pub wct: usize,
    /// Offset of ByteCount low byte.
    pub bc_off: usize,
}

impl<'a> Request<'a> {
    pub fn word_bytes(&self) -> &'a [u8] {
        let start = self.wc_off + 1;
        let end = (start + self.wct * 2).min(self.buf.len());
        &self.buf[start..end]
    }
    /// Bytes area as slice (after ByteCount).
    pub fn data(&self) -> &'a [u8] {
        if self.bc_off == 0 || self.bc_off + 2 > self.buf.len() {
            return &[];
        }
        let bc = u16::from_le_bytes([self.buf[self.bc_off], self.buf[self.bc_off + 1]]) as usize;
        let start = self.bc_off + 2;
        let end = (start + bc).min(self.buf.len());
        &self.buf[start..end]
    }
    pub fn andx_command(&self) -> Option<u8> {
        let w = self.word_bytes();
        if self.wct >= 2 && w[0] != 0xFF {
            Some(w[0])
        } else {
            None
        }
    }
    pub fn andx_offset(&self) -> Option<usize> {
        let w = self.word_bytes();
        if self.wct >= 3 && w[0] != 0xFF {
            Some(u16::from_le_bytes([w[2], w[3]]) as usize)
        } else {
            None
        }
    }
    pub fn unicode(&self) -> bool {
        self.hdr.flags2 & FLAGS2_UNICODE != 0
    }
    pub fn status32(&self) -> bool {
        self.hdr.flags2 & FLAGS2_NT_STATUS != 0
    }
}

/// Parse an SMB header; returns header plus offsets.
pub fn parse_header(buf: &[u8]) -> Option<(SmbHeader, usize)> {
    if buf.len() < HDR_LEN + 1 {
        return None;
    }
    if buf[0..4] != SMB_MAGIC {
        return None;
    }
    let status_raw = u32::from_le_bytes(buf[5..9].try_into().ok()?);
    let flags2 = u16::from_le_bytes(buf[10..12].try_into().ok()?);
    let hdr = SmbHeader {
        command: buf[4],
        status: Status(status_raw),
        flags: buf[9],
        flags2,
        pid_high: u16::from_le_bytes(buf[12..14].try_into().ok()?),
        tid: u16::from_le_bytes(buf[24..26].try_into().ok()?),
        pid: u16::from_le_bytes(buf[26..28].try_into().ok()?),
        uid: u16::from_le_bytes(buf[28..30].try_into().ok()?),
        mid: u16::from_le_bytes(buf[30..32].try_into().ok()?),
    };
    let wc_off = HDR_LEN;
    Some((hdr, wc_off))
}

/// Build a sub-Request view for AndX chained commands.
pub fn chained_request<'a>(buf: &'a [u8], offset: usize) -> Option<Request<'a>> {
    if offset + 1 >= buf.len() {
        return None;
    }
    let wct = buf[offset] as usize;
    // words then bytecount
    let bc_off = offset + 1 + wct * 2;
    if bc_off + 2 > buf.len() {
        return None;
    }
    // Re-parse full header for shared fields
    let (hdr, _) = parse_header(buf)?;
    Some(Request {
        hdr,
        buf,
        wc_off: offset,
        wct,
        bc_off,
    })
}

/// One response body (parameters + bytes), possibly part of an AndX chain.
#[derive(Clone)]
pub struct RespBody {
    pub command: u8,
    pub params: Vec<u8>,
    /// Some messages (NEGOTIATE) carry one extra byte between words and
    /// ByteCount (e.g. ChallengeLength).
    pub trailer_byte: Option<u8>,
    pub bytes: Vec<u8>,
    /// SESSION_SETUP/TREE_CONNECT return freshly allocated IDs in the header.
    pub uid_override: Option<u16>,
    pub tid_override: Option<u16>,
}

impl RespBody {
    pub fn new(command: u8, params: Vec<u8>, bytes: Vec<u8>) -> Self {
        RespBody {
            command,
            params,
            trailer_byte: None,
            bytes,
            uid_override: None,
            tid_override: None,
        }
    }
}

/// Slimmed view for TRANS2 subcommands. The parameter buffer starts with a
/// 1-byte subcommand, then (typically) one pad byte, then fixed u16 params.
pub struct SubReq<'a> {
    pub subcmd: u8,
    /// Fixed parameters (after subcommand + pad).
    pub params: &'a [u8],
    /// Data section contents.
    pub data: &'a [u8],
    /// Absolute frame offset of params[0] (for string parity math).
    pub param_base: usize,
    /// Absolute frame offset of data[0].
    pub data_base: usize,
    pub unicode: bool,
}

/// Assemble a complete SMB frame from header info + bodies. Handles AndX
/// chaining: first body gets a full header; subsequent bodies are appended
/// after their predecessors with AndXOffset/AndXCommand patched in.
pub fn build_response(req_hdr: &SmbHeader, status: Status, mut bodies: Vec<RespBody>) -> Vec<u8> {
    if bodies.is_empty() {
        // Bare error response: header + WordCount=0 + ByteCount=0.
        bodies.push(RespBody::new(req_hdr.command, Vec::new(), Vec::new()));
    }
    let has_andx = |cmd: u8| {
        matches!(
            cmd,
            COM_SESSION_SETUP_ANDX
                | COM_TREE_CONNECT_ANDX
                | COM_OPEN_ANDX
                | COM_READ_ANDX
                | COM_WRITE_ANDX
                | COM_LOGOFF_ANDX
                | COM_LOCKING_ANDX
        )
    };
    // Terminate every chain: set AndXCommand=0xFF unless another body follows.
    for i in 0..bodies.len() {
        if has_andx(bodies[i].command) && bodies[i].params.len() >= 4 {
            let next = bodies.get_mut(i + 1);
            match next {
                Some(_) => {} // patched during assembly below
                None => {
                    bodies[i].params[0] = 0xFF;
                    bodies[i].params[1] = 0;
                    // AndXOffset = end of this body; computed below but a safe
                    // value is fine because clients stop at 0xFF anyway.
                    bodies[i].params[2..4].copy_from_slice(&0u16.to_le_bytes());
                }
            }
        }
    }

    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&SMB_MAGIC);
    out.push(bodies[0].command);
    // Status: honor client's NT_STATUS capability.
    if req_hdr.flags2 & FLAGS2_NT_STATUS != 0 {
        out.extend_from_slice(&status.0.to_le_bytes());
    } else {
        let (class, code) = to_dos(status);
        out.extend_from_slice(&[(code), 0u8, class, 0u8]);
    }
    out.push(FLAGS_RESPONSE | (req_hdr.flags & FLAGS_CASE_SENSITIVE));
    let mut flags2 =
        req_hdr.flags2 & (FLAGS2_UNICODE | FLAGS2_LONG_NAMES | FLAGS2_NT_STATUS);
    flags2 |= FLAGS2_LONG_NAMES;
    if req_hdr.flags2 & FLAGS2_NT_STATUS != 0 {
        flags2 |= FLAGS2_NT_STATUS;
    }
    out.extend_from_slice(&flags2.to_le_bytes());
    out.extend_from_slice(&req_hdr.pid_high.to_le_bytes());
    out.extend_from_slice(&[0u8; 8]); // signature
    out.extend_from_slice(&[0u8; 2]); // reserved
    out.extend_from_slice(
        &bodies[0]
            .tid_override
            .unwrap_or(req_hdr.tid)
            .to_le_bytes(),
    );
    out.extend_from_slice(&req_hdr.pid.to_le_bytes());
    out.extend_from_slice(
        &bodies[0]
            .uid_override
            .unwrap_or(req_hdr.uid)
            .to_le_bytes(),
    );
    out.extend_from_slice(&req_hdr.mid.to_le_bytes());

    for (i, body) in bodies.iter().enumerate() {
        let body_start = out.len();
        let mut wcb = body.params.len();
        debug_assert!(body.trailer_byte.is_some() || wcb % 2 == 0);
        if body.trailer_byte.is_some() && wcb % 2 != 0 {
            wcb -= 1; // last param byte is actually the trailer
        }
        out.push((wcb / 2) as u8);
        out.extend_from_slice(&body.params[..wcb]);
        if let Some(tb) = body.trailer_byte {
            out.push(tb);
        }
        out.extend_from_slice(&(body.bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&body.bytes);

        if has_andx(body.command) && body.params.len() >= 4 {
            match bodies.get(i + 1) {
                Some(next_body) => {
                    let next_off = out.len();
                    out[body_start + 1] = next_body.command;
                    out[body_start + 2] = 0;
                    out[body_start + 3..body_start + 5]
                        .copy_from_slice(&(next_off as u16).to_le_bytes());
                }
                None => {
                    // Terminal response: AndXCommand=0xFF, AndXOffset=0
                    // (matches what real servers do).
                    out[body_start + 1] = 0xFF;
                    out[body_start + 2] = 0;
                    out[body_start + 3..body_start + 5].copy_from_slice(&0u16.to_le_bytes());
                }
            }
        }
    }
    out
}

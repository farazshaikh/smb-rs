//! TRANSACTION2 envelope ([MS-CIFS] §2.2.4.46) and the subcommand extensions
//! defined by [MS-SMB] §2.2.6: FIND_FIRST2 (§2.2.6.1), FIND_NEXT2 (§2.2.6.2),
//! QUERY_FS (§2.2.6.3), QUERY/SET PATH (§2.2.6.5/6), QUERY/SET FILE
//! (§2.2.6.7/8). Information levels per §2.2.8.

use smb_proto::buf::Reader;

/// TRANS2 subcommand codes ([MS-SMB] §2.2.6).
pub mod subcmd {
    /// TRANS2_FIND_FIRST2.
    pub const FIND_FIRST2: u8 = 0x01;
    /// TRANS2_FIND_NEXT2.
    pub const FIND_NEXT2: u8 = 0x02;
    /// TRANS2_QUERY_FS_INFORMATION.
    pub const QUERY_FS_INFO: u8 = 0x03;
    /// TRANS2_SET_FS_INFORMATION.
    pub const SET_FS_INFO: u8 = 0x04;
    /// TRANS2_QUERY_PATH_INFORMATION.
    pub const QUERY_PATH_INFO: u8 = 0x05;
    /// TRANS2_SET_PATH_INFORMATION.
    pub const SET_PATH_INFO: u8 = 0x06;
    /// TRANS2_QUERY_FILE_INFORMATION.
    pub const QUERY_FILE_INFO: u8 = 0x07;
    /// TRANS2_SET_FILE_INFORMATION.
    pub const SET_FILE_INFO: u8 = 0x08;
}

/// Information levels for QUERY/SET operations ([MS-SMB] §2.2.8).
pub mod level {
    /// Basic information (times + attributes).
    pub const BASIC: u16 = 0x004;
    /// Standard information (sizes, links, dir flag).
    pub const STANDARD: u16 = 0x005;
    /// Extended attribute size.
    pub const EA_SIZE: u16 = 0x006;
    /// Stream information.
    pub const STREAMS: u16 = 0x010;
    /// Pass-through `FILE_BASIC_INFORMATION`.
    pub const PT_BASIC: u16 = 0x1004;
    /// Pass-through `FILE_STANDARD_INFORMATION`.
    pub const PT_STANDARD: u16 = 0x1005;
    /// Pass-through `FILE_INTERNAL_INFORMATION`.
    pub const PT_INTERNAL: u16 = 0x1006;
    /// Pass-through `FILE_EA_INFORMATION`.
    pub const PT_EA: u16 = 0x1007;
    /// Pass-through name query.
    pub const PT_NAME: u16 = 0x1009;
    /// Pass-through allocation size.
    pub const PT_ALLOC: u16 = 0x100B;
    /// Pass-through end-of-file.
    pub const PT_EOF: u16 = 0x100C;
    /// Pass-through disposition.
    pub const PT_DISPOSITION: u16 = 0x100D;
    /// Pass-through all-information composite.
    pub const PT_ALL: u16 = 0x1012;
    /// Pass-through alternate name.
    pub const PT_ALT_NAME: u16 = 0x1015;
    /// Client getattr composite (SMB_QUERY_FILE_ATTRIBUTE).
    pub const ATTRIBUTE_COMPOSITE: u16 = 0x107;
}

/// Find information levels ([MS-SMB] §2.2.8.1).
pub mod find_level {
    /// DOS-standard OEM-name entries.
    pub const STANDARD: u16 = 0x001;
    /// Unicode names only.
    pub const DIRECTORY: u16 = 0x102;
    /// Full directory info.
    pub const FULL: u16 = 0x103;
    /// Both directory info (with short name slot).
    pub const BOTH: u16 = 0x104;
    /// Names only.
    pub const NAMES: u16 = 0x105;
}

/// Parsed TRANSACTION2 request envelope: subcommand plus fixed parameters
/// and data sections.
#[derive(Debug)]
pub struct Trans2Req {
    /// Subcommand byte from the start of the parameter buffer, or Setup[0].
    pub subcmd: u8,
    /// Fixed parameter words following the subcommand/pad.
    pub params: Vec<u8>,
    /// Data section contents (clamped to the frame).
    pub data: Vec<u8>,
    /// Absolute frame offset of `params[0]` (parity reference).
    pub param_base: usize,
    /// Absolute frame offset of `data[0]`.
    pub data_base: usize,
    /// Unicode strings requested by the client.
    pub unicode: bool,
}

impl Trans2Req {
    /// Parse the envelope from the request frame body.
    ///
    /// Two client styles are supported:
    /// * SetupCount=0 — subcommand is the first parameter-buffer byte,
    ///   followed by one pad byte and the fixed words.
    /// * SetupCount≥1 — the subcommand rides in `Setup[0]`; the buffer holds
    ///   only the fixed fields (Impacket style).
    pub fn parse(
        wct: u8,
        words: &[u8],
        buf: &[u8],
        bc_off_abs: usize,
        unicode: bool,
    ) -> Option<Trans2Req> {
        if words.len() < 30 {
            return None;
        }
        let g = |i: usize| -> u16 {
            if i + 2 <= words.len() {
                u16::from_le_bytes([words[i], words[i + 1]])
            } else {
                0
            }
        };
        let pcount = g(18) as usize; // vwv9 ParameterCount
        let poff = g(20) as usize; // vwv10 ParameterOffset
        let dcount = g(24) as usize; // vwv12 DataCount
        let doff = g(26) as usize; // vwv13 DataOffset

        if poff > buf.len() || poff + pcount > buf.len() {
            return None;
        }
        let params_all = &buf[poff..poff + pcount];
        if params_all.is_empty() {
            return None;
        }
        let setup_count = *words.get(26)? as usize;
        let (subcmd, fixed, param_base) = if setup_count >= 1 {
            // Impacket style: Setup[0] carries the subcommand.
            let sc = *words.get(28).unwrap_or(&params_all[0]);
            (sc, params_all.to_vec(), poff)
        } else if pcount >= 2 {
            // Classic style: subcommand byte then pad then fixed words.
            (params_all[0], params_all[2..].to_vec(), poff + 2)
        } else {
            return None;
        };

        // Clamp bogus data sections instead of rejecting: request data is
        // only consumed by SET_FILE/PATH handlers which re-check bounds.
        let mut dcount = dcount;
        if doff > buf.len() || doff + dcount > buf.len() {
            dcount = buf.len().saturating_sub(doff).min(dcount);
        }
        let data: Vec<u8> = if dcount > 0 && doff >= HDR_ABS_MIN && doff + dcount <= buf.len() {
            buf[doff..doff + dcount].to_vec()
        } else {
            Vec::new()
        };

        Some(Trans2Req {
            subcmd,
            params: fixed,
            data,
            param_base,
            data_base: doff,
            unicode,
        })
    }
}

/// Minimum bytes before a data section may plausibly begin.
const HDR_ABS_MIN: usize = 32;

/// Build the WC=10 TRANS2 response with even-aligned Param/Data offsets
/// ([MS-CIFS] §2.2.4.46.2 layout used by every subcommand reply).
pub fn trans2_resp(params: Vec<u8>, data: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    const WORDS_BYTES: usize = 20;
    const BC_START: usize = 32 + 1 + WORDS_BYTES + 2; // 55

    let plen = params.len();
    let dlen = data.len();
    let poff = if plen > 0 { (BC_START + 1) & !1 } else { 0 };
    let raw_doff = if plen > 0 { poff + plen } else { BC_START };
    let doff = if dlen > 0 { (raw_doff + 1) & !1 } else { 0 };

    let mut p = Vec::with_capacity(WORDS_BYTES);
    p.extend_from_slice(&(plen as u16).to_le_bytes()); // TotalParameterCount
    p.extend_from_slice(&(dlen as u16).to_le_bytes()); // TotalDataCount
    p.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    p.extend_from_slice(&(plen as u16).to_le_bytes()); // ParameterCount
    p.extend_from_slice(&(poff as u16).to_le_bytes()); // ParameterOffset
    p.extend_from_slice(&0u16.to_le_bytes()); // ParameterDisplacement
    p.extend_from_slice(&(dlen as u16).to_le_bytes()); // DataCount
    p.extend_from_slice(&(doff as u16).to_le_bytes()); // DataOffset
    p.extend_from_slice(&0u16.to_le_bytes()); // DataDisplacement
    p.push(0); // SetupCount
    p.push(0); // Reserved

    debug_assert_eq!(p.len(), WORDS_BYTES);

    let mut bytes = Vec::new();
    if plen > 0 {
        bytes.resize(poff - BC_START, 0);
        bytes.extend_from_slice(&params);
    }
    if dlen > 0 {
        bytes.resize(doff - BC_START, 0);
        bytes.extend_from_slice(&data);
    }
    (p, bytes)
}

/// Read a NUL-terminated string out of the fixed-parameters area at `pos`,
/// using `param_base` as parity base.
pub fn read_param_zstring<'a>(
    rd: &mut Reader<'a>,
    pos: usize,
    param_base: usize,
    unicode: bool,
) -> String {
    rd.zstring(unicode, param_base)
}

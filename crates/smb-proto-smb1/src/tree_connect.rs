//! `SMB_COM_TREE_CONNECT_ANDX` (§2.2.4.7) and `TREE_DISCONNECT` (0x71).

use smb_proto::buf::Reader;

use crate::session_setup::BodyError;

/// Parsed tree connect request (WC=4: AndX triple, Flags, PasswordLength).
#[derive(Debug)]
pub struct TreeConnectReq {
    /// UNC path (`\\server\share`).
    pub path: String,
    /// Service string (`A:`, `IPC`, `?????`, …).
    pub service: String,
}

impl TreeConnectReq {
    /// Parse from words/data. `data_base` is the absolute frame offset of
    /// `data[0]` for Unicode parity.
    pub fn parse(
        words: &[u8],
        data: &[u8],
        unicode: bool,
        data_base: usize,
    ) -> Result<Self, BodyError> {
        use super::session_setup::BodyError;
        if words.len() < 8 || data.is_empty() {
            return Err(BodyError::TooShort);
        }
        let pw_len = u16le(words, 6) as usize;
        if pw_len > data.len() {
            return Err(BodyError::BadBlob);
        }
        let mut rd = Reader::new(data, pw_len);
        let base = data_base + pw_len;
        let path = rd.zstring(unicode, base);
        let service = rd.zstring(false, base + rd.pos());
        Ok(Self { path, service })
    }
}

fn u16le(w: &[u8], off: usize) -> u16 {
    w.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Build the WC=4 response (AndX triple + OptionalSupport) with the service
/// and native-filesystem strings in the buffer.
pub fn build_response(
    optional_support: u16,
    service: &str,
    native_fs: &str,
    unicode: bool,
    params_base_abs: usize,
) -> (Vec<u8>, Vec<u8>) {
    let mut params = Vec::with_capacity(8);
    params.push(0xFF);
    params.push(0);
    params.extend_from_slice(&0u16.to_le_bytes());
    params.extend_from_slice(&optional_support.to_le_bytes());

    let bytes_start_abs = params_base_abs;
    let mut bytes = Vec::new();
    // Service string is always ASCII.
    bytes.extend_from_slice(service.as_bytes());
    bytes.push(0);
    while (bytes_start_abs + bytes.len()) & 1 != 0 && unicode {
        bytes.push(0);
    }
    if unicode {
        for u in native_fs.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0]);
    } else {
        bytes.extend_from_slice(native_fs.as_bytes());
        bytes.push(0);
    }
    (params, bytes)
}

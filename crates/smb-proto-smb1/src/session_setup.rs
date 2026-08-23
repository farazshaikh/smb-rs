//! `SMB_COM_SESSION_SETUP_ANDX` ([MS-SMB] §2.2.4.6).
//!
//! Two request shapes exist on this command:
//! * **WC=13** — legacy non-extended security (password blobs + account).
//! * **WC=12** — extended security ([MS-NLMP] via SPNEGO): the buffer holds
//!   an opaque `SecurityBlob` instead of passwords.

use smb_proto::buf::Reader;

/// Parse error for body decoders.
#[derive(Debug)]
pub enum BodyError {
    /// Word/parameter block too small for the command.
    TooShort,
    /// Password/blob length exceeded the available buffer.
    BadBlob,
}

fn u16le(w: &[u8], off: usize) -> u16 {
    w.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Parsed legacy (WC=13) session setup request.
#[derive(Debug)]
pub struct SessionSetupLegacyReq {
    /// Case-insensitive (LM) password response bytes.
    pub lm_resp: Vec<u8>,
    /// Case-sensitive (NTLM/NTLMv2) response bytes.
    pub nt_resp: Vec<u8>,
    /// Requested account name.
    pub account: String,
    /// Client primary domain string.
    pub domain: String,
}

impl SessionSetupLegacyReq {
    /// Parse WC=13 words: CIPLen@14, CSPLen@16, Capabilities@22.
    pub fn parse(
        words: &[u8],
        data: &[u8],
        unicode: bool,
        data_base: usize,
    ) -> Result<Self, BodyError> {
        if words.len() < 26 || data.len() < 2 {
            return Err(BodyError::TooShort);
        }
        let cip = u16le(words, 14) as usize;
        let csp = u16le(words, 16) as usize;
        if cip.checked_add(csp).map(|t| t > data.len()).unwrap_or(true) {
            return Err(BodyError::BadBlob);
        }
        let lm_resp = data[..cip].to_vec();
        let nt_resp = data[cip..cip + csp].to_vec();

        let mut rd = Reader::new(data, cip + csp);
        let account = rd.zstring(unicode, data_base);
        let domain = rd.zstring(unicode, data_base);
        Ok(Self { lm_resp, nt_resp, account, domain })
    }
}

/// Parsed extended (WC=12) session setup request: opaque security blob.
#[derive(Debug)]
pub struct SessionSetupExtReq {
    /// SPNEGO/NTLMSSP token bytes.
    pub blob: Vec<u8>,
}

impl SessionSetupExtReq {
    /// Parse WC=12 words: SecurityBlobLength @vwv7 (bytes 14–15).
    pub fn parse(words: &[u8], data: &[u8]) -> Result<Self, BodyError> {
        if words.len() < 16 || data.is_empty() {
            return Err(BodyError::TooShort);
        }
        let blen = u16le(words, 14) as usize;
        if blen == 0 || blen > data.len() {
            return Err(BodyError::BadBlob);
        }
        Ok(SessionSetupExtReq { blob: data[..blen].to_vec() })
    }
}

/// Build a WC=4 session setup response (blob + OEM strings).
pub fn build_session_setup_response(action: u16, blob: &[u8]) -> (Vec<u8>, Vec<u8>) {
    build_response(action, blob)
}

/// Build a WC=4 session setup response: AndX triple, Action word,
/// SecurityBlobLength word, then `[blob][NativeOS][NativeLanMan]` data.
///
/// Trailing strings are always OEM (some clients mis-parse UTF-16 here).
pub fn build_response(action: u16, blob: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut params = Vec::with_capacity(8);
    params.push(0xFF); // terminal AndX
    params.push(0);
    params.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    params.extend_from_slice(&action.to_le_bytes()); // Action
    params.extend_from_slice(&(blob.len() as u16).to_le_bytes());

    let mut bytes = Vec::with_capacity(blob.len() + 18);
    bytes.extend_from_slice(blob);
    bytes.extend_from_slice(b"rustsmb\0rustsmb\0");
    (params, bytes)
}

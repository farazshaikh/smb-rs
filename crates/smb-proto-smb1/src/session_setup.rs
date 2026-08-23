//! `SMB_COM_SESSION_SETUP_ANDX` ([MS-SMB] §2.2.4.6).

use smb_proto::buf::Reader;

/// Parse error for body decoders.
#[derive(Debug)]
pub enum BodyError {
    /// Word/parameter block too small for the command.
    TooShort,
    /// Password blob exceeded the available buffer.
    BadBlob,
}

fn u16le(w: &[u8], off: usize) -> u16 {
    w.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Non-extended session setup request (WC=13, §2.2.4.6.1).
#[derive(Debug)]
pub struct SessionSetupReq {
    /// Case-insensitive (LM) password response bytes.
    pub lm_resp: Vec<u8>,
    /// Case-sensitive (NTLM/NTLMv2) response bytes — variable length for v2.
    pub nt_resp: Vec<u8>,
    /// Requested account name.
    pub account: String,
    /// Client primary domain string.
    pub domain: String,
}

impl SessionSetupReq {
    /// Parse from words/data. `data_base` is the absolute frame offset of
    /// `data[0]` so Unicode parity is computed correctly.
    pub fn parse(
        words: &[u8],
        data: &[u8],
        unicode: bool,
        data_base: usize,
    ) -> Result<Self, BodyError> {
        if words.len() < 24 || data.len() < 2 {
            return Err(BodyError::TooShort);
        }
        let cip = u16le(words, 14) as usize;
        let csp = u16le(words, 16) as usize;
        if cip + csp > data.len() {
            return Err(BodyError::BadBlob);
        }
        let lm_resp = data[..cip].to_vec();
        let nt_resp = data[cip..cip + csp].to_vec();

        let mut rd = Reader::new(data, cip + csp);
        let account = rd.zstring(unicode, data_base);
        let domain = rd.zstring(unicode, data_base);
        Ok(Self { lm_resp, nt_resp, account, domain })
    }

    /// Build the WC=4 response: AndX triple, Action word, blob length word,
    /// followed by OEM `NativeOS`/`NativeLanMan` strings in the data block
    /// (OEM always — some clients mis-parse UTF-16 here).
    pub fn build_response(action: u16, blob: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut params = Vec::with_capacity(8);
        params.push(0xFF); // terminal AndX
        params.push(0);
        params.extend_from_slice(&0u16.to_le_bytes());
        params.extend_from_slice(&action.to_le_bytes());
        params.extend_from_slice(&(blob.len() as u16).to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(blob);
        bytes.extend_from_slice(b"rustsmb\0rustsmb\0");
        (params, bytes)
    }
}

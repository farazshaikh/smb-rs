//! Minimal NTLMSSP ([MS-NLMP]) message construction/parsing plus the SPNEGO
//! DER wrapping used during extended-security session setup.
//!
//! Both SMB1 (`SESSION_SETUP_ANDX` with `CAP_EXTENDED_SECURITY`) and SMB2
//! session setup speak this exact dialect of tokens, so the module is
//! shared between protocol implementations.

/// Wire signature every NTLMSSP message begins with.
pub const NTLMSSP_SIG: &[u8; 8] = b"NTLMSSP\0";

/// NEGOTIATE message identifier.
pub const MSG_TYPE1: u32 = 1;
/// CHALLENGE message identifier.
pub const MSG_TYPE2: u32 = 2;
/// AUTHENTICATE message identifier.
pub const MSG_TYPE3: u32 = 3;

/// Request/response Unicode strings.
pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
/// Server must include a target name in the CHALLENGE.
pub const REQUEST_TARGET: u32 = 0x0000_0004;
/// NTLM authentication (as opposed to LM-only).
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
/// Client requests anonymous authentication.
pub const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
/// Domain name supplied by the client.
pub const NEGOTIATE_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
/// Always sign messages.
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
/// Extended session security (NTLM2).
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
/// Target info AV pairs are present.
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
/// 128-bit crypto strength requested.
pub const NEGOTIATE_128: u32 = 0x2000_0000;
/// Version structure present.
pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
/// Target type is a domain.
pub const TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;
/// Message signing is supported.
pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;

/// Sealing (encryption) is supported.
pub const NEGOTIATE_SEAL: u32 = 0x0000_0020;

/// Key exchange negotiated ([MS-NLMP] §2.2.2.5): the AUTHENTICATE
/// message carries an RC4-encrypted RandomSessionKey.
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;

/// Parsed AUTHENTICATE (type 3) message.
#[derive(Debug, Default)]
pub struct Type3 {
    /// Account name supplied by the client.
    pub user: String,
    /// Authentication target domain.
    pub domain: String,
    /// Client workstation name.
    pub workstation: String,
    /// LM response bytes (may be empty for NTLMv2-only clients).
    pub lm_response: Vec<u8>,
    /// NTLM/NTLMv2 response bytes (proof + blob for v2).
    pub ntlm_response: Vec<u8>,
    /// Encrypted random session key (present with NEGOTIATE_KEY_EXCH).
    pub encrypted_session_key: Vec<u8>,
    /// Flags echoed by the client in the type 3 message.
    pub flags: u32,
}

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
fn rd_u32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
fn rd_u16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Find `needle` inside `haystack`, returning its offset.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract the inner NTLMSSP message from a possibly-SPNEGO-wrapped blob:
/// returns the slice starting at the `"NTLMSSP\0"` marker, when present.
pub fn unwrap_blob(blob: &[u8]) -> Option<&[u8]> {
    find(blob, NTLMSSP_SIG).map(|pos| &blob[pos..])
}

/// True when the blob looks like DER/SPNEGO (starts with ASN.1 tags) rather
/// than a raw NTLMSSP message.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
pub fn is_spnego(blob: &[u8]) -> bool {
    matches!(blob.first(), Some(0x60) | Some(0xA1)) || (blob.len() > 1 && blob[0] == 0x06)
}

/// Identify an NTLMSSP message type (1/2/3), if the buffer is one.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
pub fn msg_type(blob: &[u8]) -> Option<u32> {
    if blob.len() < 12 || &blob[..8] != NTLMSSP_SIG {
        return None;
    }
    Some(rd_u32(blob, 8))
}

/// Build an NTLMSSP CHALLENGE (type 2) message carrying our `challenge`,
/// target `domain`/`hostname` and a complete TargetInfo AV list.
///
/// The layout follows [MS-NLMP] §2.2.1.2 including the `Version` field
/// (NEGOTIATE_VERSION is always granted here, matching what Windows sends).
/// Build an NTLMSSP CHALLENGE (Type 2) message ([MS-NLMP] §2.2.1.2 fixed layout).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
pub fn build_type2(challenge: &[u8; 8], domain: &str, hostname: &str) -> Vec<u8> {
    // TargetInfo AV pairs — required input for client-side NTLMv2.
    let mut ti = Vec::new();
    {
        let mut put_av = |ti: &mut Vec<u8>, typ: u16, val: &[u16]| {
            ti.extend_from_slice(&typ.to_le_bytes());
            ti.extend_from_slice(&((val.len() * 2) as u16).to_le_bytes());
            for u in val {
                ti.extend_from_slice(&u.to_le_bytes());
            }
        };
        put_av(&mut ti, 0x0001, &domain.encode_utf16().collect::<Vec<_>>()); // NbDomainName
        put_av(&mut ti, 0x0002, &hostname.encode_utf16().collect::<Vec<_>>()); // NbComputerName
        put_av(&mut ti, 0x0003, &domain.encode_utf16().collect::<Vec<_>>()); // DnsDomainName
        put_av(&mut ti, 0x0004, &hostname.encode_utf16().collect::<Vec<_>>()); // DnsComputerName
        // MsvAvTimestamp: current FILETIME split into four LE u16 units.
        let now = smb_server_proto::types::FileTime::now().0;
        let ts: [u16; 4] = [
            (now & 0xffff) as u16,
            ((now >> 16) & 0xffff) as u16,
            ((now >> 32) & 0xffff) as u16,
            ((now >> 48) & 0xffff) as u16,
        ];
        put_av(&mut ti, 0x0007, &ts);
           // MsvAvEOL is a full AV_PAIR: type=0 AND length=0.
        ti.extend_from_slice(&[0u8; 4]);
    }

    let dom_utf16: Vec<u8> = domain.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

    let mut flags = NEGOTIATE_UNICODE
        | REQUEST_TARGET
        | NEGOTIATE_NTLM
        | NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NEGOTIATE_TARGET_INFO
        | TARGET_TYPE_DOMAIN
        | NEGOTIATE_128;
    // Extra grants/clears for interop testing ("-0x8" clears a bit).
    if let Ok(extra) = std::env::var("RUSTSMB_T2_FLAGS") {
        for part in extra.split(',') {
            let part = part.trim();
            if let Some(neg) = part.strip_prefix('-') {
                if let Ok(v) = u32::from_str_radix(neg.trim_start_matches("0x"), 16) {
                    flags &= !v;
                }
            } else if let Ok(v) = u32::from_str_radix(part.trim_start_matches("0x"), 16) {
                flags |= v;
            }
        }
    }
    flags |= NEGOTIATE_VERSION;

    const PAYLOAD_BASE: usize = 56; // fixed header + 8-byte Version

    let mut m = Vec::with_capacity(PAYLOAD_BASE + dom_utf16.len() + ti.len());
    m.extend_from_slice(NTLMSSP_SIG);
    m.extend_from_slice(&MSG_TYPE2.to_le_bytes());
    m.extend_from_slice(&(dom_utf16.len() as u16).to_le_bytes()); // len
    m.extend_from_slice(&(dom_utf16.len() as u16).to_le_bytes()); // max len
    m.extend_from_slice(&(PAYLOAD_BASE as u32).to_le_bytes()); // offset
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(challenge);
    m.extend_from_slice(&[0u8; 8]); // reserved
    m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
    m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
    m.extend_from_slice(&((PAYLOAD_BASE + dom_utf16.len()) as u32).to_le_bytes());
    // Version: Windows 10.0 build 14393, NTLM revision 15.
    m.extend_from_slice(&[0x0a, 0x00, 0xf9, 0x38, 0x00, 0x00, 0x00, 0x0f]);
    m.extend_from_slice(&dom_utf16);
    m.extend_from_slice(&ti);
    m
}

/// Session key field ([MS-NLMP] §2.2.1.3): len @52, max @54, offset @56.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
pub fn parse_type3_session_key(blob: &[u8]) -> Vec<u8> {
    let len = rd_u16(blob, 52) as usize;
    let off = rd_u32(blob, 56) as usize;
    if len == 0 || off + len > blob.len() {
        return Vec::new();
    }
    blob[off..off + len].to_vec()
}

/// Parse an NTLMSSP AUTHENTICATE (type 3) message per [MS-NLMP] §2.2.1.3.
/// Parse an NTLMSSP AUTHENTICATE (Type 3) message ([MS-NLMP] §2.2.1.3 fixed layout).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
pub fn parse_type3(blob: &[u8]) -> Option<Type3> {
    if blob.len() < 32 || msg_type(blob) != Some(MSG_TYPE3) {
        return None;
    }
    let field = |len_off: usize, off_off: usize| -> Vec<u8> {
        let len = rd_u16(blob, len_off) as usize;
        let off = rd_u32(blob, off_off) as usize;
        if len == 0 || off + len > blob.len() {
            return Vec::new();
        }
        blob[off..off + len].to_vec()
    };
    let utf16 = |b: &[u8]| -> String {
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
            .collect();
        String::from_utf16_lossy(&units)
    };
    Some(Type3 {
        lm_response: field(12, 16),
        ntlm_response: field(20, 24),
        domain: utf16(&field(28, 32)),
        user: utf16(&field(36, 40)),
        workstation: utf16(&field(44, 48)),
        encrypted_session_key: parse_type3_session_key(blob),
        flags: rd_u32(blob, 60),
    })
}

// ---------------- Minimal DER/SPNEGO helpers ----------------

/// Encode an ASN.1 DER length ([X.690] §8.1.3): short form < 128, else long form.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))]
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Wrap an NTLMSSP token in a SPNEGO NegTokenTarg declaring
/// `negResult = accept-incomplete` and `supportedMech = NTLMSSP`.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SPNEGO negTokenTarg DER
pub fn wrap_negtoken_targ(token: &[u8]) -> Vec<u8> {
    let result = der_tlv(0xA0, &der_tlv(0x0A, &[0x01]));
    let oid_bytes = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]; // 1.3.6.1.4.1.311.2.2.10
    let mech = der_tlv(0xA1, &der_tlv(0x06, &oid_bytes));
    let resp = der_tlv(0xA2, &der_tlv(0x04, token));
    let mut seq_content = result;
    seq_content.extend_from_slice(&mech);
    seq_content.extend_from_slice(&resp);
    der_tlv(0xA1, &der_tlv(0x30, &seq_content))
}

/// SPNEGO NegTokenTarg carrying only `negResult = accept-completed`.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SPNEGO negTokenTarg DER
pub fn wrap_accept_complete() -> Vec<u8> {
    let result = der_tlv(0xA0, &der_tlv(0x0A, &[0x00]));
    der_tlv(0xA1, &der_tlv(0x30, &result))
}

/// SPNEGO NegTokenResp with `accept-completed` plus a mechListMIC
/// ([RFC 4178] §4.2.2): the client validates it against the exported
/// session key whenever it sent a MIC in its AUTHENTICATE message.
///
/// `mic` is HMAC-MD5(ExportedSessionKey, init || targ || auth) computed by
/// the caller over the exact exchanged SPNEGO blobs.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SPNEGO negTokenTarg DER
pub fn wrap_accept_complete_with_mic(mic: &[u8]) -> Vec<u8> {
    let result = der_tlv(0xA0, &der_tlv(0x0A, &[0x00]));
    let mic_field = der_tlv(0xA3, &der_tlv(0x04, mic));
    let mut seq = result;
    seq.extend_from_slice(&mic_field);
    der_tlv(0xA1, &der_tlv(0x30, &seq))
}

// Minimal NTLMSSP ([MS-NLMP]) message construction/parsing for
// extended-security session setup.

pub const NTLMSSP_SIG: &[u8; 8] = b"NTLMSSP\0";
pub const MSG_TYPE1: u32 = 1;
pub const MSG_TYPE2: u32 = 2;
pub const MSG_TYPE3: u32 = 3;

// Negotiate flags we care about.
pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub const NTLMSSP_NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
pub const NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
pub const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
pub const NTLMSSP_NEGOTIATE_KEY_EXCHANGE: u32 = 0x4000_0000;
pub const NTLMSSP_TARGET_TYPE_DOMAIN: u32 = 0x0001_0000;

#[derive(Debug, Default)]
pub struct Type3 {
    pub user: String,
    pub domain: String,
    pub workstation: String,
    pub lm_response: Vec<u8>,
    pub ntlm_response: Vec<u8>,
    pub flags: u32,
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    if off + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    if off + 2 > b.len() {
        return 0;
    }
    u16::from_le_bytes(b[off..off + 2].try_into().unwrap())
}

/// Extract the inner NTLMSSP message from a possibly-SPNEGO-wrapped blob.
pub fn unwrap_blob(blob: &[u8]) -> Option<&[u8]> {
    if let Some(pos) = find(blob, NTLMSSP_SIG) {
        return Some(&blob[pos..]);
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

pub fn msg_type(blob: &[u8]) -> Option<u32> {
    if blob.len() < 12 || &blob[..8] != NTLMSSP_SIG {
        return None;
    }
    Some(rd_u32(blob, 8))
}

/// Build an NTLMSSP CHALLENGE (type 2) message.
pub fn build_type2(challenge: &[u8; 8], domain: &str, hostname: &str) -> Vec<u8> {
    // TargetInfo AV pairs (required for NTLMv2).
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
        // MsvAvTimestamp (av7) like real servers
        ti.extend_from_slice(&0x0007u16.to_le_bytes());
        ti.extend_from_slice(&8u16.to_le_bytes());
        let now = crate::smb::now_filetime();
        ti.extend_from_slice(&now.to_le_bytes());
        // MsvAvEOL is a full AV_PAIR: type=0 AND length=0 (4 bytes).
        ti.extend_from_slice(&0u16.to_le_bytes());
        ti.extend_from_slice(&0u16.to_le_bytes());
    }

    let dom_utf16: Vec<u8> = domain
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();

    let mut flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_NTLM
        | 0x0008_0000 // EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_TARGET_TYPE_DOMAIN
        | NTLMSSP_NEGOTIATE_128;

    // Optional grants/clears for interop testing ("-0x8" clears a bit).
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
    if std::env::var("RUSTSMB_NO_VERSION_FLAG").is_ok() {
        flags &= !0x0200_0000;
    }

    // NEGOTIATE_VERSION -> include the 8-byte Version struct (payload +8).
    let with_version = std::env::var("RUSTSMB_NO_VERSION").is_err();
    if with_version {
        flags |= 0x0200_0000;
    }
    const BASE_NO_VERSION: usize = 48;
    let payload_base = BASE_NO_VERSION + if with_version { 8 } else { 0 };

    let mut m = Vec::with_capacity(payload_base + dom_utf16.len() + ti.len());
    m.extend_from_slice(NTLMSSP_SIG); // sig
    m.extend_from_slice(&MSG_TYPE2.to_le_bytes());
    m.extend_from_slice(&(dom_utf16.len() as u16).to_le_bytes());
    m.extend_from_slice(&(dom_utf16.len() as u16).to_le_bytes());
    m.extend_from_slice(&(payload_base as u32).to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(challenge);
    m.extend_from_slice(&[0u8; 8]); // reserved
    m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
    m.extend_from_slice(&(ti.len() as u16).to_le_bytes());
    m.extend_from_slice(&((payload_base + dom_utf16.len()) as u32).to_le_bytes());
    if with_version {
        // Windows 10.0 build 14393
        m.extend_from_slice(&[0x0a, 0x00, 0xf9, 0x38, 0x00, 0x00, 0x00, 0x0f]);
    }
    m.extend_from_slice(&dom_utf16);
    m.extend_from_slice(&ti);
    debug_assert_eq!(m.len(), payload_base + dom_utf16.len() + ti.len());
    m
}

/// Parse an NTLMSSP AUTHENTICATE (type 3) message.
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
    let t = Type3 {
        lm_response: field(12, 16),
        ntlm_response: field(20, 24),
        domain: utf16(&field(28, 32)),
        user: utf16(&field(36, 40)),
        workstation: utf16(&field(44, 48)),
        flags: rd_u32(blob, 60),
    };
    Some(t)
}

// ---------------- Minimal DER/SPNEGO helpers ----------------

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

/// Wrap an NTLMSSP token in a SPNEGO NegTokenTarg ([1] resp-token),
/// declaring negResult=accept-incomplete and supportedMech=NTLMSSP.
pub fn wrap_negtoken_targ(token: &[u8]) -> Vec<u8> {
    // negResult [0] ENUMERATED accept-incomplete (1)
    let result = der_tlv(0xA0, &der_tlv(0x0A, &[0x01]));
    // supportedMech [1] OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
    let oid_bytes = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
    let mech = der_tlv(0xA1, &der_tlv(0x06, &oid_bytes));
    // responseToken [2] OCTET STRING
    let resp = der_tlv(0xA2, &der_tlv(0x04, token));
    let mut seq_content = result;
    seq_content.extend_from_slice(&mech);
    seq_content.extend_from_slice(&resp);
    der_tlv(0xA1, &der_tlv(0x30, &seq_content))
}

/// Is this blob SPNEGO-wrapped (starts with ASN.1 application/constructed)?
pub fn is_spnego(blob: &[u8]) -> bool {
    matches!(blob.first(), Some(0x60) | Some(0xA1)) ||
        (blob.len() > 1 && blob[0] == 0x06)
}

/// SPNEGO NegTokenTarg with negResult=accept-completed (no token).
pub fn wrap_accept_complete() -> Vec<u8> {
    let result = der_tlv(0xA0, &der_tlv(0x0A, &[0x00]));
    der_tlv(0xA1, &der_tlv(0x30, &result))
}

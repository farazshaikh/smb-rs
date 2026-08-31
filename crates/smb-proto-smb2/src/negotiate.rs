//! NEGOTIATE ([MS-SMB2] §2.2.3).

/// Dialect numbers (§2.2.3.1.1).
/// SMB 2.0.2 dialect revision.
pub const DIALECT_202: u16 = 0x0202;
/// SMB 2.1.0 dialect revision.
pub const DIALECT_210: u16 = 0x0210;
/// SMB 3.0 dialect revision.
pub const DIALECT_300: u16 = 0x0300;
/// SMB 3.0.2 dialect revision.
pub const DIALECT_302: u16 = 0x0302;
/// SMB 3.1.1 dialect revision.
pub const DIALECT_311: u16 = 0x0311;
/// Wildcard revision returned to a multi-protocol "SMB 2.???" offer
/// ([MS-SMB2] §2.2.4); the client then sends a real SMB2 NEGOTIATE.
pub const DIALECT_WILDCARD: u16 = 0x02FF;

/// SecurityMode bits (§2.2.3.1.1).
/// Signing is supported but not required.
pub const SIGNING_ENABLED: u16 = 0x0001;
/// Signing is required by the server.
pub const SIGNING_REQUIRED: u16 = 0x0002;

/// Capability bits (§2.2.3.2.5).
pub mod caps {
    /// Leasing (file leases) — available from dialect 2.1.
    pub const LEASING: u32 = 0x0000_0002;
    /// Large MTU — multi-credit transfers.
    pub const LARGE_MTU: u32 = 0x0000_0004;
    /// Multiple channels for one session (multichannel).
    pub const MULTI_CHANNEL: u32 = 0x0000_0008;
    /// Persistent handles (continuous availability).
    pub const PERSISTENT_HANDLES: u32 = 0x0000_0010;
    /// Directory leasing.
    pub const DIRECTORY_LEASING: u32 = 0x0000_0020;
    /// Encryption (dialects 3.0/3.0.2; 3.1.1 negotiates via context).
    pub const ENCRYPTION: u32 = 0x0000_0040;
}

/// Negotiate context types (§2.2.3.1.2).
pub mod ctx_type {
    /// PREAUTH_INTEGRITY_CAPABILITIES.
    pub const PREAUTH_INTEGRITY: u16 = 0x0001;
    /// ENCRYPTION_CAPABILITIES.
    pub const ENCRYPTION: u16 = 0x0002;
    /// COMPRESSION_CAPABILITIES.
    pub const COMPRESSION: u16 = 0x0003;
    /// SIGNING_CAPABILITIES.
    pub const SIGNING: u16 = 0x0008;
    /// SIGNING_ALGORITHM values: AES-128-CMAC.
    pub const SIGNING_AES128_CMAC: u16 = 0x0001;
    /// HASH_ALGORITHMS values: SHA-512.
    pub const SHA512: u16 = 0x0001;
    /// CIPHER values: AES-128-CCM.
    pub const AES128_CCM: u16 = 0x0001;
    /// CIPHER values: AES-128-GCM.
    pub const AES128_GCM: u16 = 0x0002;
}

/// One parsed negotiate context.
#[derive(Debug, Clone)]
pub struct Context {
    /// ContextType.
    pub kind: u16,
    /// Raw data payload (already stripped of padding).
    pub data: Vec<u8>,
}

/// Parsed SMB2 NEGOTIATE request.
#[derive(Debug)]
pub struct Request {
    /// Dialect numbers offered by the client.
    pub dialects: Vec<u16>,
    /// Client GUID.
    pub client_guid: [u8; 16],
    /// Negotiate contexts (3.1.1 only; empty otherwise).
    pub contexts: Vec<Context>,
}

impl Request {
    /// Parse from the request body (bytes after the 64-byte header).
    ///
    /// Two layouts exist ([MS-SMB2] §2.2.3.1): pre-3.1.1 clients place the
    /// dialect array directly after the fixed part (offset 28); 3.1.1-aware
    /// clients interpose NegotiateContextOffset/Count fields so dialects
    /// begin at offset 36. We accept either by validating candidates
    /// against the set of known dialect revisions.
    pub fn parse(b: &[u8]) -> Option<Request> {
        const KNOWN: &[u16] = &[0x0202, 0x0210, 0x0300, 0x0302, 0x0310, 0x0311];
        if b.len() < 28 || u16::from_le_bytes([b[0], b[1]]) != 36 {
            return None;
        }
        let dcount = u16::from_le_bytes([b[2], b[3]]) as usize;
        if dcount == 0 || dcount > 64 {
            return None;
        }
        let mut guid = [0u8; 16];
        guid.copy_from_slice(b.get(12..28)?);

        let read_dialects = |start: usize| -> Option<Vec<u16>> {
            if b.len() < start + dcount * 2 {
                return None;
            }
            let v: Vec<u16> = b[start..]
                .chunks_exact(2)
                .take(dcount)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            // Only accept when every entry is a real dialect revision.
            (v.iter().all(|d| KNOWN.contains(d))).then_some(v)
        };

        let dialects = read_dialects(28)
            .or_else(|| read_dialects(36))
            .or_else(|| read_dialects(44))?;

        // Contexts ride behind the dialect array when the 3.1.1 layout was
        // used: NegotiateContextOffset/Count replace ClientStartTime.
        let mut contexts = Vec::new();
        if b.len() >= 36 {
            let ctx_off = u32::from_le_bytes(b[28..32].try_into().unwrap()) as usize;
            let ctx_count = u16::from_le_bytes([b[32], b[33]]) as usize;
            if ctx_off >= 64 && ctx_count > 0 && ctx_off <= 64 + b.len() {
                let base = ctx_off - 64; // body-relative
                let mut p = base;
                for _ in 0..ctx_count.min(64) {
                    let Some(hdr) = b.get(p..p + 8) else { break };
                    let kind = u16::from_le_bytes([hdr[0], hdr[1]]);
                    let dlen = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
                    let Some(data) = b.get(p + 8..p + 8 + dlen) else { break };
                    contexts.push(Context { kind, data: data.to_vec() });
                    // Contexts are 8-byte aligned.
                    p += 8 + ((dlen + 7) & !7usize);
                }
            }
        }

        Some(Request { dialects, client_guid: guid, contexts })
    }
}

/// Pick the highest supported dialect.
pub fn pick(dialects: &[u16]) -> Option<u16> {
    let mut best = None;
    for &d in dialects {
        if matches!(d, DIALECT_202 | DIALECT_210 | DIALECT_300 | DIALECT_302 | DIALECT_311) {
            best = Some(best.map_or(d, |b: u16| b.max(d)));
        }
    }
    best
}

/// Build the NEGOTIATE response body (§2.2.3.1) — no security blob
/// (clients initiate NTLMSSP in SESSION_SETUP).
///
/// For dialect 3.1.1 the response carries negotiate contexts
/// ([MS-SMB2] §2.2.3.1.1): PREAUTH_INTEGRITY_CAPABILITIES announcing
/// SHA-512 with a random salt.
#[allow(clippy::too_many_arguments)]
pub fn build_response_full(
    dialect: u16,
    guid: &[u8; 16],
    now: u64,
    salt: &[u8; 32],
    encryption: Option<u16>,
    offer_signing: bool,
    compression: &[u16],
    require_signing: bool,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    let sec_mode = SIGNING_ENABLED | if require_signing { SIGNING_REQUIRED } else { 0 };
    b.extend_from_slice(&sec_mode.to_le_bytes()); // SecurityMode
    b.extend_from_slice(&dialect.to_le_bytes());
    if dialect == DIALECT_311 {
        // Echo only the contexts the client offered ([MS-SMB2] §3.3.5.4);
        // PREAUTH is mandatory, the rest are conditional.
        let count = 1
            + u16::from(offer_signing)
            + u16::from(encryption.is_some())
            + u16::from(!compression.is_empty());
        b.extend_from_slice(&count.to_le_bytes()); // NegotiateContextCount
    } else {
        b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    }
    b.extend_from_slice(guid); // ServerGuid
    let caps = if dialect >= DIALECT_300 {
        caps::LARGE_MTU | caps::MULTI_CHANNEL | caps::LEASING
    } else if dialect >= DIALECT_210 {
        caps::LARGE_MTU | caps::LEASING
    } else {
        0
    };
    b.extend_from_slice(&caps.to_le_bytes()); // Capabilities
    b.extend_from_slice(&(1024 * 1024u32).to_le_bytes()); // MaxTransactionSize
    b.extend_from_slice(&(1024 * 1024u32).to_le_bytes()); // MaxReadSize
    b.extend_from_slice(&(1024 * 1024u32).to_le_bytes()); // MaxWriteSize
    b.extend_from_slice(&now.to_le_bytes()); // SystemTime
    b.extend_from_slice(&now.to_le_bytes()); // ServerStartTime
    // Empty security buffer: the offset points just past the fixed part
    // (header 64 + padded body 64 = 128); clients validate this arithmetic.
    b.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength
    b.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset slot

    let mut ctx = Vec::new();
    if dialect == DIALECT_311 {
        let mut push_ctx = |ctx: &mut Vec<u8>, kind: u16, data: &[u8]| {
            // Each context begins 8-byte aligned; pad BEFORE it, never after,
            // so no trailing pad follows the final context. Clients (and the
            // MS-SMB2 test SDK) recompute the pre-auth hash over the canonical
            // unpadded tail, so a spurious trailing pad breaks 3.1.1 signing
            // and encryption key derivation ([MS-SMB2] §3.3.4.1 / §3.3.5.4).
            while ctx.len() % 8 != 0 {
                ctx.push(0);
            }
            ctx.extend_from_slice(&kind.to_le_bytes());
            ctx.extend_from_slice(&(data.len() as u16).to_le_bytes());
            ctx.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            ctx.extend_from_slice(data);
        };

        // PREAUTH_INTEGRITY_CAPABILITIES: SHA-512 + our salt.
        let mut preauth = Vec::new();
        preauth.extend_from_slice(&1u16.to_le_bytes()); // HashAlgorithmCount
        preauth.extend_from_slice(&(salt.len() as u16).to_le_bytes());
        preauth.extend_from_slice(&ctx_type::SHA512.to_le_bytes());
        preauth.extend_from_slice(salt);
        push_ctx(&mut ctx, ctx_type::PREAUTH_INTEGRITY, &preauth);

        // SIGNING_CAPABILITIES: AES-128-CMAC — only when the client offered
        // a SIGNING_CAPABILITIES context ([MS-SMB2] §3.3.5.4).
        if offer_signing {
            let signing = [1u16.to_le_bytes(), ctx_type::SIGNING_AES128_CMAC.to_le_bytes()].concat();
            push_ctx(&mut ctx, ctx_type::SIGNING, &signing);
        }

        // ENCRYPTION_CAPABILITIES: exactly ONE selected cipher ([MS-SMB2]
        // §2.2.3.1.2) — only when the client offered encryption.
        if let Some(cipher) = encryption {
            let enc = [1u16.to_le_bytes(), cipher.to_le_bytes()].concat();
            push_ctx(&mut ctx, ctx_type::ENCRYPTION, &enc);
        }

        // COMPRESSION_CAPABILITIES: advertise the negotiated algorithm set.
        if !compression.is_empty() {
            let comp = crate::compress::build_compression_caps(compression);
            push_ctx(&mut ctx, ctx_type::COMPRESSION, &comp);
        }

        let ctx_off = BODY_START_FIXED; // absolute offset of contexts
        b[60..64].copy_from_slice(&(ctx_off as u32).to_le_bytes()); // NegotiateContextOffset
        b.extend_from_slice(&ctx);
    }
    b
}

/// Absolute frame offset where the negotiate context list starts for a
/// response whose fixed body is 64 bytes.
const BODY_START_FIXED: usize = 64 + 64;

/// Build the NEGOTIATE response body (§2.2.3.1) — no security blob
/// (clients initiate NTLMSSP in SESSION_SETUP).
///
/// The trailing 4-byte NegotiateContextOffset is emitted as 0 even for
/// pre-3.1.1 dialects (where the spec marks it Reserved); every real-world
/// parser expects the field's presence.
pub fn build_response(dialect: u16, guid: &[u8; 16], now: u64) -> Vec<u8> {
    build_response_full(dialect, guid, now, &[0u8; 32], None, false, &[], false)
}

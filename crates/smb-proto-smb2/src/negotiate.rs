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

/// SecurityMode bits (§2.2.3.1.1).
/// Signing is supported but not required.
pub const SIGNING_ENABLED: u16 = 0x0001;

/// Negotiate context types (§2.2.3.1.2).
pub mod ctx_type {
    /// PREAUTH_INTEGRITY_CAPABILITIES.
    pub const PREAUTH_INTEGRITY: u16 = 0x0001;
    /// ENCRYPTION_CAPABILITIES.
    pub const ENCRYPTION: u16 = 0x0002;
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
    chosen_cipher: u16,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    b.extend_from_slice(&dialect.to_le_bytes());
    if dialect == DIALECT_311 {
        b.extend_from_slice(&3u16.to_le_bytes()); // NegotiateContextCount
    } else {
        b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    }
    b.extend_from_slice(guid); // ServerGuid
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&65536u32.to_le_bytes()); // MaxTransactionSize
    b.extend_from_slice(&65536u32.to_le_bytes()); // MaxReadSize
    b.extend_from_slice(&65536u32.to_le_bytes()); // MaxWriteSize
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
            ctx.extend_from_slice(&kind.to_le_bytes());
            ctx.extend_from_slice(&(data.len() as u16).to_le_bytes());
            ctx.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            ctx.extend_from_slice(data);
            while ctx.len() % 8 != 0 {
                ctx.push(0);
            }
        };

        // PREAUTH_INTEGRITY_CAPABILITIES: SHA-512 + our salt.
        let mut preauth = Vec::new();
        preauth.extend_from_slice(&1u16.to_le_bytes()); // HashAlgorithmCount
        preauth.extend_from_slice(&(salt.len() as u16).to_le_bytes());
        preauth.extend_from_slice(&ctx_type::SHA512.to_le_bytes());
        preauth.extend_from_slice(salt);
        push_ctx(&mut ctx, ctx_type::PREAUTH_INTEGRITY, &preauth);

        // SIGNING_CAPABILITIES: AES-128-CMAC (the only 3.x scheme this
        // server implements).
        let signing = [1u16.to_le_bytes(), ctx_type::SIGNING_AES128_CMAC.to_le_bytes()].concat();
        push_ctx(&mut ctx, ctx_type::SIGNING, &signing);

        // ENCRYPTION_CAPABILITIES: exactly ONE selected cipher ([MS-SMB2]
        // §2.2.3.1.2). Advertised so validate-negotiate style flows work;
        // the transform itself is not applied by this server yet.
        let enc = [1u16.to_le_bytes(), chosen_cipher.to_le_bytes()].concat();
        push_ctx(&mut ctx, ctx_type::ENCRYPTION, &enc);

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
    build_response_full(dialect, guid, now, &[0u8; 32], 0)
}

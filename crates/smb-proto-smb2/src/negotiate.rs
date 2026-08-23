//! NEGOTIATE ([MS-SMB2] §2.2.3).

/// Dialect numbers (§2.2.3.1.1).
/// SMB 2.0.2 dialect revision.
pub const DIALECT_202: u16 = 0x0202;
/// SMB 2.1.0 dialect revision.
pub const DIALECT_210: u16 = 0x0210;

/// SecurityMode bits (§2.2.3.1.1).
/// Signing is supported but not required.
pub const SIGNING_ENABLED: u16 = 0x0001;

/// Parsed SMB2 NEGOTIATE request.
#[derive(Debug)]
pub struct Request {
    /// Dialect numbers offered by the client.
    pub dialects: Vec<u16>,
    /// Client GUID.
    pub client_guid: [u8; 16],
}

impl Request {
    /// Parse from the request body (bytes after the 64-byte header).
    pub fn parse(b: &[u8]) -> Option<Request> {
        // Fixed part: StructureSize(2) DialectCount(2) SecurityMode(2)
        // Reserved(2) Capabilities(4) ClientGuid(16) = 28 bytes, followed
        // by the dialect array (§2.2.3).
        if b.len() < 28 || u16::from_le_bytes([b[0], b[1]]) != 36 {
            return None;
        }
        let dcount = u16::from_le_bytes([b[2], b[3]]) as usize;
        if b.len() < 28 + dcount * 2 {
            return None;
        }
        let dialects: Vec<u16> = b[28..]
            .chunks_exact(2)
            .take(dcount)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let mut guid = [0u8; 16];
        guid.copy_from_slice(b.get(12..28)?);
        Some(Request { dialects, client_guid: guid })
    }
}

/// Pick the highest supported dialect.
pub fn pick(dialects: &[u16]) -> Option<u16> {
    let mut best = None;
    for &d in dialects {
        if matches!(d, DIALECT_202 | DIALECT_210) {
            best = Some(best.map_or(d, |b: u16| b.max(d)));
        }
    }
    best
}

/// Build the NEGOTIATE response body (§2.2.3.1) — no security blob
/// (clients initiate NTLMSSP in SESSION_SETUP).
pub fn build_response(dialect: u16, guid: &[u8; 16], now: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(65);
    b.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityMode: signing off
    b.extend_from_slice(&dialect.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved/NegotiateContextCount
    b.extend_from_slice(guid); // ServerGuid
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&65536u32.to_le_bytes()); // MaxTransactionSize
    b.extend_from_slice(&65536u32.to_le_bytes()); // MaxReadSize
    b.extend_from_slice(&65536u32.to_le_bytes()); // MaxWriteSize
    b.extend_from_slice(&now.to_le_bytes()); // SystemTime
    b.extend_from_slice(&now.to_le_bytes()); // ServerStartTime
    b.extend_from_slice(&64u16.to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength
    b
}

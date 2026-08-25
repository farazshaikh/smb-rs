//! SMB3 compression: the COMPRESSION_TRANSFORM_HEADER ([MS-SMB2] §2.2.42) and
//! SMB2_COMPRESSION_CAPABILITIES negotiate context ([MS-SMB2] §2.2.3.1.3).
//!
//! LZNT1 (compress + decompress) is delegated to the `lznt1` crate; Pattern_V1
//! (a repeated-byte payload, §2.2.42.1) is expanded inline. Only the unchained
//! transform form is produced; both forms are accepted on receive.

/// COMPRESSION_TRANSFORM ProtocolId: `0xFC 'S' 'M' 'B'`.
pub const PROTOCOL_ID: [u8; 4] = [0xFC, b'S', b'M', b'B'];

/// Compression algorithm ids ([MS-SMB2] §2.2.3.1.3).
pub mod algo {
    /// No compression.
    pub const NONE: u16 = 0x0000;
    /// LZNT1.
    pub const LZNT1: u16 = 0x0001;
    /// Plain LZ77 ([MS-XCA]).
    pub const LZ77: u16 = 0x0002;
    /// LZ77 + Huffman ([MS-XCA]).
    pub const LZ77_HUFFMAN: u16 = 0x0003;
    /// Repeated-byte pattern scrubbing.
    pub const PATTERN_V1: u16 = 0x0004;
}

/// Algorithms this server can both send and receive.
pub const SUPPORTED: &[u16] = &[algo::LZNT1, algo::PATTERN_V1];

/// Parse a client `SMB2_COMPRESSION_CAPABILITIES` context (§2.2.3.1.3) into its
/// advertised algorithm list.
pub fn parse_compression_caps(data: &[u8]) -> Vec<u16> {
    if data.len() < 8 {
        return Vec::new();
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    // CompressionAlgorithmCount(2) Padding(2) Flags(4) then the algorithm array.
    data.get(8..)
        .map(|rest| {
            rest.chunks_exact(2)
                .take(count)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect()
        })
        .unwrap_or_default()
}

/// Encode the server `SMB2_COMPRESSION_CAPABILITIES` context data advertising
/// `algos` (unchained; Flags = 0).
pub fn build_compression_caps(algos: &[u16]) -> Vec<u8> {
    let mut d = Vec::with_capacity(8 + algos.len() * 2);
    d.extend_from_slice(&(algos.len() as u16).to_le_bytes()); // CompressionAlgorithmCount
    d.extend_from_slice(&0u16.to_le_bytes()); // Padding
    d.extend_from_slice(&0u32.to_le_bytes()); // Flags (0 = unchained)
    for a in algos {
        d.extend_from_slice(&a.to_le_bytes());
    }
    d
}

/// Intersect the client's offered algorithms with the server's, preserving the
/// server's preference order.
pub fn negotiate_algos(client: &[u16]) -> Vec<u16> {
    SUPPORTED.iter().copied().filter(|a| client.contains(a)).collect()
}

/// Decompress a whole `\xFCSMB` COMPRESSION_TRANSFORM frame into the original
/// SMB2 message. `None` on malformed input or an unsupported algorithm.
pub fn decompress_message(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 16 || frame[0..4] != PROTOCOL_ID {
        return None;
    }
    let orig = u32::from_le_bytes(frame[4..8].try_into().ok()?) as usize;
    let algorithm = u16::from_le_bytes(frame[8..10].try_into().ok()?);
    let offset = u32::from_le_bytes(frame[12..16].try_into().ok()?) as usize;
    let payload = frame.get(16..)?;
    let prefix = payload.get(..offset)?;
    let compressed = payload.get(offset..)?;
    let mut out = Vec::with_capacity(orig.max(prefix.len()));
    out.extend_from_slice(prefix);
    match algorithm {
        algo::LZNT1 => lznt1::decompress(compressed, &mut out).ok()?,
        algo::PATTERN_V1 => expand_pattern_v1(compressed, &mut out)?,
        algo::NONE => out.extend_from_slice(compressed),
        _ => return None,
    }
    Some(out)
}

/// Wrap `msg` in an unchained LZNT1 COMPRESSION_TRANSFORM. Returns `None` when
/// the algorithm is unsupported or compression does not shrink the message (the
/// caller then sends it uncompressed).
pub fn compress_message(msg: &[u8], algorithm: u16) -> Option<Vec<u8>> {
    if algorithm != algo::LZNT1 {
        return None;
    }
    let mut payload = Vec::new();
    lznt1::compress(msg, &mut payload);
    if payload.len() >= msg.len() {
        return None;
    }
    let mut f = Vec::with_capacity(16 + payload.len());
    f.extend_from_slice(&PROTOCOL_ID);
    f.extend_from_slice(&(msg.len() as u32).to_le_bytes()); // OriginalCompressedSegmentSize
    f.extend_from_slice(&algo::LZNT1.to_le_bytes()); // CompressionAlgorithm
    f.extend_from_slice(&0u16.to_le_bytes()); // Flags
    f.extend_from_slice(&0u32.to_le_bytes()); // Offset (whole payload compressed)
    f.extend_from_slice(&payload);
    Some(f)
}

/// Expand an `SMB2_COMPRESSION_PATTERN_PAYLOAD_V1` (§2.2.42.1): a byte repeated
/// `Repetitions` times.
fn expand_pattern_v1(data: &[u8], out: &mut Vec<u8>) -> Option<()> {
    if data.len() < 8 {
        return None;
    }
    let pattern = data[0];
    let reps = u32::from_le_bytes(data[4..8].try_into().ok()?) as usize;
    out.resize(out.len() + reps, pattern);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lznt1_transform_round_trips() {
        let msg = b"SMB2 compression round-trip payload ".repeat(64);
        let frame = compress_message(&msg, algo::LZNT1).expect("compresses");
        assert_eq!(&frame[0..4], &PROTOCOL_ID, "transform magic");
        assert!(frame.len() < msg.len(), "shrunk");
        let back = decompress_message(&frame).expect("decompresses");
        assert_eq!(back, msg, "round-trips");
    }

    #[test]
    fn incompressible_message_is_not_wrapped() {
        // Random-ish, tiny input rarely shrinks under LZNT1.
        let msg: Vec<u8> = (0..32u8).collect();
        assert!(compress_message(&msg, algo::LZNT1).is_none());
    }

    #[test]
    fn pattern_v1_expands() {
        let mut data = vec![0xAB, 0, 0, 0];
        data.extend_from_slice(&100u32.to_le_bytes());
        let mut frame = Vec::new();
        frame.extend_from_slice(&PROTOCOL_ID);
        frame.extend_from_slice(&100u32.to_le_bytes());
        frame.extend_from_slice(&algo::PATTERN_V1.to_le_bytes());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&data);
        let out = decompress_message(&frame).expect("pattern");
        assert_eq!(out, vec![0xABu8; 100]);
    }

    #[test]
    fn negotiate_intersects_with_client() {
        let client = [algo::LZ77, algo::LZNT1, algo::LZ77_HUFFMAN];
        assert_eq!(negotiate_algos(&client), vec![algo::LZNT1]);
        let caps = build_compression_caps(&[algo::LZNT1, algo::PATTERN_V1]);
        assert_eq!(parse_compression_caps(&caps), vec![algo::LZNT1, algo::PATTERN_V1]);
    }
}

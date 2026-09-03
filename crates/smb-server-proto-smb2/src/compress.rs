//! SMB3 compression: the COMPRESSION_TRANSFORM_HEADER ([MS-SMB2] §2.2.42) and
//! SMB2_COMPRESSION_CAPABILITIES negotiate context ([MS-SMB2] §2.2.3.1.3).
//!
//! LZNT1 (compress + decompress) is delegated to the `lznt1` crate; Pattern_V1
//! (a repeated-byte payload, §2.2.42.1) is expanded inline. Only the unchained
//! transform form is produced; both forms are accepted on receive.

/// COMPRESSION_TRANSFORM ProtocolId: `0xFC 'S' 'M' 'B'`.
pub const PROTOCOL_ID: [u8; 4] = [0xFC, b'S', b'M', b'B'];

/// SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED ([MS-SMB2] §2.2.3.1.3): advertised
/// in the negotiate context Flags field when chained compression is supported.
pub const CAP_FLAG_CHAINED: u32 = 0x0000_0001;

/// SMB2_COMPRESSION_FLAG_CHAINED ([MS-SMB2] §2.2.42.2.1): set in the first
/// chained payload header. Its position (the Flags field at frame offset 10)
/// also distinguishes a chained COMPRESSION_TRANSFORM_HEADER from the unchained
/// form, whose Flags field is zero there ([MS-SMB2] §2.2.42).
const CHAINED_FLAG: u16 = 0x0001;

/// Minimum single-byte run length worth emitting as a Pattern_V1 payload. A
/// Pattern_V1 payload costs 16 bytes (8-byte chained header + 8-byte pattern),
/// so only longer runs shrink the message.
const CHAINED_PATTERN_MIN: usize = 32;

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
pub const SUPPORTED: &[u16] = &[algo::LZNT1, algo::LZ77, algo::PATTERN_V1];

/// Compress with Plain LZ77 (LZXpress, [MS-XCA]); `None` if the codec errors.
fn lz77_compress(data: &[u8]) -> Option<Vec<u8>> {
    xpress_rs::lz77::LZ77Compressor::new(data.to_vec())
        .compress()
        .ok()
}

/// Decompress a Plain LZ77 (LZXpress, [MS-XCA]) stream. Wrapped in `catch_unwind`
/// so malformed attacker-supplied input that panics the codec is contained as a
/// decode failure (the dispatcher then disconnects) instead of unwinding the
/// connection task.
fn lz77_decompress(data: &[u8]) -> Option<Vec<u8>> {
    let input = data.to_vec();
    std::panic::catch_unwind(move || {
        xpress_rs::lz77::LZ77Decompressor::new(input)
            .decompress()
            .ok()
    })
    .ok()
    .flatten()
}

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

/// Read the Flags field of a client `SMB2_COMPRESSION_CAPABILITIES` context
/// (§2.2.3.1.3).
pub fn parse_compression_flags(data: &[u8]) -> u32 {
    data.get(4..8)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .unwrap_or(0)
}

/// Encode the server `SMB2_COMPRESSION_CAPABILITIES` context data advertising
/// `algos`, setting SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED when `chained`.
pub fn build_compression_caps(algos: &[u16], chained: bool) -> Vec<u8> {
    let mut d = Vec::with_capacity(8 + algos.len() * 2);
    d.extend_from_slice(&(algos.len() as u16).to_le_bytes()); // CompressionAlgorithmCount
    d.extend_from_slice(&0u16.to_le_bytes()); // Padding
    let flags = if chained { CAP_FLAG_CHAINED } else { 0 };
    d.extend_from_slice(&flags.to_le_bytes()); // Flags
    for a in algos {
        d.extend_from_slice(&a.to_le_bytes());
    }
    d
}

/// Intersect the client's offered algorithms with the server's, preserving the
/// client's order so the negotiate response echoes the requested CompressionIds
/// when all are supported ([MS-SMB2] §3.3.5.4).
pub fn negotiate_algos(client: &[u16]) -> Vec<u16> {
    client
        .iter()
        .copied()
        .filter(|a| SUPPORTED.contains(a))
        .collect()
}

/// Decompress a whole `\xFCSMB` COMPRESSION_TRANSFORM frame into the original
/// SMB2 message. `None` on malformed input or an unsupported algorithm.
pub fn decompress_message(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 16 || frame[0..4] != PROTOCOL_ID {
        return None;
    }
    // The Flags field at offset 10 distinguishes the chained transform (0x0001)
    // from the unchained form (0) ([MS-SMB2] §2.2.42).
    if u16::from_le_bytes([frame[10], frame[11]]) & CHAINED_FLAG != 0 {
        return decompress_chained(frame);
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
        algo::LZ77 => out.extend_from_slice(&lz77_decompress(compressed)?),
        algo::PATTERN_V1 => expand_pattern_v1(compressed, &mut out)?,
        algo::NONE => out.extend_from_slice(compressed),
        _ => return None,
    }
    Some(out)
}

/// Decompress a chained COMPRESSION_TRANSFORM_HEADER ([MS-SMB2] \u00a72.2.42.2) by
/// concatenating each payload's contribution. Per \u00a73.1.5.3 any malformed payload
/// (an unknown algorithm, a Length reaching past the buffer, a Repetitions or
/// decompressed size exceeding OriginalCompressedSegmentSize) yields `None`,
/// which the dispatcher treats as fatal and disconnects the connection.
fn decompress_chained(frame: &[u8]) -> Option<Vec<u8>> {
    let orig = u32::from_le_bytes(frame[4..8].try_into().ok()?) as usize;
    let mut out = Vec::with_capacity(orig);
    let mut pos = 8;
    while pos < frame.len() {
        // SMB2_COMPRESSION_CHAINED_PAYLOAD_HEADER: Algorithm(2) Flags(2) Length(4).
        let hdr = frame.get(pos..pos + 8)?;
        let algorithm = u16::from_le_bytes([hdr[0], hdr[1]]);
        let length = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        pos += 8;
        let payload = frame.get(pos..pos + length)?;
        match algorithm {
            algo::NONE => {
                if length > orig {
                    return None;
                }
                out.extend_from_slice(payload);
            }
            algo::PATTERN_V1 => {
                // SMB2_COMPRESSION_PATTERN_PAYLOAD_V1: Pattern(1) Reserved1(1)
                // Reserved2(2) Repetitions(4).
                let reps = u32::from_le_bytes(payload.get(4..8)?.try_into().ok()?) as usize;
                if reps > orig {
                    return None;
                }
                out.resize(out.len().checked_add(reps)?, payload[0]);
            }
            algo::LZNT1 => {
                // Length includes the leading 4-byte OriginalPayloadSize field.
                let orig_payload = u32::from_le_bytes(payload.get(0..4)?.try_into().ok()?) as usize;
                let before = out.len();
                lznt1::decompress(&payload[4..], &mut out).ok()?;
                if out.len() - before != orig_payload {
                    return None;
                }
            }
            algo::LZ77 => {
                // Length includes the leading 4-byte OriginalPayloadSize field.
                let orig_payload = u32::from_le_bytes(payload.get(0..4)?.try_into().ok()?) as usize;
                let data = lz77_decompress(payload.get(4..)?)?;
                if data.len() != orig_payload {
                    return None;
                }
                out.extend_from_slice(&data);
            }
            _ => return None,
        }
        pos += length;
    }
    Some(out)
}

/// Wrap `msg` in an unchained LZNT1 COMPRESSION_TRANSFORM. Returns `None` when
/// the algorithm is unsupported or compression does not shrink the message (the
/// caller then sends it uncompressed).
///
/// For a READ response only the file data is compressed, leaving the SMB2 header
/// and READ response structure uncompressed via the transform Offset field. This
/// mirrors Windows and, per [MS-SMB2] §3.1.4.4 step 5/6, avoids emitting a
/// transform when compression would not shrink the payload (e.g. a tiny or
/// incompressible read).
pub fn compress_message(msg: &[u8], algorithm: u16) -> Option<Vec<u8>> {
    let offset = read_response_data_offset(msg).unwrap_or(0);
    compress_message_at(msg, algorithm, offset)
}

/// Compress the portion of `msg` at or after `offset`, leaving the leading
/// `offset` bytes uncompressed ([MS-SMB2] §3.1.4.4 step 2).
fn compress_message_at(msg: &[u8], algorithm: u16, offset: usize) -> Option<Vec<u8>> {
    let prefix = msg.get(..offset)?;
    let body = msg.get(offset..)?;
    let payload = match algorithm {
        algo::LZNT1 => {
            let mut p = Vec::new();
            lznt1::compress(body, &mut p);
            p
        }
        algo::LZ77 => lz77_compress(body)?,
        _ => return None,
    };
    // §3.1.4.4 step 6: send uncompressed when compression does not shrink the
    // compressed portion.
    if payload.len() >= body.len() {
        return None;
    }
    let mut f = Vec::with_capacity(16 + prefix.len() + payload.len());
    f.extend_from_slice(&PROTOCOL_ID);
    f.extend_from_slice(&(body.len() as u32).to_le_bytes()); // OriginalCompressedSegmentSize
    f.extend_from_slice(&algorithm.to_le_bytes()); // CompressionAlgorithm
    f.extend_from_slice(&0u16.to_le_bytes()); // Flags
    f.extend_from_slice(&(offset as u32).to_le_bytes()); // Offset of the compressed portion
    f.extend_from_slice(prefix);
    f.extend_from_slice(&payload);
    Some(f)
}

/// Wrap `msg` in a chained COMPRESSION_TRANSFORM_HEADER ([MS-SMB2] \u00a72.2.42.2),
/// emitting a Pattern_V1 payload for each long single-byte run and an `algorithm`
/// (or uncompressed NONE) payload for the data between runs ([MS-SMB2] \u00a73.1.4.4).
/// For a READ response the SMB2 header and READ structure are carried in a
/// leading NONE payload so only the file data is compressed. Returns `None` when
/// the result would not shrink the message.
pub fn compress_message_chained(msg: &[u8], algorithm: u16) -> Option<Vec<u8>> {
    let offset = read_response_data_offset(msg).unwrap_or(0);
    let mut payloads = Vec::new();
    let mut first = true;
    if offset > 0 {
        push_chained_payload(&mut payloads, &mut first, algo::NONE, &msg[..offset], None);
    }
    let body = msg.get(offset..)?;
    let mut i = 0;
    while i < body.len() {
        let run = run_length(&body[i..]);
        if run >= CHAINED_PATTERN_MIN {
            let mut pattern = Vec::with_capacity(8);
            pattern.push(body[i]); // Pattern
            pattern.push(0); // Reserved1
            pattern.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
            pattern.extend_from_slice(&(run as u32).to_le_bytes()); // Repetitions
            push_chained_payload(&mut payloads, &mut first, algo::PATTERN_V1, &pattern, None);
            i += run;
            continue;
        }
        // Accumulate a non-pattern segment up to the next long run.
        let seg_start = i;
        while i < body.len() && run_length(&body[i..]) < CHAINED_PATTERN_MIN {
            i += 1;
        }
        let seg = &body[seg_start..i];
        let comp = match algorithm {
            algo::LZ77 => lz77_compress(seg),
            _ => {
                let mut c = Vec::new();
                lznt1::compress(seg, &mut c);
                Some(c)
            }
        };
        match comp {
            Some(comp) if comp.len() < seg.len() => push_chained_payload(
                &mut payloads,
                &mut first,
                algorithm,
                &comp,
                Some(seg.len() as u32),
            ),
            _ => push_chained_payload(&mut payloads, &mut first, algo::NONE, seg, None),
        }
    }
    let mut f = Vec::with_capacity(8 + payloads.len());
    f.extend_from_slice(&PROTOCOL_ID);
    f.extend_from_slice(&(msg.len() as u32).to_le_bytes()); // OriginalCompressedSegmentSize
    f.extend_from_slice(&payloads);
    (f.len() < msg.len()).then_some(f)
}

/// Append one SMB2_COMPRESSION_CHAINED_PAYLOAD_HEADER plus its payload. The
/// first payload sets SMB2_COMPRESSION_FLAG_CHAINED; `orig_payload` is the
/// decompressed size prepended for algorithms that carry it (LZNT1/LZ77/\u2026).
fn push_chained_payload(
    out: &mut Vec<u8>,
    first: &mut bool,
    algorithm: u16,
    data: &[u8],
    orig_payload: Option<u32>,
) {
    out.extend_from_slice(&algorithm.to_le_bytes());
    let flags = if *first { CHAINED_FLAG } else { 0 };
    *first = false;
    out.extend_from_slice(&flags.to_le_bytes());
    let length = data.len() + orig_payload.map_or(0, |_| 4);
    out.extend_from_slice(&(length as u32).to_le_bytes());
    if let Some(op) = orig_payload {
        out.extend_from_slice(&op.to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Length of the leading run of the first byte in `data`.
fn run_length(data: &[u8]) -> usize {
    match data.first() {
        Some(&b) => data.iter().take_while(|&&x| x == b).count(),
        None => 0,
    }
}
fn read_response_data_offset(msg: &[u8]) -> Option<usize> {
    const SMB2_HEADER_LEN: usize = 64;
    const CMD_READ: u16 = 0x0008;
    const FLAG_SERVER_TO_REDIR: u32 = 0x0000_0001;
    if msg.len() < SMB2_HEADER_LEN + 16 || msg[0..4] != crate::SMB2_MAGIC {
        return None;
    }
    let command = u16::from_le_bytes([msg[12], msg[13]]);
    let flags = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]);
    let next = u32::from_le_bytes([msg[20], msg[21], msg[22], msg[23]]);
    if command != CMD_READ || next != 0 || flags & FLAG_SERVER_TO_REDIR == 0 {
        return None;
    }
    // READ Response ([MS-SMB2] §2.2.20): StructureSize(2) then DataOffset(1),
    // measured from the start of the SMB2 header.
    let data_offset = msg[SMB2_HEADER_LEN + 2] as usize;
    (data_offset < msg.len()).then_some(data_offset)
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
    fn lz77_transform_round_trips() {
        let msg = b"abc".repeat(100);
        let frame = compress_message(&msg, algo::LZ77).expect("compresses");
        assert_eq!(&frame[0..4], &PROTOCOL_ID, "transform magic");
        assert_eq!(
            u16::from_le_bytes([frame[8], frame[9]]),
            algo::LZ77,
            "advertises LZ77"
        );
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
        // Order follows the client's request; LZ77+Huffman is not yet supported.
        let client = [algo::LZ77, algo::LZNT1, algo::LZ77_HUFFMAN];
        assert_eq!(negotiate_algos(&client), vec![algo::LZ77, algo::LZNT1]);
        let caps = build_compression_caps(&[algo::LZNT1, algo::PATTERN_V1], true);
        assert_eq!(
            parse_compression_caps(&caps),
            vec![algo::LZNT1, algo::PATTERN_V1]
        );
        assert_eq!(parse_compression_flags(&caps), CAP_FLAG_CHAINED);
    }

    #[test]
    fn chained_pattern_and_lznt1_round_trip() {
        // A long single-byte run (Pattern_V1) followed by compressible data.
        let mut msg = vec![0xAAu8; 256];
        msg.extend(b"chained compression payload data ".repeat(64));
        let frame = compress_message_chained(&msg, algo::LZNT1).expect("compresses");
        assert_eq!(&frame[0..4], &PROTOCOL_ID, "transform magic");
        assert_eq!(
            u16::from_le_bytes([frame[10], frame[11]]) & CHAINED_FLAG,
            CHAINED_FLAG,
            "first payload carries the chained flag"
        );
        assert!(frame.len() < msg.len(), "shrunk");
        let back = decompress_message(&frame).expect("decompresses");
        assert_eq!(back, msg, "round-trips");
    }

    #[test]
    fn chained_bad_length_is_rejected() {
        // ProtocolId + OriginalCompressedSegmentSize + one payload header whose
        // Length runs past the buffer.
        let mut frame = Vec::new();
        frame.extend_from_slice(&PROTOCOL_ID);
        frame.extend_from_slice(&64u32.to_le_bytes());
        frame.extend_from_slice(&algo::NONE.to_le_bytes());
        frame.extend_from_slice(&CHAINED_FLAG.to_le_bytes());
        frame.extend_from_slice(&999u32.to_le_bytes()); // Length past end
        assert!(decompress_message(&frame).is_none());
    }
}

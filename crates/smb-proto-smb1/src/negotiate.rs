//! `SMB_COM_NEGOTIATE` ([MS-SMB] §2.2.4.5).

/// Parsed client request (§2.2.4.5.1): the offered dialect list.
#[derive(Debug)]
pub struct NegotiateReq {
    /// Dialect strings offered by the client.
    pub dialects: Vec<String>,
}

impl NegotiateReq {
    /// Parse the dialect list from the request data area
    /// (each entry: BufferFormat `0x02` + NUL-terminated name).
    pub fn parse(data: &[u8]) -> Self {
        let mut dialects = Vec::new();
        let mut i = 0usize;
        while i < data.len() && data[i] == 0x02 {
            i += 1;
            match data[i..].iter().position(|&b| b == 0) {
                Some(p) => {
                    let end = i + p;
                    dialects.push(String::from_utf8_lossy(&data[i..end]).to_string());
                    i = end + 1;
                }
                None => break,
            }
        }
        NegotiateReq { dialects }
    }

    /// Pick the highest dialect we support; returns `(index, name)`.
    pub fn select(&self) -> Option<(usize)> {
        self.dialects
            .iter()
            .position(|d| d.eq_ignore_ascii_case("NT LM 0.12"))
            .map(|i| (i))
    }
}

/// Server response (§2.2.4.5.2): WordCount 17 with the byte-packed layout —
/// DialectIndex(2), SecurityMode(1), MaxMpx(2), VCs(2), MaxBuf(4), MaxRaw(4),
/// SessionKey(4), Capabilities(4), SystemTime(8), TimeZone(2),
/// ChallengeLength(1) = 34 bytes; challenge bytes follow ByteCount.
pub const WORD_COUNT: u8 = 17;

/// Build response parameter words (34 bytes incl. ChallengeLength).
pub fn build_params(dialect_index: u16, caps: u32, now: smb_proto::types::FileTime) -> Vec<u8> {
    let mut p = Vec::with_capacity(34);
    p.extend_from_slice(&(dialect_index as u16).to_le_bytes()); // [0-1]
    p.push(0x03); //                                            [2] USER|ENCRYPT
    p.extend_from_slice(&16u16.to_le_bytes()); //                [3-4] MaxMpx
    p.extend_from_slice(&1u16.to_le_bytes()); //                 [5-6] VCs
    p.extend_from_slice(&65535u32.to_le_bytes()); //             [7-10] MaxBuffer
    p.extend_from_slice(&65536u32.to_le_bytes()); //             [11-14] MaxRaw
    p.extend_from_slice(&0x1234_5678u32.to_le_bytes()); //       [15-18] SessionKey
    p.extend_from_slice(&caps.to_le_bytes()); //                 [19-22] Capabilities
    p.extend_from_slice(&now.0.to_le_bytes()); //                [23-30] SystemTime
    p.extend_from_slice(&0i16.to_le_bytes()); //                 [31-32] TimeZone UTC
    p.push(8u8); //                                              [33] ChallengeLength
    debug_assert_eq!(p.len(), 34);
    p
}

/// Build the response data block (the raw 8-byte challenge).
pub fn build_bytes(challenge: &[u8; 8]) -> Vec<u8> {
    challenge.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_nt_lm_dialect() {
        let req = NegotiateReq::parse(
            b"\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00",
        );
        assert_eq!(req.select().unwrap(), 1);
    }
}

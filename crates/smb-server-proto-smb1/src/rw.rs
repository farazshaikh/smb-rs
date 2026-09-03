//! `WRITE_ANDX` / `READ_ANDX` codecs.
//!
//! WRITE_ANDX word layout per [MS-SMB] §2.2.4.3.1:
//!
//! ```text
//! Offset  Size  Field
//!  0       1    AndXCommand
//!  1       1    AndXReserved
//!  2       2    AndXOffset
//!  4       2    FID
//!  6       4    Offset
//! 10       4    Timeout
//! 14       2    WriteMode
//! 16       2    Remaining
//! 18       2    DataLengthHigh   ← [MS-SMB] extension
//! 20       2    DataLength
//! 22       2    DataOffset
//! 24       4    OffsetHigh       (optional, when WC=14)
//! ```

use smb_server_proto::types::Status;

// ---- Named field offsets into the Words area ----

/// WRITE_ANDX parameter block field offsets ([MS-SMB] §2.2.4.3.1).
pub mod write_offs {
    /// AndXCommand byte offset.
    pub const ANDX_COMMAND: usize = 0;
    /// AndXReserved byte offset.
    pub const ANDX_RESERVED: usize = 1;
    /// AndXOffset byte offset.
    pub const ANDX_OFFSET: usize = 2;
    /// FID byte offset.
    pub const FID: usize = 4;
    /// Offset low u32 byte offset.
    pub const OFFSET_LOW: usize = 6;
    /// Timeout u32 byte offset.
    pub const TIMEOUT: usize = 10;
    /// WriteMode u16 byte offset.
    pub const WRITE_MODE: usize = 14;
    /// Remaining u16 byte offset.
    pub const REMAINING: usize = 16;
    /// DataLengthHigh u16 byte offset (always present in WC=14).
    pub const DATA_LENGTH_HIGH: usize = 18;
    /// DataLength u16 byte offset (always present after high part).
    pub const DATA_LENGTH: usize = 20;
    /// DataOffset u16 byte offset (always present after DataLength).
    pub const DATA_OFFSET: usize = 22;
    /// OffsetHigh u32 byte offset (optional, only in some WC=14 forms).
    pub const OFFSET_HIGH: usize = 24;

    /// Minimum word bytes for a valid WRITE_ANDX (WC=12 → 24 bytes).
    pub const MIN_WORDS_BYTES: usize = 24;
}

/// READ_ANDX parameter block field offsets ([MS-CIFS] §2.2.4.43.1,
/// extended by [MS-SMB] §2.2.4.x for large reads).
pub mod read_offs {
    /// FID byte offset.
    pub const FID: usize = 4;
    /// Offset low u32 byte offset.
    pub const OFFSET_LOW: usize = 6;
    /// MaxCount u16 byte offset.
    pub const MAX_COUNT: usize = 10;
    /// MinCount u16 byte offset.
    pub const MIN_COUNT: usize = 12;
    /// OffsetHigh u32 byte offset (only when WC ≥ 12).
    pub const OFFSET_HIGH: usize = 20;
}

// ---- Helper readers ----

fn g16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}

fn g32(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

// ---- WRITE_ANDX ----

/// Parsed WRITE_ANDX request body.
#[derive(Debug)]
pub struct WriteReq {
    /// Open file identifier.
    pub fid: u16,
    /// Absolute file offset.
    pub offset: u64,
    /// Write-through requested (`WriteMode` bit 0).
    pub write_through: bool,
    /// Payload bytes to write.
    pub payload: Vec<u8>,
}

impl WriteReq {
    /// Parse the WRITE_ANDX request body from words + full frame.
    ///
    /// Reads all fields by their spec-defined offsets; combines
    /// `DataLengthHigh` and `DataLength` for the effective size, and
    /// `OffsetLow` + `OffsetHigh` (when present) for the 64-bit offset.
    pub fn parse(words: &[u8], frame: &[u8]) -> Result<WriteReq, Status> {
        use write_offs as wo;

        if words.len() < wo::MIN_WORDS_BYTES {
            return Err(Status::INVALID_PARAMETER);
        }

        let fid = g16(words, wo::FID);
        let offset_low = g32(words, wo::OFFSET_LOW);
        let write_mode = g16(words, wo::WRITE_MODE);

        // Effective data length combines high and low parts.
        let len_high = g16(words, wo::DATA_LENGTH_HIGH) as usize;
        let len_low = g16(words, wo::DATA_LENGTH) as usize;
        let data_len = (len_high << 16) | len_low;

        // Data offset is relative to the SMB header start.
        let data_off = g16(words, wo::DATA_OFFSET) as usize;

        // Optional 64-bit offset high part.
        let mut offset = offset_low as u64;
        if words.len() >= wo::OFFSET_HIGH + 4 {
            offset |= (g32(words, wo::OFFSET_HIGH) as u64) << 32;
        }

        // Validate: payload must be within the frame.
        let frame_len = frame.len();
        if data_off < 32 || data_off + data_len > frame_len || data_len == 0 {
            return Err(Status::INVALID_PARAMETER);
        }

        Ok(WriteReq {
            fid,
            offset,
            write_through: write_mode & 0x0001 != 0,
            payload: frame[data_off..data_off + data_len].to_vec(),
        })
    }
}

/// Build a successful WRITE_ANDX response (WC=6).
///
/// Fields: AndX triple(terminal), CountLow, Available, CountHigh, Reserved.
pub fn write_response(written: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(12);
    p.push(0xFF); // terminal AndX
    p.push(0);
    p.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    p.extend_from_slice(&(written as u16).to_le_bytes()); // CountLow
    p.extend_from_slice(&65535u16.to_le_bytes()); // Available
    p.extend_from_slice(&((written >> 16) as u16).to_le_bytes()); // CountHigh
    p.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    p
}

// ---- READ_ANDX ----

/// Parsed READ_ANDX request body.
#[derive(Debug)]
pub struct ReadReq {
    /// Open file identifier.
    pub fid: u16,
    /// Absolute file offset.
    pub offset: u64,
    /// Maximum bytes the client will accept.
    pub max_count: usize,
}

impl ReadReq {
    /// Parse the READ_ANDX request using spec-named offsets.
    pub fn parse(words: &[u8]) -> Result<ReadReq, Status> {
        use read_offs as ro;

        if words.len() < ro::MIN_COUNT + 2 {
            return Err(Status::INVALID_PARAMETER);
        }

        let fid = g16(words, ro::FID);
        let mut offset = g32(words, ro::OFFSET_LOW) as u64;
        let max_count = g16(words, ro::MAX_COUNT) as usize;

        // 64-bit offset extension when WC is large enough.
        if words.len() >= ro::OFFSET_HIGH + 4 {
            let hi = g32(words, ro::OFFSET_HIGH);
            offset |= (hi as u64) << 32;
        }

        Ok(ReadReq { fid, offset, max_count })
    }
}

/// Build a READ_ANDX response (WC=12).
///
/// Layout per [MS-CIFS] §2.2.4.43.2 / [MS-SMB] extensions:
/// AndX triple, Remaining, CompactionMode, Reserved, DataLength, DataOffset,
/// DataLengthHigh(u32), Reserved(u32), Reserved tail(2B) = 24 bytes total.
///
/// Data starts after ByteCount, padded to even alignment.
pub fn read_response(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Named offsets into the response parameter block.
    const PARAMS_LEN: usize = 24; // WC=12
    const DATA_LEN_OFF: usize = 10;
    const DATA_OFFS_OFF: usize = 12;

    // Data area begins after header(32)+wcnt(1)+params(PARAMS_LEN)+bytecount(2).
    let bc_end = 32 + 1 + PARAMS_LEN + 2;
    let doff = (bc_end + 1) & !1usize; // even-aligned

    let mut params = Vec::with_capacity(PARAMS_LEN);
    params.push(0xFF); // terminal AndX
    params.push(0);
    params.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    params.extend_from_slice(&0u16.to_le_bytes()); // Available
    params.extend_from_slice(&0u16.to_le_bytes()); // DataCompactionMode
    params.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    params.extend_from_slice(&(data.len() as u16).to_le_bytes()); // DataLength @DATA_LEN_OFF
    params.extend_from_slice(&(doff as u16).to_le_bytes()); // DataOffset @DATA_OFFS_OFF
    params.extend_from_slice(&0u32.to_le_bytes()); // DataLengthHigh
    params.extend_from_slice(&[0u8; 6]); // reserved tail (total = 24B)

    debug_assert_eq!(params.len(), PARAMS_LEN);
    debug_assert_eq!(
        u16::from_le_bytes(params[DATA_LEN_OFF..DATA_LEN_OFF + 2].try_into().unwrap()),
        data.len() as u16
    );
    debug_assert_eq!(
        u16::from_le_bytes(params[DATA_OFFS_OFF..DATA_OFFS_OFF + 2].try_into().unwrap()),
        doff as u16
    );

    let pad = doff - bc_end;
    let mut bytes = vec![0u8; pad];
    bytes.extend_from_slice(data);
    (params, bytes)
}

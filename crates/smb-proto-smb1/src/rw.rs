//! `READ_ANDX` / `WRITE_ANDX` ([MS-CIFS] §2.2.4.43/44, extended by
//! [MS-SMB] for large read/write and 64-bit offsets).

use smb_proto::types::Status;

fn u16le(w: &[u8], off: usize) -> u16 {
    w.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

fn u32le(w: &[u8], off: usize) -> u32 {
    w.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Parsed `READ_ANDX` request ([MS-CIFS] WC=10/12).
#[derive(Debug)]
pub struct ReadReq {
    /// Handle to read from.
    pub fid: u16,
    /// Byte offset (64-bit when OffsetHigh present).
    pub offset: u64,
    /// Maximum bytes the client will accept.
    pub max_count: usize,
}

impl ReadReq {
    /// Parse defensively: Fid@vwv2, Offset@vwv3-4, MaxCount@vwv5,
    /// OffsetHigh@vwv10-11 (WC≥12, [MS-SMB] large-read extension).
    pub fn parse(words: &[u8]) -> Result<Self, ()> {
        if words.len() < 12 {
            return Err(());
        }
        let fid = u16le(words, 4);
        let mut offset = u32le(words, 6) as u64;
        if words.len() >= 24 {
            offset |= (u32le(words, 20) as u64) << 32;
        }
        let max_count = u16le(words, 10) as usize;
        Ok(ReadReq { fid, offset, max_count })
    }
}

/// Build a successful READ_ANDX response (WC=12). `data` is copied into the
/// frame at an even-aligned absolute DataOffset.
///
/// Returns `(params, data_block)` — the caller assembles the frame.
pub fn read_response(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    const PARAMS_LEN: usize = 24;
    // Absolute offset of the data block from the SMB header start:
    // header(32) + wcnt(1) + words(24) + bytecount(2) = 59 → round to even.
    let mut doff = 32 + 1 + PARAMS_LEN + 2;
    if doff % 2 != 0 {
        doff += 1;
    }

    let mut params = Vec::with_capacity(PARAMS_LEN);
    params.push(0xFF); // no successor
    params.push(0);
    params.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    params.extend_from_slice(&0u16.to_le_bytes()); // Remaining/Available
    params.extend_from_slice(&0u16.to_le_bytes()); // DataCompactionMode
    params.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    params.extend_from_slice(&(data.len() as u16).to_le_bytes()); // DataLength
    params.extend_from_slice(&(doff as u16).to_le_bytes()); // DataOffset
    params.extend_from_slice(&0u32.to_le_bytes()); // DataLengthHigh
    params.extend_from_slice(&0u32.to_le_bytes()); // Reserved

    // Padding between ByteCount and the first data byte.
    let pad = doff - (32 + 1 + PARAMS_LEN + 2);
    let mut bytes = vec![0u8; pad];
    bytes.extend_from_slice(data);
    (params, bytes)
}

/// Parsed `WRITE_ANDX` request ([MS-CIFS] WC=12/14 plus the Impacket-style
/// variant with `DataLength@vwv8`, `DataOffset@vwv10`).
#[derive(Debug)]
pub struct WriteReq {
    /// Handle to write to.
    pub fid: u16,
    /// Byte offset.
    pub offset: u64,
    /// Write-through flag from WriteMode bit 0.
    pub write_through: bool,
    /// Payload bytes (borrowed from the request frame).
    pub payload: Vec<u8>,
}

/// Pick `(len, offset)` pair whose layout lands inside the frame; prefers the
/// MS-CIFS ordering, falls back to the Impacket ordering.
fn pick_layout(w: &[u8], wc: usize, bc: usize, framelen: usize) -> Option<(usize, usize)> {
    if wc < 12 {
        return None;
    }
    let mut candidates = Vec::new();
    if wc >= 14 {
        // MS-CIFS: OffsetHigh @18-21 (must be 0), DataLength @22, DataOffset @24.
        let hi = u32le(w, 18);
        if hi == 0 {
            candidates.push((u16le(w, 22) as usize, u16le(w, 24) as usize));
        }
    }
    // Impacket variant: DataLength @16, DataOffset @20.
    if wc >= 9 {
        candidates.push((u16le(w, 16) as usize, u16le(w, 20) as usize));
    }
    // Plain WC=12 ordering: DataLength @18, DataOffset @20.
    if wc >= 11 {
        candidates.push((u16le(w, 18) as usize, u16le(w, 20) as usize));
    }
    candidates.into_iter().find(|&(dl, dof)| {
        dl > 0 && dof >= 35 && dof + dl <= framelen && dl <= bc.max(dl)
    })
}

impl WriteReq {
    /// Parse the request, extracting the payload slice position from the
    /// validated candidate layouts. Returns `Err` on malformed input.
    pub fn parse(
        words: &[u8],
        bc: usize,
        framelen: usize,
        buf: &[u8],
    ) -> Result<WriteReq, Status> {
        let wc = words.len() / 2;
        if wc < 12 {
            return Err(Status::INVALID_PARAMETER);
        }
        let fid = u16le(words, 4);
        let mut offset = u32le(words, 6) as u64;
        if wc >= 14 {
            offset |= (u32le(words, 18) as u64) << 32;
        }
        let write_mode = u16le(words, 14);

        let Some((data_len, data_offset)) = pick_layout(words, wc, bc, framelen) else {
            return Err(Status::INVALID_PARAMETER);
        };
        let end = (data_offset + data_len).min(buf.len());
        if data_offset > end {
            return Err(Status::INVALID_PARAMETER);
        }
        Ok(WriteReq {
            fid,
            offset,
            write_through: u16le(words, 14) & 0x0001 != 0 || write_mode & 0x0001 != 0,
            payload: buf[data_offset..end].to_vec(),
        })
    }
}

/// Build a successful WRITE_ANDX response (WC=6): CountLow, Available,
/// CountHigh, Reserved.
pub fn write_response(written: u64) -> Vec<u8> {
    let mut params = Vec::with_capacity(12);
    params.push(0xFF); // terminal AndX
    params.push(0);
    params.extend_from_slice(&0u16.to_le_bytes());
    params.extend_from_slice(&(written as u16).to_le_bytes()); // CountLow
    params.extend_from_slice(&65535u16.to_le_bytes()); // Available
    params.extend_from_slice(&((written >> 16) as u16).to_le_bytes()); // CountHigh
    params.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    params
}

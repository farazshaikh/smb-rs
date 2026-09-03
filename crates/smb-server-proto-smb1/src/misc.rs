//! Small commands: CLOSE, FLUSH, SEEK, ECHO, LOGOFF_ANDX, TREE_DISCONNECT,
//! QUERY_INFORMATION_DISK, PROCESS_EXIT and LOCKING_ANDX.


fn u16le(w: &[u8], off: usize) -> u16 {
    w.get(off..off + 2)
        .map(|s| u16::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// CLOSE request (WC=3): FID plus optional mtime.
#[derive(Debug)]
pub struct CloseReq {
    /// Handle to close.
    pub fid: u16,
    /// Client-supplied last-write time (0 = leave unchanged).
    pub mtime: u32,
}

impl CloseReq {
    /// Parse WC=3 words.
    pub fn parse(words: &[u8]) -> Option<Self> {
        if words.len() < 6 {
            return None;
        }
        Some(CloseReq {
            fid: u16le(words, 0),
            mtime: u32le(words, 2),
        })
    }
}

/// Empty WC=0 response body.
pub fn empty_response(_command: u8) -> (Vec<u8>, Vec<u8>) {
    (Vec::new(), Vec::new())
}

/// FLUSH request: FID or `0xFFFF` for all handles of the PID.
pub fn flush_fid(words: &[u8]) -> Option<u16> {
    words.len().checked_sub(2).map(|_| u16le(words, 0))
}

/// ECHO request: repeat count plus echo data.
#[derive(Debug)]
pub struct EchoReq {
    /// Number of responses requested.
    pub count: u16,
    /// Data to be echoed back verbatim.
    pub data: Vec<u8>,
}

impl EchoReq {
    /// Parse WC=1 request; remaining bytes are the echoed payload.
    pub fn parse(words: &[u8], data: &[u8]) -> Self {
        EchoReq { count: u16le(words, 0).max(1), data: data.to_vec() }
    }

    /// Build one echo response with sequence number `seq`.
    pub fn build_response(seq: u16, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut params = Vec::with_capacity(4);
        params.extend_from_slice(&seq.to_le_bytes());
        params.extend_from_slice(&0u16.to_le_bytes());
        let mut bytes = Vec::new();
        bytes.extend_from_slice(data);
        (params, bytes)
    }
}

/// LOGOFF_ANDX response (AndX triple only).
#[derive(Debug)]
pub struct LogoffResp;
impl LogoffResp {
    /// Build WC=2 terminal AndX body.
    pub fn body() -> (Vec<u8>, Vec<u8>) {
        (vec![0xFF, 0, 0, 0], Vec::new())
    }
}

/// TREE_DISCONNECT response (WC=0).
#[derive(Debug)]
pub struct TreeDisconnectResp;
impl TreeDisconnectResp {
    /// Build WC=0 body.
    pub fn body() -> (Vec<u8>, Vec<u8>) {
        (Vec::new(), Vec::new())
    }
}

/// QUERY_INFORMATION_DISK response (WC=5).
#[derive(Debug)]
pub struct QueryDiskInfo {
    /// Total allocation units.
    pub total_units: u32,
    /// Free allocation units.
    pub free_units: u32,
    /// Bytes per sector.
    pub bps: u16,
    /// Sectors per cluster/unit.
    pub spc: u16,
}

impl QueryDiskInfo {
    /// Encode WC=5 parameter block.
    pub fn encode(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(10);
        p.extend_from_slice(&self.total_units.to_le_bytes());
        p.extend_from_slice(&self.free_units.to_le_bytes());
        p.extend_from_slice(&self.bps.to_le_bytes());
        p.extend_from_slice(&self.spc.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // reserved
        p
    }
}

/// SEEK request ([MS-CIFS] §2.2.4.x): FID, mode, offset.
#[derive(Debug)]
pub struct SeekReq {
    /// Open file identifier.
    pub fid: u16,
    /// Origin mode (0 start / 1 current / 2 end).
    pub mode: u16,
    /// Signed offset from that origin.
    pub offset: i64,
}

impl SeekReq {
    /// Parse WC=4 words.
    pub fn parse(words: &[u8]) -> Option<Self> {
        if words.len() < 8 {
            return None;
        }
        Some(SeekReq {
            fid: u16le(words, 0),
            mode: u16le(words, 2),
            offset: i32::from_le_bytes(words.get(4..8)?.try_into().ok()?) as i64,
        })
    }

    /// Build WC=2 response carrying the resulting position.
    pub fn build_response(new_pos: u64) -> Vec<u8> {
        (new_pos as u32).to_le_bytes().to_vec()
    }
}

/// LOCKING_ANDX request — accepted but not enforced ([MS-CIFS] §2.2.4.32).
#[derive(Debug)]
pub struct LockingAndxReq;

impl LockingAndxReq {
    /// Build the WC=2 success response (terminal AndX triple).
    pub fn build_response() -> Vec<u8> {
        vec![0xFF, 0, 0, 0]
    }
}

/// NT_CANCEL has no dedicated response beyond a CANCELLED status echo.
#[derive(Debug)]
pub struct NtCancel;

fn u32le(w: &[u8], off: usize) -> u32 {
    w.get(off..off + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

// Core SMB1 wire-format helpers: header codec, constants, NTSTATUS codes,
// FILETIME conversion, byte reader/writer utilities.

pub const SMB_MAGIC: [u8; 4] = [0xFF, b'S', b'M', b'B'];

// ---- Commands ----
pub const COM_CREATE_DIRECTORY: u8 = 0x00;
pub const COM_DELETE_DIRECTORY: u8 = 0x01;
pub const COM_OPEN: u8 = 0x02;
pub const COM_CREATE: u8 = 0x03;
pub const COM_CLOSE: u8 = 0x04;
pub const COM_FLUSH: u8 = 0x05;
pub const COM_DELETE: u8 = 0x06;
pub const COM_RENAME: u8 = 0x07;
pub const COM_QUERY_INFORMATION: u8 = 0x08;
pub const COM_SET_INFORMATION: u8 = 0x09;
pub const COM_READ: u8 = 0x0A;
pub const COM_WRITE: u8 = 0x0B;
pub const COM_LOCK_BYTE_RANGE: u8 = 0x0C;
pub const COM_UNLOCK_BYTE_RANGE: u8 = 0x0D;
pub const COM_CHECK_DIRECTORY: u8 = 0x10;
pub const COM_PROCESS_EXIT: u8 = 0x11;
pub const COM_SEEK: u8 = 0x12;
pub const COM_LOCKING_ANDX: u8 = 0x24;
pub const COM_TRANSACTION: u8 = 0x25;
pub const COM_ECHO: u8 = 0x26;
pub const COM_OPEN_ANDX: u8 = 0x2D;
pub const COM_READ_ANDX: u8 = 0x2E;
pub const COM_WRITE_ANDX: u8 = 0x2F;
pub const COM_TRANSACTION2: u8 = 0x32;
pub const COM_NEGOTIATE: u8 = 0x72;
pub const COM_TREE_DISCONNECT: u8 = 0x71;
pub const COM_SESSION_SETUP_ANDX: u8 = 0x73;
pub const COM_LOGOFF_ANDX: u8 = 0x74;
pub const COM_TREE_CONNECT_ANDX: u8 = 0x75;
pub const COM_QUERY_INFORMATION_DISK: u8 = 0x80;
pub const COM_SEARCH: u8 = 0x81;
pub const COM_NT_TRANSACT: u8 = 0xA0;
pub const COM_NT_CREATE_ANDX: u8 = 0xA2;
pub const COM_NT_CANCEL: u8 = 0xA4;
pub const COM_NT_RENAME: u8 = 0xA5;

// ---- Header flags ----
pub const FLAGS_RESPONSE: u8 = 0x80;
pub const FLAGS_CASE_SENSITIVE: u8 = 0x08;

// ---- Header flags2 ----
pub const FLAGS2_LONG_NAMES: u16 = 0x0001;
pub const FLAGS2_UNICODE: u16 = 0x8000;
pub const FLAGS2_NT_STATUS: u16 = 0x4000;

// ---- Negotiate capabilities ----
pub const CAP_UNICODE: u32 = 0x0004;
pub const CAP_LARGE_FILES: u32 = 0x0008;
pub const CAP_NT_SMBS: u32 = 0x0010;
pub const CAP_STATUS32: u32 = 0x0040;
pub const CAP_LEVEL2_OPLOCKS: u32 = 0x0080;
pub const CAP_LOCK_AND_READ: u32 = 0x0100;
pub const CAP_NT_FIND: u32 = 0x0200;
pub const CAP_INFOLEVEL_PASSTHRU: u32 = 0x2000;
pub const CAP_LARGE_READX: u32 = 0x4000_0000;
pub const CAP_LARGE_WRITEX: u32 = 0x8000_0000;

pub const SEC_MODE_USER: u8 = 0x01;
pub const SEC_MODE_ENCRYPT: u8 = 0x02;

// ---- File attributes ----
pub const ATTR_READONLY: u32 = 0x001;
pub const ATTR_HIDDEN: u32 = 0x002;
pub const ATTR_SYSTEM: u32 = 0x004;
pub const ATTR_DIRECTORY: u32 = 0x010;
pub const ATTR_ARCHIVE: u32 = 0x020;
pub const ATTR_NORMAL: u32 = 0x080;

// ---- Create dispositions ----
pub const DISP_SUPERSEDE: u32 = 0;
pub const DISP_OPEN: u32 = 1;
pub const DISP_CREATE: u32 = 2;
pub const DISP_OPEN_IF: u32 = 3;
pub const DISP_OVERWRITE: u32 = 4;
pub const DISP_OVERWRITE_IF: u32 = 5;

// ---- Create options ----
pub const OPT_DIRECTORY_FILE: u32 = 0x1;
pub const OPT_NON_DIRECTORY_FILE: u32 = 0x40;
pub const OPT_DELETE_ON_CLOSE: u32 = 0x1000;

// ---- Access rights ----
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const DELETE_ACCESS: u32 = 0x0001_0000;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_READ_ATTRS: u32 = 0x0080;
pub const FILE_WRITE_ATTRS: u32 = 0x0100;

// ---- TRANS2 subcommands ----
pub const TRANS2_FIND_FIRST2: u16 = 0x0001;
pub const TRANS2_FIND_NEXT2: u16 = 0x0002;
pub const TRANS2_QUERY_FS_INFO: u16 = 0x0003;
pub const TRANS2_SET_FS_INFO: u16 = 0x0004;
pub const TRANS2_QUERY_PATH_INFO: u16 = 0x0005;
pub const TRANS2_SET_PATH_INFO: u16 = 0x0006;
pub const TRANS2_QUERY_FILE_INFO: u16 = 0x0007;
pub const TRANS2_SET_FILE_INFO: u16 = 0x0008;

// Find information levels
pub const FIND_INFO_STANDARD: u16 = 0x001;
pub const FIND_INFO_DIRECTORY: u16 = 0x102;
pub const FIND_INFO_FULL: u16 = 0x103;
pub const FIND_INFO_BOTH: u16 = 0x104;
pub const FIND_INFO_NAMES: u16 = 0x105;

// Query/Set info levels (non pass-through)
pub const QL_BASIC: u16 = 0x004;
pub const QL_STANDARD: u16 = 0x005;
pub const QL_EA_SIZE: u16 = 0x006;
pub const QL_ALL_EAS: u16 = 0x007;
pub const QL_STREAMS: u16 = 0x010;
// Pass-through
pub const QL_PT_BASIC: u16 = 0x1004;
pub const QL_PT_STANDARD: u16 = 0x1005;
pub const QL_PT_INTERNAL: u16 = 0x1006;
pub const QL_PT_EA: u16 = 0x1007;
pub const QL_PT_ACCESS: u16 = 0x1008;
pub const QL_PT_NAME: u16 = 0x1009;
pub const QL_PT_ALLOC: u16 = 0x100B;
pub const QL_PT_EOF: u16 = 0x100C;
pub const QL_PT_DISPOSITION: u16 = 0x100D;
pub const QL_PT_ALL: u16 = 0x1012;
pub const QL_PT_ALT_NAME: u16 = 0x1015;
pub const QL_PT_STREAMS: u16 = 0x1016;

pub const SL_BASIC: u16 = 0x101;
pub const SL_DISPOSITION: u16 = 0x102;
pub const SL_ALLOC: u16 = 0x103;
pub const SL_EOF: u16 = 0x104;

// Query FS info levels
pub const FS_VOLUME_INFO: u16 = 0x102;
pub const FS_SIZE_INFO: u16 = 0x103;
pub const FS_DEVICE_INFO: u16 = 0x201;
pub const FS_ATTRIBUTE_INFO: u16 = 0x202;

// ---- NTSTATUS codes ----
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Status(pub u32);

impl Status {
    pub const SUCCESS: Status = Status(0x0000_0000);
    pub const UNSUCCESSFUL: Status = Status(0xC000_0001);
    pub const NOT_IMPLEMENTED: Status = Status(0xC000_0002);
    pub const END_OF_FILE: Status = Status(0xC000_0011);
    pub const INVALID_HANDLE: Status = Status(0xC000_0008);
    pub const INVALID_PARAMETER: Status = Status(0xC000_000D);
    pub const NO_SUCH_FILE: Status = Status(0xC000_000F);
    pub const LOGON_FAILURE: Status = Status(0xC000_006D);
    pub const OBJECT_NAME_NOT_FOUND: Status = Status(0xC000_0034);
    pub const OBJECT_NAME_COLLISION: Status = Status(0xC000_0035);
    pub const OBJECT_PATH_NOT_FOUND: Status = Status(0xC000_003A);
    pub const ACCESS_DENIED: Status = Status(0xC000_0022);
    pub const SHARING_VIOLATION: Status = Status(0xC000_0043);
    pub const DELETE_PENDING: Status = Status(0xC000_0056);
    pub const MORE_PROCESSING_REQUIRED: Status = Status(0xC000_0016);
    pub const DIRECTORY_NOT_EMPTY: Status = Status(0xC000_0101);
    pub const NOT_A_DIRECTORY: Status = Status(0xC000_0103);
    pub const FILE_IS_A_DIRECTORY: Status = Status(0xC000_00BA);
    pub const BAD_NETWORK_NAME: Status = Status(0xC000_00CC);
    pub const CANCELLED: Status = Status(0xC000_0120);
    pub const NO_MORE_FILES: Status = Status(0x8000_0006);
    pub const INVALID_DEVICE_REQUEST: Status = Status(0xC000_0010);
}

// DOS error classes/codes for clients that don't do NT_STATUS.
pub fn to_dos(s: Status) -> (u8, u8) {
    match s {
        Status::SUCCESS => (0, 0),
        Status::OBJECT_NAME_NOT_FOUND | Status::NO_SUCH_FILE | Status::OBJECT_PATH_NOT_FOUND => {
            (0x01, 0x52) // ERRbadfile
        }
        Status::OBJECT_NAME_COLLISION => (0x01, 0x50), // ERRfilexists
        Status::ACCESS_DENIED => (0x01, 0x05),         // ERRnoaccess
        Status::SHARING_VIOLATION => (0x01, 0x20),     // ERRshare
        Status::INVALID_HANDLE | Status::BAD_NETWORK_NAME => (0x01, 0x51), // ERRbadfid
        Status::DIRECTORY_NOT_EMPTY => (0x01, 0x05),
        Status::END_OF_FILE | Status::NO_MORE_FILES => (0x01, 0x12), // ERRnomorefiles
        _ => (0x02, 0x01), // ERRgeneral / SRV class
    }
}

// ---- FILETIME ----
pub const WIN_EPOCH_SECS: i64 = 11_644_473_600;

pub fn unix_to_filetime(secs: i64, nanos: u32) -> u64 {
    let t = (secs + WIN_EPOCH_SECS) as i128 * 10_000_000i128 + nanos as i128 / 100;
    if t <= 0 { 0 } else { t as u64 }
}

pub fn filetime_to_unix(ft: u64) -> (i64, u32) {
    if ft == 0 { return (0, 0); }
    let total = ft as i128 - WIN_EPOCH_SECS as i128 * 10_000_000i128;
    if total < 0 { return (0, 0); }
    let secs = (total / 10_000_000) as i64;
    let nanos = ((total % 10_000_000) * 100) as u32;
    (secs, nanos)
}

pub fn now_filetime() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    unix_to_filetime(now.as_secs() as i64, now.subsec_nanos())
}

// ---- Byte reader ----
pub struct Rd<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Rd<'a> {
    pub fn new(buf: &'a [u8], pos: usize) -> Self {
        Rd { buf, pos }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    pub fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }
    pub fn u8(&mut self) -> u8 {
        let v = *self.buf.get(self.pos).unwrap_or(&0);
        self.pos += 1;
        v
    }
    pub fn u16le(&mut self) -> u16 {
        let a = self.u8() as u16;
        a | ((self.u8() as u16) << 8)
    }
    pub fn u32le(&mut self) -> u32 {
        let a = self.u16le() as u32;
        a | ((self.u16le() as u32) << 16)
    }
    pub fn u64le(&mut self) -> u64 {
        let a = self.u32le() as u64;
        a | ((self.u32le() as u64) << 32)
    }
    pub fn skip(&mut self, n: usize) {
        self.pos += n;
    }
    /// Null-terminated string honoring unicode flag.
    pub fn zstring(&mut self, unicode: bool, base: usize) -> String {
        if unicode {
            // Unicode strings must start at an even offset from SMB start.
            if (base + self.pos) & 1 != 0 && !self.at_end() {
                self.pos += 1;
            }
            let mut units = Vec::new();
            while self.pos + 1 < self.buf.len() {
                let lo = self.u8();
                let hi = self.u8();
                let u = lo as u16 | ((hi as u16) << 8);
                if u == 0 {
                    break;
                }
                units.push(u);
            }
            String::from_utf16_lossy(&units)
        } else {
            let mut bytes = Vec::new();
            while self.pos < self.buf.len() {
                let b = self.u8();
                if b == 0 {
                    break;
                }
                bytes.push(b);
            }
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }
    pub fn fixed_string(&mut self, len: usize, unicode: bool) -> String {
        let end = (self.pos + len).min(self.buf.len());
        let raw = &self.buf[self.pos..end];
        self.pos = end;
        if unicode {
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(raw).into_owned()
        }
    }
}

// ---- Byte writer ----
#[derive(Default)]
pub struct Wr {
    pub buf: Vec<u8>,
}

impl Wr {
    pub fn new() -> Self {
        Wr { buf: Vec::new() }
    }
    pub fn u8v(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16v(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u32v(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64v(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    pub fn pad_to_parity(&mut self, base: usize) {
        if (base + self.buf.len()) & 1 != 0 {
            self.buf.push(0);
        }
    }
    /// Append null-terminated string honoring unicode.
    pub fn zstring(&mut self, s: &str, unicode: bool, base: usize) {
        if unicode {
            self.pad_to_parity(base);
            for unit in s.encode_utf16() {
                self.buf.extend_from_slice(&unit.to_le_bytes());
            }
            self.buf.extend_from_slice(&[0, 0]);
        } else {
            self.buf.extend_from_slice(s.as_bytes());
            self.buf.push(0);
        }
    }
}

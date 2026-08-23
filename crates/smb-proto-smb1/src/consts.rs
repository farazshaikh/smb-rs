//! SMB1 command opcodes ([MS-CIFS] §2.2.2, extended by [MS-SMB] §2.2.4).

/// SMB_COM_CREATE_DIRECTORY.
pub const COM_CREATE_DIRECTORY: u8 = 0x00;
/// SMB_COM_DELETE_DIRECTORY.
pub const COM_DELETE_DIRECTORY: u8 = 0x01;
/// SMB_COM_CLOSE.
pub const COM_CLOSE: u8 = 0x04;
/// SMB_COM_FLUSH.
pub const COM_FLUSH: u8 = 0x05;
/// SMB_COM_DELETE.
pub const COM_DELETE: u8 = 0x06;
/// SMB_COM_RENAME.
pub const COM_RENAME: u8 = 0x07;
/// SMB_COM_QUERY_INFORMATION.
pub const COM_QUERY_INFORMATION: u8 = 0x08;
/// SMB_COM_SET_INFORMATION.
pub const COM_SET_INFORMATION: u8 = 0x09;
/// SMB_COM_CHECK_DIRECTORY.
pub const COM_CHECK_DIRECTORY: u8 = 0x10;
/// SMB_COM_PROCESS_EXIT.
pub const COM_PROCESS_EXIT: u8 = 0x11;
/// SMB_COM_SEEK.
pub const COM_SEEK: u8 = 0x12;
/// SMB_COM_LOCKING_ANDX (byte-range locks).
pub const COM_LOCKING_ANDX: u8 = 0x24;
/// SMB_COM_ECHO.
pub const COM_ECHO: u8 = 0x26;
/// SMB_COM_NT_CANCEL.
pub const COM_NT_CANCEL: u8 = 0xA4;
/// SMB_COM_NT_RENAME.
pub const COM_NT_RENAME: u8 = 0xA5;
/// SMB_COM_READ_ANDX.
pub const COM_READ_ANDX: u8 = 0x2E;
/// SMB_COM_WRITE_ANDX.
pub const COM_WRITE_ANDX: u8 = 0x2F;
/// SMB_COM_TRANSACTION2.
pub const COM_TRANSACTION2: u8 = 0x32;
/// SMB_COM_TREE_DISCONNECT.
pub const COM_TREE_DISCONNECT: u8 = 0x71;
/// SMB_COM_NEGOTIATE ([MS-SMB] §2.2.4.5).
pub const COM_NEGOTIATE: u8 = 0x72;
/// SMB_COM_SESSION_SETUP_ANDX ([MS-SMB] §2.2.4.6).
pub const COM_SESSION_SETUP_ANDX: u8 = 0x73;
/// SMB_COM_LOGOFF_ANDX.
pub const COM_LOGOFF_ANDX: u8 = 0x74;
/// SMB_COM_TREE_CONNECT_ANDX ([MS-SMB] §2.2.4.7).
pub const COM_TREE_CONNECT_ANDX: u8 = 0x75;
/// SMB_COM_QUERY_INFORMATION_DISK.
pub const COM_QUERY_INFORMATION_DISK: u8 = 0x80;
/// SMB_COM_NT_CREATE_ANDX ([MS-SMB] §2.2.4.9).
pub const COM_NT_CREATE_ANDX: u8 = 0xA2;

/// AndX terminator: no successor command follows.
pub const ANDX_NONE: u8 = 0xFF;

/// Header flags ([MS-CIFS] §2.2.1.2).
pub mod flags {
    /// This message is a response.
    pub const RESPONSE: u8 = 0x80;
    /// Case-insensitive pathnames requested.
    pub const CASE_SENSITIVE: u8 = 0x08;
}

/// Header flags2 ([MS-CIFS] §2.2.1.3, extended by [MS-SMB]).
pub mod flags2 {
    /// Long file names supported/used.
    pub const LONG_NAMES: u16 = 0x0001;
    /// Strings are UTF-16LE.
    pub const UNICODE: u16 = 0x8000;
    /// Status field carries NTSTATUS codes instead of DOS errors.
    pub const NT_STATUS: u16 = 0x4000;
}

/// Server capabilities advertised at negotiate time ([MS-SMB] §2.2.4.5).
pub mod caps {
    /// Unicode string support.
    pub const CAP_UNICODE: u32 = 0x0000_0004;
    /// 64-bit file offsets.
    pub const CAP_LARGE_FILES: u32 = 0x0000_0008;
    /// NT SMB command set (`NT_CREATE_ANDX`, TRANS2 pass-through, …).
    pub const CAP_NT_SMBS: u32 = 0x0000_0010;
    /// NT status codes in the header status field.
    pub const CAP_STATUS32: u32 = 0x0000_0040;
    /// Level II oplocks.
    pub const CAP_LEVEL2_OPLOCKS: u32 = 0x0000_0080;
    /// Lock-and-read supported.
    pub const CAP_LOCK_AND_READ: u32 = 0x0000_0100;
    /// NT-style FIND commands.
    pub const CAP_NT_FIND: u32 = 0x0000_0200;
    /// Pass-through information levels.
    pub const CAP_INFOLEVEL_PASSTHRU: u32 = 0x0000_2000;
    /// Large reads via READ_ANDX.
    pub const CAP_LARGE_READX: u32 = 0x4000_0000;
    /// Large writes via WRITE_ANDX.
    pub const CAP_LARGE_WRITEX: u32 = 0x8000_0000;
}

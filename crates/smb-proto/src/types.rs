//! Shared value types: NT status codes, FILETIME and attribute flags.

/// NT status code carried in the SMB header status field.
///
/// Values follow the `NTSTATUS` numbering used throughout [MS-SMB]/[MS-CIFS];
/// when the client did not negotiate `CAP_STATUS32` the dispatcher converts
/// these to DOS class/code pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status(pub u32);

impl Status {
    /// The operation completed successfully.
    pub const SUCCESS: Status = Status(0x0000_0000);
    /// Generic failure.
    pub const UNSUCCESSFUL: Status = Status(0xC000_0001);
    /// Function not implemented by this server.
    pub const NOT_IMPLEMENTED: Status = Status(0xC000_0002);
    /// A create traversed a symbolic link ([MS-SMB2] §2.2.2.2.1).
    pub const STOPPED_ON_SYMLINK: Status = Status(0x8000_002D);
    /// End of file reached during a read.
    pub const END_OF_FILE: Status = Status(0xC000_0011);
    /// The supplied handle (FID) is not valid on this session/tree.
    pub const INVALID_HANDLE: Status = Status(0xC000_0008);
    /// A parameter passed to the operation was invalid.
    pub const INVALID_PARAMETER: Status = Status(0xC000_000D);
    /// Requested file does not exist.
    pub const NO_SUCH_FILE: Status = Status(0xC000_000F);
    /// Supplied credentials are invalid.
    pub const LOGON_FAILURE: Status = Status(0xC000_006D);
    /// More processing is required (multi-leg authentication).
    pub const MORE_PROCESSING_REQUIRED: Status = Status(0xC000_0016);
    /// The object name was not found.
    pub const OBJECT_NAME_NOT_FOUND: Status = Status(0xC000_0034);
    /// An object with the given name already exists.
    pub const OBJECT_NAME_COLLISION: Status = Status(0xC000_0035);
    /// A component of the path was not found.
    pub const OBJECT_PATH_NOT_FOUND: Status = Status(0xC000_003A);
    /// Access to the object was denied.
    pub const ACCESS_DENIED: Status = Status(0xC000_0022);
    /// The output buffer was too small to hold the requested data.
    pub const BUFFER_TOO_SMALL: Status = Status(0xC000_0023);
    /// The requested item was not found (e.g. a non-DFS path for a referral).
    pub const NOT_FOUND: Status = Status(0xC000_0225);
    /// Another handle holds a conflicting open on the object.
    pub const SHARING_VIOLATION: Status = Status(0xC000_0043);
    /// Deletion has already been requested for this object.
    pub const DELETE_PENDING: Status = Status(0xC000_0056);
    /// Cannot remove a directory that still contains entries.
    pub const DIRECTORY_NOT_EMPTY: Status = Status(0xC000_0101);
    /// An operation expected a file but found a directory (or vice versa).
    pub const NOT_A_DIRECTORY: Status = Status(0xC000_0103);
    /// An operation expected a directory but found a file.
    pub const FILE_IS_A_DIRECTORY: Status = Status(0xC000_00BA);
    /// The share name is unknown to the server.
    pub const BAD_NETWORK_NAME: Status = Status(0xC000_00CC);
    /// The tree connect referenced by TreeId no longer exists on the server.
    pub const NETWORK_NAME_DELETED: Status = Status(0xC000_00C9);
    /// A prior open was force-closed by an application-instance failover.
    pub const FILE_FORCED_CLOSED: Status = Status(0xC000_00B6);
    /// The handle was closed out from under this open (app-instance failover).
    pub const FILE_CLOSED: Status = Status(0xC000_0128);
    /// The request was cancelled by the client.
    pub const CANCELLED: Status = Status(0xC000_0120);
    /// A pending CHANGE_NOTIFY was completed because its handle was closed
    /// ([MS-SMB2] §3.3.5.10). Severity is success, so clients treat the
    /// CHANGE_NOTIFY response as a (non-error) notification.
    pub const NOTIFY_CLEANUP: Status = Status(0x0000_010B);
    /// A byte-range lock request conflicts with an existing lock
    /// ([MS-SMB2] §2.2.26, STATUS_LOCK_NOT_GRANTED).
    pub const LOCK_NOT_GRANTED: Status = Status(0xC000_0055);
    /// A read/write overlapped a conflicting byte-range lock ([MS-SMB2] §2.2.26).
    pub const FILE_LOCK_CONFLICT: Status = Status(0xC000_0054);
    /// SMB 3.1.1 negotiate carried no hash algorithm the server supports
    /// ([MS-SMB2] §3.3.5.4).
    pub const SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP: Status = Status(0xC05D_0000);
    /// The operation is being processed asynchronously; an interim response
    /// ([MS-SMB2] §3.3.4.2) precedes the final one.
    pub const PENDING: Status = Status(0x0000_0103);
    /// No more matching directory entries (warning severity).
    pub const NO_MORE_FILES: Status = Status(0x8000_0006);
    /// The request specified an unknown device or request type.
    pub const INVALID_DEVICE_REQUEST: Status = Status(0xC000_0010);

    /// Raw NTSTATUS value.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// True when the severity bits indicate an error (severity 3).
    pub fn is_error(self) -> bool {
        self.0 & 0xC000_0000 == 0xC000_0000
    }

    /// Map to a DOS error `(class, code)` for clients without
    /// `CAP_STATUS32` ([MS-CIFS] §2.2.2.4 error classes and codes).
    pub fn to_dos(self) -> (u8, u8) {
        match self {
            Self::SUCCESS => (0x00, 0x00),
            Self::OBJECT_NAME_NOT_FOUND | Self::NO_SUCH_FILE | Self::OBJECT_PATH_NOT_FOUND => {
                (0x01, 0x52) // ERRbadfile
            }
            Self::OBJECT_NAME_COLLISION => (0x01, 0x50), // ERRfilexists
            Self::ACCESS_DENIED => (0x01, 0x05),         // ERRnoaccess
            Self::SHARING_VIOLATION => (0x01, 0x20),     // ERRshare
            Self::DIRECTORY_NOT_EMPTY => (0x01, 0x05),
            Self::END_OF_FILE | Self::NO_MORE_FILES => (0x01, 0x12), // ERRnomorefiles
            _ => (0x02, 0x01),                                       // ERRSRV/ERRgeneral
        }
    }
}

/// Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
/// ([MS-DTYP] §2.3.3). Zero denotes "not set".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileTime(pub u64);

/// Seconds between the Windows epoch (1601) and the Unix epoch (1970).
pub const WIN_EPOCH_SECS: i64 = 11_644_473_600;

impl FileTime {
    /// Current system time as FILETIME.
    pub fn now() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_unix(d.as_secs() as i64, d.subsec_nanos())
    }

    /// Build from Unix seconds + nanoseconds.
    pub fn from_unix(secs: i64, nanos: u32) -> Self {
        let t = (secs + WIN_EPOCH_SECS) as i128 * 10_000_000 + nanos as i128 / 100;
        FileTime(if t <= 0 { 0 } else { t as u64 })
    }

    /// Convert to Unix `(seconds, nanoseconds)`; saturates at the epoch.
    pub fn to_unix(self) -> (i64, u32) {
        if self.0 == 0 {
            return (0, 0);
        }
        let total = self.0 as i128 - WIN_EPOCH_SECS as i128 * 10_000_000;
        if total < 0 {
            return (0, 0);
        }
        ((total / 10_000_000) as i64, ((total % 10_000_000) * 100) as u32)
    }
}

/// File attribute flags ([MS-SMB] §2.2.1.2.1 / [MS-FSCC] §2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AttrFlags(pub u32);

impl AttrFlags {
    /// Read-only file.
    pub const READONLY: u32 = 0x0000_0001;
    /// Hidden file.
    pub const HIDDEN: u32 = 0x0000_0002;
    /// System file.
    pub const SYSTEM: u32 = 0x0000_0004;
    /// Directory.
    pub const DIRECTORY: u32 = 0x0000_0010;
    /// Archive bit.
    pub const ARCHIVE: u32 = 0x0000_0020;
    /// Normal file (no other attributes).
    pub const NORMAL: u32 = 0x0000_0080;

    /// Wrap raw attribute bits.
    pub fn new(bits: u32) -> Self {
        AttrFlags(bits)
    }

    /// True when [`AttrFlags::DIRECTORY`] is set.
    pub fn is_directory(self) -> bool {
        self.0 & Self::DIRECTORY != 0
    }
}

/// NT create disposition ([MS-SMB] §2.2.4.9.1 `CreateDisposition`,
/// originally [MS-CIFS] §2.2.4.63.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Overwrite existing or create new (attributes superseded).
    Supersede,
    /// Open only; fail when missing.
    Open,
    /// Create only; fail when present.
    Create,
    /// Open existing or create new.
    OpenIf,
    /// Open existing and truncate; fail when missing.
    Overwrite,
    /// Truncate-or-create.
    OverwriteIf,
}

impl Disposition {
    /// From the wire `CreateDisposition` field.
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Supersede,
            1 => Self::Open,
            2 => Self::Create,
            3 => Self::OpenIf,
            4 => Self::Overwrite,
            5 => Self::OverwriteIf,
            _ => return None,
        })
    }
}

/// Result of a create/open operation (`FILE_*` action codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateAction {
    /// Existing file was replaced (`FILE_SUPERSEDED`).
    Superseded,
    /// Existing file was opened (`FILE_OPENED`).
    Opened,
    /// New file was created (`FILE_CREATED`).
    Created,
    /// Existing file was overwritten (`FILE_OVERWRITTEN`).
    Overwritten,
}

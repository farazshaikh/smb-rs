//! Dialect-neutral virtual filesystem interface.
//!
//! Protocol dispatchers (SMB1/SMB2) translate incoming commands into the
//! operations of the [`Vfs`] trait; storage backends implement those
//! operations. This keeps information-level encoding, access-mask mapping
//! and status translation entirely inside the protocol layers.
//!
//! Every method receives an [`IoCtxView`](crate::IoCtxView)-free simple
//! signature on purpose: backends only need the operation arguments plus the
//! [`OpenFile`] handle whose opaque `inner` they own.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

mod vfs;

pub use vfs::Vfs;

use smb_proto::types::{AttrFlags, FileTime};

/// An open file or directory handle owned by a backend.
///
/// The server tracks common bookkeeping (path, access flags, delete state);
/// backend-private state lives in [`OpenFile::inner`].
#[derive(Debug)]
pub struct OpenFile {
    /// Backend-relative path this handle was opened on (kept in sync across
    /// rename-by-handle).
    pub path: String,
    /// True when the handle refers to a directory.
    pub is_dir: bool,
    /// Read data access was granted at open time.
    pub can_read: bool,
    /// Write/append/delete-data access was granted at open time.
    pub can_write: bool,
    /// Delete-on-close requested via create options.
    pub delete_on_close: bool,
    /// Deletion requested through SET_INFORMATION; applied on close.
    pub delete_pending: bool,
    /// Opaque backend state (file descriptor wrapper, cached cursor, …).
    pub inner: Box<dyn std::any::Any + Send + Sync>,
}

impl OpenFile {
    /// Downcast the backend-private state to a concrete type.
    pub fn inner_as<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.inner.downcast_ref::<T>()
    }

    /// Immutably downcast the backend-private state (alias of [`Self::inner_as`]).
    pub fn inner_as_ref<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.inner.downcast_ref::<T>()
    }

    /// Mutably downcast the backend-private state to a concrete type.
    pub fn inner_as_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.inner.downcast_mut::<T>()
    }
}

/// Snapshot of file metadata shared between protocol layers and backends.
#[derive(Debug, Clone, Default)]
pub struct FileMeta {
    /// Creation / last-access / last-write / change times.
    pub times: [FileTime; 4],
    /// Attribute flags.
    pub attrs: AttrFlags,
    /// Allocation size in bytes (block rounded).
    pub alloc: u64,
    /// End of file in bytes.
    pub eof: u64,
    /// True when the object is a directory.
    pub is_dir: bool,
}

/// One directory enumeration entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// File name as presented to clients.
    pub name: String,
    /// Metadata snapshot for the entry.
    pub meta: FileMeta,
}

/// Neutralised set-information operations. Dialect layers translate their
/// wire levels into these before calling [`Vfs::set_info`].
#[derive(Debug, Clone)]
pub enum SetOp {
    /// Mark the object for deletion (`FILE_DISPOSITION_INFORMATION`).
    Disposition {
        /// True = delete when the last handle closes.
        delete: bool,
    },
    /// Set allocation size.
    Allocation(u64),
    /// Set end-of-file (truncate/extend).
    EndOfFile(u64),
    /// Update timestamps; `None` fields are left untouched
    /// (`FILE_BASIC_INFORMATION`).
    Basic {
        /// Last-write time to apply, if any.
        write: Option<FileTime>,
    },
    /// Rename the target to `name` relative to the share root.
    Rename {
        /// Whether an existing destination may be replaced.
        replace_if_exists: bool,
        /// New path relative to the share root.
        name: String,
    },
}

/// Errors returned by backends. Backends should map their native failures to
/// these; the protocol layer translates them into NT status codes.
#[derive(Debug, thiserror::Error)]
pub enum VfsError {
    /// Underlying I/O failure.
    #[error("vfs i/o: {0}")]
    Io(#[from] std::io::Error),
    /// Object does not exist.
    #[error("not found")]
    NotFound,
    /// Object already exists.
    #[error("already exists")]
    AlreadyExists,
    /// Operation not permitted for this principal.
    #[error("access denied")]
    AccessDenied,
    /// Directory not empty during removal.
    #[error("directory not empty")]
    DirectoryNotEmpty,
    /// A parameter was out of range or malformed.
    #[error("invalid argument")]
    InvalidArgument,
    /// The backend does not implement the requested operation.
    #[error("not supported")]
    NotSupported,
}

/// Result alias used throughout the VFS surface.
pub type VfsResult<T> = Result<T, VfsError>;

/// Map an [`std::io::Error`] onto the closest [`VfsError`].
pub fn map_io(e: std::io::Error) -> VfsError {
    match e.kind() {
        std::io::ErrorKind::NotFound => VfsError::NotFound,
        std::io::ErrorKind::PermissionDenied => VfsError::AccessDenied,
        std::io::ErrorKind::AlreadyExists => VfsError::AlreadyExists,
        std::io::ErrorKind::DirectoryNotEmpty => VfsError::DirectoryNotEmpty,
        _ => e.into(),
    }
}

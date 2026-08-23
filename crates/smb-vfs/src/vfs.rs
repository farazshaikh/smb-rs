//! The virtual filesystem trait every storage backend implements.

use async_trait::async_trait;

use crate::{Entry, FileMeta, OpenFile, SetOp, VfsResult};

/// Storage abstraction used by the protocol dispatchers.
///
/// Implementations own their handle state (inside
/// [`OpenFile::inner`](crate::OpenFile::inner)) and are responsible for
/// mapping relative share paths onto physical storage, including refusing
/// path traversal.
#[async_trait]
pub trait Vfs: Send + Sync {
    /// Create or open `rel` according to the NT-style parameters.
    ///
    /// Returns the populated [`OpenFile`], a metadata snapshot and the create
    /// action taken (superseded / opened / created / overwritten).
    async fn create(
        &self,
        rel: &str,
        is_dir: bool,
        access: u32,
        disposition: u32,
        options: u32,
        attrs: u32,
    ) -> VfsResult<(Box<OpenFile>, FileMeta, u32)>;

    /// Read up to `len` bytes at `offset`.
    async fn read(&self, open: &mut OpenFile, offset: u64, len: usize) -> VfsResult<Vec<u8>>;

    /// Write `data` at `offset`, returning bytes written. When `write_through`
    /// is set the data must reach stable storage before returning.
    async fn write(
        &self,
        open: &mut OpenFile,
        offset: u64,
        data: &[u8],
        write_through: bool,
    ) -> VfsResult<u64>;

    /// Reposition the file pointer; `mode` follows the SMB1 SEEK semantics
    /// (0 = from start, 1 = current, 2 = from end) and returns the new offset.
    async fn seek(&self, open: &mut OpenFile, mode: u16, offset: i64) -> VfsResult<u64>;

    /// Flush one handle.
    async fn flush(&self, open: &mut OpenFile) -> VfsResult<()>;

    /// Flush every handle the backend currently keeps.
    async fn flush_all(&self) -> VfsResult<()>;

    /// Close a handle, applying pending deletion when requested.
    async fn close(&self, open: Box<OpenFile>) -> VfsResult<()>;

    /// Create a directory.
    async fn mkdir(&self, rel: &str) -> VfsResult<()>;

    /// Remove an (empty) directory.
    async fn rmdir(&self, rel: &str) -> VfsResult<()>;

    /// Verify a directory exists.
    async fn check_dir(&self, rel: &str) -> VfsResult<()>;

    /// Delete exactly one file (never directories).
    async fn unlink(&self, rel: &str) -> VfsResult<()>;

    /// Delete all files matching `pattern` inside directory `dir_rel`;
    /// returns whether anything was removed. Wildcards `*`/`?` honoured.
    async fn delete_pattern(&self, dir_rel: &str, pattern: &str) -> VfsResult<bool>;

    /// Rename `old_rel` to `new_rel`.
    async fn rename(&self, old_rel: &str, new_rel: &str) -> VfsResult<()>;

    /// List entries of `dir_rel` with metadata snapshots.
    async fn list(&self, dir_rel: &str) -> VfsResult<Vec<Entry>>;

    /// Stat a path without opening it.
    async fn stat(&self, rel: &str) -> VfsResult<FileMeta>;

    /// Apply one neutral set-information operation to an open handle.
    async fn set_info_open(&self, open: &mut OpenFile, op: &SetOp) -> VfsResult<()>;

    /// Apply one neutral set-information operation to a path.
    async fn set_info_path(&self, rel: &str, op: &SetOp) -> VfsResult<()>;

    /// Query disk `(total_units, free_units, sectors_per_unit, bytes_per_sector)`.
    async fn query_disk(&self) -> VfsResult<(u32, u32, u16, u16)>;
}

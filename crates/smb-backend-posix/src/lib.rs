//! Default storage backend mapping the [`Vfs`] interface onto POSIX file
//! semantics.
//!
//! The data path (open / read / write / fsync) and mutating directory ops
//! (mkdir / rmdir / rename / unlink) run on **io_uring** via `tokio_uring::fs`
//! — non-blocking, zero-copy, completion-based. Read-only metadata and
//! directory *enumeration* use `std::fs` because Linux has no async / io_uring
//! `getdents` op; those are page-cache-backed syscalls that complete in
//! microseconds.
//!
//! All client paths are resolved inside the configured share root; `..`
//! traversal and absolute components are refused and existing entries are
//! matched case-insensitively to emulate Windows semantics.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

use async_trait::async_trait;
use smb_proto::types::{AttrFlags, Disposition, FileTime};
use smb_vfs::{map_io, Entry, FileMeta, OpenFile, SetOp, Vfs, VfsError, VfsResult};
use tokio_uring::fs::{File, OpenOptions};

/// POSIX backend rooted at a single directory.
#[derive(Debug)]
pub struct PosixVfs {
    root: std::path::PathBuf,
}

/// Backend-private state attached to every open handle.
///
/// Holds an io_uring [`File`], which is `!Send`; the handle therefore lives
/// entirely on its connection's runtime and is never sent across threads.
pub struct PosixInner {
    /// Open io_uring file (None for directory handles).
    pub file: Option<File>,
    /// Tracked cursor for SEEK support.
    pub pos: u64,
}

impl std::fmt::Debug for PosixInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PosixInner")
            .field("open", &self.file.is_some())
            .field("pos", &self.pos)
            .finish()
    }
}

impl PosixVfs {
    /// Create a backend serving `root`.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        // Canonicalize to an absolute root so paths stored on open handles are
        // absolute and re-resolve cleanly. With a relative root (e.g.
        // `./share`) the stored `./share/foo` would otherwise be treated as
        // share-relative on stat/set_info and double-prefix the root.
        let root = std::fs::canonicalize(&root).unwrap_or(root);
        PosixVfs { root }
    }

    fn resolve(&self, path: &str) -> std::path::PathBuf {
        // If already absolute and under our root (stored by create/open),
        // return as-is; otherwise treat as share-relative.
        let abs = std::path::PathBuf::from(path);
        if abs.is_absolute() && abs.starts_with(&self.root) {
            return abs;
        }
        resolve_under(&self.root, path)
    }
}

fn resolve_under(root: &std::path::Path, rel: &str) -> std::path::PathBuf {
    let mut cur = root.to_path_buf();
    for comp in rel.split(['\\', '/']) {
        if comp.is_empty() || comp == "." || comp == ".." || comp.contains(':') {
            continue;
        }
        cur.push(comp);
    }
    // Case-insensitive fix-up of components that already exist.
    let mut fixed = root.to_path_buf();
    let suffix = cur.strip_prefix(root).unwrap_or(std::path::Path::new(""));
    for comp in suffix.components() {
        let candidate = fixed.join(comp.as_os_str());
        if candidate.symlink_metadata().is_ok() {
            fixed.push(comp.as_os_str());
            continue;
        }
        match find_case_insensitive(&fixed, &comp.as_os_str().to_string_lossy()) {
            Some(actual) => fixed.push(actual),
            None => fixed.push(comp.as_os_str()),
        }
    }
    fixed
}

fn find_case_insensitive(dir: &std::path::Path, name: &str) -> Option<String> {
    let rd = std::fs::read_dir(dir).ok()?;
    let lower = name.to_lowercase();
    rd.flatten()
        .find(|e| e.file_name().to_string_lossy().to_lowercase() == lower)
        .map(|e| e.file_name().to_string_lossy().into_owned())
}

fn meta_of(md: &std::fs::Metadata) -> FileMeta {
    use std::os::unix::fs::MetadataExt;
    let attrs = AttrFlags::new(if md.is_dir() {
        AttrFlags::DIRECTORY
    } else if md.mode() & 0o222 == 0 {
        AttrFlags::ARCHIVE | AttrFlags::READONLY
    } else {
        AttrFlags::ARCHIVE
    });
    let eof = if md.is_dir() { 0 } else { md.len() };
    FileMeta {
        times: [
            FileTime::from_unix(md.ctime(), md.ctime_nsec() as u32),
            FileTime::from_unix(md.atime(), md.atime_nsec() as u32),
            FileTime::from_unix(md.mtime(), md.mtime_nsec() as u32),
            FileTime::from_unix(md.ctime(), md.ctime_nsec() as u32),
        ],
        alloc: ((eof + 4095) / 4096) * 4096,
        eof,
        attrs,
        is_dir: md.is_dir(),
    }
}

fn set_mtime(path: &std::path::Path, ft: u64) -> VfsResult<()> {
    use std::fs::FileTimes;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(map_io)?;
    let (secs, nanos) = FileTime(ft).to_unix();
    let t = std::time::SystemTime::UNIX_EPOCH
        + std::time::Duration::new(secs.max(0) as u64, nanos);
    f.set_times(FileTimes::new().set_modified(t)).map_err(map_io)?;
    Ok(())
}

/// DOS wildcard match supporting `*` and `?` (case-insensitive callers).
pub fn wildcard_match(name: &str, pattern: &str) -> bool {
    fn rec(s: &[char], p: &[char]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        match p[0] {
            '*' => (0..=s.len()).any(|i| rec(&s[i..], &p[1..])),
            '?' => !s.is_empty() && rec(&s[1..], &p[1..]),
            c => !s.is_empty() && s[0] == c && rec(&s[1..], &p[1..]),
        }
    }
    rec(&name.chars().collect::<Vec<_>>(), &pattern.chars().collect::<Vec<_>>())
}

#[async_trait(?Send)]
impl Vfs for PosixVfs {
    async fn create(
        &self,
        rel: &str,
        is_dir: bool,
        access: u32,
        disposition: u32,
        options: u32,
        _attrs: u32,
    ) -> VfsResult<(Box<OpenFile>, FileMeta, u32)> {
        const OPT_DIRECTORY_FILE: u32 = 0x1;
        const OPT_DELETE_ON_CLOSE: u32 = 0x1000;

        let path = self.resolve(rel);
        let want_dir = is_dir || options & OPT_DIRECTORY_FILE != 0;
        let existing = std::fs::symlink_metadata(&path).ok();
        let exists = existing.is_some();
        let existing_is_dir = existing.as_ref().map(|m| m.is_dir()).unwrap_or(false);

        // Directory handle: no io_uring file object, create the directory tree
        // if needed ([MS-SMB2] FILE_DIRECTORY_FILE).
        if want_dir || existing_is_dir {
            let action = if exists {
                1
            } else {
                match Disposition::from_u32(disposition) {
                    Some(Disposition::Open) | Some(Disposition::Overwrite) => {
                        return Err(VfsError::NotFound)
                    }
                    _ => {}
                }
                tokio_uring::fs::create_dir_all(&path).await.map_err(map_io)?;
                2
            };
            let md = std::fs::metadata(&path).map_err(map_io)?;
            let open = Box::new(OpenFile {
                path: path.to_string_lossy().into_owned(),
                rel: rel.to_string(),
                is_dir: true,
                can_read: true,
                can_write: false,
                delete_on_close: options & OPT_DELETE_ON_CLOSE != 0,
                delete_pending: false,
                inner: Box::new(PosixInner { file: None, pos: 0 }),
            });
            return Ok((open, meta_of(&md), action));
        }

        // Regular file: derive create/truncate semantics from the disposition.
        let (action, truncate, create) = if exists {
            match Disposition::from_u32(disposition) {
                Some(Disposition::Supersede) => (0u32, true, false),
                Some(Disposition::Overwrite) | Some(Disposition::OverwriteIf) => (3, true, false),
                _ => (1, false, false),
            }
        } else {
            match Disposition::from_u32(disposition) {
                Some(Disposition::Open) | Some(Disposition::Overwrite) => {
                    return Err(VfsError::NotFound)
                }
                _ => {}
            }
            if let Some(parent) = path.parent() {
                let _ = tokio_uring::fs::create_dir_all(parent).await;
            }
            (2, false, true)
        };

        let read_access =
            access & (0x8000_0000 | 0x0000_0001 | 0x0000_0008 | 0x0000_0080 | 0x1000_0000) != 0;
        let write_access = access
            & (0x4000_0000 | 0x0000_0002 | 0x0000_0004 | 0x0001_0000 | 0x2000_0000 | 0x1000_0000)
            != 0;

        let mut oo = OpenOptions::new();
        oo.read(read_access || !write_access);
        oo.write(write_access || truncate || create);
        if create {
            oo.create(true);
        }
        if truncate {
            oo.truncate(true);
        }
        let file = oo.open(&path).await.map_err(map_io)?;
        let md = std::fs::metadata(&path).map_err(map_io)?;

        let open = Box::new(OpenFile {
            path: path.to_string_lossy().into_owned(),
            rel: rel.to_string(),
            is_dir: false,
            can_read: read_access,
            can_write: write_access,
            delete_on_close: options & OPT_DELETE_ON_CLOSE != 0,
            delete_pending: false,
            inner: Box::new(PosixInner { file: Some(file), pos: 0 }),
        });
        Ok((open, meta_of(&md), action))
    }

    async fn read(&self, open: &mut OpenFile, offset: u64, len: usize) -> VfsResult<Vec<u8>> {
        let inner = open.inner_as_mut::<PosixInner>().ok_or(VfsError::NotSupported)?;
        let f = inner.file.as_ref().ok_or(VfsError::AccessDenied)?;
        // io_uring positional read; the buffer round-trips through the kernel.
        let (res, mut buf) = f.read_at(vec![0u8; len], offset).await;
        let n = res.map_err(map_io)?;
        buf.truncate(n);
        Ok(buf)
    }

    async fn write(
        &self,
        open: &mut OpenFile,
        offset: u64,
        data: &[u8],
        write_through: bool,
    ) -> VfsResult<u64> {
        let inner = open.inner_as_mut::<PosixInner>().ok_or(VfsError::NotSupported)?;
        let f = inner.file.as_ref().ok_or(VfsError::AccessDenied)?;
        let total = data.len();
        let (res, _buf) = f.write_all_at(data.to_vec(), offset).await;
        res.map_err(map_io)?;
        if write_through {
            f.sync_all().await.map_err(map_io)?;
        }
        Ok(total as u64)
    }

    async fn seek(&self, open: &mut OpenFile, mode: u16, offset: i64) -> VfsResult<u64> {
        // Positional I/O needs no lseek; track the cursor for SMB1 SEEK.
        let size = std::fs::metadata(&open.path).map(|m| m.len()).unwrap_or(0);
        let inner = open.inner_as_mut::<PosixInner>().ok_or(VfsError::NotSupported)?;
        let base = match mode & 3 {
            0 => 0i64,
            1 => inner.pos as i64,
            _ => size as i64,
        };
        let np = base.saturating_add(offset).max(0) as u64;
        inner.pos = np;
        Ok(np)
    }

    async fn flush(&self, open: &mut OpenFile) -> VfsResult<()> {
        let inner = open.inner_as_ref::<PosixInner>().ok_or(VfsError::NotSupported)?;
        if let Some(f) = inner.file.as_ref() {
            f.sync_all().await.map_err(map_io)?;
        }
        Ok(())
    }

    async fn flush_all(&self) -> VfsResult<()> {
        Ok(())
    }

    async fn close(&self, mut open: Box<OpenFile>) -> VfsResult<()> {
        // Close the io_uring file explicitly (async close), then honor
        // delete-on-close.
        if let Some(inner) = open.inner_as_mut::<PosixInner>() {
            if let Some(f) = inner.file.take() {
                let _ = f.close().await;
            }
        }
        if open.delete_on_close || open.delete_pending {
            if open.is_dir {
                tokio_uring::fs::remove_dir(&open.path).await.map_err(map_io)?;
            } else {
                tokio_uring::fs::remove_file(&open.path).await.map_err(map_io)?;
            }
        }
        Ok(())
    }

    async fn mkdir(&self, rel: &str) -> VfsResult<()> {
        let p = self.resolve(rel);
        tokio_uring::fs::create_dir(&p).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => VfsError::AlreadyExists,
            std::io::ErrorKind::NotFound => VfsError::NotFound,
            _ => VfsError::AccessDenied,
        })
    }

    async fn rmdir(&self, rel: &str) -> VfsResult<()> {
        let p = self.resolve(rel);
        tokio_uring::fs::remove_dir(&p).await.map_err(|e| match e.kind() {
            std::io::ErrorKind::DirectoryNotEmpty => VfsError::DirectoryNotEmpty,
            std::io::ErrorKind::NotFound => VfsError::NotFound,
            _ => VfsError::AccessDenied,
        })
    }

    async fn check_dir(&self, rel: &str) -> VfsResult<()> {
        let p = self.resolve(rel);
        if p.is_dir() {
            Ok(())
        } else {
            Err(VfsError::NotFound)
        }
    }

    async fn unlink(&self, rel: &str) -> VfsResult<()> {
        let p = self.resolve(rel);
        let md = p.symlink_metadata().map_err(|_| VfsError::NotFound)?;
        if md.is_dir() {
            return Err(VfsError::InvalidArgument);
        }
        tokio_uring::fs::remove_file(&p).await.map_err(map_io)
    }

    async fn delete_pattern(&self, dir_rel: &str, pattern: &str) -> VfsResult<bool> {
        let dir_abs = self.resolve(dir_rel);
        let names = std::fs::read_dir(&dir_abs).map_err(|_| VfsError::NotFound)?;
        let mut deleted_any = false;
        for entry in names.flatten() {
            let n = entry.file_name().to_string_lossy().into_owned();
            if wildcard_match(&n.to_lowercase(), &pattern.to_lowercase())
                && entry.path().is_file()
            {
                tokio_uring::fs::remove_file(entry.path()).await.map_err(map_io)?;
                deleted_any = true;
            }
        }
        Ok(deleted_any)
    }

    async fn rename(&self, old_rel: &str, new_rel: &str) -> VfsResult<()> {
        let src = self.resolve(old_rel);
        let dst = self.resolve(new_rel);
        if !src.exists() {
            return Err(VfsError::NotFound);
        }
        tokio_uring::fs::rename(&src, &dst).await.map_err(map_io)
    }

    async fn list(&self, dir_rel: &str) -> VfsResult<Vec<Entry>> {
        let dir_abs = self.resolve(dir_rel);
        let rd = std::fs::read_dir(&dir_abs).map_err(|_| VfsError::NotFound)?;
        let mut out = Vec::new();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let md = e.metadata().map_err(map_io)?;
            out.push(Entry { name, meta: meta_of(&md) });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    async fn stat(&self, rel: &str) -> VfsResult<FileMeta> {
        let p = self.resolve(rel);
        let md = p.symlink_metadata().map_err(|_| VfsError::NotFound)?;
        Ok(meta_of(&md))
    }

    async fn set_info_open(&self, open: &mut OpenFile, op: &SetOp) -> VfsResult<()> {
        match op {
            SetOp::Disposition { delete } => open.delete_pending = *delete,
            other => {
                let target = open.path.clone();
                self.set_info_path(&target, other).await?;
            }
        }
        Ok(())
    }

    async fn set_info_path(&self, rel: &str, op: &SetOp) -> VfsResult<()> {
        let p = self.resolve(rel);
        match op {
            SetOp::Disposition { delete } => {
                if *delete {
                    if p.is_dir() {
                        tokio_uring::fs::remove_dir(&p).await.map_err(map_io)?;
                    } else {
                        tokio_uring::fs::remove_file(&p).await.map_err(map_io)?;
                    }
                }
            }
            SetOp::Allocation(size) => {
                if *size == 0 {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&p)
                        .map_err(map_io)?
                        .set_len(0)
                        .map_err(map_io)?;
                }
            }
            SetOp::EndOfFile(len) => {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&p)
                    .map_err(map_io)?
                    .set_len(*len)
                    .map_err(map_io)?;
            }
            SetOp::Basic { write } => {
                if let Some(ft) = write {
                    if *ft != FileTime(0) && ft.0 != u64::MAX {
                        set_mtime(&p, ft.0)?;
                    }
                }
            }
            SetOp::Rename { replace_if_exists: _, name } => {
                let dest = self.resolve(name);
                tokio_uring::fs::rename(&p, &dest).await.map_err(map_io)?;
            }
        }
        Ok(())
    }

    async fn query_disk(&self) -> VfsResult<(u32, u32, u16, u16)> {
        // Static values keep clients happy; real statvfs wiring can come later.
        Ok((100_000, 50_000, 512, 64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smb_vfs::Vfs;

    /// A relative share root historically double-prefixed on stat-by-stored
    /// handle path (the getattrib step of `smbclient get`), returning
    /// STATUS_OBJECT_PATH_NOT_FOUND. Canonicalizing the root to absolute must
    /// make the stored handle path re-resolve cleanly.
    #[test]
    fn stat_by_stored_path_survives_relative_root() {
        tokio_uring::start(async {
            let dir = format!("target/it_share_{}", std::process::id());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(format!("{dir}/hello.txt"), b"hello!").unwrap();

            let vfs = PosixVfs::new(&dir);
            // FILE_OPEN (disposition 1), GENERIC_READ access.
            let (open, _meta, _action) = vfs
                .create("hello.txt", false, 0x8000_0000, 1, 0, 0)
                .await
                .expect("open existing file");
            // The exact call that used to fail during getattrib.
            let meta = vfs.stat(&open.path).await.expect("stat by stored handle path");
            assert_eq!(meta.eof, 6, "reported size matches file contents");

            std::fs::remove_dir_all(&dir).ok();
        });
    }
}

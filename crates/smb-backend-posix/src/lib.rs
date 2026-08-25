//! Default storage backend mapping the [`Vfs`] interface onto POSIX file
//! semantics via `std::fs` / `tokio::fs`.
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

/// POSIX backend rooted at a single directory.
#[derive(Debug)]
pub struct PosixVfs {
    root: std::path::PathBuf,
}

/// Backend-private state attached to every open handle.
pub struct PosixInner {
    /// Open file descriptor (None for directory handles).
    pub file: Option<std::fs::File>,
    /// Tracked cursor for SEEK support.
    pub pos: u64,
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

    fn open_inner(path: &std::path::Path, read: bool, write: bool) -> VfsResult<std::fs::File> {
        let mut oo = std::fs::OpenOptions::new();
        if read {
            oo.read(true);
        }
        if write {
            oo.write(true).append(false);
        }
        if !read && !write {
            oo.read(true);
        }
        oo.open(path).map_err(map_io)
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

#[async_trait]
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
        let exists = path.symlink_metadata().is_ok();

        let action: u32;
        if exists {
            match Disposition::from_u32(disposition) {
                Some(Disposition::Overwrite) | Some(Disposition::OverwriteIf)
                | Some(Disposition::Supersede)
                    if !path.is_dir() =>
                {
                    std::fs::write(&path, b"").map_err(map_io)?;
                    action = if disposition == 0 { 0 } else { 3 };
                }
                _ => action = 1,
            }
        } else {
            match Disposition::from_u32(disposition) {
                Some(Disposition::Open) | Some(Disposition::Overwrite) => {
                    return Err(VfsError::NotFound)
                }
                _ => {}
            }
            if want_dir {
                std::fs::create_dir_all(&path).map_err(map_io)?;
            } else {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(&path, b"").map_err(map_io)?;
            }
            action = 2;
        }

        if path.is_dir() || want_dir {
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

        let read_access =
            access & (0x8000_0000 | 0x0000_0001 | 0x0000_0008 | 0x0000_0080 | 0x1000_0000) != 0;
        let write_access = access
            & (0x4000_0000 | 0x0000_0002 | 0x0000_0004 | 0x0001_0000 | 0x2000_0000 | 0x1000_0000)
            != 0;

        let file = Self::open_inner(&path, read_access || !write_access, write_access)?;
        let md = file.metadata().map_err(map_io)?;
        let inner = PosixInner { file: Some(file), pos: 0 };
        let open = Box::new(OpenFile {
            path: path.to_string_lossy().into_owned(),
            rel: rel.to_string(),
            is_dir: false,
            can_read: read_access,
            can_write: write_access,
            delete_on_close: options & OPT_DELETE_ON_CLOSE != 0,
            delete_pending: false,
            inner: Box::new(inner),
        });

        Ok((open, meta_of(&md), action))
    }

    async fn read(&self, open: &mut OpenFile, offset: u64, len: usize) -> VfsResult<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let inner = open.inner_as_mut::<PosixInner>().ok_or(VfsError::NotSupported)?;
        let f = inner.file.as_mut().ok_or(VfsError::AccessDenied)?;
        f.seek(SeekFrom::Start(offset)).map_err(map_io)?;
        let mut buf = vec![0u8; len];
        loop {
            match f.read(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_io(e)),
            }
        }
    }

    async fn write(
        &self,
        open: &mut OpenFile,
        offset: u64,
        data: &[u8],
        write_through: bool,
    ) -> VfsResult<u64> {
        use std::io::{Seek, SeekFrom, Write};
        let inner = open.inner_as_mut::<PosixInner>().ok_or(VfsError::NotSupported)?;
        let f = inner.file.as_mut().ok_or(VfsError::AccessDenied)?;
        f.seek(SeekFrom::Start(offset)).map_err(map_io)?;
        let written = loop {
            match f.write(data) {
                Ok(n) => break n as u64,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(map_io(e)),
            }
        };
        if write_through {
            f.flush().map_err(map_io)?;
        }
        Ok(written)
    }

    async fn seek(&self, open: &mut OpenFile, mode: u16, offset: i64) -> VfsResult<u64> {
        use std::io::{Seek, SeekFrom};
        let inner = open.inner_as_mut::<PosixInner>().ok_or(VfsError::NotSupported)?;
        let f = inner.file.as_mut().ok_or(VfsError::AccessDenied)?;
        let from = match mode & 3 {
            0 => SeekFrom::Start(offset.max(0) as u64),
            1 => SeekFrom::Current(offset),
            _ => SeekFrom::End(offset),
        };
        f.seek(from).map_err(map_io)
    }

    async fn flush(&self, open: &mut OpenFile) -> VfsResult<()> {
        let inner = open.inner_as_ref::<PosixInner>().ok_or(VfsError::NotSupported)?;
        if let Some(f) = inner.file.as_ref() {
            f.sync_all().map_err(map_io)?;
        }
        Ok(())
    }

    async fn flush_all(&self) -> VfsResult<()> {
        Ok(())
    }

    async fn close(&self, open: Box<OpenFile>) -> VfsResult<()> {
        if open.delete_on_close || open.delete_pending {
            if open.is_dir {
                std::fs::remove_dir_all(&open.path).map_err(map_io)?;
            } else {
                std::fs::remove_file(&open.path).map_err(map_io)?;
            }
        }
        Ok(())
    }

    async fn mkdir(&self, rel: &str) -> VfsResult<()> {
        let p = self.resolve(rel);
        std::fs::create_dir(&p).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => VfsError::AlreadyExists,
            std::io::ErrorKind::NotFound => VfsError::NotFound,
            _ => VfsError::AccessDenied,
        })
    }

    async fn rmdir(&self, rel: &str) -> VfsResult<()> {
        let p = self.resolve(rel);
        std::fs::remove_dir(&p).map_err(|e| match e.kind() {
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
        std::fs::remove_file(&p).map_err(map_io)
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
                std::fs::remove_file(entry.path()).map_err(map_io)?;
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
        std::fs::rename(&src, &dst).map_err(map_io)
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
                        std::fs::remove_dir(&p).map_err(map_io)?;
                    } else {
                        std::fs::remove_file(&p).map_err(map_io)?;
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
                std::fs::rename(&p, &dest).map_err(map_io)?;
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
    #[tokio::test]
    async fn stat_by_stored_path_survives_relative_root() {
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
    }
}

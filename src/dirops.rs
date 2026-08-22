// Legacy (non-AndX) commands: MKDIR, RMDIR, DELETE, RENAME,
// CHECK_DIRECTORY, QUERY/SET_INFORMATION, PROCESS_EXIT.

use crate::files::{map_io_err, share_root};
use crate::message::*;
use crate::message::*;
use crate::smb::*;
use crate::state::*;
use crate::trans2::{list_dir, split_pattern, wildcard_match};

fn read_path(req: &Request) -> String {
    let data = req.data();
    let mut rd = Rd::new(data, 0);
    let base = req.bc_off + 2; // absolute offset of data[0]
    if !data.is_empty() && data[0] == 0x04 {
        rd.skip(1);
    }
    rd.zstring(req.unicode(), base)
}

fn read_two_paths(req: &Request) -> (String, String) {
    let data = req.data();
    let mut rd = Rd::new(data, 0);
    let base = req.bc_off + 2; // absolute offset of data[0]
    // Each string may be prefixed with a BufferFormat byte (0x04).
    if !data.is_empty() && data[0] == 0x04 {
        rd.skip(1);
    }
    let a = rd.zstring(req.unicode(), base);
    if !req.unicode() {
        // ASCII: first string ends at its NUL; next may carry 0x04 format.
        while rd.pos < data.len() && data[rd.pos] != 0x00 {
            rd.skip(1);
        }
        rd.skip(1.min(data.len() - rd.pos));
        if rd.pos < data.len() && data[rd.pos] == 0x04 {
            rd.skip(1);
        }
    } else {
        // Unicode: zstring consumed terminator; realign to even if needed.
        if (base + rd.pos) & 1 != 0 && rd.pos < data.len() {
            rd.skip(1);
        }
        if rd.pos < data.len() && data[rd.pos] == 0x04 {
            rd.skip(1);
            let _ = 0;
        }
    }
    let b = rd.zstring(req.unicode(), base);
    (a, b)
}

pub fn create_directory(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let share = share_root(server, conn, req.hdr.tid)?;
    if share.is_ipc {
        return Err(Status::ACCESS_DENIED);
    }
    let path = resolve_path(&share.root, &read_path(req));
    std::fs::create_dir(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => Status::OBJECT_NAME_COLLISION,
        _ => Status::OBJECT_PATH_NOT_FOUND,
    })?;
    Ok(vec![RespBody::new(COM_CREATE_DIRECTORY, Vec::new(), Vec::new())])
}

pub fn delete_directory(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let share = share_root(server, conn, req.hdr.tid)?;
    let raw = read_path(req);
    let path = resolve_path(&share.root, &raw);
    std::fs::remove_dir(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::DirectoryNotEmpty => Status::DIRECTORY_NOT_EMPTY,
        std::io::ErrorKind::NotFound => Status::OBJECT_PATH_NOT_FOUND,
        _ => Status::ACCESS_DENIED,
    })?;
    Ok(vec![RespBody::new(COM_DELETE_DIRECTORY, Vec::new(), Vec::new())])
}

pub fn check_directory(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let share = share_root(server, conn, req.hdr.tid)?;
    let path = resolve_path(&share.root, &read_path(req));
    if !path.is_dir() {
        return Err(Status::OBJECT_PATH_NOT_FOUND);
    }
    Ok(vec![RespBody::new(COM_CHECK_DIRECTORY, Vec::new(), Vec::new())])
}

pub fn delete(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let share = share_root(server, conn, req.hdr.tid)?;
    let pattern = read_path(req);
    let (dir_rel, fname_pat) = split_pattern(&pattern);
    let dir_abs = resolve_path(&share.root, &dir_rel);

    // Exact file?
    if !fname_pat.contains('*') && !fname_pat.contains('?') {
        let target = resolve_path(&dir_abs, &fname_pat);
            let md = target.symlink_metadata().map_err(|_| Status::OBJECT_NAME_NOT_FOUND)?;
        return if md.is_dir() {
            Err(Status::FILE_IS_A_DIRECTORY)
        } else {
            std::fs::remove_file(&target).map_err(map_io_err)?;
            Ok(vec![RespBody::new(COM_DELETE, Vec::new(), Vec::new())])
        };
    }

    let names = list_dir(&dir_abs)?;
    let mut deleted_any = false;
    for n in names {
        if wildcard_match(&n.to_lowercase(), &fname_pat.to_lowercase()) {
            let t = dir_abs.join(&n);
            if t.is_file() {
                std::fs::remove_file(&t).map_err(map_io_err)?;
                deleted_any = true;
            }
        }
    }
    if !deleted_any {
        return Err(Status::NO_SUCH_FILE);
    }
    Ok(vec![RespBody::new(COM_DELETE, Vec::new(), Vec::new())])
}

pub fn rename(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let share = share_root(server, conn, req.hdr.tid)?;
    let (old, new) = read_two_paths(req);
    if new.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    let src = resolve_path(&share.root, &old);
    let dst = resolve_path(&share.root, &new);
    if !src.exists() {
        return Err(Status::OBJECT_NAME_NOT_FOUND);
    }
    std::fs::rename(&src, &dst).map_err(map_io_err)?;
    Ok(vec![RespBody::new(COM_RENAME, Vec::new(), Vec::new())])
}

pub fn nt_rename(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let w = req.word_bytes();
    if w.len() < 4 {
        return Err(Status::INVALID_PARAMETER);
    }
    let level = u16::from_le_bytes([w[0], w[1]]);
    if level != 1 && level != 2 {
        return Err(Status::INVALID_PARAMETER); // hard link / copy unsupported
    }
    rename(server, conn, req)
}

pub fn query_information(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let share = share_root(server, conn, req.hdr.tid)?;
    let path = resolve_path(&share.root, &read_path(req));
    let md = path.symlink_metadata().map_err(|_| Status::OBJECT_NAME_NOT_FOUND)?;
    use std::os::unix::fs::MetadataExt;

    let attrs = if md.is_dir() {
        ATTR_DIRECTORY
    } else if md.mode() & 0o222 == 0 {
        ATTR_READONLY | ATTR_ARCHIVE
    } else {
        ATTR_ARCHIVE
    };
    let utime = md.mtime().max(0) as u32;
    let size = if md.is_dir() { 0 } else { md.len() };

    let mut params = Vec::new();
    params.extend_from_slice(&(attrs as u16).to_le_bytes());
    params.extend_from_slice(&utime.to_le_bytes());
    params.extend_from_slice(&(size as u32).to_le_bytes());
    params.extend_from_slice(&[0u8; 20]); // 5 reserved u32
    Ok(vec![RespBody::new(COM_QUERY_INFORMATION, params, Vec::new())])
}

pub fn set_information(server: &ServerShared, conn: &ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let w = req.word_bytes();
    let share = share_root(server, conn, req.hdr.tid)?;
    let path = resolve_path(&share.root, &read_path(req));
    if w.len() >= 6 {
        let utime = u32::from_le_bytes([w[2], w[3], w[4], w[5]]);
        if utime != 0 && utime != 0xFFFFFFFF {
            let ft = (utime as u64 + WIN_EPOCH_SECS as u64) * 10_000_000;
            let _ = crate::files::set_write_time(&path, ft);
        }
    }
    Ok(vec![RespBody::new(COM_SET_INFORMATION, Vec::new(), Vec::new())])
}

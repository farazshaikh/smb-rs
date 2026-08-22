// TRANS2 subcommands: FIND_FIRST2/FIND_NEXT2, QUERY_FS/PATH/FILE INFO,
// SET_FILE/PATH_INFORMATION.

use crate::files::{map_io_err, share_root};
use crate::handlers::check_tree;
use crate::message::{RespBody, SubReq, COM_TRANSACTION2, HDR_LEN};
use crate::smb::*;
use crate::state::*;

use std::path::{Path, PathBuf};
use crate::smb::*;
use crate::state::*;

fn file_attrs(md: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    if md.is_dir() {
        ATTR_DIRECTORY
    } else {
        let mut a = ATTR_ARCHIVE;
        if md.mode() & 0o222 == 0 {
            a |= ATTR_READONLY;
        }
        a
    }
}

fn times_of(md: &std::fs::Metadata) -> [u64; 4] {
    use std::os::unix::fs::MetadataExt;
    [
        unix_to_filetime(md.ctime(), md.ctime_nsec() as u32),
        unix_to_filetime(md.atime(), md.atime_nsec() as u32),
        unix_to_filetime(md.mtime(), md.mtime_nsec() as u32),
        unix_to_filetime(md.ctime(), md.ctime_nsec() as u32),
    ]
}

/// Build a TRANS2 response body from params/data. Offsets are even-aligned
/// and zero when the corresponding section is empty (matches real servers).
fn trans2_resp(params: Vec<u8>, data: Vec<u8>) -> RespBody {
    const WORDS_BYTES: usize = 20; // 10 response words
    let bc_area_start = HDR_LEN + 1 + WORDS_BYTES + 2; // 55
    let plen = params.len();
    let dlen = data.len();

    let poff = if plen > 0 { (bc_area_start + 1) & !1 } else { 0 };
    let raw_doff = if plen > 0 { poff + plen } else { bc_area_start };
    let doff = if dlen > 0 { (raw_doff + 1) & !1 } else { 0 };

    let mut p = Vec::new();
    p.extend_from_slice(&(plen as u16).to_le_bytes()); // TotalParameterCount
    p.extend_from_slice(&(dlen as u16).to_le_bytes()); // TotalDataCount
    p.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    p.extend_from_slice(&(plen as u16).to_le_bytes()); // ParamCount
    p.extend_from_slice(&(poff as u16).to_le_bytes()); // ParamOffset
    p.extend_from_slice(&0u16.to_le_bytes()); // ParamDisplacement
    p.extend_from_slice(&(dlen as u16).to_le_bytes()); // DataCount
    p.extend_from_slice(&(doff as u16).to_le_bytes()); // DataOffset
    p.extend_from_slice(&0u16.to_le_bytes()); // DataDisplacement
    p.push(0); // SetupCount
    p.push(0); // Reserved

    debug_assert_eq!(p.len(), WORDS_BYTES);

    let mut bytes = Vec::new();
    if plen > 0 {
        bytes.resize(poff - bc_area_start, 0);
        bytes.extend_from_slice(&params);
    }
    if dlen > 0 {
        let cur = bc_area_start + bytes.len();
        bytes.resize(doff - bc_area_start, 0);
        let _ = cur;
        bytes.extend_from_slice(&data);
    }
    RespBody::new(COM_TRANSACTION2, p, bytes)
}

// ---------------- FIND_FIRST2 ----------------
pub fn find_first2(server: &ServerShared, conn: &mut ConnState, tid: u16, req: &SubReq) -> Result<RespBody, Status> {
    if req.params.len() < 12 {
        return Err(Status::INVALID_PARAMETER);
    }
    let p = req.params;
    let search_count = u16::from_le_bytes([p[2], p[3]]) as usize;
    let flags = u16::from_le_bytes([p[4], p[5]]);
    let level = u16::from_le_bytes([p[6], p[7]]);

    let share = share_root(server, conn, tid)?;
    if share.is_ipc {
        return Err(Status::ACCESS_DENIED);
    }

    // Search pattern follows the fixed params inside the parameter buffer.
    let mut rd = Rd::new(req.params, 12);
    let pattern = rd.zstring(req.unicode, req.param_base);

    let (dir_rel, fname_pat) = split_pattern(&pattern);

    // Pattern naming an existing FILE returns that single entry.
    let direct = resolve_path(&share.root, &pattern);
    if !pattern.contains('*')
        && !pattern.contains('?')
        && direct.is_file()
    {
        let (data_buf, last_off) =
            encode_entries(&[direct.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()], 
                           &share.root.to_path_buf(), level, req.unicode);
            let mut params = Vec::new();
        params.extend_from_slice(&sid_placeholder().to_le_bytes());
        params.extend_from_slice(&1u16.to_le_bytes());
        params.extend_from_slice(&1u16.to_le_bytes());
        params.extend_from_slice(&0u16.to_le_bytes());
        params.extend_from_slice(&(last_off.unwrap_or(0) as u16).to_le_bytes());
        return Ok(trans2_resp(params, data_buf));
    }

    let dir_abs = resolve_path(&share.root, &dir_rel);
    if !dir_abs.is_dir() {
        return Err(Status::OBJECT_PATH_NOT_FOUND);
    }

    let mut names = list_dir(&dir_abs)?;
    names.retain(|n| wildcard_match(&n.to_lowercase(), &fname_pat.to_lowercase()));
    names.sort();

    let total = names.len();
    let take = total.min(search_count.max(1));
    let returned: Vec<String> = names.drain(..take).collect();
    let end_of_search = names.is_empty() || flags & 0x0001 != 0;

    let sid = next_sid();
    conn.searches.insert(
        sid,
        SearchCtx {
            queue: names.into_iter(),
            info_level: level,
            pattern: pattern.clone(),
            base_dir: dir_abs.clone(),
        },
    );

    let (data_buf, last_off) =
        encode_entries(&returned, &dir_abs, level, req.unicode);

    let mut params = Vec::new();
    params.extend_from_slice(&sid.to_le_bytes());
    params.extend_from_slice(&(returned.len() as u16).to_le_bytes());
    params.extend_from_slice(&(end_of_search as u16).to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes()); // EaErrorOffset
    params.extend_from_slice(&(last_off.unwrap_or(0) as u16).to_le_bytes());

    Ok(trans2_resp(params, data_buf))
}

pub fn find_next2(conn: &mut ConnState, req: &SubReq) -> Result<RespBody, Status> {
    if req.params.len() < 12 {
        return Err(Status::INVALID_PARAMETER);
    }
    let p = req.params;
    let sid = u16::from_le_bytes([p[0], p[1]]);
    let search_count = u16::from_le_bytes([p[2], p[3]]) as usize;
    let level = u16::from_le_bytes([p[4], p[5]]);
    let flags = u16::from_le_bytes([p[10], p[11]]);

    // Pattern may come in bytes for resume-with-new-pattern; ignore.
    let ctx = conn.searches.get_mut(&sid).ok_or(Status::INVALID_HANDLE)?;

    let mut returned = Vec::new();
    for _ in 0..search_count.max(1) {
        match ctx.queue.next() {
            Some(n) => returned.push(n),
            None => break,
        }
    }
    let drained = ctx.queue.clone().count() == 0;
    let end_of_search = drained || flags & 0x0001 != 0;

    let base = ctx.base_dir.clone();
    let lvl = if level == 0 { ctx.info_level } else { level };
    let (data_buf, last_off) = encode_entries(&returned, &base, lvl, req.unicode);

    let mut params = Vec::new();
    params.extend_from_slice(&(returned.len() as u16).to_le_bytes());
    params.extend_from_slice(&(end_of_search as u16).to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes());
    params.extend_from_slice(&(last_off.unwrap_or(0) as u16).to_le_bytes());

    Ok(trans2_resp(params, data_buf))
}

// ---------------- QUERY_FS_INFO ----------------
pub fn query_fs_info(server: &ServerShared, conn: &ConnState, tid: u16, req: &SubReq) -> Result<RespBody, Status> {
    if req.params.len() < 2 {
        return Err(Status::INVALID_PARAMETER);
    }
    let level = u16::from_le_bytes([req.params[0], req.params[1]]);
    let _share = share_root(server, conn, tid)?;

    let mut d = Wr::new();
    match level {
        FS_VOLUME_INFO => {
            d.u64v(now_filetime());
            d.u32v(0x1234_5678); // serial
            let label = "RUSTSMB";
            d.u32v((label.len() * 2) as u32);
            for u in label.encode_utf16() {
                d.u16v(u);
            }
        }
        FS_SIZE_INFO => {
            d.u64v(1_048_576); // total units
            d.u64v(524_288); // free units
            d.u32v(64); // sectors per unit
            d.u32v(512); // bytes per sector
        }
        FS_DEVICE_INFO => {
            d.u32v(0); // disk
            d.u32v(0x20); // characteristics
        }
        FS_ATTRIBUTE_INFO => {
            d.u32v(0x0004_2700 | 0x8 | 0x200 | 0x4); // CASE_PRESERVED|PERSISTENT_ACLS|UNICODE|NAMED_STREAMS-ish
            d.u32v(255); // max component length
            const NAME: &str = "NTFS";
            d.u32v((NAME.len() * 2) as u32);
            for u in NAME.encode_utf16() {
                d.u16v(u);
            }
        }
        _ => return Err(Status::INVALID_PARAMETER),
    }
    Ok(trans2_resp(Vec::new(), d.buf))
}

// ---------------- QUERY_PATH / FILE INFORMATION ----------------
pub fn query_path_info(server: &ServerShared, conn: &ConnState, tid: u16, req: &SubReq) -> Result<RespBody, Status> {
    if req.params.len() < 6 {
        return Err(Status::INVALID_PARAMETER);
    }
    let level = u16::from_le_bytes([req.params[0], req.params[1]]);
    let share = share_root(server, conn, tid)?;

    let mut rd = Rd::new(req.params, 6);
    let name = rd.zstring(req.unicode, req.param_base);
    if name.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    let full = resolve_path(&share.root, &name);
    let md = full.symlink_metadata().map_err(|_| Status::OBJECT_NAME_NOT_FOUND)?;

    encode_query_info(level, &full, &md, &name, req.unicode)
}

pub fn query_file_info(conn: &ConnState, req: &SubReq) -> Result<RespBody, Status> {
    eprintln!(
        "qfileinfo: params={:02x?} len={}",
        req.params,
        req.params.len()
    );
    if req.params.len() < 4 {
        return Err(Status::INVALID_PARAMETER);
    }
    let fid = u16::from_le_bytes([req.params[0], req.params[1]]);
    let level = u16::from_le_bytes([req.params[2], req.params[3]]);
    let h = conn.handles.get(&fid).ok_or(Status::INVALID_HANDLE)?;
    let md = h.metadata().map_err(map_io_err)?;
    let name = h
        .path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    encode_query_info(level, &h.path, &md, &name, req.unicode)
}

fn encode_query_info(
    level: u16,
    path: &PathBuf,
    md: &std::fs::Metadata,
    name: &str,
    _unicode: bool,
) -> Result<RespBody, Status> {
    use std::os::unix::fs::MetadataExt;
    let times = times_of(md);
    let eof = if md.is_dir() { 0 } else { md.len() };
    let alloc = ((eof + 4095) / 4096) * 4096;
    let attrs = file_attrs(md);

    let mut d = Wr::new();
    match level {
        QL_BASIC | QL_PT_BASIC | SL_BASIC => {
            for t in &times {
                d.u64v(*t);
            }
            d.u32v(attrs);
        }
        QL_STANDARD => {
            d.u64v(alloc);
            d.u64v(eof);
            d.u32v(1); // links
            d.u8v(if attrs & ATTR_READONLY != 0 { 1 } else { 0 }); // delete pending
            d.u8v(md.is_dir() as u8);
        }
        QL_PT_STANDARD => {
            d.u64v(alloc);
            d.u64v(eof);
            d.u32v(1);
            d.u8v(0); // delete pending
            d.u8v(md.is_dir() as u8);
            d.u16v(0); // reserved
        }
        QL_EA_SIZE | QL_PT_EA => {
            d.u32v(0);
        }
        QL_ALL_EAS => {
            d.u32v(4); // list length
            d.u32v(0); // full list length
        }
        QL_PT_INTERNAL => {
            d.u64v(md.ino() as u64);
        }
        QL_PT_ACCESS => {
            let rw = 0x0010_0089u32 | 0x0001_0016u32; // read+write generic combo
            d.u32v(rw);
        }
        QL_PT_NAME | QL_PT_ALT_NAME => {
            d.u32v((name.len() * 2) as u32);
            for u in name.encode_utf16() {
                d.u16v(u);
            }
        }
        QL_PT_ALLOC | SL_ALLOC => {
            d.u64v(alloc);
        }
        QL_PT_EOF | SL_EOF => {
            d.u64v(eof);
        }
        QL_PT_DISPOSITION => {
            d.u8v(0);
        }
        QL_PT_ALL => {
            for t in &times {
                d.u64v(*t);
            }
            d.u64v(alloc);
            d.u64v(eof);
            d.u32v(1); // links
            d.u8v(0); // delete pending
            d.u8v(md.is_dir() as u8);
            d.u16v(0); // reserved
            d.u32v(0); // EA size
            d.u32v(0x120089 | 0x16); // access flags
            d.u64v(0); // current byte offset
            d.u32v(attrs);
        }
        QL_STREAMS | QL_PT_STREAMS => {
            d.u32v(0); // next entry offset = end of list
        }
        0x107 => {
            // Composite getattr reply (mirrors reference servers):
            // times x4, attrs u32, rsvd u32, alloc u64, eof u64,
            // links u32, delPending u8, dir u8, pad u16, index u32,
            // nameLen u32, name UTF-16LE.
            for t in &times {
                d.u64v(*t);
            }
            d.u32v(attrs);
            d.u32v(0); // reserved
            d.u64v(alloc);
            d.u64v(eof);
            d.u32v(1); // links
            d.u8v(0); // delete pending
            d.u8v(md.is_dir() as u8);
            d.u16v(0); // pad
            d.u32v(0); // index
            let units: Vec<u16> = name.encode_utf16().collect();
            d.u32v((units.len() * 2) as u32);
            for u in &units {
                d.u16v(*u);
            }
        }
        _ => {
            eprintln!("query_info: unsupported level {:#06x}", level);
            return Err(Status::INVALID_PARAMETER);
        }
    }
    let _ = path;
    Ok(trans2_resp(Vec::new(), d.buf))
}

// ---------------- SET_FILE / SET_PATH INFORMATION ----------------
pub fn set_file_info(server: &ServerShared, conn: &mut ConnState, tid: u16, req: &SubReq) -> Result<RespBody, Status> {
    if req.params.len() < 4 {
        return Err(Status::INVALID_PARAMETER);
    }
    let fid = u16::from_le_bytes([req.params[0], req.params[1]]);
    let level = u16::from_le_bytes([req.params[2], req.params[3]]);
    let share_name = check_tree(conn, tid)?.clone();
    let share = server.shares.get(&share_name).ok_or(Status::INVALID_HANDLE)?;

    apply_set_info(conn, level, req.data, None, fid, &share.root)
}

pub fn set_path_info(server: &ServerShared, conn: &mut ConnState, tid: u16, req: &SubReq) -> Result<RespBody, Status> {
    if req.params.len() < 6 {
        return Err(Status::INVALID_PARAMETER);
    }
    let level = u16::from_le_bytes([req.params[0], req.params[1]]);
    let share_name = check_tree(conn, tid)?.clone();
    let share = server.shares.get(&share_name).ok_or(Status::INVALID_HANDLE)?;

    let mut rd = Rd::new(req.params, 6);
    let name = rd.zstring(req.unicode, req.param_base);
    apply_set_info(conn, level, req.data, Some(name), 0, &share.root)
}

fn apply_set_info(
    conn: &mut ConnState,
    level: u16,
    data: &[u8],
    name_opt: Option<String>,
    fid: u16,
    root: &Path,
) -> Result<RespBody, Status> {
    let r = |idx: usize| -> u64 {
        let b = data.get(idx..idx + 8).unwrap_or(&[0u8; 8]);
        u64::from_le_bytes(b.try_into().unwrap())
    };

    // Resolve target path.
    let target: PathBuf = match &name_opt {
        Some(name) => {
            if name.is_empty() {
                return Err(Status::INVALID_PARAMETER);
            }
            resolve_path(root, name)
        }
        None => {
            let h = conn.handles.get(&fid).ok_or(Status::INVALID_HANDLE)?;
            h.path.clone()
        }
    };

    match level {
        SL_BASIC | QL_PT_BASIC => {
            // create, access, write, [change], attrs...
            let write_ft = r(16);
            if write_ft != 0 && write_ft != 0xFFFF_FFFF_FFFF_FFFF {
                crate::files::set_write_time(&target, write_ft).map_err(map_io_err)?;
            }
        }
        SL_EOF | QL_PT_EOF => {
            let new_eof = r(0);
            if let Some(h) = conn.handles.get_mut(&fid) {
                if let Some(f) = h.file.as_mut() {
                    f.set_len(new_eof).map_err(map_io_err)?;
                }
            } else {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&target)
                    .map_err(map_io_err)?;
                f.set_len(new_eof).map_err(map_io_err)?;
            }
        }
        SL_ALLOC | QL_PT_ALLOC => {
            let new_alloc = r(0);
            if new_alloc == 0 {
                if let Some(h) = conn.handles.get_mut(&fid) {
                    if let Some(f) = h.file.as_mut() {
                        f.set_len(0).map_err(map_io_err)?;
                    }
                }
            }
        }
        SL_DISPOSITION | QL_PT_DISPOSITION => {
            let flag = data.first().copied().unwrap_or(0);
            if name_opt.is_some() {
                // delete by path directly
                if flag != 0 {
                    if target.is_dir() {
                        std::fs::remove_dir(&target).map_err(map_io_err)?;
                    } else {
                        std::fs::remove_file(&target).map_err(map_io_err)?;
                    }
                }
            } else {
                let h = conn.handles.get_mut(&fid).ok_or(Status::INVALID_HANDLE)?;
                h.delete_pending = flag != 0;
            }
        }
        QL_PT_NAME => {
            // rename via set-file-info passthrough: data = Replace(4)+RootDir(4)+NameLen(4)+Name
            let namelen =
                u32::from_le_bytes(data.get(8..12).unwrap_or(&[0; 4]).try_into().unwrap()) as usize;
            let raw = data
                .get(12..12 + namelen)
                .ok_or(Status::INVALID_PARAMETER)?
                .to_vec();
            let units: Vec<u16> = raw.chunks_exact(2).map(|c| c[0] as u16 | ((c[1] as u16) << 8)).collect();
            let newname = String::from_utf16_lossy(&units);
            let dest = resolve_path(root, &newname);
            std::fs::rename(&target, &dest).map_err(map_io_err)?;
            if let Some(h) = conn.handles.get_mut(&fid) {
                h.path = dest;
            }
        }
        _ => return Err(Status::INVALID_PARAMETER),
    }
    Ok(trans2_resp(Vec::new(), Vec::new()))
}

// ---------------- helpers ----------------

pub fn split_pattern(pattern: &str) -> (String, String) {
    let p = pattern.trim_start_matches(['\\', '/']);
    match p.rfind(['\\', '/']) {
        Some(idx) => (
            p[..idx].to_string(),
            p[idx + 1..].to_string(),
        ),
        None => (String::new(), p.to_string()),
    }
}

pub fn list_dir(dir: &Path) -> Result<Vec<String>, Status> {
    let rd = std::fs::read_dir(dir).map_err(|_| Status::OBJECT_PATH_NOT_FOUND)?;
    let mut out = Vec::new();
    for e in rd.flatten() {
        out.push(e.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

/// DOS-style wildcard match supporting * and ?.
pub fn wildcard_match(name: &str, pat: &str) -> bool {
    fn rec(s: &[char], p: &[char]) -> bool {
        if p.is_empty() {
            return s.is_empty();
        }
        match p[0] {
            '*' => {
                for i in 0..=s.len() {
                    if rec(&s[i..], &p[1..]) {
                        return true;
                    }
                }
                false
            }
            '?' => !s.is_empty() && rec(&s[1..], &p[1..]),
            c => !s.is_empty() && s[0] == c && rec(&s[1..], &p[1..]),
        }
    }
    let sc: Vec<char> = name.chars().collect();
    let pc: Vec<char> = pat.chars().collect();
    rec(&sc, &pc)
}


fn encode_entries(
    names: &[String],
    dir: &Path,
    level: u16,
    unicode: bool,
) -> (Vec<u8>, Option<usize>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut last_off: Option<usize> = None;
    for name in names {
        let entry_start = buf.len();
        let full = dir.join(name);
        let md = match std::fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let times = times_of(&md);
        let eof = if md.is_dir() { 0 } else { md.len() };
        let alloc = ((eof + 511) / 512) * 512;
        let attrs = file_attrs(&md);
        // Names are UTF-16LE only when the client negotiated UNICODE;
        // otherwise they are OEM/ASCII bytes.
        let name_bytes: Vec<u8> = if unicode {
            let mut v = Vec::new();
            for u in name.encode_utf16() {
                v.extend_from_slice(&u.to_le_bytes());
            }
            v
        } else {
            name.as_bytes().to_vec()
        };
        let name_units = name_bytes;

        let fixed: usize = match level {
            FIND_INFO_BOTH => 94, // 4+4+times32+eof8+alloc8+attr4+len4+ea4+short1+res1+short24
            FIND_INFO_FULL => 68, // 4+4+times32+eof8+alloc8+attr4+len4
            FIND_INFO_DIRECTORY => 32,
            FIND_INFO_NAMES => 12,
            FIND_INFO_STANDARD => 27,
            _ => 94,
        };

        let total = match level {
            FIND_INFO_STANDARD => fixed + name.len() + 1,
            _ => fixed + name_units.len(),
        };
        let padded = (total + 3) & !3usize;

        let put_u32 = |buf: &mut Vec<u8>, v: u32| buf.extend_from_slice(&v.to_le_bytes());
        let put_u64 = |buf: &mut Vec<u8>, v: u64| buf.extend_from_slice(&v.to_le_bytes());

        put_u32(&mut buf, padded as u32); // NextEntryOffset
        match level {
            FIND_INFO_STANDARD => {
                put_u32(&mut buf, 0); // FileIndex
                for t in &times[..3] {
                    let (secs, _) = filetime_to_unix(*t);
                    put_u32(&mut buf, secs as u32);
                }
                put_u32(&mut buf, eof as u32);
                put_u32(&mut buf, alloc as u32);
                buf.extend_from_slice(&(attrs as u16).to_le_bytes());
                buf.push(name_units.len() as u8);
                buf.extend_from_slice(&name_units);
                // pad to 8.3 slot? spec says name field is 13 chars min; keep simple
            }
            _ => {
                put_u32(&mut buf, 0); // FileIndex
                for t in &times {
                    put_u64(&mut buf, *t);
                }
                match level {
                    FIND_INFO_NAMES => {
                        put_u32(&mut buf, name_units.len() as u32);
                    }
                    FIND_INFO_DIRECTORY => {
                        put_u64(&mut buf, eof);
                        put_u64(&mut buf, alloc);
                        put_u32(&mut buf, attrs);
                        put_u32(&mut buf, name_units.len() as u32);
                    }
                    _ => {
                        put_u64(&mut buf, eof);
                        put_u64(&mut buf, alloc);
                        put_u32(&mut buf, attrs);
                        put_u32(&mut buf, name_units.len() as u32);
                        put_u32(&mut buf, 0); // EaSize
                        if level == FIND_INFO_BOTH {
                            buf.push(0); // ShortNameLength
                            buf.push(0); // Reserved
                            buf.extend(std::iter::repeat_n(0u8, 24));
                        }
                    }
                }
                buf.extend_from_slice(&name_units);
            }
        }
        while buf.len() < padded + entry_start {
            buf.push(0);
        }
        last_off = Some(entry_start);
    }
    (buf, last_off)
}

fn sid_placeholder() -> u16 {
    // Searches opened via the file-shortcut path are closed immediately by
    // clients; a fresh SID keeps state consistent.
    crate::state::next_sid()
}

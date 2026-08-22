// File operations: NT_CREATE_ANDX, READ_ANDX, WRITE_ANDX, CLOSE, FLUSH,
// LOCKING_ANDX, SEEK and the legacy directory/file commands.

use crate::message::*;
use crate::smb::*;
use crate::handlers::check_tree;
use crate::state::*;
use std::path::{Path, PathBuf};

pub fn share_root<'a>(server: &'a ServerShared, conn: &ConnState, tid: u16) -> Result<&'a Share, Status> {
    let name = check_tree(conn, tid)?;
    server.shares.get(name).ok_or(Status::INVALID_HANDLE)
}

fn attrs_of(md: &std::fs::Metadata) -> u32 {
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
        unix_to_filetime(md.ctime(), md.ctime_nsec() as u32), // creation ~ ctime
        unix_to_filetime(md.atime(), md.atime_nsec() as u32),
        unix_to_filetime(md.mtime(), md.mtime_nsec() as u32),
        unix_to_filetime(md.ctime(), md.ctime_nsec() as u32),
    ]
}

pub fn set_write_time(path: &Path, ft: u64) -> std::io::Result<()> {
    use std::fs::FileTimes;
    let f = std::fs::OpenOptions::new().write(true).open(path)?;
    let (secs, nanos) = filetime_to_unix(ft);
    let t = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(secs.max(0) as u64, nanos);
    f.set_times(FileTimes::new().set_modified(t))?;
    Ok(())
}

// ---------------- NT_CREATE_ANDX (0xA2) ----------------
#[allow(clippy::too_many_arguments)]
pub fn nt_create(
    server: &ServerShared,
    conn: &mut ConnState,
    req: &Request,
) -> Result<Vec<RespBody>, Status> {
    let w = req.word_bytes();
    if w.len() < 24 {
        return Err(Status::INVALID_PARAMETER);
    }
    // Layout (bytes within Words): [0]cmd [1]res [2-3]off [4]rsvd [5-6]
    // NameLength [7-10]CreateFlags [11-14]RootFid [15-18]DesiredAccess
    // [19-26]AllocSize [27-30]ExtAttrs [31-34]ShareAccess [35-38]Disposition
    // [39-42]CreateOptions [43-46]Impersonation [47]SecFlags
    let name_len = u16::from_le_bytes([w[5], w[6]]) as usize;
    let root_fid = u32::from_le_bytes([w[11], w[12], w[13], w[14]]);
    let desired_access = u32::from_le_bytes([w[15], w[16], w[17], w[18]]);
    let _ext_attrs = u32::from_le_bytes([w[27], w[28], w[29], w[30]]);
    let disposition = u32::from_le_bytes([w[35], w[36], w[37], w[38]]);
    let create_options = u32::from_le_bytes([w[39], w[40], w[41], w[42]]);

    let data = req.data();
    // The Name field must start at an even offset from the SMB header; when
    // ByteCount lands odd the client inserts one pad byte before the name.
    let mut name_start = 0;
    if (req.bc_off + 2) % 2 != 0 && !data.is_empty() {
        name_start = 1;
    }
    let raw_name: Vec<u8> = data
        .get(name_start..(name_start + name_len).min(data.len()))
        .unwrap_or(&[])
        .to_vec();
    let name = decode_name(&raw_name, req.unicode());

    let share = share_root(server, conn, req.hdr.tid)?;
    if share.is_ipc {
        return Err(Status::OBJECT_NAME_NOT_FOUND); // named pipes unsupported
    }

    // Root-directory relative opens.
    let mut base_path = share.root.clone();
    if root_fid != 0 && root_fid <= 0xFFFF {
        if let Some(h) = conn.handles.get(&(root_fid as u16)) {
            base_path = h.path.clone();
        } else {
            return Err(Status::INVALID_HANDLE);
        }
    }

    if name.is_empty() {
        // Open the share root itself.
        return open_directory_handle(
            conn,
            req,
            base_path,
            create_options,
        );
    }

    let full = resolve_path(&base_path, &name);
    let want_dir = create_options & OPT_DIRECTORY_FILE != 0;
    let no_dir = create_options & OPT_NON_DIRECTORY_FILE != 0;
    let exists = full.symlink_metadata().is_ok();

    let mut action = 1u32; // FILE_OPENED
    let path = full.clone();

    match exists {
        true => {
            let is_dir = path.is_dir();
            match disposition {
                DISP_OPEN | DISP_OPEN_IF => {}
                DISP_SUPERSEDE => action = 0,
                DISP_OVERWRITE | DISP_OVERWRITE_IF => action = 3,
                _ => {}
            }
            if want_dir && !is_dir {
                return Err(Status::FILE_IS_A_DIRECTORY);
            }
            if no_dir && is_dir {
                return Err(Status::FILE_IS_A_DIRECTORY);
            }
            if !want_dir && !is_dir {
                match disposition {
                    DISP_OVERWRITE => {
                        std::fs::write(&path, b"").map_err(|_| Status::ACCESS_DENIED)?
                    }
                    DISP_OVERWRITE_IF => {
                        std::fs::write(&path, b"").map_err(|_| Status::ACCESS_DENIED)?
                    }
                    DISP_SUPERSEDE => {
                        std::fs::write(&path, b"").map_err(|_| Status::ACCESS_DENIED)?
                    }
                    _ => {}
                }
            }
        }
        false => {
            match disposition {
                DISP_CREATE | DISP_OPEN_IF | DISP_SUPERSEDE | DISP_OVERWRITE_IF => {
                    if want_dir {
                        std::fs::create_dir_all(&path)
                            .map_err(|_| Status::OBJECT_PATH_NOT_FOUND)?;
                    } else {
                        if let Some(parent) = path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        std::fs::write(&path, b"")
                            .map_err(|_| Status::OBJECT_PATH_NOT_FOUND)?;
                    }
                    action = 2; // FILE_CREATED
                }
                _ => return Err(Status::OBJECT_NAME_NOT_FOUND),
            }
        }
    }

    if want_dir || (exists && path.is_dir()) || (action == 2 && want_dir) {
        return open_directory_handle(conn, req, path, create_options);
    }

    // Regular file open.
    let mut oo = std::fs::OpenOptions::new();
    let read_access = desired_access & (GENERIC_READ | FILE_READ_DATA | GENERIC_ALL) != 0
        || desired_access & 0x120089 != 0;
    let write_access = desired_access
        & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE_ACCESS | GENERIC_ALL)
        != 0;
    if read_access {
        oo.read(true);
    }
    if write_access {
        oo.write(true).append(false);
    }
    if !read_access && !write_access {
        oo.read(true);
    }
    let file = oo.open(&path).map_err(map_io_err)?;

    let md = file.metadata().map_err(|_| Status::ACCESS_DENIED)?;
    let times = times_of(&md);
    let alloc = (md.len() + 511) / 512 * 512;
    let fid = next_fid();

    conn.handles.insert(
        fid,
        FileHandle {
            path: path.clone(),
            is_dir: false,
            file: Some(file),
            pos: 0,
            access_read: read_access,
            access_write: write_access,
            delete_on_close: create_options & OPT_DELETE_ON_CLOSE != 0,
            delete_pending: false,
        },
    );

    let mut params = Vec::new();
    params.push(0xFFu8);
    params.push(0u8);
    params.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset patched by assembler
    params.push(0u8); // OplockLevel: none
    params.extend_from_slice(&fid.to_le_bytes());
    params.extend_from_slice(&action.to_le_bytes());
    for t in &times {
        params.extend_from_slice(&t.to_le_bytes());
    }
    params.extend_from_slice(&attrs_of(&md).to_le_bytes());
    params.extend_from_slice(&alloc.to_le_bytes());
    params.extend_from_slice(&md.len().to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes()); // FileType: disk
    params.extend_from_slice(&0u16.to_le_bytes()); // DeviceState
    params.push(0u8); // not directory

    Ok(vec![RespBody::new(COM_NT_CREATE_ANDX, params, Vec::new())])
}

fn open_directory_handle(
    conn: &mut ConnState,
    req: &Request,
    path: PathBuf,
    create_options: u32,
) -> Result<Vec<RespBody>, Status> {
    let md = std::fs::metadata(&path).map_err(|_| Status::OBJECT_PATH_NOT_FOUND)?;
    if !md.is_dir() {
        return Err(Status::NOT_A_DIRECTORY);
    }
    let times = times_of(&md);
    let fid = next_fid();
    conn.handles.insert(
        fid,
        FileHandle {
            path: path.clone(),
            is_dir: true,
            file: None,
            pos: 0,
            access_read: true,
            access_write: false,
            delete_on_close: create_options & OPT_DELETE_ON_CLOSE != 0,
            delete_pending: false,
        },
    );
    let alloc = (md.len() + 511) / 512 * 512;
    let mut params = Vec::new();
    params.push(0xFFu8);
    params.push(0u8);
    params.extend_from_slice(&0u16.to_le_bytes());
    params.push(0u8); // oplock none
    params.extend_from_slice(&fid.to_le_bytes());
    params.extend_from_slice(&1u32.to_le_bytes()); // FILE_OPENED
    for t in &times {
        params.extend_from_slice(&t.to_le_bytes());
    }
    params.extend_from_slice(&ATTR_DIRECTORY.to_le_bytes());
    params.extend_from_slice(&alloc.to_le_bytes());
    params.extend_from_slice(&0u64.to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes());
    params.push(1u8); // is directory

    let _ = req;
    Ok(vec![RespBody::new(COM_NT_CREATE_ANDX, params, Vec::new())])
}

pub fn map_io_err(e: std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::NotFound => Status::OBJECT_NAME_NOT_FOUND,
        std::io::ErrorKind::PermissionDenied => Status::ACCESS_DENIED,
        std::io::ErrorKind::AlreadyExists => Status::OBJECT_NAME_COLLISION,
        std::io::ErrorKind::DirectoryNotEmpty => Status::DIRECTORY_NOT_EMPTY,
        _ => Status::UNSUCCESSFUL,
    }
}

fn decode_name(raw: &[u8], unicode: bool) -> String {
    if unicode {
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| c[0] as u16 | ((c[1] as u16) << 8))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw.split(|&b| b == 0).next().unwrap_or(&[])).into_owned()
    }
}

// ---------------- READ_ANDX (0x2E) ----------------
pub fn read_andx(conn: &mut ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let w = req.word_bytes();
    if w.len() < 12 {
        return Err(Status::INVALID_PARAMETER);
    }
    let fid = u16::from_le_bytes([w[4], w[5]]);
    let mut offset = u32::from_le_bytes([w[6], w[7], w[8], w[9]]) as u64;
    let write_mode = u16::from_le_bytes([w[14], w[15]]);
    let mut maxcount = u16::from_le_bytes([w[10], w[11]]) as usize;
    if w.len() >= 24 {
        let hi = u32::from_le_bytes([w[20], w[21], w[22], w[23]]) as u64;
        offset |= hi << 32;
    }
    if w.len() >= 22 {
        let mh = u16::from_le_bytes([w[12], w[13]]) as usize; // MinCount slot? defensive
        let _ = mh;
    }

    let cap = 65_000usize;
    if maxcount > cap {
        maxcount = cap;
    }

    let h = conn.handles.get_mut(&fid).ok_or(Status::INVALID_HANDLE)?;
    if h.is_dir || !h.access_read {
        return Err(Status::ACCESS_DENIED);
    }
    let f = h.file.as_mut().ok_or(Status::INVALID_HANDLE)?;
    use std::io::{Read, Seek, SeekFrom};
    f.seek(SeekFrom::Start(offset)).map_err(|_| Status::UNSUCCESSFUL)?;
    let mut buf = vec![0u8; maxcount];
    let n = f.read(&mut buf).map_err(map_io_err)?;
    buf.truncate(n);

    // Response WC=12.
    let params_len = 24usize;
    // DataOffset absolute from SMB start: hdr(32)+wc(1)+params(24)+bc(2)+pad->even
    let mut doff = HDR_LEN + 1 + params_len + 2;
    if doff % 2 != 0 {
        doff += 1;
    }
    let mut params = Vec::with_capacity(params_len);
    params.push(0xFFu8);
    params.push(0u8);
    params.extend_from_slice(&0u16.to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes()); // Remaining/Available
    params.extend_from_slice(&0u16.to_le_bytes()); // DataCompactionMode
    params.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    params.extend_from_slice(&(n as u16).to_le_bytes()); // DataLength
    params.extend_from_slice(&(doff as u16).to_le_bytes()); // DataOffset
    params.extend_from_slice(&0u32.to_le_bytes()); // DataLengthHigh
    params.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    params.extend_from_slice(&[0u8; 2]); // tail of reserved area (WC=12 => 24B)

    debug_assert_eq!(params.len(), params_len);

    let mut bytes = Vec::new();
    bytes.resize(doff - (HDR_LEN + 1 + params_len + 2), 0);
    bytes.extend_from_slice(&buf);

    Ok(vec![RespBody::new(COM_READ_ANDX, params, bytes)])
}

// ---------------- WRITE_ANDX (0x2F) ----------------
pub fn write_andx(conn: &mut ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let w = req.word_bytes();
    let wc = w.len() / 2;
    if wc < 12 {
        return Err(Status::INVALID_PARAMETER);
    }
    let fid = u16::from_le_bytes([w[4], w[5]]);
    let mut offset = u32::from_le_bytes([w[6], w[7], w[8], w[9]]) as u64;
    let write_mode = u16::from_le_bytes([w[14], w[15]]);

    // Two WC=14 variants exist in the wild:
    //  A) MS-CIFS:  OffsetHigh @18, DataLength @22, DataOffset @24
    //  B) Impacket: DataLength @16, DataOffset @20 (no OffsetHigh)
    // Pick the one whose (offset,len) lands inside the frame.
    let bc = match req.buf.get(req.bc_off..req.bc_off + 2) {
        Some(two) => u16::from_le_bytes(two.try_into().unwrap()) as usize,
        None => 0,
    };
    let mut candidates: Vec<(usize, usize)> = Vec::new(); // (len, offset)
    if wc >= 14 {
        // MS-CIFS variant: OffsetHigh @18, DataLength @22, DataOffset @24
        let hi = u32::from_le_bytes([w[18], w[19], w[20], w[21]]) as u64;
        if hi == 0 {
            candidates.push((
                u16::from_le_bytes([w[22], w[23]]) as usize,
                u16::from_le_bytes([w[24], w[25]]) as usize,
            ));
        }
    }
    // Impacket-style variant: DataLength @20, DataOffset @22
    candidates.push((
        u16::from_le_bytes([w[20], w[21]]) as usize,
        u16::from_le_bytes([w[22], w[23]]) as usize,
    ));
    // Plain WC=12 style: DataLength @18, DataOffset @20
    candidates.push((
        u16::from_le_bytes([w[18], w[19]]) as usize,
        u16::from_le_bytes([w[20], w[21]]) as usize,
    ));
    let mut data_len = 0usize;
    let mut data_offset = 0usize;
    for (dl, dof) in &candidates {
        if *dl > 0
            && *dof >= HDR_LEN + 1 + wc * 2 + 2
            && *dof + *dl <= req.buf.len()
            && *dl <= bc.max(*dl)
        {
            data_len = *dl;
            data_offset = *dof;
            break;
        }
    }
    if data_len == 0 {
        return Err(Status::INVALID_PARAMETER);
    }

    let start = data_offset; // absolute from SMB start
    let end = (start + data_len).min(req.buf.len());
    if start > end {
        return Err(Status::INVALID_PARAMETER);
    }
    let payload = &req.buf[start..end];
    eprintln!(
        "write_andx: wc={} fid={:#x} off={} dlen={} doff={} paylen={}",
        wc,
        fid,
        offset,
        data_len,
        data_offset,
        payload.len()
    );

    let h = conn.handles.get_mut(&fid).ok_or(Status::INVALID_HANDLE)?;
    if h.is_dir || !h.access_write {
        return Err(Status::ACCESS_DENIED);
    }
    let f = h.file.as_ref().ok_or(Status::INVALID_HANDLE)?;
    use std::io::{Seek, SeekFrom, Write};
    let mut f = f;
    f.seek(SeekFrom::Start(offset)).map_err(|_| Status::UNSUCCESSFUL)?;
    let written = match f.write(payload) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("write failed: {}", e);
            return Err(map_io_err(e));
        }
    };
    if write_mode & 0x0001 != 0 {
        let _ = f.flush();
    }

    let mut params = Vec::new();
    params.push(0xFFu8);
    params.push(0u8);
    params.extend_from_slice(&0u16.to_le_bytes());
    params.extend_from_slice(&(written as u16).to_le_bytes()); // CountLow
    params.extend_from_slice(&65535u16.to_le_bytes()); // Available
    params.extend_from_slice(&0u16.to_le_bytes()); // CountHigh
    params.extend_from_slice(&0u16.to_le_bytes()); // Reserved

    Ok(vec![RespBody::new(COM_WRITE_ANDX, params, Vec::new())])
}

// ---------------- CLOSE (0x04) ----------------
pub fn close(conn: &mut ConnState, req: &Request) -> Vec<RespBody> {
    let w = req.word_bytes();
    if w.len() >= 3 {
        let fid = u16::from_le_bytes([w[0], w[1]]);
        let mtime = u32::from_le_bytes([w[2], w[3], w[4], w[5]]);
        let path = conn.handles.get(&fid).map(|h| h.path.clone());
        if mtime != 0 && mtime != 0xFFFFFFFF {
            if let Some(p) = path {
                let ft = ((mtime as u64) + WIN_EPOCH_SECS as u64) * 10_000_000;
                let _ = set_write_time(&p, ft);
            }
        }
        let _ = conn.close_fid(fid);
    }
    vec![RespBody::new(COM_CLOSE, Vec::new(), Vec::new())]
}

// ---------------- FLUSH (0x05) ----------------
pub fn flush(conn: &mut ConnState, req: &Request) -> Vec<RespBody> {
    let w = req.word_bytes();
    if w.len() >= 2 {
        let fid = u16::from_le_bytes([w[0], w[1]]);
        if fid == 0xFFFF {
            for h in conn.handles.values_mut() {
                if let Some(f) = h.file.as_mut() {
                    let _ = f.sync_all();
                }
            }
        } else if let Some(h) = conn.handles.get_mut(&fid) {
            if let Some(f) = h.file.as_mut() {
                let _ = f.sync_all();
            }
        }
    }
    vec![RespBody::new(COM_FLUSH, Vec::new(), Vec::new())]
}

// ---------------- SEEK (0x12) ----------------
pub fn seek(conn: &mut ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    let w = req.word_bytes();
    if w.len() < 8 {
        return Err(Status::INVALID_PARAMETER);
    }
    let fid = u16::from_le_bytes([w[0], w[1]]);
    let mode = u16::from_le_bytes([w[2], w[3]]);
    let off = i32::from_le_bytes([w[4], w[5], w[6], w[7]]) as i64;

    let h = conn.handles.get_mut(&fid).ok_or(Status::INVALID_HANDLE)?;
    use std::io::{Seek, SeekFrom};
    let f = h.file.as_mut().ok_or(Status::INVALID_HANDLE)?;
    let from = match mode & 3 {
        0 => SeekFrom::Start(off.max(0) as u64),
        1 => SeekFrom::Current(off),
        _ => SeekFrom::End(off),
    };
    let pos = f.stream_position().unwrap_or(0);
    let newpos = f.seek(from).map_err(map_io_err)?;
    let _ = pos;
    let mut params = Vec::new();
    params.extend_from_slice(&(newpos as u32).to_le_bytes());
    Ok(vec![RespBody::new(COM_SEEK, params, Vec::new())])
}

// ---------------- LOCKING_ANDX (0x24) ----------------
pub fn locking_andx(_conn: &mut ConnState, req: &Request) -> Result<Vec<RespBody>, Status> {
    // We accept all locks (no enforcement yet).
    let params = vec![0xFFu8, 0u8, 0u8, 0u8];
    Ok(vec![RespBody::new(COM_LOCKING_ANDX, params, Vec::new())])
}

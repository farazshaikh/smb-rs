//! File command handlers: NT_CREATE_ANDX, READ/WRITE_ANDX, CLOSE, FLUSH,
//! SEEK, LOCKING_ANDX and QUERY_INFORMATION_DISK.

use smb_server_proto::types::Status;
use smb_server_proto_smb1::consts;
use smb_server_proto_smb1::create as create_codec;
use smb_server_proto_smb1::header::RespBody;
use smb_server_proto_smb1::misc;
use smb_server_proto_smb1::rw::{self, ReadReq, WriteReq};
use smb_server_vfs::{OpenFile, SetOp};

use crate::cmds::{IoCtx, share_vfs};
use crate::dispatch::ReqView;
use crate::state::next_fid;

/// QUERY_INFORMATION_DISK (0x80).
pub async fn query_disk(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    let (total, free, bps, spc) = vfs.query_disk().await.map_err(vfs_err)?;
    let info = misc::QueryDiskInfo {
        total_units: total,
        free_units: free,
        bps,
        spc,
    };
    bodies.push(RespBody::new(
        consts::COM_QUERY_INFORMATION_DISK,
        info.encode(),
        Vec::new(),
    ));
    Ok(Status::SUCCESS)
}

/// NT_CREATE_ANDX ([MS-SMB] §2.2.4.9).
pub async fn nt_create(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let is_ipc = io
        .conn
        .trees
        .get(&req.hdr.tid)
        .map(|n| n == "ipc$")
        .unwrap_or(false);
    if is_ipc {
        return Err(Status::OBJECT_NAME_NOT_FOUND);
    }
    let creq = create_codec::NtCreateReq::parse(
        req.words,
        req.data,
        req.unicode(),
        req.bc_off_abs + smb_server_proto_smb1::consts::WORD_LEN,
    )
    .map_err(|_| Status::INVALID_PARAMETER)?;

    let base_rel = if creq.root_fid != 0 && creq.root_fid <= u16::MAX as u32 {
        io.conn
            .handles
            .get(&(creq.root_fid as u16))
            .map(|h| h.path.clone())
            .ok_or(Status::INVALID_HANDLE)?
    } else {
        String::new()
    };
    let rel = join_rel(&base_rel, &creq.name);

    let want_dir =
        creq.create_options & smb_server_proto_smb1::consts::create_options::FILE_DIRECTORY_FILE != 0;
    let no_dir =
        creq.create_options & smb_server_proto_smb1::consts::create_options::FILE_NON_DIRECTORY_FILE != 0;
    let delete_on_close =
        creq.create_options & smb_server_proto_smb1::consts::create_options::FILE_DELETE_ON_CLOSE != 0;

    let vfs = share_vfs(io, req.hdr.tid);
    let (mut open, meta, action) = vfs
        .create(
            &rel,
            want_dir,
            creq.desired_access,
            creq.disposition,
            creq.create_options,
            creq.ext_attrs,
        )
        .await
        .map_err(vfs_err)?;

    if no_dir && open.is_dir {
        return Err(Status::FILE_IS_A_DIRECTORY);
    }
    open.delete_on_close |= delete_on_close;

    let fid = next_fid();
    io.conn.handles.insert(fid, open);

    let body = create_codec::build_response(
        fid,
        action,
        meta.times,
        meta.attrs.0,
        meta.alloc,
        meta.eof,
        meta.is_dir,
    );
    tracing::debug!(
        fid = format!("{:#06x}", fid),
        eof = meta.eof,
        dir = meta.is_dir,
        "nt_create"
    );
    metrics::counter!("smb_creates_total").increment(1);
    bodies.push(RespBody::new(consts::COM_NT_CREATE_ANDX, body, Vec::new()));
    Ok(Status::SUCCESS)
}

/// READ_ANDX.
pub async fn read_andx(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let rr = ReadReq::parse(req.words).map_err(|_| Status::INVALID_PARAMETER)?;
    tracing::trace!(
        fid = format!("{:#06x}", rr.fid),
        offset = rr.offset,
        want = rr.max_count,
        "read_andx"
    );
    let vfs = share_vfs(io, req.hdr.tid);

    let Some(h) = io.conn.handles.get_mut(&rr.fid).map(|b| &mut **b) else {
        return Err(Status::INVALID_HANDLE);
    };
    if h.is_dir || !h.can_read {
        return Err(Status::ACCESS_DENIED);
    }
    let data = vfs
        .read(h, rr.offset, rr.max_count)
        .await
        .map_err(vfs_err)?;
    metrics::counter!("smb_bytes_read_total").increment(data.len() as u64);

    let (params, bytes) = rw::read_response(&data);
    bodies.push(RespBody::new(consts::COM_READ_ANDX, params, bytes));
    Ok(Status::SUCCESS)
}

/// WRITE_ANDX.
pub async fn write_andx(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let wr = WriteReq::parse(req.words, req.frame).map_err(|s| s)?;
    let vfs = share_vfs(io, req.hdr.tid);

    let Some(h) = io.conn.handles.get_mut(&wr.fid).map(|b| &mut **b) else {
        return Err(Status::INVALID_HANDLE);
    };
    if h.is_dir || !h.can_write {
        return Err(Status::ACCESS_DENIED);
    }
    let written = vfs
        .write(h, wr.offset, &wr.payload, wr.write_through)
        .await
        .map_err(vfs_err)?;

    bodies.push(RespBody::new(
        consts::COM_WRITE_ANDX,
        rw::write_response(written),
        Vec::new(),
    ));
    Ok(Status::SUCCESS)
}

/// CLOSE (0x04): optional mtime update then close.
pub async fn close(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let Some(cr) = misc::CloseReq::parse(req.words) else {
        return Err(Status::INVALID_PARAMETER);
    };
    let vfs = share_vfs(io, req.hdr.tid);
    let Some(mut h) = io.conn.handles.remove(&cr.fid) else {
        return Err(Status::INVALID_HANDLE);
    };
    if cr.mtime != 0 && cr.mtime != u32::MAX {
        // Legacy UTIME field: seconds since 1970 in the low word.
        let ft = smb_server_proto::types::FileTime::from_unix(cr.mtime as i64, 0);
        let _ = vfs
            .set_info_open(
                &mut h,
                &SetOp::Basic {
                    access: None,
                    write: Some(ft),
                },
            )
            .await;
    }
    vfs.close(h).await.map_err(vfs_err)?;
    bodies.push(RespBody::new(consts::COM_CLOSE, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// FLUSH (0x05).
pub async fn flush(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    match misc::flush_fid(req.words) {
        None => return Err(Status::INVALID_PARAMETER),
        Some(0xFFFF) => vfs.flush_all().await.map_err(vfs_err)?,
        Some(fid) => {
            if let Some(h) = io.conn.handles.get_mut(&fid) {
                vfs.flush(h).await.map_err(vfs_err)?;
            }
        }
    }
    bodies.push(RespBody::new(consts::COM_FLUSH, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// SEEK (0x12).
pub async fn seek(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let Some(sr) = misc::SeekReq::parse(req.words) else {
        return Err(Status::INVALID_PARAMETER);
    };
    let vfs = share_vfs(io, req.hdr.tid);
    let Some(h) = io.conn.handles.get_mut(&sr.fid) else {
        return Err(Status::INVALID_HANDLE);
    };
    let pos = vfs.seek(h, sr.mode, sr.offset).await.map_err(vfs_err)?;
    bodies.push(RespBody::new(
        consts::COM_SEEK,
        misc::SeekReq::build_response(pos),
        Vec::new(),
    ));
    Ok(Status::SUCCESS)
}

/// LOCKING_ANDX / byte-range lock+unlock — accepted unenforced.
pub async fn locking(
    _io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let cmd = req.hdr.command;
    bodies.push(RespBody::new(
        cmd,
        vec![smb_server_proto_smb1::consts::ANDX_NONE, 0, 0, 0],
        Vec::new(),
    ));
    Ok(Status::SUCCESS)
}

// ---- helpers ----

pub(crate) fn vfs_err(e: smb_server_vfs::VfsError) -> Status {
    use smb_server_vfs::VfsError as E;
    match e {
        E::NotFound => Status::OBJECT_PATH_NOT_FOUND,
        E::AlreadyExists => Status::OBJECT_NAME_COLLISION,
        E::AccessDenied => Status::ACCESS_DENIED,
        E::DirectoryNotEmpty => Status::DIRECTORY_NOT_EMPTY,
        E::InvalidArgument => Status::INVALID_PARAMETER,
        E::NotSupported => Status::NOT_IMPLEMENTED,
        E::StoppedOnSymlink { .. } => Status::STOPPED_ON_SYMLINK,
        E::Io(_) => Status::UNSUCCESSFUL,
    }
}

fn join_rel(base: &str, name: &str) -> String {
    let name = name.trim_start_matches(['\\', '/']);
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{}\\{}", base.trim_end_matches(['\\', '/']), name)
    }
}

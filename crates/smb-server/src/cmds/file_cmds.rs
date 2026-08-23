//! File command handlers: NT_CREATE_ANDX, READ/WRITE_ANDX, CLOSE, FLUSH,
//! SEEK, LOCKING_ANDX and QUERY_INFORMATION_DISK.

use smb_proto::types::Status;
use smb_proto_smb1::consts;
use smb_proto_smb1::create as create_codec;
use smb_proto_smb1::header::RespBody;
use smb_proto_smb1::misc;
use smb_proto_smb1::rw;
use smb_vfs::{OpenFile, SetOp};

use crate::cmds::{share_vfs, IoCtx};
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
    let info = misc::QueryDiskInfo { total_units: total, free_units: free, bps, spc };
    bodies.push(RespBody::new(consts::COM_QUERY_INFORMATION_DISK, info.encode(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// NT_CREATE_ANDX ([MS-SMB] §2.2.4.9).
pub async fn nt_create(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let share = share_of(io, req.hdr.tid)?;
    if share.is_ipc {
        return Err(Status::OBJECT_NAME_NOT_FOUND);
    }
    let creq =
        create_codec::NtCreateReq::parse(req.words, req.data, req.unicode(), req.bc_off_abs + 2)
            .map_err(|_| Status::INVALID_PARAMETER)?;

    let base_rel = if creq.root_fid != 0 && creq.root_fid <= 0xFFFF {
        io.conn
            .handles
            .get(&(creq.root_fid as u16))
            .map(|h| h.path.clone())
            .ok_or(Status::INVALID_HANDLE)?
    } else {
        String::new()
    };
    let rel = join_rel(&base_rel, &creq.name);

    let want_dir = creq.create_options & 0x1 != 0; // FILE_DIRECTORY_FILE
    let no_dir = creq.create_options & 0x40 != 0; // FILE_NON_DIRECTORY_FILE
    let delete_on_close = creq.create_options & 0x1000 != 0; // FILE_DELETE_ON_CLOSE

    let vfs = share.vfs.as_ref();
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
    bodies.push(RespBody::new(consts::COM_NT_CREATE_ANDX, body, Vec::new()));
    Ok(Status::SUCCESS)
}

/// READ_ANDX.
pub async fn read_andx(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let rr = rw::ReadReq::parse(req.words).map_err(|_| Status::INVALID_PARAMETER)?;
    let vfs = share_vfs(io, req.hdr.tid);

    let Some(h): Option<&mut OpenFile> = io.conn.handles.get_mut(&rr.fid) else {
        return Err(Status::INVALID_HANDLE);
    };
    if h.is_dir || !h.can_read {
        return Err(Status::ACCESS_DENIED);
    }
    let data = vfs.read(h, rr.offset, rr.max_count).await.map_err(vfs_err)?;

    let (params, bytes) = rw::read_response(&data[..rr.max_count.min(data.len())]);
    bodies.push(RespBody::new(consts::COM_READ_ANDX, params, bytes));
    Ok(Status::SUCCESS)
}

/// WRITE_ANDX.
pub async fn write_andx(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let wr = rw::WriteReq::parse(req.words, req.data.len() + 35 + 24 + 8, req.frame.len())
        .map_err(|s| s)?;
    let vfs = share_vfs(io, req.hdr.tid);

    let Some(h) = io.conn.handles.get_mut(&wr.fid) else {
        return Err(Status::INVALID_HANDLE);
    };
    if h.is_dir || !h.can_write {
        return Err(Status::ACCESS_DENIED);
    }
    let written = vfs.write(h, wr.offset, &wr.payload, wr.write_through).await.map_err(vfs_err)?;

    bodies.push(RespBody::new(consts::COM_WRITE_ANDX, rw::write_response(written), Vec::new()));
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
        let ft = smb_proto::types::FileTime((cr.mtime as u64 + 11_644_473_600) * 10_000_000);
        let _ = vfs
            .set_info_open(&mut h, &SetOp::Basic { write: Some(ft) })
            .await;
    }
    vfs.close(h).await?;
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
        Some(0xFFFF) => vfs.flush_all().await?,
        Some(fid) => {
            if let Some(h) = io.conn.handles.get_mut(&fid) {
                vfs.flush(h).await?;
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
    let pos = vfs.seek(h, sr.mode, sr.offset).await?;
    bodies.push(RespBody::new(consts::COM_SEEK, misc::SeekReq::build_response(pos), Vec::new()));
    Ok(Status::SUCCESS)
}

/// LOCKING_ANDX / byte-range lock+unlock — accepted unenforced.
pub async fn locking(
    _io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let cmd = req.hdr.command;
    bodies.push(RespBody::new(cmd, vec![0xFF, 0, 0, 0], Vec::new()));
    Ok(Status::SUCCESS)
}

// ---- helpers ----

fn share_of(io: &IoCtx<'_>, tid: u16) -> Result<&crate::state::Share, Status> {
    static IPC: std::sync::OnceLock<crate::state::Share> = std::sync::OnceLock::new();
    io.conn
        .trees
        .get(&tid)
        .and_then(|n| io.server.shares.get(n))
        .ok_or(Status::INVALID_HANDLE)
        .or_else(|_| {
            Ok(IPC.get_or_init(|| crate::state::Share {
                name: "ipc$".into(),
                root: "/nonexistent".into(),
                is_ipc: true,
            }))
        })
}

fn join_rel(base: &str, name: &str) -> String {
    let name = name.trim_start_matches(['\\', '/']);
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{}\\{}", base.trim_end_matches(['\\', '/']), name)
    }
}

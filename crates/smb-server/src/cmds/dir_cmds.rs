//! Legacy path command handlers ([MS-CIFS] core/LANMAN set).

use smb_proto::types::Status;
use smb_proto_smb1::consts;
use smb_proto_smb1::header::RespBody;
use smb_proto_smb1::legacy as legacy_codec;
use smb_vfs::SetOp;

use crate::cmds::{share_vfs, IoCtx};
use crate::dispatch::ReqView;

fn read_path(req: &ReqView<'_>) -> String {
    let mut rd = smb_proto::buf::Reader::new(req.data, 0);
    if !req.data.is_empty() && req.data[0] == 0x04 {
        rd.skip(1);
    }
    rd.zstring(req.unicode(), req.bc_off_abs + 2)
}

fn read_two_paths(req: &ReqView<'_>) -> (String, String) {
    let data = req.data;
    let mut rd = smb_proto::buf::Reader::new(data, 0);
    let base = req.bc_off_abs + 2;
    if !data.is_empty() && data[0] == 0x04 {
        rd.skip(1);
    } else if unicode(req) && base % 2 != 0 && !data.is_empty() {
        rd.skip(1);
    }
    let a = rd.zstring(unicode(req), base);
    if !rd.at_end() {
        if unicode(req) && (base + rd.pos()) & 1 != 0 {
            rd.skip(1);
        }
        if rd.pos() < data.len() && data[rd.pos()] == 0x04 {
            rd.skip(1);
        }
    }
    let b = rd.zstring(unicode(req), base + rd.pos());
    (a, b)
}

fn unicode(req: &ReqView<'_>) -> bool {
    req.unicode()
}

/// CREATE_DIRECTORY (0x00).
pub async fn mkdir(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    vfs.mkdir(&read_path(req)).await.map_err(vfs_err)?;
    bodies.push(RespBody::new(consts::COM_CREATE_DIRECTORY, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// DELETE_DIRECTORY (0x01).
pub async fn rmdir(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    vfs.rmdir(&read_path(req)).await.map_err(vfs_err)?;
    bodies.push(RespBody::new(consts::COM_DELETE_DIRECTORY, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// CHECK_DIRECTORY (0x10).
pub async fn check_dir(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    vfs.check_dir(&read_path(req)).await.map_err(vfs_err)?;
    bodies.push(RespBody::new(consts::COM_CHECK_DIRECTORY, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// DELETE (0x06): exact file or wildcard pattern.
pub async fn delete(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    let pattern = read_path(req);
    let (dir_rel, name_pat) = split_pattern_pub(&pattern);

    if !name_pat.contains('*') && !name_pat.contains('?') {
        let rel = join_rel(&dir_rel, &name_pat);
        vfs.unlink(&rel).await.map_err(vfs_err)?;
    } else {
        let deleted = vfs.delete_pattern(&dir_rel, &name_pat).await.map_err(vfs_err)?;
        if !deleted {
            return Err(Status::NO_SUCH_FILE);
        }
    }
    bodies.push(RespBody::new(consts::COM_DELETE, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// RENAME (0x07) — also used by NT_RENAME level 1.
pub async fn rename(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    let (old, new) = read_two_paths(req);
    if new.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    vfs.rename(&old, &new).await.map_err(vfs_err)?;
    bodies.push(RespBody::new(consts::COM_RENAME, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// QUERY_INFORMATION (0x08): attributes + DOS time + size.
pub async fn query_info_legacy(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    let path = read_path(req);
    let m = vfs.stat(&path).await.map_err(vfs_err)?;
    let (secs, _) = smb_proto::types::FileTime(m.times[2].0).to_unix();

    // DOS date/time packing ([MS-DTYP] §2.3.4/5).
    let secs = secs.max(0);
    let days = secs / 86400;
    let tod = secs % 86400;
    let (year, month, day) = civil_from_days(days);
    let hours = tod / 3600;
    let minutes = (tod % 3600) / 60;
    let seconds = tod % 60 / 2 * 2;
    let dos_time = ((hours as u32) << 11) | ((minutes as u32) << 5) | (seconds as u32);
    let dos_date =
        (((year - 1980).clamp(0, 127) as u32) << 9) | ((month as u32) << 5) | day as u32;

    let attrs = if m.is_dir {
        0x10u16
    } else if m.attrs.0 & smb_proto::types::AttrFlags::READONLY != 0 {
        0x21u16
    } else {
        0x20u16
    };
    let resp = legacy_codec::QueryInfoResp { attrs, dos_time: dos_date | dos_time, size: m.eof as u32 };
    bodies.push(RespBody::new(consts::COM_QUERY_INFORMATION, resp.encode(), Vec::new()));
    Ok(Status::SUCCESS)
}

/// SET_INFORMATION (0x09): apply the last-write time.
pub async fn set_info_legacy(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let vfs = share_vfs(io, req.hdr.tid);
    let path = read_path(req);
    let w = req.words;
    if w.len() >= 6 {
        let utime = u32::from_le_bytes([w[2], w[3], w[4], w[5]]);
        if utime != 0 && utime != u32::MAX {
            let ft = smb_proto::types::FileTime((utime as u64 + 11_644_473_600) * 10_000_000);
            vfs.set_info_path(&path, &SetOp::Basic { write: Some(ft) })
                .await
                .map_err(vfs_err)?;
        }
    }
    bodies.push(RespBody::new(consts::COM_SET_INFORMATION, Vec::new(), Vec::new()));
    Ok(Status::SUCCESS)
}

// ---- helpers ----

/// Split a find pattern into `(directory, filename-pattern)` parts.
pub fn split_pattern_pub(pattern: &str) -> (String, String) {
    let p = pattern.trim_start_matches(['\\', '/']);
    match p.rfind(['\\', '/']) {
        Some(i) => (p[..i].to_string(), p[i + 1..].to_string()),
        None => (String::new(), p.to_string()),
    }
}

pub(crate) fn join_rel(base: &str, name: &str) -> String {
    let name = name.trim_start_matches(['\\', '/']);
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{}\\{}", base.trim_end_matches(['\\', '/']), name)
    }
}

pub(crate) fn vfs_err(e: smb_vfs::VfsError) -> Status {
    use smb_vfs::VfsError as E;
    match e {
        E::NotFound => Status::OBJECT_PATH_NOT_FOUND,
        E::AlreadyExists => Status::OBJECT_NAME_COLLISION,
        E::AccessDenied => Status::ACCESS_DENIED,
        E::DirectoryNotEmpty => Status::DIRECTORY_NOT_EMPTY,
        E::InvalidArgument => Status::INVALID_PARAMETER,
        E::NotSupported => Status::NOT_IMPLEMENTED,
        E::Io(_) => Status::UNSUCCESSFUL,
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

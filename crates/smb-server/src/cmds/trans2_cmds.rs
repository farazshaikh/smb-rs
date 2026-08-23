//! TRANSACTION2 subcommand dispatch ([MS-SMB] §2.2.6).

use smb_proto::types::Status;
use smb_proto_smb1::consts;
use smb_proto_smb1::header::RespBody;
use smb_proto_smb1::query;
use smb_proto_smb1::trans2 as t2;

use crate::cmds::{share_vfs, IoCtx};
use crate::state::SearchCtx;
use crate::dispatch::ReqView;

/// Route a TRANS2 request to its subcommand handler.
pub async fn dispatch_trans2(
    io: &mut IoCtx<'_>,
    req: &ReqView<'_>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let Some(t) = t2::Trans2Req::parse(
        req.wct as u8,
        req.words,
        req.frame,
        req.bc_off_abs,
        req.unicode(),
    ) else {
        return Err(Status::INVALID_PARAMETER);
    };


    eprintln!("TRANS2 dispatch called subcmd={:#06x}", t.subcmd);
    eprintln!("T2REQ subcmd={:#06x} unicode={} params={:02x?}", t.subcmd, t.unicode, &t.params[..t.params.len().min(20)]);
    let (params, data) = match t.subcmd {
        t2::subcmd::FIND_FIRST2 => find_first2(io, req.hdr.tid, &t).await?,
        t2::subcmd::FIND_NEXT2 => find_next2(io, &t).await?,
        t2::subcmd::QUERY_FS_INFO => query_fs(io, req.hdr.tid, &t)?,
        t2::subcmd::QUERY_PATH_INFO => query_path(io, req.hdr.tid, &t).await?,
        t2::subcmd::QUERY_FILE_INFO => query_file(io, req.hdr.tid, &t).await?,
        t2::subcmd::SET_FILE_INFO => set_file(io, &t).await?,
        t2::subcmd::SET_PATH_INFO => set_path(io, req.hdr.tid, &t).await?,
        other => {
            eprintln!("trans2: unsupported subcmd {:#06x}", other);
            return Err(Status::INVALID_PARAMETER);
        }
    };

    let (rp, rd) = t2::trans2_resp(params, data);
    bodies.push(RespBody::new(consts::COM_TRANSACTION2, rp, rd));
    Ok(Status::SUCCESS)
}

// ---------------- FIND_FIRST2 / FIND_NEXT2 ----------------

async fn find_first2(
    io: &mut IoCtx<'_>,
    tid: u16,
    t: &t2::Trans2Req,
) -> Result<(Vec<u8>, Vec<u8>), Status> {
    eprintln!("find_first2: params={:02x?} unicode={} param_base={} data={:02x?} data_base={}",
        t.params, t.unicode, t.param_base, t.data_base, t.data_base);
    if t.params.len() < 12 {
        return Err(Status::INVALID_PARAMETER);
    }
    let g16 = |o: usize| -> u16 {
        match t.params.get(o..o + 2) {
            Some(s) => u16::from_le_bytes([s[0], s[1]]),
            None => 0,
        }
    };
    let count = g16(2) as usize;
    let level = g16(6);

    // Fixed params: SearchAttributes(2) SearchCount(2) OpenFlags(2)
    // InformationLevel(2) SearchStorageType(4) = 12 bytes; name follows.
    let mut rd = smb_proto::buf::Reader::new(&t.params, 12);
    let pattern = rd.zstring(t.unicode, t.param_base);
    eprintln!("find_first2: level={:#06x} pattern={:?}", level, pattern);

    let share = share_name(io, tid)?;
    let vfs = share_vfs(io, tid);
    let (dir_rel, fname_pat) = crate::cmds::dir_cmds_split(&pattern);

    // Pattern naming an existing file returns that single entry.
    if !pattern.contains('*') && !pattern.contains('?') {
        if let Ok(m) = vfs.stat(pattern.trim_start_matches(['\\', '/'])).await {
            let name = pattern.rsplit(['\\', '/']).next().unwrap_or("").to_string();
            let entry = smb_proto_smb1::find::FindEntry {
                name,
                meta: smb_proto_smb1::query::QueryMeta {
                    times: [m.times[0].0, m.times[1].0, m.times[2].0, m.times[3].0],
                    attrs: m.attrs,
                    eof: m.eof,
                    alloc: m.alloc,
                    is_dir: m.is_dir,
                },
            };
            let (data_buf, last) =
                smb_proto_smb1::find::encode_entries(std::slice::from_ref(&entry), level, t.unicode);
            return Ok(find_params(sid(), 1, true, last, data_buf));
        }
    }

    let entries = vfs.list(&dir_rel).await.map_err(vfs_err)?;
    let matched: Vec<smb_vfs::Entry> = entries
        .into_iter()
        .filter(|e| {
            crate::cmds::wildcard(&e.name.to_lowercase(), &fname_pat.to_lowercase())
        })
        .collect();
    let end_of_search = true; // full result set returned in one batch

    let sid_v = sid();
    let returned: Vec<String> = matched.iter().map(|e| e.name.clone()).collect();
    io.conn.searches.insert(
        sid_v,
        SearchCtx {
            queue: Vec::new().into_iter(),
            level,
            base_dir: std::path::PathBuf::new(),
        },
    );

    let find_entries: Vec<smb_proto_smb1::find::FindEntry> = matched
        .into_iter()
        .map(|e| smb_proto_smb1::find::FindEntry {
            name: e.name,
            meta: smb_proto_smb1::query::QueryMeta {
                times: [e.meta.times[0].0, e.meta.times[1].0, e.meta.times[2].0, e.meta.times[3].0],
                attrs: e.meta.attrs,
                eof: e.meta.eof,
                alloc: e.meta.alloc,
                is_dir: e.meta.is_dir,
            },
        })
        .collect();
    let (data_buf, last_off) =
        smb_proto_smb1::find::encode_entries(&find_entries, level, t.unicode);
    Ok(find_params(sid_v, returned.len() as u16, end_of_search, last_off, data_buf))
}

fn find_params(
    sid: u16,
    count: u16,
    eos: bool,
    last_off: Option<usize>,
    data: Vec<u8>,
) -> (Vec<u8>, Vec<u8>) {
    let mut p = Vec::with_capacity(10);
    p.extend_from_slice(&sid.to_le_bytes());
    p.extend_from_slice(&count.to_le_bytes());
    p.extend_from_slice(&(eos as u16).to_le_bytes());
    p.extend_from_slice(&0u16.to_le_bytes()); // EaErrorOffset
    p.extend_from_slice(&(last_off.unwrap_or(0) as u16).to_le_bytes());
    (p, data)
}

fn sid() -> u16 {
    crate::state::next_sid()
}

/// FIND_NEXT2 resumes from the SID table.
async fn find_next2(io: &mut IoCtx<'_>, t: &t2::Trans2Req) -> Result<(Vec<u8>, Vec<u8>), Status> {
    if t.params.len() < 4 {
        return Err(Status::INVALID_PARAMETER);
    }
    let sid_v = u16::from_le_bytes([t.params[0], t.params[1]]);
    // Take the search out of the table to borrow the VFS independently.
    let Some(mut ctx) = io.conn.searches.remove(&sid_v) else {
        return Err(Status::INVALID_HANDLE);
    };
    let vfs = share_vfs(io, tid_placeholder());
    let mut out: Vec<smb_proto_smb1::find::FindEntry> = Vec::new();
    while out.len() < 64 {
        let Some(name) = ctx.queue.next() else { break };
        let m = match vfs.stat(&format!("{}\\{}", ctx.base_dir.display(), name)).await {
            Ok(m) => m,
            Err(_) => continue,
        };
        out.push(smb_proto_smb1::find::FindEntry {
            name,
            meta: smb_proto_smb1::query::QueryMeta {
                times: [m.times[0].0, m.times[1].0, m.times[2].0, m.times[3].0],
                attrs: m.attrs,
                eof: m.eof,
                alloc: m.alloc,
                is_dir: m.is_dir,
            },
        });
    }
    let drained = ctx.queue.len() == 0 && out.is_empty();
    let lvl = if t.params.len() >= 6 {
        u16::from_le_bytes([t.params[4], t.params[5]])
    } else {
        ctx.level
    };
    let eos = ctx.queue.as_slice().is_empty();
    let _ = drained;
    io.conn.searches.insert(sid_v, ctx);
    let eos_final = io.conn.searches.contains_key(&sid_v) == false || {
        // still entries pending?
        false
    };
    let _ = eos_final;
    let (data_buf, last_off) =
        smb_proto_smb1::find::encode_entries(&out, lvl, t.unicode);
    let has_more = !io.conn.searches.contains_key(&sid_v);
    let _ = has_more;
    Ok(find_params(sid_v, out.len() as u16, true, last_off, data_buf))
}

// ---------------- QUERY_FS / PATH / FILE ----------------

fn query_fs(
    io: &IoCtx<'_>,
    tid: u16,
    t: &t2::Trans2Req,
) -> Result<(Vec<u8>, Vec<u8>), Status> {
    if t.params.len() < 2 {
        return Err(Status::INVALID_PARAMETER);
    }
    let level = u16::from_le_bytes([t.params[0], t.params[1]]);
    share_vfs(io, tid); // tree must exist
    let mut d = smb_proto::buf::Writer::new(0);
    match level {
        0x102 => {
            d.push_u64(smb_proto::types::FileTime::now().0);
            d.push_u32(0x1234_5678);
            const LABEL: &str = "RUSTSMB";
            d.push_u32((LABEL.len() * 2) as u32);
            for u in LABEL.encode_utf16() {
                d.push_u16(u);
            }
        }
        0x103 => {
            d.push_u64(1_048_576);
            d.push_u64(524_288);
            d.push_u32(64);
            d.push_u32(512);
        }
        0x201 => {
            d.push_u32(0);
            d.push_u32(0x20);
        }
        0x202 => {
            d.push_u32(0x0004_2700 | 0x8 | 0x200 | 0x4);
            d.push_u32(255);
            const NAME: &str = "NTFS";
            d.push_u32((NAME.len() * 2) as u32);
            for u in NAME.encode_utf16() {
                d.push_u16(u);
            }
        }
        _ => return Err(Status::INVALID_PARAMETER),
    }
    Ok((Vec::new(), d.into_inner()))
}

/// QUERY_PATH_INFORMATION by name.
async fn query_path(
    io: &IoCtx<'_>,
    tid: u16,
    t: &t2::Trans2Req,
) -> Result<(Vec<u8>, Vec<u8>), Status> {
    if t.params.len() < 2 {
        return Err(Status::INVALID_PARAMETER);
    }
    let level = u16::from_le_bytes([t.params[0], t.params[1]]);
    let vfs = share_vfs(io, tid);

    let mut rd = smb_proto::buf::Reader::new(&t.params, 2);
    let name = rd.zstring(t.unicode, t.param_base);
    if name.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    let m = vfs.stat(&name).await.map_err(vfs_err)?;
    let short = name.rsplit(['\\', '/']).next().unwrap_or("").to_string();
    let qm = qmeta_from(&m);
    eprintln!("query_path: name={:?} level={:#06x} eof={}", name, level, qm.eof);
    query::encode_payload(level, &qm, &short)
        .map(|d| (Vec::new(), d))
        .map_err(|_| Status::INVALID_PARAMETER)
}

/// QUERY_FILE_INFORMATION by FID.
pub(crate) async fn query_file(
    io: &IoCtx<'_>,
    tid: u16,
    t: &t2::Trans2Req,
) -> Result<(Vec<u8>, Vec<u8>), Status> {
    if t.params.len() < 4 {
        return Err(Status::INVALID_PARAMETER);
    }
    let fid = u16::from_le_bytes([t.params[0], t.params[1]]);
    let level = u16::from_le_bytes([t.params[2], t.params[3]]);
    let Some(h) = io.conn.handles.get(&fid) else {
        return Err(Status::INVALID_HANDLE);
    };
    let name = h.path.rsplit(['\\', '/']).next().unwrap_or("").to_string();
    let vfs = share_vfs(io, tid);
    let m = vfs.stat(&h.path).await.unwrap_or_default();
    let qm = smb_proto_smb1::query::QueryMeta {
        times: [m.times[0].0, m.times[1].0, m.times[2].0, m.times[3].0],
        attrs: m.attrs,
        eof: m.eof,
        alloc: m.alloc,
        is_dir: m.is_dir,
    };
    query::encode_payload(level, &qm, &name)
        .map(|d| (Vec::new(), d))
        .map_err(|_| Status::INVALID_PARAMETER)
}

/// Metadata snapshot of an open handle (path re-statted when possible).

// ---------------- SET_FILE / SET_PATH ----------------

/// SET_FILE_INFORMATION by FID.
async fn set_file(
    io: &mut IoCtx<'_>,
    t: &t2::Trans2Req,
) -> Result<(Vec<u8>, Vec<u8>), Status> {
    if t.params.len() < 4 || t.data.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    let fid = u16::from_le_bytes([t.params[0], t.params[1]]);
    let level = u16::from_le_bytes([t.params[2], t.params[3]]);
    let op = decode_set_op(level, &t.data)?;
    let vfs = share_vfs(io, tid_placeholder());
    let Some(h) = io.conn.handles.get_mut(&fid) else {
        return Err(Status::INVALID_HANDLE);
    };
    vfs.set_info_open(h, &op).await.map_err(vfs_err)?;
    Ok((Vec::new(), Vec::new()))
}

/// SET_PATH_INFORMATION by name.
async fn set_path(
    io: &mut IoCtx<'_>,
    tid: u16,
    t: &t2::Trans2Req,
) -> Result<(Vec<u8>, Vec<u8>), Status> {
    if t.params.len() < 2 {
        return Err(Status::INVALID_PARAMETER);
    }
    let level = u16::from_le_bytes([t.params[0], t.params[1]]);
    let mut rd = smb_proto::buf::Reader::new(&t.params, 2);
    let name = rd.zstring(t.unicode, t.param_base);
    if name.is_empty() {
        return Err(Status::INVALID_PARAMETER);
    }
    let op = decode_set_op(level, &t.data)?;
    let vfs = share_vfs(io, tid);
    vfs.set_info_path(&name, &op).await.map_err(vfs_err)?;
    Ok((Vec::new(), Vec::new()))
}

/// Translate wire set-levels onto neutral [`SetOp`] values.
fn decode_set_op(level: u16, data: &[u8]) -> Result<smb_vfs::SetOp, Status> {
    let r64 = |i: usize| -> u64 {
        data.get(i..i + 8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0)
    };
    match level {
        0x101 | 0x1004 => {
            let ft = r64(16);
            Ok(smb_vfs::SetOp::Basic {
                write: (ft != 0 && ft != u64::MAX).then_some(smb_proto::types::FileTime(ft)),
            })
        }
        0x103 | 0x100B => Ok(smb_vfs::SetOp::Allocation(r64(0))),
        0x104 | 0x100C => Ok(smb_vfs::SetOp::EndOfFile(r64(0))),
        0x102 | 0x100D => {
            Ok(smb_vfs::SetOp::Disposition { delete: data.first().copied().unwrap_or(0) != 0 })
        }
        _ => Err(Status::INVALID_PARAMETER),
    }
}

// ---- helpers ----

fn share_name<'a>(io: &'a IoCtx<'_>, tid: u16) -> Result<&'a str, Status> {
    io.conn.trees.get(&tid).map(String::as_str).ok_or(Status::INVALID_HANDLE)
}

fn tid_placeholder() -> u16 {
    0
}
fn vfs_err(e: smb_vfs::VfsError) -> Status {
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



/// Convert storage metadata into the neutral query-payload snapshot.
pub(crate) fn qmeta_from(m: &smb_vfs::FileMeta) -> smb_proto_smb1::query::QueryMeta {
    smb_proto_smb1::query::QueryMeta {
        times: [m.times[0].0, m.times[1].0, m.times[2].0, m.times[3].0],
        attrs: m.attrs,
        eof: m.eof,
        alloc: m.alloc,
        is_dir: m.is_dir,
    }
}

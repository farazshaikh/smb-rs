//! SMB2 protocol loop ([MS-SMB2]).
//!
//! Implements the full file-serving command surface on top of the shared
//! [`Vfs`](smb_vfs::Vfs) abstraction: NEGOTIATE, SESSION_SETUP (both NTLMSSP
//! legs), TREE_CONNECT/DISCONNECT, LOGOFF, CREATE, READ, WRITE, CLOSE, FLUSH,
//! LOCK, QUERY_DIRECTORY, QUERY_INFO and SET_INFO. Frames whose magic is
//! `\xFESMB` route here from [`crate::dispatch`].

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use smb_proto::types::Status;
use smb_proto_smb2::commands as c;
use smb_proto_smb2::info as info;
use smb_proto_smb2::session_setup as ss;
use smb_transport::Transport;

use crate::state::{ServerShared, Share};

/// Per-connection SMB2 state.
pub struct Smb2Conn {
    /// Negotiated dialect revision (set after successful NEGOTIATE).
    pub dialect: Option<u16>,
    /// Current session id (0 = none).
    pub session_id: u64,
    /// True once credentials were accepted.
    pub authenticated: bool,
    /// NTLM challenge used during authentication.
    pub challenge: [u8; 8],
    /// Authenticated principal (`nobody` for guests).
    pub user: String,
    /// True when mapped to guest.
    pub guest: bool,
    /// Exported NTLM session key; enables SMB2 signing for this session
    /// ([MS-SMB2] §3.2.5.3).
    pub session_key: Option<[u8; 16]>,
    /// TID -> share name map.
    pub trees: HashMap<u32, String>,
    /// Open handles keyed by 16-byte SMB2 FileId.
    pub handles: HashMap<[u8; 16], Box<smb_vfs::OpenFile>>,
    /// Directory-enumeration continuation queues keyed by directory FileId.
    pub searches: HashMap<[u8; 16], VecDeque<info::FindEntry>>,
}

impl Smb2Conn {
    /// Create SMB2 connection state with the given NTLM challenge.
    pub fn new(challenge: [u8; 8]) -> Self {
        Smb2Conn {
            dialect: None,
            session_id: 0,
            authenticated: false,
            challenge,
            user: String::new(),
            guest: false,
            session_key: None,
            trees: HashMap::new(),
            handles: HashMap::new(),
            searches: HashMap::new(),
        }
    }
}

fn next_session_id() -> u64 {
    static S: AtomicU64 = AtomicU64::new(1);
    S.fetch_add(1, Ordering::Relaxed)
}

/// Allocate a 16-byte SMB2 FileId (counter in the first quadword).
fn next_file_id() -> [u8; 16] {
    static F: AtomicU64 = AtomicU64::new(0x2000);
    let mut fid = [0u8; 16];
    fid[..8].copy_from_slice(&F.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    fid
}

/// Allocate a fresh TreeId.
fn next_tree_id() -> u32 {
    static T: AtomicU64 = AtomicU64::new(1);
    (T.fetch_add(1, Ordering::Relaxed) & 0x7fff_ffff) as u32
}

/// Serve an SMB2 client connection until EOF/error (used when a connection
/// starts life directly in SMB2 rather than upgrading through SMB1).
pub async fn serve_client(
    server: Arc<ServerShared>,
    mut transport: Box<dyn Transport>,
    mut pending: Option<Vec<u8>>,
) {
    let mut conn = Smb2Conn::new(crate::dispatch::rand_challenge_pub());
    loop {
        let frame = if let Some(f) = pending.take() {
            f
        } else {
            match transport.recv().await {
                Ok(Some(f)) => f.0,
                _ => return,
            }
        };
        if frame.len() < 64 || frame[0..4] != smb_proto_smb2::SMB2_MAGIC {
            continue;
        }
        if let Some(resp) = process_frame(&server, &mut conn, &frame).await {
            if transport.send(&resp).await.is_err() {
                return;
            }
        }
    }
}

/// Respond to an SMB1 multi-protocol NEGOTIATE that carries the `\xFESMB`
/// dialect marker: builds the SMB2 negotiate response so the client upgrades.
pub fn handle_multiprotocol_negotiate(
    buf: &[u8],
    guid: &[u8; 16],
) -> Option<Vec<u8>> {
    let (hdr, _wc_off) = smb_proto_smb1::header::parse_header(buf)?;
    // The upgrade reply rides on MessageId|1 ([MS-SMB2] §3.2.5.1 style).
    let mid = u64::from(hdr.mid) | 1;
    let h2 = smb_proto_smb2::Header2 {
        credit_charge: 0,
        status: 0,
        command: 0,
        credits: 1,
        flags: 1,
        next_command: 0,
        message_id: mid,
        tree_id: 0,
        session_id: 0,
        signature: [0u8; 16],
    };
    Some(response(
        &h2,
        Status::SUCCESS,
        smb_proto_smb2::negotiate::build_response(
            smb_proto_smb2::negotiate::DIALECT_210,
            guid,
            smb_proto::types::FileTime::now().0,
        ),
        0,
    ))
}

/// Execute one frame (possibly compound) and build its response (`None` to
/// stay silent). Chained requests ([MS-SMB2] §3.3.5.2) are dispatched in
/// order and their replies concatenated with 8-byte alignment.
pub(crate) async fn process_frame(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    let mut off = 0usize;
    loop {
        if off + 64 > buf.len() {
            break;
        }
        let rest = &buf[off..];
        let Some(single) = process_single(server, conn, rest).await else {
            return None;
        };
        parts.push(single);

        let next = u32::from_le_bytes(rest[20..24].try_into().unwrap()) as usize;
        if next == 0 || next >= rest.len() {
            break;
        }
        off += next;
    }
    if parts.is_empty() {
        return None;
    }

    // Assemble compound reply: every frame except the last carries
    // NextCommand pointing at the following frame, 8-byte aligned.
    let mut out: Vec<u8> = Vec::with_capacity(parts.iter().map(|p| p.len() + 7).sum());
    let mut starts = Vec::with_capacity(parts.len());
    for p in &parts {
        while out.len() % 8 != 0 {
            out.push(0);
        }
        starts.push(out.len());
        out.extend_from_slice(p);
    }
    for w in 0..starts.len().saturating_sub(1) {
        let next = starts[w + 1] - starts[w];
        let pos = starts[w] + 20; // NextCommand field offset
        out[pos..pos + 4].copy_from_slice(&(next as u32).to_le_bytes());
    }
    Some(out)
}

/// Process exactly one SMB2 request starting at `buf` (its own header).
async fn process_single(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let hdr = match smb_proto_smb2::Header2::parse(buf) {
        Some(h) => h,
        None => return None,
    };
    if std::env::var_os("RUSTSMB_DEBUG").is_some() {
        eprintln!(
            "smb2: cmd={} mid={} sid={:#x} tid={:#x} len={} body={:02x?}",
            hdr.command,
            hdr.message_id,
            hdr.session_id,
            hdr.tree_id,
            buf.len(),
            &buf[64..buf.len().min(104)]
        );
    }
    let body_start = 64usize;
    let tid = hdr.tree_id;
    let sid = hdr.session_id;

    // Commands valid without an authenticated session.
    let pre_session = matches!(hdr.command, ss::cmd::NEGOTIATE | ss::cmd::SESSION_SETUP | ss::cmd::ECHO);
    if !pre_session && (!conn.authenticated || sid != conn.session_id) {
        return Some(response(&hdr, Status::ACCESS_DENIED, Vec::new(), 0));
    }

    // TREE_CONNECT overrides the response TreeId with the fresh value.
    let mut resp_tid: Option<u32> = None;

    let (status, body): (Status, Vec<u8>) = match hdr.command {
        ss::cmd::NEGOTIATE => {
            // Clients probing for SMB2 support send either a header-only
            // NEGOTIATE or one carrying Status = STATUS_INVALID_PARAMETER
            // ([MS-SMB2] §3.3.5.3). Answer both with the wildcard-dialect
            // response so they retry a real negotiation.
            if hdr.status == Status::INVALID_PARAMETER.raw()
                || smb_proto_smb2::negotiate::Request::parse(buf.get(body_start..).unwrap_or(&[]))
                    .is_none()
            {
                return Some(response(
                    &hdr,
                    Status::INVALID_PARAMETER,
                    probe_negotiate_resp(),
                    conn.session_id,
                ));
            }
            let req = smb_proto_smb2::negotiate::Request::parse(buf.get(body_start..).unwrap_or(&[]))
                .unwrap();
            let Some(dialect) = smb_proto_smb2::negotiate::pick(&req.dialects) else {
                return Some(response(&hdr, Status::INVALID_PARAMETER, Vec::new(), 0));
            };
            conn.dialect = Some(dialect);
            (
                Status::SUCCESS,
                smb_proto_smb2::negotiate::build_response(
                    dialect,
                    &server.guid,
                    smb_proto::types::FileTime::now().0,
                ),
            )
        }
        ss::cmd::SESSION_SETUP => match session_setup(server, conn, buf) {
            Ok((status, body)) => (status, body),
            Err(status) => (status, Vec::new()),
        },
        ss::cmd::TREE_CONNECT => match tree_connect(server, conn, buf) {
            Ok((name, share_type)) => {
                let new_tid = next_tree_id();
                conn.trees.insert(new_tid, name);
                resp_tid = Some(new_tid);
                (Status::SUCCESS, c::build_tree_connect_resp(share_type))
            }
            Err(status) => (status, Vec::new()),
        },
        ss::cmd::TREE_DISCONNECT => {
            if conn.trees.remove(&tid).is_none() {
                (Status::INVALID_PARAMETER, Vec::new())
            } else {
                (Status::SUCCESS, c::build_tree_disconnect_resp())
            }
        }
        ss::cmd::LOGOFF => {
            close_all_handles(conn);
            conn.trees.clear();
            conn.searches.clear();
            conn.authenticated = false;
            conn.session_id = 0;
            (Status::SUCCESS, c::build_logoff_resp())
        }
        ss::cmd::CREATE => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match create(conn, vfs, buf).await {
                Ok(body) => (Status::SUCCESS, body),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::READ => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match read(conn, vfs, buf).await {
                Ok(body) => (Status::SUCCESS, body),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::WRITE => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match write(conn, vfs, buf).await {
                Ok(body) => (Status::SUCCESS, body),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::CLOSE => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match close(conn, vfs, buf).await {
                Ok(body) => (Status::SUCCESS, body),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::FLUSH => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match flush(conn, vfs, buf).await {
                Ok(()) => (Status::SUCCESS, c::build_flush_resp()),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::IOCTL => {
            let Some(req) = c::IoctlReq::parse(buf) else {
                return Some(response(&hdr, Status::INVALID_PARAMETER, Vec::new(), conn.session_id));
            };
            match req.ctl_code {
                // Echo the negotiated parameters back ([MS-SMB2] §3.3.5.15):
                // capabilities, server GUID, security mode and dialect.
                c::fsctl::VALIDATE_NEGOTIATE_INFO if req.input.len() >= 24 => {
                    let mut out = Vec::with_capacity(24);
                    out.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
                    out.extend_from_slice(&server.guid);
                    out.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode
                    out.extend_from_slice(
                        &conn.dialect.unwrap_or(smb_proto_smb2::negotiate::DIALECT_210)
                            .to_le_bytes(),
                    );
                    // Ignore the client's copy; success means "validated".
                    let _ = &req.input;
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &out))
                }
                // Resiliency handshake carries no output data.
                c::fsctl::LMR_REQUEST_RESILIENCY | c::fsctl::PIPE_WAIT => {
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &[]))
                }
                _ => (Status::NOT_IMPLEMENTED, Vec::new()),
            }
        }
        ss::cmd::LOCK => match c::LockReq::parse(buf) {
            Some(_) => (Status::SUCCESS, c::build_lock_resp()),
            None => (Status::INVALID_PARAMETER, Vec::new()),
        },
        ss::cmd::QUERY_DIRECTORY => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match query_directory(conn, vfs, buf).await {
                Ok(Some(buffer)) => (Status::SUCCESS, c::build_info_resp(&buffer)),
                Ok(None) => (Status::NO_MORE_FILES, Vec::new()),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::QUERY_INFO => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match query_info(conn, vfs, buf).await {
                Ok(Some(buffer)) => (Status::SUCCESS, c::build_info_resp(&buffer)),
                Ok(None) => (Status::NOT_IMPLEMENTED, Vec::new()),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::SET_INFO => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return Some(response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id)),
            };
            match set_info(conn, vfs, buf).await {
                Ok(()) => (Status::SUCCESS, c::build_set_info_resp()),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::ECHO => (Status::SUCCESS, 4u16.to_le_bytes().to_vec()),
        _ => (Status::NOT_IMPLEMENTED, Vec::new()),
    };

    let mut resp = response(&hdr, status, body, conn.session_id);
    if let Some(new_tid) = resp_tid {
        resp[36..40].copy_from_slice(&new_tid.to_le_bytes()); // TreeId
    }
    // Mirror the client's signing flag ([MS-SMB2] §3.3.4.2): authenticated
    // sessions get HMAC-SHA256 signatures over the full PDU.
    if hdr.is_signed() {
        if let Some(key) = conn.session_key {
            resp[16] |= 0x08; // SMB2_FLAGS_SIGNED in response flags
            let mut msg = Vec::with_capacity(resp.len());
            msg.extend_from_slice(&resp[..48]);
            msg.extend_from_slice(&[0u8; 16]); // zeroed Signature field
            msg.extend_from_slice(&resp[64..]);
            let sig = smb_auth::crypto::hmac_sha256(&key, &msg);
            resp[48..64].copy_from_slice(&sig[..16]);
        }
    }
    Some(resp)
}

/// Build the wildcard-dialect NEGOTIATE response used to answer the
/// invalid-status probe ([MS-SMB2] §2.2.3.1.1): DialectRevision 0x02FF with
/// all other fields zero.
fn probe_negotiate_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(68);
    b.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityMode
    b.extend_from_slice(&0x02FFu16.to_le_bytes()); // DialectRevision wildcard
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved/NegotiateContextCount
    b.extend_from_slice(&[0u8; 16]); // ServerGuid
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0u32.to_le_bytes()); // MaxTransactionSize
    b.extend_from_slice(&0u32.to_le_bytes()); // MaxReadSize
    b.extend_from_slice(&0u32.to_le_bytes()); // MaxWriteSize
    b.extend_from_slice(&0u64.to_le_bytes()); // SystemTime
    b.extend_from_slice(&0u64.to_le_bytes()); // ServerStartTime
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // SecurityBufferLength
    b.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    b
}

// ---------------- SESSION_SETUP ----------------

/// Handle one leg of SPNEGO/NTLMSSP session establishment ([MS-SMB2]
/// §3.3.5.5).
fn session_setup(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Result<(Status, Vec<u8>), Status> {
    let req = ss::Request::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let inner = smb_auth::ntlm::unwrap_blob(&req.blob).unwrap_or(&[]);
    eprintln!(
        "smb2 setup: blob_len={} first={:02x?} inner_type={:?}",
        req.blob.len(),
        &req.blob[..req.blob.len().min(12)],
        smb_auth::ntlm::msg_type(inner)
    );
    match smb_auth::ntlm::msg_type(inner) {
        Some(smb_auth::ntlm::MSG_TYPE1) | None => {
            // Leg 1: issue CHALLENGE under MORE_PROCESSING_REQUIRED.
            conn.session_id = next_session_id();
            let t2 =
                smb_auth::ntlm::build_type2(&conn.challenge, &server.domain, &server.server_name);
            let wrapped = smb_auth::ntlm::wrap_negtoken_targ(&t2);
            Ok((
                Status::MORE_PROCESSING_REQUIRED,
                ss::build_response(0, &wrapped),
            ))
        }
        Some(smb_auth::ntlm::MSG_TYPE3) => {
            if smb_auth::ntlm::parse_type3(inner).is_none() {
                eprintln!("smb2 setup: parse_type3 FAILED");
                return Err(Status::INVALID_PARAMETER);
            }
            let t3 = smb_auth::ntlm::parse_type3(inner).unwrap();
            let out = crate::auth::authenticate_ntlmssp(
                &server.users,
                server.allow_guest,
                &conn.challenge,
                &t3,
            );
            if !out.ok {
                return Err(Status::LOGON_FAILURE);
            }
            eprintln!(
                "smb2 setup leg2: ok={} guest={} user={:?}",
                out.ok, out.guest, out.user
            );
            conn.user = out.user.clone();
            conn.guest = out.guest;
            conn.session_key = out.session_key;
            conn.authenticated = true;
            let flags: u16 = if out.guest { 0x0001 } else { 0x0000 };
            // Close the SPNEGO exchange: clients require a NegTokenResp
            // with negResult = accept-completed in the final leg.
            let wrapped = smb_auth::ntlm::wrap_accept_complete();
            Ok((Status::SUCCESS, ss::build_response(flags, &wrapped)))
        }
        _ => Err(Status::LOGON_FAILURE),
    }
}

// ---------------- TREE_CONNECT ----------------

fn tree_connect(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Result<(String, u8), Status> {
    let path_len = g16(buf, c::tcon_off::PATH_LENGTH) as usize;
    let path_off = g16(buf, c::tcon_off::PATH_OFFSET) as usize;
    let raw = buf.get(path_off..path_off + path_len).unwrap_or(&[]);
    let path = String::from_utf16_lossy(
        &raw.chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect::<Vec<_>>(),
    )
    .trim_end_matches('\0')
    .to_string();
    let name = path
        .rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_lowercase();
    let share = server.shares.get(&name).ok_or(Status::BAD_NETWORK_NAME)?;
    let share_type = if share.is_ipc {
        c::share_type::PIPE
    } else {
        c::share_type::DISK
    };
    Ok((name, share_type))
}

// ---------------- CREATE ----------------

async fn create(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::CreateReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;

    const OPT_DIRECTORY_FILE: u32 = 0x1;
    const OPT_NON_DIRECTORY_FILE: u32 = 0x40;
    const OPT_DELETE_ON_CLOSE: u32 = 0x1000;

    let rel = req.name.trim_start_matches(['\\', '/']).to_string();
    let want_dir = req.options & OPT_DIRECTORY_FILE != 0;

    let (mut open, meta, action) = vfs
        .create(
            &rel,
            want_dir,
            req.desired_access,
            req.disposition,
            req.options,
            req.attrs,
        )
        .await
        .map_err(vfs_err)?;

    if req.options & OPT_NON_DIRECTORY_FILE != 0 && open.is_dir {
        return Err(Status::FILE_IS_A_DIRECTORY);
    }
    open.delete_on_close |= req.options & OPT_DELETE_ON_CLOSE != 0;

    let fid_bytes = next_file_id();
    let fid = c::FileId(fid_bytes);
    conn.searches.remove(&fid_bytes);
    conn.handles.insert(fid_bytes, open);

    eprintln!(
        "SMB2 CREATE: name={:?} eof={} is_dir={} action={}",
        rel, meta.eof, meta.is_dir, action
    );
    Ok(c::build_create_resp(
        fid,
        action,
        [meta.times[0].0, meta.times[1].0, meta.times[2].0, meta.times[3].0],
        meta.attrs.0,
        meta.alloc,
        meta.eof,
        meta.is_dir,
    ))
}

// ---------------- READ / WRITE / CLOSE / FLUSH ----------------

async fn read(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::ReadReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let len = (req.length as usize).min(1 << 20); // clamp to 1 MiB
    let Some(h) = conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) else {
        return Err(Status::INVALID_HANDLE);
    };
    if h.is_dir || !h.can_read {
        return Err(Status::ACCESS_DENIED);
    }
    let data = vfs.read(h, req.offset, len).await.map_err(vfs_err)?;
    eprintln!("SMB2 READ: offset={} want={} got={}", req.offset, len, data.len());
    Ok(c::build_read_resp(&data))
}

async fn write(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::WriteReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let Some(h) = conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) else {
        return Err(Status::INVALID_HANDLE);
    };
    if h.is_dir || !h.can_write {
        return Err(Status::ACCESS_DENIED);
    }
    let written = vfs.write(h, req.offset, &req.payload, false)
        .await
        .map_err(vfs_err)?;
    eprintln!("SMB2 WRITE: offset={} wrote={}", req.offset, written);
    Ok(c::build_write_resp(written as u32))
}

async fn close(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::CloseReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let Some(mut h) = conn.handles.remove(&req.file_id.0) else {
        return Err(Status::INVALID_HANDLE);
    };
    conn.searches.remove(&req.file_id.0);
    let meta = vfs.stat(&h.path).await.ok().unwrap_or_default();
    vfs.close(h).await.map_err(vfs_err)?;
    eprintln!("SMB2 CLOSE: fid={:02x?}", req.file_id.0);
    Ok(c::build_close_resp(
        [meta.times[0].0, meta.times[1].0, meta.times[2].0, meta.times[3].0],
        meta.alloc,
        meta.eof,
        meta.attrs.0,
    ))
}

async fn flush(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<(), Status> {
    let req = c::FlushReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    if let Some(h) = conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) {
        vfs.flush(h).await.map_err(vfs_err)?;
    }
    Ok(())
}

fn close_all_handles(conn: &mut Smb2Conn) {
    conn.handles.clear();
}

// ---------------- QUERY_DIRECTORY ----------------

async fn query_directory(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Option<Vec<u8>>, Status> {
    let req = c::QueryDirReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;

    // Clients repeat the original pattern on every continuation call, so a
    // fresh enumeration starts only when no search state exists yet or the
    // client asks to restart/rescan ([MS-SMB2] §3.3.5.24).
    let has_state = conn.searches.contains_key(&req.file_id.0);
    let restart = !has_state
        || req.flags
            & (c::find_flags::RESTART_SCANS | c::find_flags::REOPEN | c::find_flags::SCAN)
            != 0;

    if restart {
        let dir_rel = {
            let h = conn
                .handles
                .get(&req.file_id.0)
                .ok_or(Status::INVALID_HANDLE)?;
            if !h.is_dir {
                return Err(Status::NOT_A_DIRECTORY);
            }
            // Enumeration runs inside the opened directory; the pattern may
            // still carry a subdirectory prefix relative to it.
            let pattern = req.pattern.trim_start_matches(['\\', '/']).to_string();
            let (dir_part, _) = crate::cmds::dir_cmds_split(&pattern);
            if dir_part.is_empty() {
                h.rel.clone()
            } else if h.rel.is_empty() {
                dir_part
            } else {
                format!("{}\\{}", h.rel.trim_end_matches(['\\', '/']), dir_part)
            }
        };

        let (_, name_pat) = crate::cmds::dir_cmds_split(
            &req.pattern.trim_start_matches(['\\', '/']),
        );
        let entries = vfs.list(&dir_rel).await.map_err(vfs_err)?;
        let matched: Vec<info::FindEntry> = entries
            .into_iter()
            .filter(|e| {
                name_pat.is_empty()
                    || crate::cmds::wildcard(&e.name.to_lowercase(), &name_pat.to_lowercase())
            })
            .map(|e| info::FindEntry { name: e.name, meta: info::QueryMeta::from_vfs(&e.meta) })
            .collect();
        conn.searches.insert(req.file_id.0, matched.into());
    } else if !conn.searches.contains_key(&req.file_id.0) {
        return Err(Status::INVALID_PARAMETER);
    }

    // Take up to one batch of entries (single entry when requested).
    let take = if req.flags & c::find_flags::RETURN_SINGLE_ENTRY != 0 {
        1
    } else {
        512
    };
    let Some(queue) = conn.searches.get_mut(&req.file_id.0) else {
        return Err(Status::INVALID_PARAMETER);
    };
    let out: Vec<info::FindEntry> =
        (0..take).filter_map(|_| queue.pop_front()).collect();

    if out.is_empty() {
        return Ok(None); // STATUS_NO_MORE_FILES
    }
    Ok(Some(info::encode_find_entries(&out, req.class)))
}

// ---------------- QUERY_INFO ----------------

async fn query_info(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Option<Vec<u8>>, Status> {
    let req = c::QueryInfoReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    match req.info_type {
        c::info_type::FILE => {
            let h = conn.handles.get(&req.file_id.0).ok_or(Status::INVALID_HANDLE)?;
            let m = vfs.stat(&h.path).await.map_err(vfs_err)?;
            let qm = info::QueryMeta::from_vfs(&m);
            let name = h
                .rel
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("")
                .to_string();
            info::encode_file_info(req.class, &qm, &name)
                .map(Some)
                .ok_or(Status::NOT_IMPLEMENTED)
        }
        c::info_type::FS => {
            info::encode_fs_info(req.class).map(Some).ok_or(Status::NOT_IMPLEMENTED)
        }
        _ => Ok(None), // SECURITY / QUOTA unsupported for now
    }
}

// ---------------- SET_INFO ----------------

async fn set_info(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<(), Status> {
    let req = c::SetInfoReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    match req.info_type {
        c::info_type::FILE => {
            let op = match info::decode_set_file_op(req.class, &req.buffer) {
                Ok(op) => op,
                Err(_) => return Err(Status::INVALID_PARAMETER),
            };
            let Some(op) = op else { return Ok(()) }; // advisory-only class
            let Some(h) = conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) else {
                return Err(Status::INVALID_HANDLE);
            };
            vfs.set_info_open(h, &op).await.map_err(vfs_err)
        }
        _ => Err(Status::NOT_IMPLEMENTED),
    }
}

// ---------------- helpers ----------------

fn g16(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}

/// Resolve the VFS backing `tid`, mirroring the SMB1 path (share by name,
/// unknown trees rejected before handlers run).
fn share_vfs(
    server: &Arc<ServerShared>,
    conn: &Smb2Conn,
    tid: u32,
) -> Option<Arc<dyn smb_vfs::Vfs>> {
    conn.trees.get(&tid).and_then(|n| server.shares.get(n)).map(|s| s.vfs.clone())
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

/// Build the generic ERROR response body ([MS-SMB2] §2.2.2): StructureSize
/// 9 with no error data. Every failed command carries this so clients can
/// parse the frame (a bare header breaks their compound parser). The body
/// is padded to the structure's declared 8-byte footprint.
fn error_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.push(0); // Reserved
    b.push(0); // ByteCount
    b.resize(8, 0); // ErrorData area (empty, padded)
    b
}

/// Build a 64-byte SMB2 response header + body, echoing MessageId/TreeId
/// and stamping the effective session id ([MS-SMB2] §3.3.4.1).
pub(crate) fn response(
    req: &smb_proto_smb2::Header2,
    status: Status,
    body: Vec<u8>,
    session_id: u64,
) -> Vec<u8> {
    // Any failing/warning status without a handler-built body uses the
    // generic ERROR structure (clients cannot parse a bare header).
    let body = if status != Status::SUCCESS && body.is_empty() {
        error_resp()
    } else {
        body
    };
    let mut f = Vec::with_capacity(64 + body.len());
    f.extend_from_slice(&smb_proto_smb2::SMB2_MAGIC);
    f.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    f.extend_from_slice(&req.credit_charge.to_le_bytes()); // CreditCharge echo
    f.extend_from_slice(&status.raw().to_le_bytes());
    f.extend_from_slice(&req.command.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes()); // Credits granted
    f.extend_from_slice(&1u32.to_le_bytes()); // FLAGS_SERVER_TO_REDIR
    f.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    f.extend_from_slice(&req.message_id.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes()); // Reserved/ProcessId
    f.extend_from_slice(&req.tree_id.to_le_bytes());
    f.extend_from_slice(&session_id.to_le_bytes());
    f.extend_from_slice(&[0u8; 16]); // Signature
    debug_assert_eq!(f.len(), 64);
    f.extend_from_slice(&body);
    f
}

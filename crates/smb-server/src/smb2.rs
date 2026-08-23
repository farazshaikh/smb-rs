//! SMB2 protocol loop ([MS-SMB2]).
//!
//! Handles frames whose magic is `\xFESMB`. Currently implements
//! NEGOTIATE and SESSION_SETUP (both NTLMSSP legs); remaining commands
//! return `INVALID_PARAMETER` so clients degrade gracefully while
//! additional phases land.

use std::collections::HashMap;
use std::sync::Arc;

use smb_proto::types::Status;
use smb_proto_smb2::session_setup as ss;
use smb_transport::Transport;

use crate::state::{next_uid, ServerShared, Share};

/// Per-connection SMB2 state.
pub struct Smb2Conn {
    /// Negotiated dialect revision (set after successful NEGOTIATE).
    pub dialect: Option<u16>,
    /// Current session id (0 = none).
    pub session_id: u64,
    /// NTLM challenge used during authentication.
    pub challenge: [u8; 8],
    /// Authenticated principal (`nobody` for guests).
    pub user: String,
    /// True when mapped to guest.
    pub guest: bool,
    /// TID -> share name map.
    pub trees: HashMap<u64, String>,
}

impl Smb2Conn {
    /// Create SMB2 connection state with the given NTLM challenge.
    pub fn new(challenge: [u8; 8]) -> Self {
        Smb2Conn {
            dialect: None,
            session_id: 0,
            challenge,
            user: String::new(),
            guest: false,
            trees: HashMap::new(),
        }
    }
}

fn next_session_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static S: AtomicU64 = AtomicU64::new(1);
    S.fetch_add(1, Ordering::Relaxed)
}

/// Respond to an SMB1 multi-protocol NEGOTIATE that carries the `\xFESMB`
/// dialect marker: builds the SMB2 negotiate response so the client upgrades.
pub fn handle_multiprotocol_negotiate(
    buf: &[u8],
    guid: &[u8; 16],
) -> Option<Vec<u8>> {
    let (hdr, _wc_off) = smb_proto_smb1::header::parse_header(buf)?;
    let mid = u64::from(hdr.mid) | 1;
    Some(build_smb2_response(
        smb_proto_smb2::Header2 {
            credit_charge: 0,
            status: 0,
            command: 0,
            credits: 1,
            flags: 1,
            next_command: 0,
            message_id: mid,
            session_id: 0,
            signature: [0u8; 16],
        },
        Status::SUCCESS,
        1,
        smb_proto_smb2::negotiate::build_response(
            smb_proto_smb2::negotiate::DIALECT_210,
            guid,
            smb_proto::types::FileTime::now().0,
        ),
        0,
        mid,
    ))
}

/// Serve an SMB2 client connection until EOF/error.
pub async fn serve_client(
    server: Arc<ServerShared>,
    mut transport: Box<dyn Transport>,
    mut pending: Option<Vec<u8>>,
) {
    let mut conn = Smb2Conn::new(crate::dispatch::rand_challenge_pub());
    let mut message_id: u64 = 1;

    eprintln!("smb2: connection start");
    loop {
        eprintln!("smb2: pending={:?} waiting...", pending.is_some());
        let frame = if let Some(f) = pending.take() {
            f
        } else {
            match transport.recv().await {
                Ok(Some(f)) => f.0,
                _ => return,
            }
        };
        eprintln!("smb2: got frame len={} magic={:02x?}", frame.len(), &frame[0..4.min(frame.len())]);
        if frame.len() < 64 || frame[0..4] != smb_proto_smb2::SMB2_MAGIC {
            continue;
        }
        if let Some(resp) = process_frame(&server, &mut conn, &mut message_id, &frame) {
            if transport.send(&resp).await.is_err() {
                return;
            }
        }
    }
}

pub(crate) fn process_frame(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    mid: &mut u64,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let hdr = match smb_proto_smb2::Header2::parse(buf) {
        Some(h) => h,
        None => { eprintln!("smb2: HEADER PARSE FAILED"); return None; }
    };
    let command = hdr.command;
    let body_start = 64usize;

    let (status, body): (Status, Vec<u8>) = match command {
        ss::cmd::NEGOTIATE => {
            let req = smb_proto_smb2::negotiate::Request::parse(
                buf.get(body_start..).unwrap_or(&[]),
            )?;
            let Some(dialect) = smb_proto_smb2::negotiate::pick(&req.dialects) else {
                *mid += 1;
                return Some(smb2_response(hdr, Status::INVALID_PARAMETER, 1, Vec::new(), *mid));
            };
            conn.dialect = Some(dialect);
            (
                Status::SUCCESS,
                smb_proto_smb2::negotiate::build_response(dialect, &server.guid, smb_proto::types::FileTime::now().0),
            )
        }
        ss::cmd::SESSION_SETUP => {
            let Some(req) = ss::Request::parse(buf.get(body_start..).unwrap_or(&[])) else {
                *mid += 1;
                return Some(smb2_response(hdr, Status::INVALID_PARAMETER, 1, Vec::new(), *mid));
            };
            let inner = smb_auth::ntlm::unwrap_blob(&req.blob).unwrap_or(&[]);
            match smb_auth::ntlm::msg_type(inner) {
                Some(smb_auth::ntlm::MSG_TYPE1) | None => {
                    // Leg 1: issue CHALLENGE under MORE_PROCESSING_REQUIRED.
                    conn.session_id = next_session_id();
                    let t2 = smb_auth::ntlm::build_type2(
                        &conn.challenge,
                        &server.domain,
                        &server.server_name,
                    );
                    let wrapped = smb_auth::ntlm::wrap_negtoken_targ(&t2);
                    // Body = StructureSize(9) + flags + offset + blob.
                    let mut body = Vec::with_capacity(8 + wrapped.len());
                    body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
                    body.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags
                    body.extend_from_slice(&((64 + 72) as u16).to_le_bytes()); // SecurityBufferOffset
                    body.extend_from_slice(&(wrapped.len() as u16).to_le_bytes());
                    body.extend_from_slice(&wrapped);
                    return Some(build_smb2_response(
                        hdr,
                        Status::MORE_PROCESSING_REQUIRED,
                        1,
                        body,
                        conn.session_id,
                        *mid,
                    ));
                }
                Some(smb_auth::ntlm::MSG_TYPE3) => {
                    let t3 = smb_auth::ntlm::parse_type3(inner)?;
                    let out = crate::auth::authenticate_ntlmssp(
                        &server.users,
                        server.allow_guest,
                        &conn.challenge,
                        &t3,
                    );
                    if !out.ok {
                        *mid += 1;
                        return Some(smb2_response(hdr, Status::LOGON_FAILURE, 1, Vec::new(), *mid));
                    }
                    conn.user = out.user.clone();
                    conn.guest = out.guest;
                    let flags: u16 = if out.guest { 0x0001 } else { 0x0000 };
                    (
                        Status::SUCCESS,
                        smb_proto_smb2::session_setup::build_response(flags, &[], 64),
                    )
                }
                _ => {
                    *mid += 1;
                    return Some(smb2_response(hdr, Status::LOGON_FAILURE, 1, Vec::new(), *mid));
                }
            }
        }
        ss::cmd::TREE_CONNECT => {
            let body = buf.get(64..)?;
            let path_len = g16(body, 4) as usize;
            let path_off = g16(body, 6) as usize;
            let path = String::from_utf8_lossy(
                buf.get(path_off..path_off + path_len).unwrap_or(&[])
            ).trim_end_matches('\0').to_string();
            let name = path.rsplit(['/', '\\'])
                .find(|s| !s.is_empty())
                .unwrap_or("")
                .to_lowercase();
            if name != "ipc$" && !server.shares.contains_key(&name) {
                (Status::BAD_NETWORK_NAME, Vec::new())
            } else {
                use std::sync::atomic::{AtomicU64, Ordering};
                static TID: AtomicU64 = AtomicU64::new(1);
                let tid = TID.fetch_add(1, Ordering::Relaxed);
                conn.trees.insert(tid, name);
                (Status::SUCCESS, vec![16u8, 0].to_vec())
            }
        }
        ss::cmd::TREE_DISCONNECT => {
            let tid = buf.get(60..68)
                .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
                .unwrap_or(0);
            conn.trees.remove(&tid);
            (Status::SUCCESS, vec![16u8, 0].to_vec())
        }
        ss::cmd::CREATE => {
            // Minimal CREATE for testing — full impl in next phase.
            (Status::NOT_IMPLEMENTED, Vec::new())
        }
        ss::cmd::READ => {
            (Status::NOT_IMPLEMENTED, Vec::new())
        }
        ss::cmd::WRITE => {
            (Status::NOT_IMPLEMENTED, Vec::new())
        }
        ss::cmd::ECHO => {
            (Status::SUCCESS, buf.get(64..).unwrap_or(&[]).to_vec())
        }
        _ => (Status::NOT_IMPLEMENTED, Vec::new()),
    };

    *mid += 1;
    let sid = if last_status_is_error(status) { 0 } else { conn.session_id };
    let _ = sid;
    Some(build_smb2_response(hdr, status, 1, body, conn.session_id, *mid))
}

fn g16(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).unwrap_or(0)
}

fn last_status_is_error(_s: Status) -> bool {
    false
}

/// Build a 64-byte SMB2 response header + body.
#[allow(clippy::too_many_arguments)]
fn build_smb2_response(
    req: smb_proto_smb2::Header2,
    status: Status,
    credits: u16,
    body: Vec<u8>,
    session_id: u64,
    mid: u64,
) -> Vec<u8> {
    let mut f = Vec::with_capacity(64 + body.len());
    f.extend_from_slice(&smb_proto_smb2::SMB2_MAGIC);
    f.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    f.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    f.extend_from_slice(&status.raw().to_le_bytes());
    f.extend_from_slice(&req.command.to_le_bytes());
    f.extend_from_slice(&credits.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes()); // FLAGS_RESPONSE
    f.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    f.extend_from_slice(&mid.to_le_bytes());
    f.extend_from_slice(&0u32.to_le_bytes()); // Reserved/ProcessId
    f.extend_from_slice(&session_id.to_le_bytes());
    f.extend_from_slice(&[0u8; 16]); // signature
    f.extend_from_slice(&[0u8; 4]); // reserved (header is 64 bytes)
    debug_assert_eq!(f.len(), 64);
    f.extend_from_slice(&body);
    f
}

/// Build an SMB2 response frame directly from parts (legacy helper).
fn smb2_response(
    req: smb_proto_smb2::Header2,
    status: Status,
    credits: u16,
    body: Vec<u8>,
    _mid: u64,
) -> Vec<u8> {
    build_smb2_response(req, status, credits, body, 0, 1)
}

/// The share lookup helper mirrors the SMB1 path (share by name).
pub fn share_for<'a>(
    server: &'a ServerShared,
    conn: &Smb2Conn,
    tid: u64,
) -> Result<&'a Share, Status> {
    let name = conn.trees.get(&tid).ok_or(Status::INVALID_HANDLE)?;
    server.shares.get(name).ok_or(Status::INVALID_HANDLE)
}

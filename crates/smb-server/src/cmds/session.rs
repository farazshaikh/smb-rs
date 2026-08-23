//! Negotiate / session setup / tree connect / echo handlers.

use smb_proto::types::{FileTime, Status};
use smb_proto_smb1::consts::{self, caps, flags2};
use smb_proto_smb1::header::RespBody;
use smb_proto_smb1::negotiate;
use smb_proto_smb1::session_setup as ss;
use smb_proto_smb1::tree_connect as tc;

use crate::auth::authenticate_ntlmssp;
use crate::dispatch::{IoContext, ReqView};
use crate::state::{next_tid, next_uid, Session};

/// Our negotiated capability set.
pub fn our_caps() -> u32 {
    caps::CAP_UNICODE
        | caps::CAP_LARGE_FILES
        | caps::CAP_NT_SMBS
        | caps::CAP_STATUS32
        | caps::CAP_LEVEL2_OPLOCKS
        | caps::CAP_LOCK_AND_READ
        | caps::CAP_NT_FIND
        | caps::CAP_INFOLEVEL_PASSTHRU
        | caps::CAP_LARGE_READX
        | caps::CAP_LARGE_WRITEX
}

/// NEGOTIATE: pick dialect, advertise capabilities, hand out the challenge.
pub fn negotiate(req: &ReqView, bodies: &mut Vec<RespBody>) -> Result<Status, Status> {
    let parsed = negotiate::NegotiateReq::parse(req.data);
    let idx = parsed.select().ok_or(Status::INVALID_PARAMETER)?;
    let body = RespBody::new(
        consts::COM_NEGOTIATE,
        negotiate::build_params(idx as u16, our_caps(), FileTime::now()),
        Vec::new(), // challenge patched into words by the dispatcher
    );
    *bodies = vec![body];
    Ok(Status::SUCCESS)
}

/// SESSION_SETUP_ANDX extended security: NTLMSSP two-leg flow.
pub fn setup(
    io: &mut IoContext,
    req: &ReqView,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let conn = &mut io.conn;
    let parsed = ss::SessionSetupReq::parse(
        req.words,
        req.data,
        req.unicode(),
        req.bc_off_abs + 2,
    )
    .map_err(|_| Status::LOGON_FAILURE)?;

    let inner = smb_auth::ntlm::unwrap_blob(&parsed.nt_resp).unwrap_or(&[]);
    match smb_auth::ntlm::msg_type(inner) {
        Some(smb_auth::ntlm::MSG_TYPE1) | Some(smb_auth::ntlm::MSG_TYPE2) | None => {
            // Leg 1 — issue the CHALLENGE.
            let uid = if conn.uid != 0 { conn.uid } else { next_uid() };
            conn.uid = uid;
            conn.auth_pending = true;
            conn.spnego = smb_auth::ntlm::is_spnego(&parsed.nt_resp);

            let t2 = smb_auth::ntlm::build_type2(
                &conn.challenge,
                &io.server.domain,
                &io.server.server_name,
            );
            let out_blob = if conn.spnego {
                smb_auth::ntlm::wrap_negtoken_targ(&t2)
            } else {
                t2.clone()
            };
            let (params, bytes) = ss::SessionSetupReq::build_response(0, &out_blob);
            let mut b = RespBody::new(consts::COM_SESSION_SETUP_ANDX, params, bytes);
            b.uid_override = Some(uid);
            *bodies = vec![b];
            Ok(Status::MORE_PROCESSING_REQUIRED)
        }
        Some(smb_auth::ntlm::MSG_TYPE3) => {
            // Leg 2 — verify the AUTHENTICATE message.
            let t3 = smb_auth::ntlm::parse_type3(inner).ok_or(Status::LOGON_FAILURE)?;
            let out =
                authenticate_ntlmssp(&io.server.users, io.server.allow_guest, &conn.challenge, &t3);
            if !out.ok {
                return Err(Status::LOGON_FAILURE);
            }
            let uid = if conn.uid != 0 { conn.uid } else { next_uid() };
            conn.uid = uid;
            conn.auth_pending = false;
            conn.session = Some(Session {
                user: out.user.clone(),
                guest: out.guest,
                trees: Vec::new(),
            });

            let action: u16 = if out.guest { 0x0001 } else { 0x0000 };
            let fin = if conn.spnego {
                smb_auth::ntlm::wrap_accept_complete()
            } else {
                Vec::new()
            };
            let (params, mut bytes) = ss::SessionSetupReq::build_response(action, &fin);
            // Drop OEM strings when a SPNEGO accept-complete token is present:
            // some parsers mis-detect string boundaries after DER blobs.
            if !fin.is_empty() {
                bytes.truncate(fin.len());
            }
            let mut b = RespBody::new(consts::COM_SESSION_SETUP_ANDX, params, bytes);
            b.uid_override = Some(uid);
            *bodies = vec![b];
            Ok(Status::SUCCESS)
        }
        _ => Err(Status::LOGON_FAILURE),
    }
}

/// TREE_CONNECT_ANDX: resolve share name to its VFS-backed entry.
pub fn tree_connect(
    io: &mut IoContext,
    req: &ReqView,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let tc = tc::TreeConnectReq::parse(
        req.words,
        req.data,
        req.unicode(),
        req.bc_off_abs + 2,
    )
    .map_err(|_| Status::INVALID_PARAMETER)?;

    let name = tc
        .path
        .rsplit(['\\', '/'])
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_lowercase();
    let ipc = name == "ipc$" || tc.service.starts_with("IPC");
    if !ipc && !io.server.shares.contains_key(&name) {
        return Err(Status::BAD_NETWORK_NAME);
    }
    let tid = next_tid();
    io.conn.trees.insert(tid, name.clone());
    if let Some(sess) = io.conn.session.as_mut() {
        sess.trees.push(tid);
    }

    let svc = if ipc { "IPC" } else { "A:" };
    let fs = if ipc { "" } else { "NTFS" };
    let (params, mut bytes) = tc::build_response(0x0001, svc, fs, req.unicode(), 43);
    if fs.is_empty() && unicode_tail_ok(&bytes) {
        bytes.truncate(bytes.len().saturating_sub(if req.unicode() { 2 } else { 1 }));
    }
    let mut b = RespBody::new(consts::COM_TREE_CONNECT_ANDX, params, bytes);
    b.tid_override = Some(tid);
    *bodies = vec![b];
    Ok(Status::SUCCESS)
}

fn unicode_tail_ok(_bytes: &[u8]) -> bool {
    true
}

/// ECHO: reply `count` times with identical payloads.
pub fn echo(req: &ReqView, bodies: &mut Vec<RespBody>) -> Result<Status, Status> {
    let count = if req.words.len() >= 2 {
        u16::from_le_bytes([req.words[0], req.words[1]]).max(1)
    } else {
        1
    };
    bodies.clear();
    for seq in 0..count {
        bodies.push(ss_echo_body(seq, &req.data));
    }
    Ok(Status::SUCCESS)
}

fn ss_echo_body(seq: u16, data: &[u8]) -> RespBody {
    let mut params = Vec::with_capacity(4);
    params.extend_from_slice(&seq.to_le_bytes());
    params.extend_from_slice(&0u16.to_le_bytes());
    RespBody::new(consts::COM_ECHO, params, data.to_vec())
}

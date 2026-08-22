// Handlers: NEGOTIATE, SESSION_SETUP_ANDX, TREE_CONNECT_ANDX/DISCONNECT,
// LOGOFF_ANDX, ECHO, QUERY_INFORMATION_DISK and other simple commands.

use crate::crypto::{hmac_md5, md4, md5};
use crate::message::*;
use crate::smb::*;
use crate::state::*;

// ---------------- NEGOTIATE (0x72) ----------------
pub fn handle_negotiate(req: &Request, guid: &[u8; 16]) -> Vec<RespBody> {
    // Parse dialect list from bytes area.
    let data = req.data();
    let mut best_idx: Option<usize> = None;
    let mut i = 0usize;
    let mut idx = 0usize;
    while i < data.len() {
        let fmt = data[i];
        if fmt != 0x02 {
            break;
        }
        i += 1;
        let end = data[i..].iter().position(|&b| b == 0).map(|p| p + i);
        let stop = match end {
            Some(s) => s,
            None => break,
        };
        let name = String::from_utf8_lossy(&data[i..stop]).to_lowercase();
        match name.as_str() {
            // Highest dialect we speak — always wins.
            "nt lm 0.12" => {
                best_idx = Some(idx);
                break;
            }
            "lanman2.1" | "lanman1.0" => {
                if best_idx.is_none() {
                    best_idx = Some(idx);
                }
            }
            _ => {}
        }
        idx += 1;
        i = stop + 1;
    }

    let dialect_index = match best_idx {
        Some(v) => v as u16,
        None => 0xFFFF,
    };

    // Server challenge stored per connection by dispatcher before calling us.
    // NOTE: per MS-CIFS 2.2.4.52.2 the NT LM 0.12 response Words are
    // BYTE-PACKED: DialectIndex(2) SecurityMode(1) MaxMpx(2) VCs(2)
    // MaxBuffer(4) MaxRaw(4) SessionKey(4) Caps(4) SystemTime(8)
    // TimeZone(2) ChallengeLength(1) == 34 bytes == WordCount 17.
    let mut params = Vec::new();
    params.extend_from_slice(&dialect_index.to_le_bytes()); // [0-1]
    params.push(SEC_MODE_USER | SEC_MODE_ENCRYPT);          // [2] SecurityMode
    params.extend_from_slice(&16u16.to_le_bytes());         // [3-4] MaxMpxCount
    params.extend_from_slice(&1u16.to_le_bytes());          // [5-6] MaxNumberVcs
    params.extend_from_slice(&65535u32.to_le_bytes());      // [7-10] MaxBufferSize
    params.extend_from_slice(&65536u32.to_le_bytes());      // [11-14] MaxRawSize
    params.extend_from_slice(&0x1234_5678u32.to_le_bytes());// [15-18] SessionKey
    let caps = CAP_UNICODE
        | CAP_LARGE_FILES
        | CAP_NT_SMBS
        | CAP_STATUS32
        | CAP_LEVEL2_OPLOCKS
        | CAP_LOCK_AND_READ
        | CAP_NT_FIND
        | CAP_INFOLEVEL_PASSTHRU
        | CAP_LARGE_READX
        | CAP_LARGE_WRITEX
        | 0x8000_0000u32; // CAP_EXTENDED_SECURITY
    params.extend_from_slice(&caps.to_le_bytes());          // [19-22] Capabilities
    params.extend_from_slice(&now_filetime().to_le_bytes());// [23-30] SystemTime
    params.extend_from_slice(&0i16.to_le_bytes());          // [31-32] ServerTimeZone
    params.push(0u8);                                       // [33] ChallengeLength (extended security)

    debug_assert_eq!(params.len(), 34);

    let bytes = guid.to_vec(); // 16-byte server GUID; empty SPNEGO blob -> raw NTLMSSP flow

    vec![RespBody::new(COM_NEGOTIATE, params, bytes)]
}

// ---------------- SESSION_SETUP_ANDX extended security (0x73) ----------------
/// Two-leg NTLMSSP: type1 -> MORE_PROCESSING(type2), then type3 -> success.
#[allow(clippy::type_complexity)]
pub fn session_setup(
    server: &ServerShared,
    conn: &mut ConnState,
    req: &Request,
) -> Result<(Vec<RespBody>, u16, bool, Status), Status> {
    let w = req.word_bytes();
    if w.len() < 24 {
        return Err(Status::INVALID_PARAMETER);
    }
    // WC=12 extended layout: [0]cmd [1]res [2-3]off [4-5]MaxBuffer
    // [6-7]MaxMpx [8-9]Vc [10-13]SessionKey [14-15]SecurityBlobLength
    // [16-19]Reserved [20-23]Capabilities
    let blob_len = u16::from_le_bytes([w[14], w[15]]) as usize;

    let data = req.data();
    if blob_len > data.len() {
        return Err(Status::INVALID_PARAMETER);
    }
    let blob = &data[..blob_len];

    use crate::ntlm::{self, build_type2, msg_type, parse_type3, unwrap_blob, MSG_TYPE1, MSG_TYPE2, MSG_TYPE3};

    match msg_type(unwrap_blob(blob).unwrap_or(&[])) {
        Some(MSG_TYPE1) | Some(MSG_TYPE2) | None => {
            // Leg 1: send NTLMSSP CHALLENGE, status MORE_PROCESSING_REQUIRED.
            let uid = if conn.uid == 0 { next_uid() } else { conn.uid };
            conn.uid = uid;
            conn.auth_pending = true;
            conn.spnego = crate::ntlm::is_spnego(blob);

            let t2 = build_type2(&conn.challenge, &server.domain, &server.server_name);
            let out_blob = if conn.spnego {
                crate::ntlm::wrap_negtoken_targ(&t2)
            } else {
                t2.clone()
            };

            let mut params = Vec::new();
            params.push(0xFF);
            params.push(0);
            params.extend_from_slice(&0u16.to_le_bytes());
            params.extend_from_slice(&0u16.to_le_bytes()); // Action: none
            params.extend_from_slice(&(out_blob.len() as u16).to_le_bytes());

            let mut bytes = Wr::new();
            bytes.raw(&out_blob);
            // Trailing NativeOS/NativeLanMan strings — clients require the
            // NUL terminators after the security blob.
            let bc_abs_base = HDR_LEN + 1 + params.len() + 2;
            bytes.zstring("rustsmb", false, bc_abs_base + out_blob.len());
            bytes.zstring("rustsmb", false, bc_abs_base + out_blob.len() + 8);

            Ok((
                vec![RespBody::new(COM_SESSION_SETUP_ANDX, params, bytes.buf)],
                uid,
                false,
                Status::MORE_PROCESSING_REQUIRED,
            ))
        }
        Some(MSG_TYPE3) => {
            let inner = unwrap_blob(blob).unwrap();
            let t3 = parse_type3(inner).ok_or(Status::LOGON_FAILURE)?;

            let (ok, guest, user) =
                authenticate_ntlmssp(server, &conn.challenge, &t3);
            if !ok {
                return Err(Status::LOGON_FAILURE);
            }
            let uid = if conn.uid != 0 { conn.uid } else { next_uid() };
            conn.uid = uid;
            conn.auth_pending = false;
            conn.session = Some(Session {
                user,
                guest,
                trees: Vec::new(),
            });

            // Final SPNEGO token: accept-complete NegTokenTarg.
            let fin = if conn.spnego {
                crate::ntlm::wrap_accept_complete()
            } else {
                Vec::new()
            };

            let mut params = Vec::new();
            params.push(0xFF);
            params.push(0);
            params.extend_from_slice(&0u16.to_le_bytes());
            let action: u16 = if guest { 0x0001 } else { 0x0000 };
            params.extend_from_slice(&action.to_le_bytes());
            params.extend_from_slice(&(fin.len() as u16).to_le_bytes());

            let mut bytes = Wr::new();
            bytes.raw(&fin);
            let bc_abs_base = HDR_LEN + 1 + params.len() + 2;
            bytes.zstring("rustsmb", req.unicode(), bc_abs_base);
            bytes.zstring("rustsmb", req.unicode(), bc_abs_base);

            let mut body = RespBody::new(COM_SESSION_SETUP_ANDX, params, bytes.buf);
            body.uid_override = Some(uid);
            Ok((vec![body], uid, guest, Status::SUCCESS))
        }
        _ => Err(Status::LOGON_FAILURE),
    }
}

fn authenticate_ntlmssp(
    server: &ServerShared,
    challenge: &[u8; 8],
    t3: &crate::ntlm::Type3,
) -> (bool, bool, String) {
    use crate::crypto::{hmac_md5, md4};

    let user = t3.user.trim().to_string();

    // Anonymous / null session?
    if t3.ntlm_response.is_empty() && t3.lm_response.is_empty() {
        return (true, true, "nobody".to_string());
    }
    if t3.flags & crate::ntlm::NTLMSSP_NEGOTIATE_ANONYMOUS != 0 {
        return (true, true, "nobody".to_string());
    }

    // Open mode when no users configured: accept anyone.
    if server.users.is_empty() && server.allow_guest {
        return (true, false, user.clone());
    }

    let pass = match server.users.get(&user.to_lowercase()) {
        Some(p) => p.clone(),
        None => {
            if server.allow_guest {
                return (true, true, user.clone());
            }
            return (false, false, String::new());
        }
    };

    let nthash = md4(&{
        let mut b = Vec::new();
        for u in pass.encode_utf16() {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b
    });

    // NTLMv2 check (MS-NLMP 3.3.2):
    //   NTLMv2Hash = HMAC-MD5(NTHash, UPPER(user)+domain in UTF-16LE)
    //   Proof      = HMAC-MD5(NTLMv2Hash, ServerChallenge + blob)
    if t3.ntlm_response.len() >= 24 {
        let mut identity: Vec<u16> = user.to_uppercase().encode_utf16().collect();
        identity.extend(t3.domain.encode_utf16());
        let mut idb = Vec::with_capacity(identity.len() * 2);
        for u in &identity {
            idb.extend_from_slice(&u.to_le_bytes());
        }
        let ntv2_hash = hmac_md5(&nthash, &idb);

        let blob = &t3.ntlm_response[16..];
        let mut msg = Vec::with_capacity(8 + blob.len());
        msg.extend_from_slice(challenge);
        msg.extend_from_slice(blob);
        let proof = hmac_md5(&ntv2_hash, &msg);
        if proof.as_slice() == &t3.ntlm_response[..16] {
            return (true, false, user);
        }
        // Some clients omit the domain from the identity string.
        let mut id2: Vec<u16> = user.to_uppercase().encode_utf16().collect();
        let mut id2b = Vec::with_capacity(id2.len() * 2);
        for u in &id2 {
            id2b.extend_from_slice(&u.to_le_bytes());
        }
        let _ = &mut id2;
        let ntv2_nodomain = hmac_md5(&nthash, &id2b);
        let proof2 = hmac_md5(&ntv2_nodomain, &msg);
        if proof2.as_slice() == &t3.ntlm_response[..16] {
            return (true, false, user);
        }
    }
    (false, false, String::new())
}


// ---------------- LOGOFF_ANDX (0x74) ----------------
pub fn logoff(_req: &Request) -> Vec<RespBody> {
    let params = [0xFFu8, 0, 0, 0].to_vec();
    vec![RespBody::new(COM_LOGOFF_ANDX, params, Vec::new())]
}

// ---------------- TREE_CONNECT_ANDX (0x75) ----------------
pub fn tree_connect(
    server: &ServerShared,
    conn: &mut ConnState,
    req: &Request,
) -> Result<Vec<RespBody>, Status> {
    let w = req.word_bytes();
    if w.len() < 6 {
        return Err(Status::INVALID_PARAMETER);
    }
    // words: [0]AndXCmd [1]res [2-3]offset [4-5]Flags [6-7]PasswordLength
    let pw_len = u16::from_le_bytes([w[6], w[7]]) as usize;
    let data = req.data();
    eprintln!(
        "tcon: wlen={} pw_len={} datalen={} unicode={}",
        w.len(),
        pw_len,
        data.len(),
        req.unicode()
    );
    let mut rd = Rd::new(data, 0);
    if pw_len > data.len() {
        return Err(Status::ACCESS_DENIED);
    }
    rd.skip(pw_len);
    let base = req.bc_off + 2;
    let path = rd.zstring(req.unicode(), base);
    let service_raw = rd.zstring(false, base + rd.pos);

    let share_name = path
        .rsplit(['\\', '/'])
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_lowercase();
    let ipc = share_name == "ipc$" || service_raw.starts_with("IPC");
    let known = server.shares.contains_key(&share_name);
    if !known && !ipc {
        return Err(Status::BAD_NETWORK_NAME);
    }

    let tid = next_tid();
    conn.trees.insert(tid, share_name.clone());
    if let Some(sess) = conn.session.as_mut() {
        sess.trees.push(tid);
    }

    let mut params = Vec::new();
    params.push(0xFF);
    params.push(0);
    params.extend_from_slice(&0u16.to_le_bytes());
    params.extend_from_slice(&0x0001u16.to_le_bytes()); // OptionalSupport: search

    let mut bytes = Wr::new();
    let bc_base = HDR_LEN + 1 + params.len() + 2;
    let svc = if ipc { "IPC" } else { "A:" };
    // Service string is ASCII per spec.
    bytes.zstring(svc, false, bc_base);
    bytes.zstring(if ipc { "" } else { "NTFS" }, req.unicode(), bc_base + 3);

    let mut body = RespBody::new(COM_TREE_CONNECT_ANDX, params, bytes.buf);
    body.tid_override = Some(tid);
    Ok(vec![body])
}

// ---------------- TREE_DISCONNECT (0x71) ----------------
pub fn tree_disconnect(conn: &mut ConnState, tid: u16) -> Vec<RespBody> {
    conn.trees.remove(&tid);
    if let Some(sess) = conn.session.as_mut() {
        sess.trees.retain(|t| *t != tid);
    }
    vec![RespBody::new(COM_TREE_DISCONNECT, Vec::new(), Vec::new())]
}

// ---------------- ECHO (0x26) ----------------
pub fn echo(req: &Request) -> Vec<RespBody> {
    let w = req.word_bytes();
    let count = if w.len() >= 2 {
        u16::from_le_bytes([w[0], w[1]]).max(1)
    } else {
        1
    };
    let data = req.data().to_vec();
    let mut out = Vec::new();
    for seq in 0..count {
        let mut params = Vec::new();
        params.extend_from_slice(&seq.to_le_bytes());
        out.push(RespBody::new(COM_ECHO, params, data.clone()));
    }
    if out.is_empty() {
        out.push(RespBody::new(COM_ECHO, vec![0, 0], Vec::new()));
    }
    out
}

// ---------------- QUERY_INFORMATION_DISK (0x80) ----------------
pub fn query_disk(req: &Request, conn: &ConnState) -> Result<Vec<RespBody>, Status> {
    check_tree(conn, req.hdr.tid)?;
    let mut params = Vec::new();
    params.extend_from_slice(&100_000u32.to_le_bytes()); // total units
    params.extend_from_slice(&50_000u32.to_le_bytes()); // free units
    params.extend_from_slice(&512u16.to_le_bytes()); // sector size
    params.extend_from_slice(&64u16.to_le_bytes()); // units per sector? sectors per cluster
    params.extend_from_slice(&0u16.to_le_bytes());
    Ok(vec![RespBody::new(COM_QUERY_INFORMATION_DISK, params, Vec::new())])
}

pub fn check_tree(conn: &ConnState, tid: u16) -> Result<&String, Status> {
    conn.trees
        .get(&tid)
        .ok_or(Status::INVALID_HANDLE)
}

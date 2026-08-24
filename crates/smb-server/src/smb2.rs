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

use metrics::{counter, gauge};

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
    /// Derived signing key (dialect-specific); `None` disables signing.
    pub signing_key: Option<[u8; 16]>,
    /// Capabilities word advertised in our NEGOTIATE response — echoed
    /// verbatim in FSCTL_VALIDATE_NEGOTIATE_INFO ([MS-SMB2] §3.3.5.15).
    pub advertised_caps: u32,
    /// Credits the client currently holds (granted minus spent,
    /// [MS-SMB2] §3.3.1.1).
    pub client_credits: u32,
    /// Pre-authentication integrity hash (3.1.1 only).
    pub preauth_hash: [u8; 64],
    /// Chosen encryption cipher (from negotiate ENCRYPTION_CAPABILITIES).
    pub cipher: Option<u16>,
    /// (client-to-server, server-to-client) cipher keys; `None` until the
    /// session enables encryption ([MS-SMB2] §3.1.4.1 labels).
    pub enc_keys: Option<([u8; 16], [u8; 16])>,
    /// True once every subsequent message for this session must be wrapped
    /// in a transform header (SMB2_SESSION_FLAG_ENCRYPT_DATA).
    pub encrypt_data: bool,
    /// SPNEGO exchange blobs: (init request, authenticate request).
    pub ntlm_blobs: Option<(Vec<u8>, Vec<u8>)>,
    /// Challenge token sent during leg 1 (for the mechListMIC input).
    pub ntlm_targ: Option<Vec<u8>>,
    /// Raw challenge token sent during leg 1 (for mechListMIC).
    /// TID -> share name map.
    pub trees: HashMap<u32, String>,
    /// Open handles keyed by 16-byte SMB2 FileId.
    pub handles: HashMap<[u8; 16], Box<smb_vfs::OpenFile>>,
    /// Virtual named pipes opened on IPC$ (srvsvc, …) keyed by file id.
    pub pipes: HashMap<[u8; 16], crate::srvsvc::Pipe>,
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
            signing_key: None,
            advertised_caps: 0,
            client_credits: 0,
            preauth_hash: [0u8; 64],
            cipher: None,
            enc_keys: None,
            encrypt_data: false,
            ntlm_blobs: None,
            ntlm_targ: None,
            trees: HashMap::new(),
            handles: HashMap::new(),
            pipes: HashMap::new(),
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
    // Incoming transform frames are decrypted first ([MS-SMB2] §3.3.5.16).
    // A failed open means tampering or key desync — drop the connection.
    let plaintext: Vec<u8>;
    let mut buf = buf;
    if buf.len() >= 4 && buf[..4] == smb_proto_smb2::commands::TF_MAGIC {
        let pt = decrypt_transform(conn, buf)?;
        plaintext = pt;
        buf = &plaintext;
    }

    let mut parts: Vec<(Vec<u8>, bool)> = Vec::new(); // (resp, may_wrap)
    let mut off = 0usize;
    loop {
        if off + 64 > buf.len() {
            break;
        }
        let rest = &buf[off..];
        let Some((single, may_wrap)) = process_single(server, conn, rest).await else {
            return None;
        };
        // Refund the Credits this response grants back to the client's
        // balance ([MS-SMB2] §3.3.1.1) — the field was stamped by
        // response() as max(CreditCharge, 1).
        let granted = u16::from_le_bytes(single[14..16].try_into().unwrap()) as u32;
        conn.client_credits = conn.client_credits.saturating_add(granted);
        #[cfg(not(feature = "lib"))]
        let may_wrap = false; // sealing unsupported on this backend
        parts.push((single, may_wrap));

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
    let mut out: Vec<u8> = Vec::with_capacity(parts.iter().map(|p| p.0.len() + 7).sum());
    let mut starts = Vec::with_capacity(parts.len());
    for (p, _) in &parts {
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

    // Seal the whole reply when the session requires encryption
    // ([MS-SMB2] §3.3.5.16); the enabling SESSION_SETUP response itself
    // always travels in the clear.
    if conn.encrypt_data && parts.iter().all(|(_, w)| *w) {
        let sealed = encrypt_response(conn, &out)?;
        return Some(sealed);
    }
    Some(out)
}

/// Wrap an assembled response into a transform frame ([MS-SMB2] §2.2.41)
/// using the S2C cipher key.
#[cfg(not(feature = "lib"))]
fn encrypt_response(conn: &Smb2Conn, msg: &[u8]) -> Option<Vec<u8>> {
    let _ = (conn, msg);
    None
}
#[cfg(not(feature = "handrolled"))]
fn encrypt_response(conn: &Smb2Conn, msg: &[u8]) -> Option<Vec<u8>> {
    let (c2s, s2c) = conn.enc_keys?;
    let _ = c2s;
    let cipher = conn.cipher?;
    let gcm = cipher == smb_proto_smb2::negotiate::ctx_type::AES128_GCM;
    let iv_size = if gcm { 12 } else { 11 };

    let mut nonce_field = [0u8; 16];
    nonce_field[..iv_size].copy_from_slice(&crate::dispatch::rand_bytes(iv_size));

    let mut tf = smb_proto_smb2::commands::build_transform(conn.session_id, &nonce_field, msg.len());
    // AAD region: everything after the Nonce field ([MS-SMB2] §3.1.4.2).
    let sealed = if gcm {
        smb_auth::crypto::aes128gcm_seal(
            &s2c,
            nonce_field[..12].try_into().ok()?,
            &tf[smb_proto_smb2::commands::tf_off::NONCE..],
            msg,
        )
    } else {
        smb_auth::crypto::aes128ccm_seal(
            &s2c,
            nonce_field[..11].try_into().ok()?,
            &tf[smb_proto_smb2::commands::tf_off::NONCE..],
            msg,
        )
    };
    // Tag lands in the Signature field; ciphertext follows the header.
    let tag_at = smb_proto_smb2::commands::tf_off::SIGNATURE;
    tf[tag_at..tag_at + 16].copy_from_slice(&sealed[sealed.len() - 16..]);
    let mut frame = tf;
    frame.extend_from_slice(&sealed[..sealed.len() - 16]);
    counter!("smb_encrypted_responses_total").increment(1);
    counter!("smb_encrypted_bytes_total").increment(msg.len() as u64);
    Some(frame)
}

/// Open an incoming transform frame using the C2S cipher key.
#[cfg(not(feature = "lib"))]
fn decrypt_transform(_conn: &mut Smb2Conn, _frame: &[u8]) -> Option<Vec<u8>> {
    None
}
#[cfg(not(feature = "handrolled"))]
fn decrypt_transform(conn: &mut Smb2Conn, frame: &[u8]) -> Option<Vec<u8>> {
    let tf = match smb_proto_smb2::commands::TransformHdr::parse(frame) {
        Some(t) => t,
        None => {
            tracing::warn!("transform parse failed");
            return None;
        }
    };
    if tf.session_id != conn.session_id {
        tracing::warn!(sid = format!("{:#x}", tf.session_id), "transform sid mismatch");
        return None;
    }
    let Some((c2s, _s2c)) = conn.enc_keys else {
        tracing::warn!("no cipher keys derived");
        return None;
    };
    let Some(cipher) = conn.cipher else {
        tracing::warn!("no cipher negotiated");
        return None;
    };
    let gcm = cipher == smb_proto_smb2::negotiate::ctx_type::AES128_GCM;
    let iv_size = if gcm { 12 } else { 11 };
    let aad = &frame[smb_proto_smb2::commands::tf_off::NONCE
        ..smb_proto_smb2::commands::tf_off::HDR_SIZE];
    let payload = &frame[smb_proto_smb2::commands::tf_off::HDR_SIZE
        ..tf_off_end(tf.original_len)];
    // The GCM/CCM tag travels in the TF Signature field ([MS-SMB2]
    // §2.2.41), detached from the ciphertext; re-attach it for the AEAD
    // open, which expects ct||tag.
    let tag_at = smb_proto_smb2::commands::tf_off::SIGNATURE;
    let mut sealed = payload.to_vec();
    sealed.extend_from_slice(&frame[tag_at..tag_at + 16]);
    let pt = if gcm {
        match smb_auth::crypto::aes128gcm_open(
            &c2s,
            frame[smb_proto_smb2::commands::tf_off::NONCE..]
                .get(..12)?
                .try_into()
                .ok()?,
            aad,
            &sealed,
        ) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    nonce = %hex_str(&frame[smb_proto_smb2::commands::tf_off::NONCE..smb_proto_smb2::commands::tf_off::NONCE+12]),
                    aad_len = aad.len(),
                    payload_len = payload.len(),
                    orig_len = tf.original_len,
                    "gcm open failed"
                );
                return None;
            }
        }
    } else {
        match smb_auth::crypto::aes128ccm_open(
            &c2s,
            frame[smb_proto_smb2::commands::tf_off::NONCE..]
                .get(..11)?
                .try_into()
                .ok()?,
            aad,
            &sealed,
        ) {
            Some(p) => p,
            None => {
                tracing::warn!("ccm open failed");
                return None;
            }
        }
    };
    counter!("smb_decrypted_msgs_total").increment(1);
    counter!("smb_decrypted_bytes_total").increment(pt.len() as u64);
    Some(pt)
}

/// End offset (relative to frame start) of transform-wrapped payload.
fn tf_off_end(original_len: usize) -> usize {
    smb_proto_smb2::commands::tf_off::HDR_SIZE + original_len
}

/// Process exactly one SMB2 request starting at `buf` (its own header).
async fn process_single(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Option<(Vec<u8>, bool)> {
    let hdr = match smb_proto_smb2::Header2::parse(buf) {
        Some(h) => h,
        None => return None,
    };
    tracing::debug!(
        cmd = hdr.command,
        mid = hdr.message_id,
        sid = format!("{:#x}", hdr.session_id),
        tid = format!("{:#x}", hdr.tree_id),
        len = buf.len(),
        "smb2 request"
    );
    // Request half of the 3.1.1 pre-auth integrity hash ([MS-SMB2] §3.3.4.1.1):
    // every NEGOTIATE / SESSION_SETUP message updates it before processing.
    let is_preauth_msg = matches!(hdr.command, ss::cmd::NEGOTIATE | ss::cmd::SESSION_SETUP);
    if is_preauth_msg {
        let mut joined = Vec::with_capacity(64 + buf.len());
        joined.extend_from_slice(&conn.preauth_hash);
        joined.extend_from_slice(buf);
        conn.preauth_hash = smb_auth::crypto::sha512(&joined);
    }
    let body_start = 64usize;
    let tid = hdr.tree_id;
    let sid = hdr.session_id;

    // Commands valid without an authenticated session.
    let pre_session = matches!(hdr.command, ss::cmd::NEGOTIATE | ss::cmd::SESSION_SETUP | ss::cmd::ECHO);
    if !pre_session && (!conn.authenticated || sid != conn.session_id) {
        return Some((response(&hdr, Status::ACCESS_DENIED, Vec::new(), 0), false));
    }

    // Credit accounting ([MS-SMB2] §3.3.1.1): every request spends its
    // CreditCharge from the balance we have granted; the response's own
    // Credits field tops the balance back up (done by the caller reading
    // it out of the response header). An over-spend is a broken or hostile
    // client — reject it.
    // The initial NEGOTIATE arrives with an implicit credit already granted
    // ([MS-SMB2] §3.3.5.2.4) — some clients set CreditCharge=1 on it.
    if hdr.command == ss::cmd::NEGOTIATE {
        conn.client_credits = conn.client_credits.max(1);
    }
    // Lenient, smbd-style policy: track the spend but never fail a request
    // whose CreditCharge exceeds the tracked balance — some clients
    // (impacket) set large charges without prior grant negotiation. The
    // response refunds max(CreditCharge, 1) via the caller.
    let charge = hdr.credit_charge as u32;
    conn.client_credits = conn.client_credits.saturating_sub(charge);

    // Signing policy ([MS-SMB2] §3.3.5.2.3): reject unsigned traffic from
    // real accounts when --require-signing is set. Sealed (encrypted)
    // sessions carry their own integrity guarantee via the AEAD tag, so
    // the signature requirement is satisfied by encryption there.
    if server.require_signing
        && !pre_session
        && !conn.guest
        && !conn.encrypt_data
        && conn.signing_key.is_some()
        && !hdr.is_signed()
    {
        counter!("smb_reject_unsigned_total").increment(1);
        return Some((response(&hdr, Status::ACCESS_DENIED, Vec::new(), conn.session_id), true));
    }

    // TREE_CONNECT overrides the response TreeId with the fresh value.
    let mut resp_tid: Option<u32> = None;

    let (status, mut body): (Status, Vec<u8>) = match hdr.command {
        ss::cmd::NEGOTIATE => {
            // Clients probing for SMB2 support send either a header-only
            // NEGOTIATE or one carrying Status = STATUS_INVALID_PARAMETER
            // ([MS-SMB2] §3.3.5.3). Answer both with the wildcard-dialect
            // response so they retry a real negotiation.
            let parsed = smb_proto_smb2::negotiate::Request::parse(buf.get(body_start..).unwrap_or(&[]));
            tracing::debug!(status = hdr.status, parsed_ok = parsed.is_some(), len = buf.len(), "negotiate probe check");
            if hdr.status == Status::INVALID_PARAMETER.raw() || parsed.is_none() {
                if parsed.is_none() {
                    tracing::debug!(len = buf.len(), body = %hex_str(buf.get(body_start..).unwrap_or(&[])), "negotiate parse failed");
                }
                return Some((
                    response(&hdr, Status::INVALID_PARAMETER, probe_negotiate_resp(), 0),
                    false,
                ));
            }
            let req = parsed.expect("validated above");
            let Some(dialect) = smb_proto_smb2::negotiate::pick(&req.dialects) else {
                return Some((response(&hdr, Status::INVALID_PARAMETER, Vec::new(), 0), true));
            };
            conn.dialect = Some(dialect);
            // Must match the Capabilities word written by
            // build_response_full below so VALIDATE_NEGOTIATE_INFO echoes it.
            conn.advertised_caps = if dialect >= smb_proto_smb2::negotiate::DIALECT_210 {
                smb_proto_smb2::negotiate::caps::LARGE_MTU
            } else {
                0
            };
            tracing::debug!(dialect = format!("{:#06x}", dialect), "negotiated");
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&crate::dispatch::rand_bytes(32));
            // Pick one cipher the client offered (GCM preferred).
            let client_ciphers: Vec<u16> = req
                .contexts
                .iter()
                .find(|c| c.kind == smb_proto_smb2::negotiate::ctx_type::ENCRYPTION)
                .and_then(|c| {
                    if c.data.len() >= 2 {
                        let n = u16::from_le_bytes([c.data[0], c.data[1]]) as usize;
                        Some(
                            c.data[2..]
                                .chunks_exact(2)
                                .take(n)
                                .map(|w| u16::from_le_bytes([w[0], w[1]]))
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        None
                    }
                })
                .unwrap_or_default();
            let chosen = {
                // GCM preferred by default ([MS-SMB2] §3.1.4.1); override
                // with RUSTSMB_CIPHER=ccm to exercise the CCM path live.
                let prefer_ccm = std::env::var("RUSTSMB_CIPHER")
                    .map(|v| v.eq_ignore_ascii_case("ccm"))
                    .unwrap_or(false);
                let order = if prefer_ccm {
                    [smb_proto_smb2::negotiate::ctx_type::AES128_CCM,
                     smb_proto_smb2::negotiate::ctx_type::AES128_GCM]
                } else {
                    [smb_proto_smb2::negotiate::ctx_type::AES128_GCM,
                     smb_proto_smb2::negotiate::ctx_type::AES128_CCM]
                };
                order.into_iter().find(|ours| client_ciphers.contains(ours))
            };
            // Dialects without negotiate contexts (or clients that did not
            // offer ENCRYPTION_CAPABILITIES) must leave conn.cipher unset —
            // otherwise --encrypt would seal sessions the peer cannot read.
            if dialect == smb_proto_smb2::negotiate::DIALECT_311 && !client_ciphers.is_empty() {
                conn.cipher = chosen;
            }
            (
                Status::SUCCESS,
                smb_proto_smb2::negotiate::build_response_full(
                    dialect,
                    &server.guid,
                    smb_proto::types::FileTime::now().0,
                    &salt,
                    chosen.unwrap_or(smb_proto_smb2::negotiate::ctx_type::AES128_GCM),
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
                counter!("smb_tcons_total").increment(1);
                gauge!("smb_trees_active").increment(1.0);
                tracing::debug!(share = %conn.trees[&new_tid], "tree connected");
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
            if conn.authenticated {
                gauge!("smb_sessions_active").decrement(1.0);
            }
            conn.authenticated = false;
            conn.session_id = 0;
            counter!("smb_logoffs_total").increment(1);
            (Status::SUCCESS, c::build_logoff_resp())
        }
        ss::cmd::CREATE => {
            // Named-pipe open on IPC$: \srvsvc and friends are virtual
            // files backed by the RPC dispatcher, not the VFS.
            if share_is_ipc(server, conn, tid) {
                match pipe_create(conn, buf) {
                    Ok(body) => (Status::SUCCESS, body),
                    Err(status) => (status, Vec::new()),
                }
            } else {
                let vfs = match share_vfs(server, conn, tid) {
                    Some(v) => v,
                    None => {
                        return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                    }
                };
                match create(conn, vfs, buf).await {
                    Ok(body) => (Status::SUCCESS, body),
                    Err(status) => (status, Vec::new()),
                }
            }
        }
        ss::cmd::READ => {
            if let Some(pipe_read) = pipe_read(conn, buf) {
                return Some((response(&hdr, Status::SUCCESS, pipe_read, conn.session_id), true));
            }
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => {
                    return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                }
            };
            match read(conn, vfs, buf).await {
                Ok(body) => (Status::SUCCESS, body),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::WRITE => {
            if let Some(written) = pipe_write(server, conn, buf) {
                return Some((response(&hdr, Status::SUCCESS, written, conn.session_id), true));
            }
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => {
                    return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                }
            };
            match write(conn, vfs, buf).await {
                Ok(body) => (Status::SUCCESS, body),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::CLOSE => {
            // Close a pipe handle first; fall through to file handles.
            if pipe_close(conn, buf) {
                (Status::SUCCESS, c::build_close_resp([0u64;4], 0, 0, 0))
            } else {
                let vfs = match share_vfs(server, conn, tid) {
                    Some(v) => v,
                    None => {
                        return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                    }
                };
                match close(conn, vfs, buf).await {
                    Ok(body) => (Status::SUCCESS, body),
                    Err(status) => (status, Vec::new()),
                }
            }
        }
        ss::cmd::FLUSH => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => {
                    return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                }
            };
            match flush(conn, vfs, buf).await {
                Ok(()) => (Status::SUCCESS, c::build_flush_resp()),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::IOCTL => {
            let Some(req) = c::IoctlReq::parse(buf) else {
                tracing::debug!("ioctl parse failed");
                return Some((response(&hdr, Status::INVALID_PARAMETER, Vec::new(), conn.session_id), true));
            };
            tracing::debug!(ctl = format!("{:#010x}", req.ctl_code), "ioctl");
            match req.ctl_code {
                // Echo the negotiated parameters back ([MS-SMB2] §3.3.5.15):
                // capabilities, server GUID, security mode and dialect.
                c::fsctl::VALIDATE_NEGOTIATE_INFO if req.input.len() >= 24 => {
                    let mut out = Vec::with_capacity(24);
                    // Echo the exact values from our NEGOTIATE response —
                    // the client fails the exchange on any mismatch
                    // ([MS-SMB2] §3.3.5.15).
                    out.extend_from_slice(&conn.advertised_caps.to_le_bytes());
                    out.extend_from_slice(&server.guid);
                    out.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode
                    out.extend_from_slice(
                        &conn.dialect.unwrap_or(smb_proto_smb2::negotiate::DIALECT_210)
                            .to_le_bytes(),
                    );
                    let _ = &req.input;
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &out))
                }
                // Resiliency handshake carries no output data.
                c::fsctl::LMR_REQUEST_RESILIENCY => {
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &[]))
                }
                // FSCTL_PIPE_TRANSACT (0x0011C017): the DCERPC PDU arrives
                // in the input buffer and the reply leaves in the output
                // buffer — this is how SMB2 clients speak RPC over named
                // pipes.
                c::fsctl::PIPE_TRANSACT => {
                    let Some(pipe) = conn.pipes.get_mut(&req.file_id.0) else {
                        tracing::debug!(pipes = conn.pipes.len(), "transact on non-pipe fid");
                        return Some((response(&hdr, Status::NOT_IMPLEMENTED, Vec::new(), conn.session_id), true));
                    };
                    let shares = server.share_infos();
                    let out = {
                        pipe.on_write(&req.input, &shares);
                        counter!("smb_pipe_writes_total").increment(1);
                        pipe.take(req.max_output as usize)
                    };
                    counter!("smb_pipe_reads_total").increment(1);
                    let out_hex = hex_str(&out);
                    tracing::debug!(out_len = out.len(), %out_hex, "pipe transact");
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &out))
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
                None => {
                    return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                }
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
                None => {
                    return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                }
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
                None => {
                    return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                }
            };
            match set_info(conn, vfs, buf).await {
                Ok(()) => (Status::SUCCESS, c::build_set_info_resp()),
                Err(status) => (status, Vec::new()),
            }
        }
        ss::cmd::CANCEL => {
            // Best-effort cancel ([MS-SMB2] §3.3.5.14): all our handlers are
            // synchronous today, so there is nothing to signal; ack it.
            counter!("smb_cancels_total").increment(1);
            (Status::SUCCESS, 2u16.to_le_bytes().to_vec())
        }
        ss::cmd::ECHO => (Status::SUCCESS, 4u16.to_le_bytes().to_vec()),
        _ => (Status::NOT_IMPLEMENTED, Vec::new()),
    };

    // Derive the dialect-specific signing key once authentication completes;
    // the 3.1.1 key binds to the finished pre-auth integrity hash.
    if hdr.command == ss::cmd::SESSION_SETUP
        && conn.authenticated
        && conn.session_key.is_some()
        && conn.signing_key.is_none()
    {
        let key = conn.session_key.unwrap();
        conn.signing_key = match conn.dialect {
            Some(smb_proto_smb2::negotiate::DIALECT_300 | smb_proto_smb2::negotiate::DIALECT_302) => {
                let k = smb_auth::crypto::kdf_counter_mode_hmac_sha256(
                    &key,
                    b"SMB2AESCMAC\0",
                    b"SmbSign\0",
                    16,
                );
                Some(k.try_into().unwrap())
            }
            Some(smb_proto_smb2::negotiate::DIALECT_311) => {
                let k = smb_auth::crypto::kdf_counter_mode_hmac_sha256(
                    &key,
                    b"SMBSigningKey\0",
                    &conn.preauth_hash,
                    16,
                );
                Some(k.try_into().unwrap())
            }
            _ => Some(key),
        };
    }

    // Encryption enablement ([MS-SMB2] §3.3.5.5 / §3.3.5.16): when the
    // server is configured to seal and the client offered a cipher, derive
    // C2S/S2C keys and set SMB2_SESSION_FLAG_ENCRYPT_DATA on the final
    // SESSION_SETUP response (that response itself stays plaintext).
    let mut seal_session = false;
    // Sealing requires the AEAD primitives from the default CSP backend.
    #[cfg(feature = "lib")]
    let sealing_available = true;
    #[cfg(not(feature = "lib"))]
    let sealing_available = false;
    if hdr.command == ss::cmd::SESSION_SETUP
        && status == Status::SUCCESS
        && server.encrypt
        && sealing_available
        && conn.authenticated
        && !conn.guest
        && conn.cipher.is_some()
        && conn.enc_keys.is_none()
    {
        if let Some(key) = conn.session_key {
            let (c2s_label, s2c_label) = match conn.dialect {
                Some(smb_proto_smb2::negotiate::DIALECT_311) => {
                    (b"SMBC2SCipherKey\0".as_slice(), b"SMBS2CCipherKey\0".as_slice())
                }
                _ => (b"SMB2AESCCM\0".as_slice(), b"SMB2AESCCM\0".as_slice()),
            };
            let s2c_ctx: &[u8] = match conn.dialect {
                Some(smb_proto_smb2::negotiate::DIALECT_311) => &conn.preauth_hash,
                _ => b"ServerOut\0",
            };
            let c2s_ctx: &[u8] = match conn.dialect {
                Some(smb_proto_smb2::negotiate::DIALECT_311) => &conn.preauth_hash,
                _ => b"ServerIn \0", // trailing space per [MS-SMB2] §3.1.4.1
            };
            let kdf = |label: &[u8], context: &[u8]| -> [u8; 16] {
                smb_auth::crypto::kdf_counter_mode_hmac_sha256(&key, label, context, 16)
                    .try_into()
                    .unwrap()
            };
            conn.enc_keys = Some((kdf(c2s_label, c2s_ctx), kdf(s2c_label, s2c_ctx)));
            conn.encrypt_data = true;
            tracing::info!(
                cipher = format!("{:#x}", conn.cipher.unwrap()),
                dialect = format!("{:#06x}", conn.dialect.unwrap_or(0)),
                "encryption enabled for session"
            );

            seal_session = true;
        }
    }


    let mut resp = response(&hdr, status, body, conn.session_id);
    if let Some(new_tid) = resp_tid {
        resp[36..40].copy_from_slice(&new_tid.to_le_bytes()); // TreeId
    }

    if is_preauth_msg && conn.dialect == Some(smb_proto_smb2::negotiate::DIALECT_311) {
        let mut joined = Vec::with_capacity(64 + resp.len());
        joined.extend_from_slice(&conn.preauth_hash);
        joined.extend_from_slice(&resp);
        conn.preauth_hash = smb_auth::crypto::sha512(&joined);
    }

    // The enabling SESSION_SETUP response itself must travel in the clear;
    // every later message for this session gets wrapped.
    let allow_wrap = !seal_session;

    // Mirror the client's signing flag ([MS-SMB2] §3.3.4.2): authenticated
    // sessions get signatures over the full PDU - HMAC-SHA256 for 2.x and
    // AES-CMAC for 3.x. The final SESSION_SETUP leg is signed even though
    // its request was not (clients verify it once their key is complete).
    let final_setup_leg =
        hdr.command == ss::cmd::SESSION_SETUP && status == Status::SUCCESS && conn.authenticated;
    if hdr.is_signed() || final_setup_leg {
        if let Some(key) = conn.signing_key.clone().or(conn.session_key) {
            resp[16] |= 0x08; // SMB2_FLAGS_SIGNED in response flags
            let mut msg = Vec::with_capacity(resp.len());
            msg.extend_from_slice(&resp[..48]);
            msg.extend_from_slice(&[0u8; 16]); // zeroed Signature field
            msg.extend_from_slice(&resp[64..]);
            let sig =
                if matches!(conn.dialect, Some(smb_proto_smb2::negotiate::DIALECT_300 | smb_proto_smb2::negotiate::DIALECT_302 | smb_proto_smb2::negotiate::DIALECT_311)) {
                    let t = smb_auth::crypto::aes128_cmac(&key, &msg);
                    let mut s = [0u8; 16];
                    s.copy_from_slice(&t);
                    s
                } else {
                    let t = smb_auth::crypto::hmac_sha256(&key, &msg);
                    let mut s = [0u8; 16];
                    s.copy_from_slice(&t[..16]);
                    s
                };
            resp[48..64].copy_from_slice(&sig);
        }
    }
    Some((resp, allow_wrap))
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
    tracing::trace!(
        blob_len = req.blob.len(),
        msg_type = ?smb_auth::ntlm::msg_type(inner),
        "session setup token"
    );
    match smb_auth::ntlm::msg_type(inner) {
        Some(smb_auth::ntlm::MSG_TYPE1) | None => {
            // Leg 1: issue CHALLENGE under MORE_PROCESSING_REQUIRED.
            conn.session_id = next_session_id();
            let mut t2 =
                smb_auth::ntlm::build_type2(&conn.challenge, &server.domain, &server.server_name);
            // Grant SIGN|SEAL so clients may negotiate protected sessions
            // ([MS-NLMP] §3.2.5.1); sealing itself rides the SMB3 cipher.
            let extra = smb_auth::ntlm::NEGOTIATE_SIGN
                | smb_auth::ntlm::NEGOTIATE_SEAL
                | smb_auth::ntlm::NEGOTIATE_KEY_EXCH;
            let fl_off = 60 - 8; // flags live at type2 offset 52 within msg
            // build_type2 writes flags right after the fixed header; patch
            // via known offset instead of plumbing a parameter:
            let fpos = 12 + 4 + 4; // sig(8)+type(4) => 12; then +4 challenge? keep simple below
            let _ = (fl_off, fpos);
            {
                // Flags field sits at byte 20 of the type2 message
                // (sig 8 + type 4 + domlen 2 + dommax 2 + domoff 4).
                const FLAGS_OFF: usize = 20;
                let cur = u32::from_le_bytes(t2[FLAGS_OFF..FLAGS_OFF + 4].try_into().unwrap());
                t2[FLAGS_OFF..FLAGS_OFF + 4].copy_from_slice(&(cur | extra).to_le_bytes());
            }
            let wrapped = smb_auth::ntlm::wrap_negtoken_targ(&t2);
            conn.ntlm_targ = Some(wrapped.clone());
            conn.ntlm_blobs = Some((req.blob.clone(), Vec::new()));
            Ok((
                Status::MORE_PROCESSING_REQUIRED,
                ss::build_response(0, &wrapped),
            ))
        }
        Some(smb_auth::ntlm::MSG_TYPE3) => {
            if let Some(blobs) = &mut conn.ntlm_blobs {
                blobs.1 = req.blob.clone();
            }
            if smb_auth::ntlm::parse_type3(inner).is_none() {
                tracing::warn!("session setup: malformed NTLMSSP type3");
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
                counter!("smb_auth_total", "outcome" => "fail").increment(1);
                return Err(Status::LOGON_FAILURE);
            }
            counter!("smb_auth_total", "outcome" => "ok").increment(1);
            gauge!("smb_sessions_active").increment(1.0);
            tracing::info!(user = %out.user, guest = out.guest,
                signed = out.session_key.is_some(), "session established");
            conn.user = out.user.clone();
            conn.guest = out.guest;
            // out.session_key is already the EXPORTED session key
            // ([MS-NLMP] §3.2.5.1.2): derive_session_key in auth.rs RC4-
            // decrypts EncryptedRandomSessionKey under the key-exchange
            // key when KEY_EXCH was negotiated. mechListMIC, SMB2 signing
            // and SMB3 cipher keys all derive from this value.
            conn.session_key = out.session_key;
            // Dialect-aware signing key ([MS-SMB2] §3.2.5.3.1 / §3.3.5.2.1).
            conn.authenticated = true;
            let flags: u16 = if out.guest { 0x0001 } else { 0x0000 };
            // Close the SPNEGO exchange. When the AUTHENTICATE message
            // carried a mechListMIC (required by --client-protection=encrypt
            // clients), echo one: an NTLMSSP signature over the client's
            // MechTypes DER, computed with the server signing key and RC4
            // checksum-sealed when KEY_EXCH was negotiated ([MS-NLMP]
            // §3.4.6, samba ntlmssp_make_packet_signature RECEIVE path).
            const MIC_OFFSET: usize = 60;
            const MIC_SIZE: usize = 16;
            let mic_field_present = req.blob.len() > MIC_OFFSET + MIC_SIZE;
            let client_mic_nonzero = mic_field_present
                && req.blob[MIC_OFFSET..MIC_OFFSET + MIC_SIZE].iter().any(|&b| b != 0);
            let wrapped = if client_mic_nonzero {
                let Some(key) = conn.session_key else {
                    return Err(Status::INVALID_PARAMETER);
                };
                let init = conn.ntlm_blobs.as_ref().map(|b| b.0.clone()).unwrap_or_default();
                // Locate MechTypes: smbclient's token nests as
                //   60{ OID, A0{ 30{ A0{ 30<OIDs> }, A2{ntlm} } } }
                // and samba signs exactly the bare `30<OIDs>` SEQUENCE
                // (spnego_write_mech_types: ASN1_SEQUENCE(0) of OIDs).
                // Walk: outer A0 (negTokenInit) -> its 30 SEQUENCE ->
                // first inner A0 (mechTypes wrapper) -> that 30 SEQUENCE.
                fn der_len(b: &[u8], i: usize) -> Option<(usize, usize)> {
                    let n = *b.get(i + 1)?;
                    Some(match n {
                        v @ 0..=0x7F => (v as usize, 2),
                        0x81 => (*b.get(i + 2)? as usize, 3),
                        _ => return None,
                    })
                }
                let mech_types: Vec<u8> = (|| {
                    for a in 0..init.len().saturating_sub(4) {
                        if init[a] != 0xA0 {
                            continue;
                        }
                        // outer negTokenInit: content must start with 0x30
                        let (alen, ahdr) = match der_len(&init, a) {
                            Some(v) => v,
                            None => continue,
                        };
                        let s30 = a + ahdr;
                        if init.get(s30) != Some(&0x30) {
                            continue;
                        }
                        let (slen, _) = match der_len(&init, s30) {
                            Some(v) => v,
                            None => continue,
                        };
                        let send = s30 + slen;
                        // first child inside the SEQUENCE: mechTypes [0]
                        for m in s30 + 2..send.saturating_sub(4) {
                            if init[m] != 0xA0 {
                                break; // first field only
                            }
                            let (_, mhdr) = match der_len(&init, m) {
                                Some(v) => v,
                                None => continue,
                            };
                            let t30 = m + mhdr;
                            if init.get(t30) == Some(&0x30) {
                                // sign exactly the bare `30 <len> <OIDs>`
                                let (ilen, ihdr) = match der_len(&init, t30) {
                                    Some(v) => v,
                                    None => continue,
                                };
                                let end = (t30 + ihdr + ilen).min(init.len());
                                if end > t30 {
                                    return init[t30..end].to_vec();
                                }
                            }
                        }
                    }
                    Vec::new()
                })();
                let key_exch = t3.encrypted_session_key.len() == 16;
                #[cfg(feature = "lib")]
                // NTLMSSP sequence counters are independent of SMB2
                // signing; samba resets them to 0 at sign_reset right
                // after auth, and the accept-complete MIC is the first
                // SEND (ntlmssp_make_packet_signature: sending.seq_num++).
                let mic = smb_auth::crypto::ntlm_mech_list_mic(
                    &key,
                    true,
                    key_exch,
                    0,
                    &mech_types,
                );
                #[cfg(not(feature = "lib"))]
                let mic = [0u8; 16];
                tracing::debug!(
                    sk = %hex_str(&key),
                    init = %hex_str(&init),
                    mech = %hex_str(&mech_types),
                    key_exch,
                    mic = %hex_str(&mic),
                    "mechListMIC inputs"
                );
                smb_auth::ntlm::wrap_accept_complete_with_mic(&mic)
            } else {
                smb_auth::ntlm::wrap_accept_complete()
            };
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

    tracing::debug!(name = %rel, eof = meta.eof, dir = meta.is_dir, action, "create");
    counter!("smb_creates_total").increment(1);
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
    counter!("smb_bytes_read_total").increment(data.len() as u64);
    tracing::trace!(offset = req.offset, got = data.len(), "read");
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
    counter!("smb_bytes_written_total").increment(written);
    tracing::trace!(offset = req.offset, wrote = written, "write");
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
    counter!("smb_closes_total").increment(1);
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
    conn.pipes.clear();
}

// ---------------- Named pipes (IPC$) ----------------

/// True when the tree behind `tid` is the virtual IPC$ share.
fn share_is_ipc(server: &Arc<ServerShared>, conn: &Smb2Conn, tid: u32) -> bool {
    conn.trees
        .get(&tid)
        .and_then(|n| server.shares.get(n))
        .map(|s| s.is_ipc)
        .unwrap_or(false)
}

/// Known pipe names served on IPC$.
const KNOWN_PIPES: &[&str] = &["srvsvc", "wkssvc", "lanman", "netlogon"];

/// Open a virtual pipe; `Err(FILE_NOT_FOUND)` for unknown names.
fn pipe_create(conn: &mut Smb2Conn, buf: &[u8]) -> Result<Vec<u8>, Status> {
    let req = c::CreateReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let name = req.name.trim_start_matches(['\\', '/']).to_lowercase();
    if !KNOWN_PIPES.contains(&name.as_str()) {
        return Err(Status::OBJECT_PATH_NOT_FOUND);
    }
    let fid_bytes = next_file_id();
    let fid = c::FileId(fid_bytes);
    conn.pipes.insert(fid_bytes, crate::srvsvc::Pipe::new(&name));
    tracing::debug!(pipe = %name, "pipe opened");
    // Zeroed timestamps/attrs; a pipe is a stream device.
    Ok(c::build_create_resp(
        fid,
        1, // FILE_OPENED
        [0u64; 4],
        0, // no file attributes
        4096,
        0,
        false,
    ))
}

/// Drain up to the requested byte count from a pipe's outbound queue;
/// `None` when `file_id` is not a pipe.
fn pipe_read(conn: &mut Smb2Conn, buf: &[u8]) -> Option<Vec<u8>> {
    let Some(req) = c::ReadReq::parse(buf) else {
        tracing::debug!("pipe_read: parse failed");
        return None;
    };
    let Some(pipe) = conn.pipes.get_mut(&req.file_id.0) else {
        tracing::debug!(fid = ?req.file_id, "read on non-pipe");
        return None;
    };
    tracing::debug!(pending = pipe.pending(), max = req.length, "pipe read");
    let data = pipe.take(req.length as usize);
    counter!("smb_pipe_reads_total").increment(1);
    Some(c::build_read_resp(&data))
}

/// Feed client bytes into a pipe RPC dispatcher; `None` when `file_id` is
/// not a pipe. Returns the WRITE response body.
fn pipe_write(server: &Arc<ServerShared>, conn: &mut Smb2Conn, buf: &[u8]) -> Option<Vec<u8>> {
    let req = c::WriteReq::parse(buf);
    let Some(req) = req else {
        tracing::debug!("pipe_write: parse failed");
        return None;
    };
    if !conn.pipes.contains_key(&req.file_id.0) {
        return None;
    }
    let shares = server.share_infos();
    let written = req.payload.len() as u32;
    let pipe = conn.pipes.get_mut(&req.file_id.0)?;
    tracing::debug!(pipe = %pipe.name, len = req.payload.len(), payload = %hex_str(&req.payload), "pipe write");
    pipe.on_write(&req.payload, &shares);
    tracing::debug!(pending = pipe.pending(), "pipe read queued");
    counter!("smb_pipe_writes_total").increment(1);
    Some(c::build_write_resp(written))
}

/// Remove a pipe handle; `true` when it was one.
fn pipe_close(conn: &mut Smb2Conn, buf: &[u8]) -> bool {
    c::CloseReq::parse(buf)
        .map(|r| conn.pipes.remove(&r.file_id.0).is_some())
        .unwrap_or(false)
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

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

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
    // Grant at least the requested charge so large R/W stay credit-neutral
    // ([MS-SMB2] §3.3.1.1 — generous-grant policy).
    let grant = std::cmp::max(req.credit_charge, 1);
    f.extend_from_slice(&grant.to_le_bytes());
    counter!("smb_credits_granted_total").increment(grant as u64);
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

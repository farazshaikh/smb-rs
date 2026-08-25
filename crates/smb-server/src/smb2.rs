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
use tokio::sync::{mpsc, oneshot};

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
    /// True once the peer has sent at least one encrypted (transform) frame,
    /// so async replies must be sealed even when the server does not force
    /// encryption on the session.
    pub peer_encrypts: bool,
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
    /// Outbound frame queue drained by the per-connection writer task. Async
    /// handlers and background tasks (CHANGE_NOTIFY, oplock/lease breaks) clone
    /// this to emit unsolicited frames without blocking the reader.
    pub outbound: mpsc::Sender<Vec<u8>>,
    /// Next async id to hand out for a STATUS_PENDING operation
    /// ([MS-SMB2] §3.3.4.2).
    pub next_async_id: u64,
    /// In-flight async operations keyed by async id; sending on the channel
    /// cancels the background task (used by CANCEL, §2.2.30).
    pub async_cancels: HashMap<u64, oneshot::Sender<()>>,
    /// Server-side-copy resume keys → source FileId ([MS-SMB2] §2.2.32.3);
    /// handed out by FSCTL_SRV_REQUEST_RESUME_KEY and consumed by COPYCHUNK.
    pub resume_keys: HashMap<[u8; 24], [u8; 16]>,
    /// Durable handles granted on this connection, keyed by FileId, preserved
    /// into the server table when the connection drops ([MS-SMB2] §3.3.1.10).
    pub durable: HashMap<[u8; 16], crate::state::DurableEntry>,
    /// Negotiated outbound compression algorithm ([MS-SMB2] §2.2.42), if the
    /// client and server share one; `None` disables compressed responses.
    pub compress_algo: Option<u16>,
}

impl Smb2Conn {
    /// Create SMB2 connection state with the given NTLM challenge and the
    /// outbound queue its writer task drains.
    pub fn new(challenge: [u8; 8], outbound: mpsc::Sender<Vec<u8>>) -> Self {
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
            peer_encrypts: false,
            ntlm_blobs: None,
            ntlm_targ: None,
            trees: HashMap::new(),
            handles: HashMap::new(),
            pipes: HashMap::new(),
            searches: HashMap::new(),
            outbound,
            next_async_id: 1,
            async_cancels: HashMap::new(),
            resume_keys: HashMap::new(),
            durable: HashMap::new(),
            compress_algo: None,
        }
    }

    /// Clone the outbound frame sender for a background/async task.
    pub fn outbound(&self) -> mpsc::Sender<Vec<u8>> {
        self.outbound.clone()
    }

    /// Allocate a fresh per-connection async id for a STATUS_PENDING op.
    pub fn alloc_async_id(&mut self) -> u64 {
        let id = self.next_async_id;
        self.next_async_id += 1;
        id
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
    transport: Box<dyn Transport>,
    mut pending: Option<Vec<u8>>,
) {
    let (mut reader, writer) = transport.split();
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    let writer_task = tokio_uring::spawn(crate::dispatch::writer_loop(writer, out_rx));

    {
        let mut conn = Smb2Conn::new(crate::dispatch::rand_challenge_pub(), out_tx.clone());
        loop {
            let frame = if let Some(f) = pending.take() {
                f
            } else {
                match reader.recv().await {
                    Ok(Some(f)) => f.0,
                    _ => break,
                }
            };
            if frame.len() < 64 || frame[0..4] != smb_proto_smb2::SMB2_MAGIC {
                continue;
            }
            if let Some(resp) = process_frame(&server, &mut conn, &frame).await {
                if out_tx.send(resp).await.is_err() {
                    break;
                }
            }
        }
    }
    drop(out_tx);
    let _ = writer_task.await;
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
    let mut request_encrypted = false;
    if buf.len() >= 4 && buf[..4] == smb_proto_smb2::commands::TF_MAGIC {
        let pt = decrypt_transform(conn, buf)?;
        plaintext = pt;
        buf = &plaintext;
        request_encrypted = true;
        conn.peer_encrypts = true;
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

    // Seal the whole reply when the session requires encryption, or when the
    // request itself arrived encrypted ([MS-SMB2] §3.3.5.16 — a sealed request
    // is answered with a sealed response even if the server does not force it).
    // The enabling SESSION_SETUP response itself always travels in the clear.
    if (conn.encrypt_data || request_encrypted) && parts.iter().all(|(_, w)| *w) {
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
#[cfg(not(feature = "lib"))]
fn seal_pdu(session_id: u64, enc_keys: ([u8; 16], [u8; 16]), cipher: u16, msg: &[u8]) -> Option<Vec<u8>> {
    let _ = (session_id, enc_keys, cipher, msg);
    None
}
#[cfg(not(feature = "handrolled"))]
fn encrypt_response(conn: &Smb2Conn, msg: &[u8]) -> Option<Vec<u8>> {
    seal_pdu(conn.session_id, conn.enc_keys?, conn.cipher?, msg)
}
/// Seal `msg` into a transform frame with explicit key material so both the
/// request path and background async tasks can encrypt without borrowing the
/// whole connection.
#[cfg(not(feature = "handrolled"))]
fn seal_pdu(session_id: u64, enc_keys: ([u8; 16], [u8; 16]), cipher: u16, msg: &[u8]) -> Option<Vec<u8>> {
    let (_c2s, s2c) = enc_keys;
    let gcm = cipher == smb_proto_smb2::negotiate::ctx_type::AES128_GCM;
    let iv_size = if gcm { 12 } else { 11 };

    let mut nonce_field = [0u8; 16];
    nonce_field[..iv_size].copy_from_slice(&crate::dispatch::rand_bytes(iv_size));

    let mut tf = smb_proto_smb2::commands::build_transform(session_id, &nonce_field, msg.len());
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
            conn.advertised_caps = if dialect >= smb_proto_smb2::negotiate::DIALECT_300 {
                smb_proto_smb2::negotiate::caps::LARGE_MTU
                    | smb_proto_smb2::negotiate::caps::MULTI_CHANNEL
            } else if dialect >= smb_proto_smb2::negotiate::DIALECT_210 {
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
            // Compression: intersect the client's advertised algorithms with
            // ours; a common set enables compressed transforms both ways.
            let comp_algos = req
                .contexts
                .iter()
                .find(|c| c.kind == smb_proto_smb2::negotiate::ctx_type::COMPRESSION)
                .map(|c| smb_proto_smb2::compress::negotiate_algos(
                    &smb_proto_smb2::compress::parse_compression_caps(&c.data),
                ))
                .unwrap_or_default();
            if dialect == smb_proto_smb2::negotiate::DIALECT_311
                && comp_algos.contains(&smb_proto_smb2::compress::algo::LZNT1)
            {
                conn.compress_algo = Some(smb_proto_smb2::compress::algo::LZNT1);
            }
            (
                Status::SUCCESS,
                smb_proto_smb2::negotiate::build_response_full(
                    dialect,
                    &server.guid,
                    smb_proto::types::FileTime::now().0,
                    &salt,
                    chosen.unwrap_or(smb_proto_smb2::negotiate::ctx_type::AES128_GCM),
                    &comp_algos,
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
            // Idempotent ([MS-SMB2] §3.3.5.8): tearing down a tree that is
            // already gone still satisfies the client's intent, so ack it.
            conn.trees.remove(&tid);
            (Status::SUCCESS, c::build_tree_disconnect_resp())
        }
        ss::cmd::LOGOFF => {
            close_all_handles(conn);
            server.locks.release_session(conn.session_id);
            server.share_modes.close_session(conn.session_id);
            server.oplocks.release_session(conn.session_id);
            server.leases.release_session(conn.session_id);
            server.sessions.remove(conn.session_id);
            conn.trees.clear();
            conn.searches.clear();
            if conn.authenticated {
                gauge!("smb_sessions_active").decrement(1.0);
            }
            conn.authenticated = false;
            // Keep session_id and cipher keys so this LOGOFF response still
            // carries the right SessionId and can be sealed when the request
            // arrived encrypted ([MS-SMB2] §3.3.5.6). A logged-off session is
            // gated by `authenticated`, not by clearing the id.
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
                match create(conn, vfs, server, hdr.is_signed(), buf).await {
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
                let close_path = c::CloseReq::parse(buf)
                    .and_then(|r| conn.handles.get(&r.file_id.0).map(|h| (r.file_id.0, h.path.clone())));
                match close(conn, vfs, buf).await {
                    Ok(body) => {
                        // Drop this open's byte-range locks and share-mode entry.
                        if let Some((fid, path)) = close_path {
                            server.locks.release_owner((conn.session_id, fid));
                            server.share_modes.close(&path, (conn.session_id, fid));
                            server.oplocks.release(&path, (conn.session_id, fid));
                            server.leases.release(&path, (conn.session_id, fid));
                            // An explicit close ends any durable-handle lease.
                            conn.durable.remove(&fid);
                            server.durables.remove(&fid);
                        }
                        (Status::SUCCESS, body)
                    }
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
                // Server-side copy: hand the client a resume key naming this
                // open so a later COPYCHUNK can use it as the source.
                c::fsctl::SRV_REQUEST_RESUME_KEY => {
                    if !conn.handles.contains_key(&req.file_id.0) {
                        return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                    }
                    let mut key = [0u8; 24];
                    key[..16].copy_from_slice(&req.file_id.0);
                    key[16..24].copy_from_slice(&next_resume_nonce().to_le_bytes());
                    conn.resume_keys.insert(key, req.file_id.0);
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &c::build_resume_key_resp(&key)))
                }
                // Server-side copy: read from the source open (named by the
                // resume key in the input) and write into this target handle.
                c::fsctl::SRV_COPYCHUNK | c::fsctl::SRV_COPYCHUNK_WRITE => {
                    let vfs = match share_vfs(server, conn, tid) {
                        Some(v) => v,
                        None => return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true)),
                    };
                    match do_copychunk(conn, vfs, &req).await {
                        Ok(out) => {
                            counter!("smb_copychunk_bytes_total").increment(copychunk_total(&out) as u64);
                            (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &out))
                        }
                        Err((status, out)) => {
                            let body = c::build_ioctl_resp(req.file_id, req.ctl_code, &out);
                            return Some((response(&hdr, status, body, conn.session_id), true));
                        }
                    }
                }
                // Linux files are implicitly sparse; accept the hint.
                c::fsctl::SET_SPARSE => {
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &[]))
                }
                // FSCTL_PIPE_WAIT ([MS-SMB2] §2.2.31.2): our named pipes are
                // always instantiable, so the wait completes immediately.
                c::fsctl::PIPE_WAIT => {
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &[]))
                }
                // DFS is not offered on this standalone server: a referral
                // query for any path is answered STATUS_NOT_FOUND so the client
                // treats the path as non-DFS ([MS-DFSC] §3.1.5.4.2).
                c::fsctl::DFS_GET_REFERRALS => {
                    return Some((response(&hdr, Status::NOT_FOUND, Vec::new(), conn.session_id), true));
                }
                // Multichannel interface discovery ([MS-SMB2] §3.3.5.15.4):
                // report the server's network interfaces so the client may open
                // additional channels for the session.
                c::fsctl::QUERY_NETWORK_INTERFACE_INFO => {
                    let out = network_interface_info();
                    (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &out))
                }
                // Zero a byte range in the target handle ([MS-FSCC] §2.3.79).
                c::fsctl::SET_ZERO_DATA => {
                    let vfs = match share_vfs(server, conn, tid) {
                        Some(v) => v,
                        None => return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true)),
                    };
                    let Some((start, end)) = c::parse_zero_data(&req.input).filter(|(s, e)| e >= s) else {
                        return Some((response(&hdr, Status::INVALID_PARAMETER, Vec::new(), conn.session_id), true));
                    };
                    let Some(h) = conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) else {
                        return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
                    };
                    match vfs.zero_range(h, start, end - start).await {
                        Ok(()) => {
                            counter!("smb_zeroed_bytes_total").increment(end - start);
                            (Status::SUCCESS, c::build_ioctl_resp(req.file_id, req.ctl_code, &[]))
                        }
                        Err(e) => (vfs_err(e), Vec::new()),
                    }
                }
                _ => (Status::NOT_IMPLEMENTED, Vec::new()),
            }
        }
        ss::cmd::LOCK => {
            let Some(req) = c::LockReq::parse(buf) else {
                return Some((response(&hdr, Status::INVALID_PARAMETER, Vec::new(), conn.session_id), true));
            };
            let Some(h) = conn.handles.get(&req.file_id.0) else {
                return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
            };
            let path = h.path.clone();
            let owner = (conn.session_id, req.file_id.0);

            // Unlocks first, then acquisitions ([MS-SMB2] §3.3.5.14).
            for l in req.locks.iter().filter(|l| l.unlock) {
                server.locks.release(&path, &[(l.offset, l.length)], owner);
            }
            let acquires: Vec<(u64, u64, bool)> = req
                .locks
                .iter()
                .filter(|l| !l.unlock)
                .map(|l| (l.offset, l.length, l.exclusive))
                .collect();

            if acquires.is_empty() || server.locks.try_acquire(&path, &acquires, owner) {
                (Status::SUCCESS, c::build_lock_resp())
            } else if req.locks.iter().any(|l| l.fail_immediately) {
                (Status::LOCK_NOT_GRANTED, Vec::new())
            } else {
                // Blocking lock ([MS-SMB2] §3.3.5.14): interim STATUS_PENDING,
                // then retry as conflicting locks are released.
                let async_id = conn.alloc_async_id();
                let crypto = AsyncCrypto::snapshot(conn, hdr.is_signed());
                let (cancel_tx, cancel_rx) = oneshot::channel();
                conn.async_cancels.insert(async_id, cancel_tx);
                gauge!("smb_async_pending").increment(1.0);
                tokio_uring::spawn(run_lock_wait(
                    server.locks.clone(),
                    path,
                    acquires,
                    owner,
                    crypto,
                    hdr.message_id,
                    async_id,
                    conn.outbound.clone(),
                    cancel_rx,
                ));
                let mut interim = build_async_frame(
                    conn.session_id,
                    hdr.message_id,
                    async_id,
                    ss::cmd::LOCK,
                    Status::PENDING,
                    &error_resp(),
                );
                if hdr.is_signed() {
                    if let Some(key) = conn.signing_key.clone().or(conn.session_key) {
                        sign_pdu(&mut interim, &key, conn.dialect);
                    }
                }
                return Some((interim, true));
            }
        }
        ss::cmd::CHANGE_NOTIFY => {
            let Some(req) = c::ChangeNotifyReq::parse(buf) else {
                return Some((response(&hdr, Status::INVALID_PARAMETER, Vec::new(), conn.session_id), true));
            };
            let Some(open) = conn.handles.get(&req.file_id.0) else {
                return Some((response(&hdr, Status::INVALID_HANDLE, Vec::new(), conn.session_id), true));
            };
            let dir_path = open.path.clone();

            // Register the async operation and hand it to a background watcher;
            // reply immediately with an interim STATUS_PENDING ([MS-SMB2]
            // §3.3.4.2). The final response fires from run_change_notify.
            let async_id = conn.alloc_async_id();
            let crypto = AsyncCrypto::snapshot(conn, hdr.is_signed());
            let (cancel_tx, cancel_rx) = oneshot::channel();
            conn.async_cancels.insert(async_id, cancel_tx);
            gauge!("smb_async_pending").increment(1.0);
            tokio_uring::spawn(run_change_notify(
                dir_path,
                req.watch_tree,
                req.filter,
                crypto,
                hdr.message_id,
                async_id,
                conn.outbound.clone(),
                cancel_rx,
            ));

            let mut interim = build_async_frame(
                conn.session_id,
                hdr.message_id,
                async_id,
                ss::cmd::CHANGE_NOTIFY,
                Status::PENDING,
                &error_resp(),
            );
            if hdr.is_signed() {
                if let Some(key) = conn.signing_key.clone().or(conn.session_key) {
                    sign_pdu(&mut interim, &key, conn.dialect);
                }
            }
            return Some((interim, true));
        }
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
            // Async CANCEL ([MS-SMB2] §3.3.5.14): signal the pending op keyed
            // by the AsyncId in the header so its task completes with
            // STATUS_CANCELLED. CANCEL itself carries no response.
            counter!("smb_cancels_total").increment(1);
            if hdr.is_async() && buf.len() >= 40 {
                let async_id = u64::from_le_bytes(buf[32..40].try_into().unwrap());
                if let Some(tx) = conn.async_cancels.remove(&async_id) {
                    let _ = tx.send(());
                }
            }
            return None;
        }
        ss::cmd::ECHO => (Status::SUCCESS, c::build_echo_resp()),
        ss::cmd::OPLOCK_BREAK => {
            // Command 18 carries both oplock (StructureSize 24) and lease
            // (StructureSize 36) break acknowledgements; dispatch on the size.
            let ss = u16::from_le_bytes([*buf.get(64).unwrap_or(&0), *buf.get(65).unwrap_or(&0)]);
            if ss == 36 {
                match c::LeaseBreakAck::parse(buf) {
                    Some(ack) => {
                        server.leases.set_state(ack.key, ack.state);
                        (Status::SUCCESS, c::build_lease_break_resp(ack.key, ack.state))
                    }
                    None => (Status::INVALID_PARAMETER, Vec::new()),
                }
            } else {
                match c::OplockBreakAck::parse(buf) {
                    // The holder acknowledges a break; we already downgraded on
                    // our side, so echo the settled level ([MS-SMB2] §3.3.5.22.2).
                    Some(ack) => (Status::SUCCESS, c::build_oplock_break_resp(ack.file_id, ack.level)),
                    None => (Status::INVALID_PARAMETER, Vec::new()),
                }
            }
        }
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
    // Derive cipher keys whenever a cipher was negotiated — even when the
    // server does not *require* encryption — so we can decrypt client-initiated
    // sealed traffic ([MS-SMB2] §3.1.5.1: a client may encrypt once a cipher is
    // agreed). `--encrypt` only controls whether we force-seal the session.
    if hdr.command == ss::cmd::SESSION_SETUP
        && status == Status::SUCCESS
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
            // Only *require* encryption (force-seal + set ENCRYPT_DATA on this
            // response) when the operator asked for it.
            if server.encrypt {
                conn.encrypt_data = true;
                seal_session = true;
            }
            tracing::info!(
                cipher = format!("{:#x}", conn.cipher.unwrap()),
                dialect = format!("{:#06x}", conn.dialect.unwrap_or(0)),
                required = server.encrypt,
                "cipher keys derived"
            );
        }
    }


    let mut resp = response(&hdr, status, body, conn.session_id);
    if let Some(new_tid) = resp_tid {
        resp[36..40].copy_from_slice(&new_tid.to_le_bytes()); // TreeId
    }

    // Register the established session so later channels can bind to it
    // ([MS-SMB2] §3.3.5.5.3 multichannel session binding).
    if hdr.command == ss::cmd::SESSION_SETUP
        && status == Status::SUCCESS
        && conn.authenticated
        && conn.session_id != 0
    {
        server.sessions.insert(
            conn.session_id,
            crate::state::SessionEntry {
                session_key: conn.session_key,
                signing_key: conn.signing_key,
                dialect: conn.dialect,
                user: conn.user.clone(),
                guest: conn.guest,
                cipher: conn.cipher,
                enc_keys: conn.enc_keys,
                encrypt_data: conn.encrypt_data,
            },
        );
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
            sign_pdu(&mut resp, &key, conn.dialect);
        }
    }
    Some((resp, allow_wrap))
}

/// Stamp an SMB2 signature over `resp` in place ([MS-SMB2] §3.3.4.1.1):
/// AES-CMAC for 3.x dialects, HMAC-SHA256 for 2.x. Sets the SIGNED flag and
/// fills the 16-byte Signature field (bytes 48..64).
fn sign_pdu(resp: &mut [u8], key: &[u8; 16], dialect: Option<u16>) {
    resp[16] |= 0x08; // SMB2_FLAGS_SIGNED
    let mut msg = Vec::with_capacity(resp.len());
    msg.extend_from_slice(&resp[..48]);
    msg.extend_from_slice(&[0u8; 16]); // zeroed Signature field
    msg.extend_from_slice(&resp[64..]);
    let sig = if matches!(
        dialect,
        Some(smb_proto_smb2::negotiate::DIALECT_300
            | smb_proto_smb2::negotiate::DIALECT_302
            | smb_proto_smb2::negotiate::DIALECT_311)
    ) {
        let t = smb_auth::crypto::aes128_cmac(key, &msg);
        let mut s = [0u8; 16];
        s.copy_from_slice(&t);
        s
    } else {
        let t = smb_auth::crypto::hmac_sha256(key, &msg);
        let mut s = [0u8; 16];
        s.copy_from_slice(&t[..16]);
        s
    };
    resp[48..64].copy_from_slice(&sig);
}

/// Per-session crypto material an async completion needs to sign/seal a frame
/// off the request path (snapshotted at request time so the background task
/// never borrows the connection).
#[derive(Clone)]
struct AsyncCrypto {
    dialect: Option<u16>,
    signing_key: Option<[u8; 16]>,
    enc_keys: Option<([u8; 16], [u8; 16])>,
    cipher: Option<u16>,
    session_id: u64,
    encrypt: bool,
    signed: bool,
}

impl AsyncCrypto {
    fn snapshot(conn: &Smb2Conn, request_signed: bool) -> Self {
        Self {
            dialect: conn.dialect,
            signing_key: conn.signing_key.or(conn.session_key),
            enc_keys: conn.enc_keys,
            cipher: conn.cipher,
            session_id: conn.session_id,
            encrypt: conn.encrypt_data || conn.peer_encrypts,
            signed: request_signed,
        }
    }
}

/// Build an async-header frame ([MS-SMB2] §3.3.4.2 async mode):
/// SERVER_TO_REDIR|ASYNC_COMMAND flags with the AsyncId occupying the
/// Reserved+TreeId slot. Returned unsigned and unsealed.
fn build_async_frame(
    session_id: u64,
    message_id: u64,
    async_id: u64,
    command: u16,
    status: Status,
    body: &[u8],
) -> Vec<u8> {
    let mut f = Vec::with_capacity(64 + body.len());
    f.extend_from_slice(&smb_proto_smb2::SMB2_MAGIC);
    f.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    f.extend_from_slice(&1u16.to_le_bytes()); // CreditCharge
    f.extend_from_slice(&status.raw().to_le_bytes());
    f.extend_from_slice(&command.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes()); // CreditResponse
    f.extend_from_slice(&0x0000_0003u32.to_le_bytes()); // SERVER_TO_REDIR|ASYNC_COMMAND
    f.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    f.extend_from_slice(&message_id.to_le_bytes());
    f.extend_from_slice(&async_id.to_le_bytes()); // AsyncId
    f.extend_from_slice(&session_id.to_le_bytes());
    f.extend_from_slice(&[0u8; 16]); // Signature
    f.extend_from_slice(body);
    f
}

/// Sign then (optionally) seal a fully-built async frame per the session's
/// protection, mirroring the request path's sign-then-encrypt order.
fn finalize_async(crypto: &AsyncCrypto, mut frame: Vec<u8>) -> Vec<u8> {
    if crypto.signed {
        if let Some(key) = crypto.signing_key {
            sign_pdu(&mut frame, &key, crypto.dialect);
        }
    }
    if crypto.encrypt {
        if let (Some(keys), Some(cipher)) = (crypto.enc_keys, crypto.cipher) {
            if let Some(sealed) = seal_pdu(crypto.session_id, keys, cipher, &frame) {
                return sealed;
            }
        }
    }
    frame
}

/// Block until a conflicting byte-range lock is released and the requested
/// ranges can be acquired, then emit the final LOCK response ([MS-SMB2]
/// §3.3.5.14). Cancellation yields STATUS_CANCELLED.
#[allow(clippy::too_many_arguments)]
async fn run_lock_wait(
    locks: Arc<crate::state::LockManager>,
    path: String,
    ranges: Vec<(u64, u64, bool)>,
    owner: crate::state::LockOwner,
    crypto: AsyncCrypto,
    message_id: u64,
    async_id: u64,
    outbound: mpsc::Sender<Vec<u8>>,
    mut cancel: oneshot::Receiver<()>,
) {
    let granted = loop {
        // Register for the wakeup before trying, so a release between the try
        // and the await is not lost.
        let notified = locks.released().notified();
        if locks.try_acquire(&path, &ranges, owner) {
            break true;
        }
        tokio::select! {
            _ = notified => {}
            _ = &mut cancel => break false,
        }
    };
    let (status, body) = if granted {
        counter!("smb_locks_granted_total").increment(1);
        (Status::SUCCESS, c::build_lock_resp())
    } else {
        (Status::CANCELLED, Vec::new())
    };
    let frame = finalize_async(
        &crypto,
        build_async_frame(crypto.session_id, message_id, async_id, ss::cmd::LOCK, status, &body),
    );
    let _ = outbound.send(frame).await;
    gauge!("smb_async_pending").decrement(1.0);
}

/// Watch `dir_path` for one filesystem change (or cancellation) and emit the
/// final CHANGE_NOTIFY response ([MS-SMB2] §2.2.36) on the outbound queue.
async fn run_change_notify(
    dir_path: String,
    _watch_tree: bool,
    filter: u32,
    crypto: AsyncCrypto,
    message_id: u64,
    async_id: u64,
    outbound: mpsc::Sender<Vec<u8>>,
    mut cancel: oneshot::Receiver<()>,
) {
    let frame = match watch_one_event(&dir_path, filter, &mut cancel).await {
        Some(entries) => {
            let pairs: Vec<(u32, &str)> =
                entries.iter().map(|(a, n)| (*a, n.as_str())).collect();
            let buf = c::build_file_notify_information(&pairs);
            let body = c::build_change_notify_resp(&buf);
            counter!("smb_notifies_sent").increment(1);
            build_async_frame(crypto.session_id, message_id, async_id, ss::cmd::CHANGE_NOTIFY, Status::SUCCESS, &body)
        }
        None => build_async_frame(
            crypto.session_id,
            message_id,
            async_id,
            ss::cmd::CHANGE_NOTIFY,
            Status::CANCELLED,
            &c::build_change_notify_resp(&[]),
        ),
    };
    let _ = outbound.send(finalize_async(&crypto, frame)).await;
    gauge!("smb_async_pending").decrement(1.0);
}

/// Await the first inotify event on `dir_path` (mapped from the SMB completion
/// filter) or a cancellation. Returns the `(action, name)` list, or `None` on
/// cancel/setup error.
async fn watch_one_event(
    dir_path: &str,
    filter: u32,
    cancel: &mut oneshot::Receiver<()>,
) -> Option<Vec<(u32, String)>> {
    use futures_util::StreamExt;
    use inotify::Inotify;

    let inotify = Inotify::init().ok()?;
    inotify.watches().add(dir_path, filter_to_mask(filter)).ok()?;
    let mut buf = [0u8; 4096];
    let mut stream = inotify.into_event_stream(&mut buf).ok()?;

    tokio::select! {
        ev = stream.next() => {
            let ev = ev?.ok()?;
            let name = ev
                .name
                .as_ref()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            Some(vec![(mask_to_action(ev.mask), name)])
        }
        _ = cancel => None,
    }
}

/// Translate an SMB completion filter ([MS-SMB2] §2.2.35) into an inotify
/// watch mask.
fn filter_to_mask(filter: u32) -> inotify::WatchMask {
    use inotify::WatchMask as M;
    use smb_proto_smb2::commands::notify_filter as nf;

    let mut m = M::empty();
    if filter & (nf::FILE_NAME | nf::DIR_NAME) != 0 {
        m |= M::CREATE | M::DELETE | M::MOVED_FROM | M::MOVED_TO;
    }
    if filter & nf::ATTRIBUTES != 0 {
        m |= M::ATTRIB;
    }
    if filter & (nf::SIZE | nf::LAST_WRITE) != 0 {
        m |= M::MODIFY | M::CLOSE_WRITE;
    }
    if m.is_empty() {
        m = M::CREATE | M::DELETE | M::MODIFY | M::MOVED_FROM | M::MOVED_TO;
    }
    m
}

/// Map an inotify event mask to a FILE_NOTIFY_INFORMATION action
/// ([MS-FSCC] §2.7.1).
fn mask_to_action(mask: inotify::EventMask) -> u32 {
    use inotify::EventMask as E;
    use smb_proto_smb2::commands::notify_action as na;

    if mask.contains(E::CREATE) {
        na::ADDED
    } else if mask.contains(E::DELETE) {
        na::REMOVED
    } else if mask.contains(E::MOVED_FROM) {
        na::RENAMED_OLD_NAME
    } else if mask.contains(E::MOVED_TO) {
        na::RENAMED_NEW_NAME
    } else {
        na::MODIFIED
    }
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
    // Channel binding ([MS-SMB2] §3.3.5.5.2): the setup carries the binding
    // flag and the header names an existing session to attach this new
    // connection (channel) to.
    let hdr_session = buf
        .get(40..48)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    let binding = req.flags & ss::FLAG_BINDING != 0
        && hdr_session != 0
        && server.sessions.get(hdr_session).is_some();
    let inner = smb_auth::ntlm::unwrap_blob(&req.blob).unwrap_or(&[]);
    tracing::trace!(
        blob_len = req.blob.len(),
        msg_type = ?smb_auth::ntlm::msg_type(inner),
        "session setup token"
    );
    match smb_auth::ntlm::msg_type(inner) {
        Some(smb_auth::ntlm::MSG_TYPE1) | None => {
            // Leg 1: issue CHALLENGE under MORE_PROCESSING_REQUIRED. A binding
            // channel keeps the existing session id instead of allocating one.
            conn.session_id = if binding { hdr_session } else { next_session_id() };
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
            // A bound channel reuses the original session's crypto material so
            // signatures/encryption stay consistent across channels.
            if binding {
                if let Some(entry) = server.sessions.get(conn.session_id) {
                    conn.session_key = entry.session_key;
                    conn.signing_key = entry.signing_key;
                    conn.cipher = entry.cipher;
                    conn.enc_keys = entry.enc_keys;
                    conn.encrypt_data = entry.encrypt_data;
                    conn.dialect = entry.dialect.or(conn.dialect);
                }
            }
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
    server: &Arc<ServerShared>,
    req_signed: bool,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::CreateReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;

    const OPT_DIRECTORY_FILE: u32 = 0x1;
    const OPT_NON_DIRECTORY_FILE: u32 = 0x40;
    const OPT_DELETE_ON_CLOSE: u32 = 0x1000;

    // Durable reconnect ([MS-SMB2] §3.3.5.9.7/§3.3.5.9.12): reclaim a preserved
    // handle instead of opening fresh.
    if let Some((id, guid)) = durable_reconnect_ids(&req.durable) {
        return durable_reconnect(conn, vfs, server, id, guid).await;
    }

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
    let path = open.path.clone();
    let is_dir = open.is_dir;
    // Sharing-violation check ([MS-FSA] §2.1.5.1): reject an open whose access
    // or share flags conflict with an existing open on the same file. Undo the
    // just-opened handle on rejection. Directories are not share-checked.
    if !is_dir
        && !server.share_modes.try_open(&path, req.desired_access, req.share_access, (conn.session_id, fid_bytes))
    {
        let _ = vfs.close(open).await;
        counter!("smb_sharing_violations_total").increment(1);
        return Err(Status::SHARING_VIOLATION);
    }

    let fid = c::FileId(fid_bytes);
    conn.searches.remove(&fid_bytes);
    conn.handles.insert(fid_bytes, open);

    // Oplock arbitration ([MS-SMB2] §2.2.23): grant an exclusive oplock only
    // to the sole opener of a file. A contending open first breaks the current
    // holder to NONE, then gets no oplock itself.
    let wants_oplock = matches!(
        req.oplock_level,
        c::oplock::LEVEL_II | c::oplock::EXCLUSIVE | c::oplock::BATCH
    );
    // A lease request (RequestedOplockLevel = LEASE + an RqLs context) uses the
    // lease path; leases and oplocks are arbitrated independently.
    let mut lease_grant: Option<c::LeaseResp> = None;
    let granted = if is_dir {
        c::oplock::NONE
    } else if req.oplock_level == c::oplock::LEASE {
        if let Some(lr) = req.lease {
            lease_grant = Some(arbitrate_lease(server, conn, &path, fid_bytes, &lr, req_signed));
            c::oplock::LEASE
        } else {
            c::oplock::NONE
        }
    } else if server.share_modes.open_count(&path) > 1 {
        if let Some(holder) = server.oplocks.take(&path) {
            send_oplock_break(&holder, c::oplock::NONE);
        }
        c::oplock::NONE
    } else if wants_oplock {
        let holder = crate::state::OplockHolder {
            session_id: conn.session_id,
            file_id: fid_bytes,
            outbound: conn.outbound.clone(),
            crypto: break_crypto(conn, req_signed),
        };
        if server.oplocks.grant(&path, holder) {
            counter!("smb_oplocks_granted_total").increment(1);
            c::oplock::EXCLUSIVE
        } else {
            c::oplock::NONE
        }
    } else {
        c::oplock::NONE
    };

    tracing::debug!(
        name = %rel, eof = meta.eof, dir = meta.is_dir, action,
        oplock = granted, lease = ?lease_grant.map(|l| l.state), "create"
    );
    counter!("smb_creates_total").increment(1);

    // Grant a durable handle when the client requested one.
    let durable_grant = grant_durable(conn, &req, fid_bytes, &rel, is_dir);

    // Assemble create-context responses (lease grant, durable-handle grant).
    let mut ctx_entries: Vec<(&[u8], Vec<u8>)> = Vec::new();
    if let Some(l) = &lease_grant {
        ctx_entries.push((c::lease::CONTEXT_NAME, c::lease_context_data(l)));
    }
    if let Some(d) = &durable_grant {
        ctx_entries.push((d.0, d.1.clone()));
    }
    let contexts = c::encode_create_contexts(&ctx_entries);
    Ok(c::build_create_resp(
        fid,
        action,
        [meta.times[0].0, meta.times[1].0, meta.times[2].0, meta.times[3].0],
        meta.attrs.0,
        meta.alloc,
        meta.eof,
        meta.is_dir,
        granted,
        &contexts,
    ))
}

/// Extract `(persistent_id, create_guid)` when a CREATE carries a durable
/// reconnect context.
fn durable_reconnect_ids(d: &Option<c::DurableReq>) -> Option<([u8; 16], Option<[u8; 16]>)> {
    match d {
        Some(c::DurableReq::ReconnectV2 { file_id, create_guid }) => Some((*file_id, Some(*create_guid))),
        Some(c::DurableReq::ReconnectV1 { file_id }) => Some((*file_id, None)),
        _ => None,
    }
}

/// Reclaim a preserved durable handle and re-open the file under its persistent
/// id (single-node durable model: the on-disk file, not a live fd, is durable).
async fn durable_reconnect(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    server: &Arc<ServerShared>,
    id: [u8; 16],
    guid: Option<[u8; 16]>,
) -> Result<Vec<u8>, Status> {
    let entry = server.durables.reclaim(id, guid).ok_or(Status::OBJECT_NAME_NOT_FOUND)?;
    // FILE_OPEN (disposition 1): the file already exists.
    let (mut open, meta, _action) = vfs
        .create(&entry.rel, entry.is_dir, entry.access, 1, entry.options, 0)
        .await
        .map_err(vfs_err)?;
    open.delete_on_close = false;
    conn.handles.insert(id, open);
    let mut again = entry.clone();
    again.session_id = conn.session_id;
    conn.durable.insert(id, again);
    counter!("smb_durable_reconnects_total").increment(1);

    let (name, data): (&[u8], Vec<u8>) = if guid.is_some() {
        let flags = if entry.persistent { c::durable::FLAG_PERSISTENT } else { 0 };
        (c::durable::REQ_V2, c::durable_v2_resp_data(entry.timeout, flags))
    } else {
        (c::durable::REQ_V1, c::durable_v1_resp_data())
    };
    let contexts = c::encode_create_contexts(&[(name, data)]);
    Ok(c::build_create_resp(
        c::FileId(id),
        1, // FILE_OPENED
        [meta.times[0].0, meta.times[1].0, meta.times[2].0, meta.times[3].0],
        meta.attrs.0,
        meta.alloc,
        meta.eof,
        meta.is_dir,
        c::oplock::NONE,
        &contexts,
    ))
}

/// Record a durable-handle grant on the connection and return the response
/// create-context to echo. Directories and one-shot deletes are ineligible.
fn grant_durable(
    conn: &mut Smb2Conn,
    req: &c::CreateReq,
    fid: [u8; 16],
    rel: &str,
    is_dir: bool,
) -> Option<(&'static [u8], Vec<u8>)> {
    /// Fallback handle timeout when the client requests 0 (60 s).
    const DEFAULT_TIMEOUT_MS: u32 = 60_000;
    let make = |create_guid: [u8; 16], persistent: bool, timeout: u32| crate::state::DurableEntry {
        persistent_id: fid,
        create_guid,
        rel: rel.to_string(),
        is_dir,
        access: req.desired_access,
        options: req.options,
        session_id: conn.session_id,
        persistent,
        timeout,
        deadline: std::time::Instant::now(),
    };
    match req.durable {
        Some(c::DurableReq::RequestV2 { timeout, flags, create_guid }) => {
            let persistent = flags & c::durable::FLAG_PERSISTENT != 0;
            let to = if timeout == 0 { DEFAULT_TIMEOUT_MS } else { timeout };
            conn.durable.insert(fid, make(create_guid, persistent, to));
            counter!("smb_durables_granted_total").increment(1);
            Some((
                c::durable::REQ_V2,
                c::durable_v2_resp_data(to, if persistent { c::durable::FLAG_PERSISTENT } else { 0 }),
            ))
        }
        Some(c::DurableReq::RequestV1) => {
            conn.durable.insert(fid, make([0u8; 16], false, DEFAULT_TIMEOUT_MS));
            counter!("smb_durables_granted_total").increment(1);
            Some((c::durable::REQ_V1, c::durable_v1_resp_data()))
        }
        _ => None,
    }
}

/// Arbitrate a caching lease for a lease-requesting CREATE ([MS-SMB2]
/// §2.2.13.2). The sole opener gets the requested state (capped at RWH); an
/// open reusing the same lease key shares the existing state; an open with a
/// different key strips write caching from the current holder (RWH -> RH) via
/// an unsolicited LEASE_BREAK and is itself granted read/handle caching.
fn arbitrate_lease(
    server: &Arc<ServerShared>,
    conn: &Smb2Conn,
    path: &str,
    fid: [u8; 16],
    lr: &c::LeaseReq,
    signed: bool,
) -> c::LeaseResp {
    let requested = lr.state & c::lease::RWH;
    if let Some((key, state, epoch, v2)) = server.leases.peek(path) {
        if key == lr.key {
            return c::LeaseResp { key: lr.key, state, flags: 0, epoch, v2 };
        }
        let new_state = state & c::lease::RH;
        if let Some((hkey, old, nepoch, outbound, crypto)) = server.leases.downgrade(path, new_state) {
            send_lease_break(&outbound, &crypto, hkey, old, new_state, nepoch);
        }
        let grant = requested & c::lease::RH;
        return c::LeaseResp { key: lr.key, state: grant, flags: 0, epoch: lr.epoch, v2: lr.v2 };
    }
    let holder = crate::state::LeaseHolder {
        key: lr.key,
        state: requested,
        epoch: lr.epoch,
        v2: lr.v2,
        session_id: conn.session_id,
        file_id: fid,
        outbound: conn.outbound.clone(),
        crypto: break_crypto(conn, signed),
    };
    server.leases.grant(path, holder);
    counter!("smb_leases_granted_total").increment(1);
    c::LeaseResp { key: lr.key, state: requested, flags: 0, epoch: lr.epoch, v2: lr.v2 }
}

/// Build a NETWORK_INTERFACE_INFO list ([MS-SMB2] §2.2.32.5) from the host's
/// interfaces so a multichannel client can discover additional server IPs.
fn network_interface_info() -> Vec<u8> {
    let mut entries: Vec<(u32, std::net::IpAddr)> = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for (i, iface) in ifaces.iter().enumerate() {
            entries.push((i as u32 + 1, iface.ip()));
        }
    }
    build_interface_list(&entries)
}

/// Encode NETWORK_INTERFACE_INFO entries (RSS/RDMA both disabled, 10 Gbps),
/// chaining `Next` links; each entry is a fixed 152 bytes (8-byte aligned).
fn build_interface_list(entries: &[(u32, std::net::IpAddr)]) -> Vec<u8> {
    const LINK_SPEED: u64 = 10_000_000_000;
    let mut out = Vec::new();
    for (idx, (ifindex, ip)) in entries.iter().enumerate() {
        let start = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // Next (patched below)
        out.extend_from_slice(&ifindex.to_le_bytes()); // IfIndex
        out.extend_from_slice(&0u32.to_le_bytes()); // Capability (no RSS/RDMA)
        out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        out.extend_from_slice(&LINK_SPEED.to_le_bytes()); // LinkSpeed
        let mut sa = [0u8; 128]; // SOCKADDR_STORAGE
        match ip {
            std::net::IpAddr::V4(v4) => {
                sa[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
                sa[4..8].copy_from_slice(&v4.octets()); // sin_addr
            }
            std::net::IpAddr::V6(v6) => {
                sa[0..2].copy_from_slice(&23u16.to_le_bytes()); // AF_INET6
                sa[8..24].copy_from_slice(&v6.octets()); // sin6_addr
            }
        }
        out.extend_from_slice(&sa);
        if idx + 1 < entries.len() {
            let next = (out.len() - start) as u32;
            out[start..start + 4].copy_from_slice(&next.to_le_bytes());
        }
    }
    out
}

/// Build, protect and enqueue an unsolicited LEASE_BREAK notification
/// ([MS-SMB2] §2.2.23.2) asking a holder to drop from `current` to `new`.
fn send_lease_break(
    outbound: &mpsc::Sender<Vec<u8>>,
    crypto: &crate::state::BreakCrypto,
    key: [u8; 16],
    current: u32,
    new: u32,
    epoch: u16,
) {
    let body = c::build_lease_break(key, current, new, epoch, c::lease::BREAK_FLAG_ACK_REQUIRED);
    let frame = finalize_break(crypto, build_break_frame(crypto.session_id, &body));
    if outbound.try_send(frame).is_ok() {
        counter!("smb_lease_breaks_total").increment(1);
    }
}


/// Snapshot the crypto material needed to protect an oplock break sent later
/// to this holder.
fn break_crypto(conn: &Smb2Conn, signed: bool) -> crate::state::BreakCrypto {
    crate::state::BreakCrypto {
        dialect: conn.dialect,
        signing_key: conn.signing_key.or(conn.session_key),
        enc_keys: conn.enc_keys,
        cipher: conn.cipher,
        session_id: conn.session_id,
        encrypt: conn.encrypt_data || conn.peer_encrypts,
        signed,
    }
}

/// Build, protect and enqueue an unsolicited OPLOCK_BREAK notification
/// ([MS-SMB2] §2.2.23.1) telling `holder` to break down to `level`.
fn send_oplock_break(holder: &crate::state::OplockHolder, level: u8) {
    let body = c::build_oplock_break(c::FileId(holder.file_id), level);
    let frame = finalize_break(&holder.crypto, build_break_frame(holder.crypto.session_id, &body));
    if holder.outbound.try_send(frame).is_ok() {
        counter!("smb_oplock_breaks_total").increment(1);
    }
}

/// Build a server-initiated OPLOCK_BREAK frame (unsolicited: MessageId all-ones,
/// sync header). Returned unsigned and unsealed.
fn build_break_frame(session_id: u64, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64 + body.len());
    f.extend_from_slice(&smb_proto_smb2::SMB2_MAGIC);
    f.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    f.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    f.extend_from_slice(&0u32.to_le_bytes()); // Status
    f.extend_from_slice(&ss::cmd::OPLOCK_BREAK.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes()); // CreditResponse
    f.extend_from_slice(&1u32.to_le_bytes()); // Flags = SERVER_TO_REDIR
    f.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    f.extend_from_slice(&u64::MAX.to_le_bytes()); // MessageId (unsolicited)
    f.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    f.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    f.extend_from_slice(&session_id.to_le_bytes());
    f.extend_from_slice(&[0u8; 16]); // Signature
    f.extend_from_slice(body);
    f
}

/// Sign/seal an oplock break for its holder, mirroring the request path order.
fn finalize_break(crypto: &crate::state::BreakCrypto, mut frame: Vec<u8>) -> Vec<u8> {
    if crypto.signed {
        if let Some(key) = crypto.signing_key {
            sign_pdu(&mut frame, &key, crypto.dialect);
        }
    }
    if crypto.encrypt {
        if let (Some(keys), Some(cipher)) = (crypto.enc_keys, crypto.cipher) {
            if let Some(sealed) = seal_pdu(crypto.session_id, keys, cipher, &frame) {
                return sealed;
            }
        }
    }
    frame
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
        c::oplock::NONE,
        &[],
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
            if req.class == info::file_class::STREAM {
                // Default `::$DATA` data stream (files only) plus any ADS.
                let mut streams = Vec::new();
                if !m.is_dir {
                    streams.push(("::$DATA".to_string(), m.eof));
                }
                streams.extend(vfs.list_streams(&h.path).await.map_err(vfs_err)?);
                return Ok(Some(info::encode_stream_info(&streams)));
            }
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
        c::info_type::SECURITY => {
            let h = conn.handles.get(&req.file_id.0).ok_or(Status::INVALID_HANDLE)?;
            let stored = vfs.get_security(&h.path).await.map_err(vfs_err)?;
            let additional = if req.additional == 0 {
                crate::security::sec_info::DEFAULT
            } else {
                req.additional
            };
            let sd = crate::security::query_security(stored.as_deref(), additional)
                .ok_or(Status::INVALID_PARAMETER)?;
            if (req.output_len as usize) < sd.len() {
                return Err(Status::BUFFER_TOO_SMALL);
            }
            Ok(Some(sd))
        }
        _ => Ok(None), // QUOTA unsupported for now
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
        c::info_type::SECURITY => {
            let h = conn.handles.get(&req.file_id.0).ok_or(Status::INVALID_HANDLE)?;
            vfs.set_security(&h.path, &req.buffer).await.map_err(vfs_err)
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

/// Server-side-copy nonce appended to a resume key so repeated keys on one
/// open stay distinct.
fn next_resume_nonce() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0x5253_554d_4b45_5900);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Read the TotalBytesWritten field out of a SRV_COPYCHUNK_RESPONSE body.
fn copychunk_total(resp: &[u8]) -> u32 {
    resp.get(8..12)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0)
}

/// Perform a server-side copy: for each chunk read from the source open named
/// by the resume key and write into the target handle. Returns the
/// SRV_COPYCHUNK_RESPONSE body, or `(status, body)` where the body carries the
/// server limits on a limits violation ([MS-SMB2] §3.3.5.15.6).
async fn do_copychunk(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    req: &c::IoctlReq,
) -> Result<Vec<u8>, (Status, Vec<u8>)> {
    use smb_proto_smb2::commands::copychunk_limits as lim;
    let cc = c::CopyChunkCopy::parse(&req.input).ok_or((Status::INVALID_PARAMETER, Vec::new()))?;

    let total: u64 = cc.chunks.iter().map(|k| k.length as u64).sum();
    if cc.chunks.len() as u32 > lim::MAX_CHUNKS
        || cc.chunks.iter().any(|k| k.length > lim::MAX_CHUNK_SIZE)
        || total > lim::MAX_TOTAL_SIZE as u64
    {
        let limits = c::build_copychunk_resp(lim::MAX_CHUNKS, lim::MAX_CHUNK_SIZE, lim::MAX_TOTAL_SIZE);
        return Err((Status::INVALID_PARAMETER, limits));
    }

    let src_fid = *conn
        .resume_keys
        .get(&cc.source_key)
        .ok_or((Status::OBJECT_NAME_NOT_FOUND, Vec::new()))?;
    let tgt_fid = req.file_id.0;

    let mut chunks_written = 0u32;
    let mut total_written = 0u32;
    for k in &cc.chunks {
        let data = {
            let src = conn.handles.get_mut(&src_fid).ok_or((Status::INVALID_HANDLE, Vec::new()))?;
            vfs.read(src, k.source_offset, k.length as usize)
                .await
                .map_err(|e| (vfs_err(e), Vec::new()))?
        };
        let tgt = conn.handles.get_mut(&tgt_fid).ok_or((Status::INVALID_HANDLE, Vec::new()))?;
        let w = vfs
            .write(tgt, k.target_offset, &data, false)
            .await
            .map_err(|e| (vfs_err(e), Vec::new()))?;
        total_written += w as u32;
        chunks_written += 1;
    }
    // On success ChunkBytesWritten is 0 ([MS-SMB2] §2.2.32.1).
    Ok(c::build_copychunk_resp(chunks_written, 0, total_written))
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

#[cfg(test)]
mod async_notify_tests {
    use super::*;

    #[test]
    fn async_frame_sets_async_flag_and_ids() {
        let f = build_async_frame(0xABCD, 42, 7, ss::cmd::CHANGE_NOTIFY, Status::PENDING, &[0u8; 8]);
        assert_eq!(&f[0..4], &smb_proto_smb2::SMB2_MAGIC);
        let flags = u32::from_le_bytes(f[16..20].try_into().unwrap());
        assert_eq!(flags & 0x2, 0x2, "ASYNC_COMMAND set");
        assert_eq!(flags & 0x1, 0x1, "SERVER_TO_REDIR set");
        assert_eq!(u64::from_le_bytes(f[24..32].try_into().unwrap()), 42, "MessageId");
        assert_eq!(u64::from_le_bytes(f[32..40].try_into().unwrap()), 7, "AsyncId");
        assert_eq!(u64::from_le_bytes(f[40..48].try_into().unwrap()), 0xABCD, "SessionId");
        assert_eq!(u32::from_le_bytes(f[8..12].try_into().unwrap()), Status::PENDING.raw());
    }

    /// End-to-end of the real inotify watcher: arm a watch on a temp dir, drop
    /// a file in, and confirm we surface a FILE_ACTION_ADDED for its name.
    #[test]
    fn watch_reports_created_file() {
        tokio_uring::start(async {
        let dir = std::env::temp_dir().join(format!("rustsmb_notify_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_string_lossy().into_owned();

        let (_tx, mut rx) = oneshot::channel();
        let watch = tokio_uring::spawn(async move {
            watch_one_event(&path, smb_proto_smb2::commands::notify_filter::FILE_NAME, &mut rx).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        std::fs::write(dir.join("created.txt"), b"hi").unwrap();

        let events = watch.await.unwrap().expect("event fired");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, smb_proto_smb2::commands::notify_action::ADDED);
        assert_eq!(events[0].1, "created.txt");
        std::fs::remove_dir_all(&dir).ok();
        });
    }

    /// Cancelling the watch resolves the watcher with no events.
    #[test]
    fn cancel_stops_watch() {
        tokio_uring::start(async {
        let dir = std::env::temp_dir().join(format!("rustsmb_notify_cancel_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_string_lossy().into_owned();

        let (tx, mut rx) = oneshot::channel();
        let watch = tokio_uring::spawn(async move {
            watch_one_event(&path, smb_proto_smb2::commands::notify_filter::FILE_NAME, &mut rx).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx.send(()).unwrap();
        assert!(watch.await.unwrap().is_none(), "cancelled watch yields no events");
        std::fs::remove_dir_all(&dir).ok();
        });
    }
}

#[cfg(test)]
mod fsctl_tests {
    use super::*;

    fn conn_with_vfs(dir: &std::path::Path) -> (Smb2Conn, Arc<dyn smb_vfs::Vfs>) {
        let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(dir));
        let (tx, _rx) = mpsc::channel(8);
        (Smb2Conn::new([0u8; 8], tx), vfs)
    }

    /// Server-side copy reads from the source open (named by a resume key) and
    /// writes into the target handle; the target file ends up with the bytes.
    #[test]
    fn copychunk_copies_between_handles() {
        tokio_uring::start(async {
        let dir = std::env::temp_dir().join(format!("rustsmb_cc_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("src.txt"), b"hello copychunk world").unwrap();
        std::fs::write(dir.join("dst.txt"), b"").unwrap();

        let (mut conn, vfs) = conn_with_vfs(&dir);
        let (src, _m, _a) = vfs.create("src.txt", false, 0x8000_0000, 1, 0, 0).await.unwrap();
        let (dst, _m, _a) = vfs.create("dst.txt", false, 0x4000_0000, 1, 0, 0).await.unwrap();
        let (src_fid, dst_fid) = ([1u8; 16], [2u8; 16]);
        conn.handles.insert(src_fid, src);
        conn.handles.insert(dst_fid, dst);

        let mut key = [0u8; 24];
        key[..16].copy_from_slice(&src_fid);
        conn.resume_keys.insert(key, src_fid);

        let mut input = Vec::new();
        input.extend_from_slice(&key);
        input.extend_from_slice(&1u32.to_le_bytes()); // ChunkCount
        input.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        input.extend_from_slice(&0u64.to_le_bytes()); // SourceOffset
        input.extend_from_slice(&0u64.to_le_bytes()); // TargetOffset
        input.extend_from_slice(&21u32.to_le_bytes()); // Length
        input.extend_from_slice(&0u32.to_le_bytes()); // Reserved

        let req = c::IoctlReq {
            ctl_code: c::fsctl::SRV_COPYCHUNK,
            file_id: c::FileId(dst_fid),
            input,
            max_output: 4096,
            is_fsctl: true,
        };
        let out = do_copychunk(&mut conn, vfs.clone(), &req).await.expect("copychunk");
        assert_eq!(&out[0..4], &1u32.to_le_bytes(), "ChunksWritten");
        assert_eq!(&out[8..12], &21u32.to_le_bytes(), "TotalBytesWritten");

        let dst = conn.handles.remove(&dst_fid).unwrap();
        vfs.close(dst).await.unwrap();
        assert_eq!(std::fs::read(dir.join("dst.txt")).unwrap(), b"hello copychunk world");
        std::fs::remove_dir_all(&dir).ok();
        });
    }

    /// A request past the server limits is rejected with the limits echoed.
    #[test]
    fn copychunk_rejects_oversized_request() {
        tokio_uring::start(async {
        use smb_proto_smb2::commands::copychunk_limits as lim;
        let dir = std::env::temp_dir().join(format!("rustsmb_cc_lim_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f"), b"x").unwrap();
        let (mut conn, vfs) = conn_with_vfs(&dir);
        let (f, _m, _a) = vfs.create("f", false, 0x8000_0000, 1, 0, 0).await.unwrap();
        let fid = [3u8; 16];
        conn.handles.insert(fid, f);
        let mut key = [0u8; 24];
        key[..16].copy_from_slice(&fid);
        conn.resume_keys.insert(key, fid);

        let mut input = Vec::new();
        input.extend_from_slice(&key);
        input.extend_from_slice(&1u32.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        input.extend_from_slice(&0u64.to_le_bytes());
        input.extend_from_slice(&0u64.to_le_bytes());
        input.extend_from_slice(&(lim::MAX_CHUNK_SIZE + 1).to_le_bytes()); // over per-chunk cap
        input.extend_from_slice(&0u32.to_le_bytes());

        let req = c::IoctlReq {
            ctl_code: c::fsctl::SRV_COPYCHUNK,
            file_id: c::FileId(fid),
            input,
            max_output: 4096,
            is_fsctl: true,
        };
        let err = do_copychunk(&mut conn, vfs, &req).await.unwrap_err();
        assert_eq!(err.0, Status::INVALID_PARAMETER);
        assert_eq!(&err.1[4..8], &lim::MAX_CHUNK_SIZE.to_le_bytes(), "limits echoed");
        std::fs::remove_dir_all(&dir).ok();
        });
    }

    /// FSCTL_SET_ZERO_DATA zeros the requested byte range.
    #[test]
    fn zero_range_zeros_bytes() {
        tokio_uring::start(async {
        let dir = std::env::temp_dir().join(format!("rustsmb_zd_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("z.bin"), vec![0xFFu8; 16]).unwrap();
        let (mut conn, vfs) = conn_with_vfs(&dir);
        let (f, _m, _a) = vfs.create("z.bin", false, 0x4000_0000, 1, 0, 0).await.unwrap();
        let fid = [4u8; 16];
        conn.handles.insert(fid, f);

        let h = conn.handles.get_mut(&fid).map(|b| &mut **b).unwrap();
        vfs.zero_range(h, 4, 8).await.expect("zero range");
        let f = conn.handles.remove(&fid).unwrap();
        vfs.close(f).await.unwrap();

        let mut expected = vec![0xFFu8; 16];
        for b in &mut expected[4..12] {
            *b = 0;
        }
        assert_eq!(std::fs::read(dir.join("z.bin")).unwrap(), expected);
        std::fs::remove_dir_all(&dir).ok();
        });
    }
}

#[cfg(test)]
mod oplock_tests {
    use super::*;

    fn server_with_share(dir: &std::path::Path) -> Arc<ServerShared> {
        use crate::state::*;
        let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(dir));
        let mut shares = HashMap::new();
        shares.insert(
            "public".to_string(),
            Share { name: "public".into(), root: dir.to_path_buf(), vfs, is_ipc: false },
        );
        Arc::new(ServerShared {
            shares,
            guid: [0; 16],
            domain: "W".into(),
            server_name: "R".into(),
            users: HashMap::new(),
            allow_guest: true,
            require_signing: false,
            encrypt: false,
            locks: Arc::new(LockManager::new()),
            share_modes: Arc::new(ShareModeTable::new()),
            oplocks: Arc::new(OplockTable::new()),
            leases: Arc::new(LeaseTable::new()),
            durables: Arc::new(DurableTable::new()),
            sessions: Arc::new(SessionTable::new()),
        })
    }

    fn create_request(name: &str, oplock: u8, access: u32, share: u32) -> Vec<u8> {
        let name16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_off = 64 + 56; // header + fixed body
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        body[3] = oplock; // RequestedOplockLevel
        body[24..28].copy_from_slice(&access.to_le_bytes()); // DesiredAccess
        body[32..36].copy_from_slice(&share.to_le_bytes()); // ShareAccess
        body[36..40].copy_from_slice(&1u32.to_le_bytes()); // Disposition = OPEN
        body[44..46].copy_from_slice(&(name_off as u16).to_le_bytes()); // NameOffset
        body[46..48].copy_from_slice(&(name16.len() as u16).to_le_bytes()); // NameLength
        let mut f = vec![0u8; 64];
        f.extend_from_slice(&body);
        f.extend_from_slice(&name16);
        f
    }

    /// The sole opener requesting an oplock gets EXCLUSIVE; a second open on the
    /// same file breaks that oplock (a break notification lands on the first
    /// connection's outbound queue) and itself gets no oplock.
    #[test]
    fn oplock_granted_then_broken_on_second_open() {
        tokio_uring::start(async {
        let dir = std::env::temp_dir().join(format!("rustsmb_op_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("shared.bin"), b"data").unwrap();
        let server = server_with_share(&dir);
        let vfs = server.shares["public"].vfs.clone();

        let access = 0x8000_0000 | 0x4000_0000; // GENERIC_READ | GENERIC_WRITE
        let share = 0x7; // READ|WRITE|DELETE

        let (tx_a, mut rx_a) = mpsc::channel(8);
        let mut conn_a = Smb2Conn::new([0u8; 8], tx_a);
        conn_a.session_id = 1;
        let resp_a = create(
            &mut conn_a,
            vfs.clone(),
            &server,
            false,
            &create_request("shared.bin", c::oplock::BATCH, access, share),
        )
        .await
        .unwrap();
        assert_eq!(resp_a[2], c::oplock::EXCLUSIVE, "sole opener granted exclusive");

        let (tx_b, _rx_b) = mpsc::channel(8);
        let mut conn_b = Smb2Conn::new([0u8; 8], tx_b);
        conn_b.session_id = 2;
        let resp_b = create(
            &mut conn_b,
            vfs.clone(),
            &server,
            false,
            &create_request("shared.bin", c::oplock::NONE, access, share),
        )
        .await
        .unwrap();
        assert_eq!(resp_b[2], c::oplock::NONE, "contending open gets no oplock");

        let brk = rx_a.try_recv().expect("break notification delivered to A");
        assert_eq!(
            u16::from_le_bytes([brk[12], brk[13]]),
            ss::cmd::OPLOCK_BREAK,
            "frame is an OPLOCK_BREAK",
        );
        assert_eq!(brk[64 + 2], c::oplock::NONE, "broken down to NONE");

        std::fs::remove_dir_all(&dir).ok();
        });
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    use crate::state::*;
    use std::collections::HashMap;

    fn server_with_share(dir: &std::path::Path) -> Arc<ServerShared> {
        let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(dir));
        let mut shares = HashMap::new();
        shares.insert(
            "public".to_string(),
            Share { name: "public".into(), root: dir.to_path_buf(), vfs, is_ipc: false },
        );
        Arc::new(ServerShared {
            shares,
            guid: [0; 16],
            domain: "W".into(),
            server_name: "R".into(),
            users: HashMap::new(),
            allow_guest: true,
            require_signing: false,
            encrypt: false,
            locks: Arc::new(LockManager::new()),
            share_modes: Arc::new(ShareModeTable::new()),
            oplocks: Arc::new(OplockTable::new()),
            leases: Arc::new(LeaseTable::new()),
            durables: Arc::new(DurableTable::new()),
            sessions: Arc::new(SessionTable::new()),
        })
    }

    /// Build a CREATE request that requests a v1 lease via an `RqLs` context.
    fn create_request_lease(name: &str, key: [u8; 16], state: u32, access: u32, share: u32) -> Vec<u8> {
        let name16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_off = 64 + 56; // header + fixed body
        let name_end = name_off + name16.len();
        let pad = (8 - (name_end % 8)) % 8; // 8-byte align the context
        let ctx_off = name_end + pad;

        let mut ctx = Vec::new();
        ctx.extend_from_slice(&0u32.to_le_bytes()); // Next
        ctx.extend_from_slice(&16u16.to_le_bytes()); // NameOffset
        ctx.extend_from_slice(&4u16.to_le_bytes()); // NameLength
        ctx.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        ctx.extend_from_slice(&24u16.to_le_bytes()); // DataOffset
        ctx.extend_from_slice(&32u32.to_le_bytes()); // DataLength (v1)
        ctx.extend_from_slice(c::lease::CONTEXT_NAME);
        ctx.extend_from_slice(&[0u8; 4]); // pad to 24
        ctx.extend_from_slice(&key);
        ctx.extend_from_slice(&state.to_le_bytes());
        ctx.extend_from_slice(&0u32.to_le_bytes()); // flags
        ctx.extend_from_slice(&0u64.to_le_bytes()); // duration

        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        body[3] = c::oplock::LEASE; // RequestedOplockLevel
        body[24..28].copy_from_slice(&access.to_le_bytes());
        body[32..36].copy_from_slice(&share.to_le_bytes());
        body[36..40].copy_from_slice(&1u32.to_le_bytes()); // Disposition = OPEN
        body[44..46].copy_from_slice(&(name_off as u16).to_le_bytes());
        body[46..48].copy_from_slice(&(name16.len() as u16).to_le_bytes());
        body[48..52].copy_from_slice(&(ctx_off as u32).to_le_bytes());
        body[52..56].copy_from_slice(&(ctx.len() as u32).to_le_bytes());

        let mut f = vec![0u8; 64];
        f.extend_from_slice(&body);
        f.extend_from_slice(&name16);
        f.extend(std::iter::repeat(0u8).take(pad));
        f.extend_from_slice(&ctx);
        f
    }

    /// Read the granted LeaseState out of a CREATE response body's `RqLs`
    /// context: fixed body 88 + ctx header 24 + LeaseKey 16 = offset 128.
    fn granted_state(resp: &[u8]) -> u32 {
        u32::from_le_bytes(resp[128..132].try_into().unwrap())
    }

    /// The sole lease requester gets its full requested state (RWH); a second
    /// open with a *different* lease key breaks the holder's write caching down
    /// to RH (an unsolicited LEASE_BREAK lands on the first connection) and the
    /// contender is granted RH.
    #[test]
    fn lease_granted_then_broken_on_second_key() {
        tokio_uring::start(async {
        let dir = std::env::temp_dir().join(format!("rustsmb_ls_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("leased.bin"), b"data").unwrap();
        let server = server_with_share(&dir);
        let vfs = server.shares["public"].vfs.clone();

        let access = 0x8000_0000 | 0x4000_0000; // GENERIC_READ | GENERIC_WRITE
        let share = 0x7; // READ|WRITE|DELETE
        let k1 = [0x11u8; 16];
        let k2 = [0x22u8; 16];

        let (tx_a, mut rx_a) = mpsc::channel(8);
        let mut conn_a = Smb2Conn::new([0u8; 8], tx_a);
        conn_a.session_id = 1;
        let resp_a = create(
            &mut conn_a,
            vfs.clone(),
            &server,
            false,
            &create_request_lease("leased.bin", k1, c::lease::RWH, access, share),
        )
        .await
        .unwrap();
        assert_eq!(resp_a[2], c::oplock::LEASE, "response is a lease grant");
        assert_eq!(granted_state(&resp_a), c::lease::RWH, "sole opener gets RWH");

        let (tx_b, _rx_b) = mpsc::channel(8);
        let mut conn_b = Smb2Conn::new([0u8; 8], tx_b);
        conn_b.session_id = 2;
        let resp_b = create(
            &mut conn_b,
            vfs.clone(),
            &server,
            false,
            &create_request_lease("leased.bin", k2, c::lease::RWH, access, share),
        )
        .await
        .unwrap();
        assert_eq!(granted_state(&resp_b), c::lease::RH, "contender gets read+handle");

        let brk = rx_a.try_recv().expect("lease break delivered to A");
        assert_eq!(
            u16::from_le_bytes([brk[12], brk[13]]),
            ss::cmd::OPLOCK_BREAK,
            "break rides the OPLOCK_BREAK command",
        );
        assert_eq!(u16::from_le_bytes([brk[64], brk[65]]), 44, "lease-break StructureSize");
        assert_eq!(&brk[72..88], &k1, "names holder A's lease key");
        assert_eq!(u32::from_le_bytes(brk[88..92].try_into().unwrap()), c::lease::RWH, "current");
        assert_eq!(u32::from_le_bytes(brk[92..96].try_into().unwrap()), c::lease::RH, "new");

        std::fs::remove_dir_all(&dir).ok();
        });
    }

    /// Reopening with the *same* lease key shares the existing state and emits
    /// no break notification.
    #[test]
    fn same_lease_key_reopen_does_not_break() {
        tokio_uring::start(async {
        let dir = std::env::temp_dir().join(format!("rustsmb_ls2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.bin"), b"data").unwrap();
        let server = server_with_share(&dir);
        let vfs = server.shares["public"].vfs.clone();
        let access = 0x8000_0000 | 0x4000_0000;
        let share = 0x7;
        let key = [0x55u8; 16];

        let (tx_a, mut rx_a) = mpsc::channel(8);
        let mut conn_a = Smb2Conn::new([0u8; 8], tx_a);
        conn_a.session_id = 1;
        let _ = create(&mut conn_a, vfs.clone(), &server, false,
            &create_request_lease("f.bin", key, c::lease::RWH, access, share)).await.unwrap();

        let (tx_b, _rx_b) = mpsc::channel(8);
        let mut conn_b = Smb2Conn::new([0u8; 8], tx_b);
        conn_b.session_id = 2;
        let resp_b = create(&mut conn_b, vfs.clone(), &server, false,
            &create_request_lease("f.bin", key, c::lease::RWH, access, share)).await.unwrap();

        assert_eq!(granted_state(&resp_b), c::lease::RWH, "same key keeps RWH");
        assert!(rx_a.try_recv().is_err(), "no break for same lease key");

        std::fs::remove_dir_all(&dir).ok();
        });
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;
    use win_sd::{AccessMask, SecurityDescriptor, SecurityDescriptorBuilder, Sid};

    fn query_info_frame(info_type: u8, class: u8, output_len: u32, additional: u32, fid: [u8; 16]) -> Vec<u8> {
        let mut b = vec![0u8; 40];
        b[0..2].copy_from_slice(&41u16.to_le_bytes()); // StructureSize
        b[2] = info_type;
        b[3] = class;
        b[4..8].copy_from_slice(&output_len.to_le_bytes());
        b[16..20].copy_from_slice(&additional.to_le_bytes()); // AdditionalInformation
        b[24..40].copy_from_slice(&fid); // FileId
        let mut f = vec![0u8; 64];
        f.extend_from_slice(&b);
        f
    }

    fn set_info_frame(info_type: u8, class: u8, additional: u32, fid: [u8; 16], buffer: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        b[0..2].copy_from_slice(&33u16.to_le_bytes()); // StructureSize
        b[2] = info_type;
        b[3] = class;
        b[4..8].copy_from_slice(&(buffer.len() as u32).to_le_bytes()); // BufferLength
        b[8..10].copy_from_slice(&((64 + 32) as u16).to_le_bytes()); // BufferOffset (absolute)
        b[12..16].copy_from_slice(&additional.to_le_bytes()); // AdditionalInformation
        b[16..32].copy_from_slice(&fid); // FileId
        let mut f = vec![0u8; 64];
        f.extend_from_slice(&b);
        f.extend_from_slice(buffer);
        f
    }

    /// A fresh file yields a synthesised default descriptor; setting a custom
    /// descriptor and querying it back round-trips through the backend store.
    #[test]
    fn security_query_set_round_trip() {
        tokio_uring::start(async {
            let dir = std::env::temp_dir().join(format!("rustsmb_sec_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("sec.bin"), b"data").unwrap();
            let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(&dir));
            let (tx, _rx) = mpsc::channel(8);
            let mut conn = Smb2Conn::new([0u8; 8], tx);
            let (open, _m, _a) = vfs
                .create("sec.bin", false, 0x8000_0000 | 0x4000_0000, 1, 0, 0)
                .await
                .unwrap();
            let fid = [1u8; 16];
            conn.handles.insert(fid, open);

            // Default query: parseable, DACL present.
            let q = query_info_frame(c::info_type::SECURITY, 0, 4096, crate::security::sec_info::DEFAULT, fid);
            let out = query_info(&mut conn, vfs.clone(), &q).await.unwrap().unwrap();
            let sd = SecurityDescriptor::from_bytes(&out).expect("default parse");
            assert!(sd.dacl().is_some(), "default DACL present");

            // Set a custom descriptor, then read the owner back.
            let custom = SecurityDescriptorBuilder::new()
                .owner(Sid::local_system())
                .allow(Sid::everyone(), AccessMask::FILE_GENERIC_READ)
                .build()
                .to_bytes()
                .unwrap();
            let s = set_info_frame(
                c::info_type::SECURITY,
                0,
                crate::security::sec_info::OWNER | crate::security::sec_info::DACL,
                fid,
                &custom,
            );
            set_info(&mut conn, vfs.clone(), &s).await.expect("set security");

            let q2 = query_info_frame(c::info_type::SECURITY, 0, 4096, crate::security::sec_info::OWNER, fid);
            let out2 = query_info(&mut conn, vfs.clone(), &q2).await.unwrap().unwrap();
            let sd2 = SecurityDescriptor::from_bytes(&out2).expect("stored parse");
            assert_eq!(sd2.owner(), Some(&Sid::local_system()), "stored owner round-trips");

            std::fs::remove_dir_all(&dir).ok();
        });
    }

    /// A too-small output buffer is rejected with STATUS_BUFFER_TOO_SMALL.
    #[test]
    fn security_query_rejects_small_buffer() {
        tokio_uring::start(async {
            let dir = std::env::temp_dir().join(format!("rustsmb_sec2_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("s.bin"), b"x").unwrap();
            let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(&dir));
            let (tx, _rx) = mpsc::channel(8);
            let mut conn = Smb2Conn::new([0u8; 8], tx);
            let (open, _m, _a) = vfs.create("s.bin", false, 0x8000_0000, 1, 0, 0).await.unwrap();
            let fid = [2u8; 16];
            conn.handles.insert(fid, open);

            let q = query_info_frame(c::info_type::SECURITY, 0, 8, crate::security::sec_info::DEFAULT, fid);
            let err = query_info(&mut conn, vfs.clone(), &q).await.unwrap_err();
            assert_eq!(err, Status::BUFFER_TOO_SMALL);

            std::fs::remove_dir_all(&dir).ok();
        });
    }
}


#[cfg(test)]
mod durable_tests {
    use super::*;
    use crate::state::*;
    use std::collections::HashMap;

    fn server_with_share(dir: &std::path::Path) -> Arc<ServerShared> {
        let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(dir));
        let mut shares = HashMap::new();
        shares.insert(
            "public".to_string(),
            Share { name: "public".into(), root: dir.to_path_buf(), vfs, is_ipc: false },
        );
        Arc::new(ServerShared {
            shares,
            guid: [0; 16],
            domain: "W".into(),
            server_name: "R".into(),
            users: HashMap::new(),
            allow_guest: true,
            require_signing: false,
            encrypt: false,
            locks: Arc::new(LockManager::new()),
            share_modes: Arc::new(ShareModeTable::new()),
            oplocks: Arc::new(OplockTable::new()),
            leases: Arc::new(LeaseTable::new()),
            durables: Arc::new(DurableTable::new()),
            sessions: Arc::new(SessionTable::new()),
        })
    }

    /// Build a CREATE frame carrying a single create-context (name, data).
    fn create_req_ctx(name: &str, access: u32, disp: u32, ctx_name: &[u8], ctx_data: &[u8]) -> Vec<u8> {
        let name16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_off = 64 + 56;
        let name_end = name_off + name16.len();
        let pad = (8 - name_end % 8) % 8;
        let ctx_off = name_end + pad;

        let data_off = (16 + ctx_name.len()).next_multiple_of(8);
        let mut ctx = Vec::new();
        ctx.extend_from_slice(&0u32.to_le_bytes());
        ctx.extend_from_slice(&16u16.to_le_bytes());
        ctx.extend_from_slice(&(ctx_name.len() as u16).to_le_bytes());
        ctx.extend_from_slice(&0u16.to_le_bytes());
        ctx.extend_from_slice(&(data_off as u16).to_le_bytes());
        ctx.extend_from_slice(&(ctx_data.len() as u32).to_le_bytes());
        ctx.extend_from_slice(ctx_name);
        while ctx.len() < data_off {
            ctx.push(0);
        }
        ctx.extend_from_slice(ctx_data);

        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        body[24..28].copy_from_slice(&access.to_le_bytes());
        body[32..36].copy_from_slice(&0x7u32.to_le_bytes());
        body[36..40].copy_from_slice(&disp.to_le_bytes());
        body[44..46].copy_from_slice(&(name_off as u16).to_le_bytes());
        body[46..48].copy_from_slice(&(name16.len() as u16).to_le_bytes());
        body[48..52].copy_from_slice(&(ctx_off as u32).to_le_bytes());
        body[52..56].copy_from_slice(&(ctx.len() as u32).to_le_bytes());
        let mut f = vec![0u8; 64];
        f.extend_from_slice(&body);
        f.extend_from_slice(&name16);
        f.extend(std::iter::repeat(0u8).take(pad));
        f.extend_from_slice(&ctx);
        f
    }

    /// A DH2Q durable request is granted (recorded + echoed); after the
    /// connection drops the handle is preserved and a DH2C reconnect on a fresh
    /// connection reclaims it under the same persistent id.
    #[test]
    fn durable_grant_then_reconnect() {
        tokio_uring::start(async {
            let dir = std::env::temp_dir().join(format!("rustsmb_dur_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("dur.bin"), b"durable-data").unwrap();
            let server = server_with_share(&dir);
            let vfs = server.shares["public"].vfs.clone();
            let guid = [0x5Au8; 16];
            let access = 0x8000_0000 | 0x4000_0000;

            let mut dq = Vec::new();
            dq.extend_from_slice(&10_000u32.to_le_bytes()); // Timeout
            dq.extend_from_slice(&0u32.to_le_bytes()); // Flags
            dq.extend_from_slice(&[0u8; 8]); // Reserved
            dq.extend_from_slice(&guid); // CreateGuid
            let frame = create_req_ctx("dur.bin", access, 1, c::durable::REQ_V2, &dq);

            let (tx, _rx) = mpsc::channel(8);
            let mut conn = Smb2Conn::new([0u8; 8], tx);
            conn.session_id = 1;
            let resp = create(&mut conn, vfs.clone(), &server, false, &frame).await.unwrap();
            assert_ne!(u32::from_le_bytes(resp[80..84].try_into().unwrap()), 0, "durable resp ctx");
            assert_eq!(conn.durable.len(), 1, "durable handle recorded");
            let pid: [u8; 16] = resp[64..80].try_into().unwrap();

            // Simulate the connection dropping: preserve into the server table.
            for (_f, mut e) in conn.durable.drain() {
                e.deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                server.durables.insert(e);
            }

            // Fresh connection reclaims the handle via DH2C reconnect.
            let mut dc = Vec::new();
            dc.extend_from_slice(&pid);
            dc.extend_from_slice(&guid);
            dc.extend_from_slice(&0u32.to_le_bytes()); // Flags
            let rframe = create_req_ctx("dur.bin", 0x8000_0000, 1, c::durable::RECONNECT_V2, &dc);
            let (tx2, _rx2) = mpsc::channel(8);
            let mut conn2 = Smb2Conn::new([0u8; 8], tx2);
            conn2.session_id = 2;
            let resp2 = create(&mut conn2, vfs.clone(), &server, false, &rframe).await.expect("reconnect");
            let rid: [u8; 16] = resp2[64..80].try_into().unwrap();
            assert_eq!(rid, pid, "reconnect returns the persistent id");
            assert!(conn2.handles.contains_key(&pid), "handle reinstated on new connection");

            std::fs::remove_dir_all(&dir).ok();
        });
    }

    /// A reconnect with an unknown persistent id is rejected.
    #[test]
    fn durable_reconnect_unknown_id_fails() {
        tokio_uring::start(async {
            let dir = std::env::temp_dir().join(format!("rustsmb_dur2_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("x.bin"), b"data").unwrap();
            let server = server_with_share(&dir);
            let vfs = server.shares["public"].vfs.clone();
            let mut dc = Vec::new();
            dc.extend_from_slice(&[0xEE; 16]);
            dc.extend_from_slice(&[0xEE; 16]);
            dc.extend_from_slice(&0u32.to_le_bytes());
            let rframe = create_req_ctx("x.bin", 0x8000_0000, 1, c::durable::RECONNECT_V2, &dc);
            let (tx, _rx) = mpsc::channel(8);
            let mut conn = Smb2Conn::new([0u8; 8], tx);
            let err = create(&mut conn, vfs.clone(), &server, false, &rframe).await.unwrap_err();
            assert_eq!(err, Status::OBJECT_NAME_NOT_FOUND);
            std::fs::remove_dir_all(&dir).ok();
        });
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn interface_list_chains_and_encodes_sockaddr() {
        let entries = [
            (1u32, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
            (2u32, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ];
        let buf = build_interface_list(&entries);
        assert_eq!(buf.len(), 152 * 2, "two fixed-size entries");
        // First entry: Next links to the second (152), IfIndex 1, AF_INET.
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 152);
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(buf[24..26].try_into().unwrap()), 2, "AF_INET");
        assert_eq!(&buf[28..32], &[10, 0, 0, 5], "sin_addr");
        // Second entry terminates the chain and carries AF_INET6.
        assert_eq!(u32::from_le_bytes(buf[152..156].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(buf[152 + 24..152 + 26].try_into().unwrap()), 23, "AF_INET6");
    }
}

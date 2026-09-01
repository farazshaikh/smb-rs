//! SMB2 protocol loop ([MS-SMB2]).
//!
//! Implements the full file-serving command surface on top of the shared
//! [`Vfs`](smb_vfs::Vfs) abstraction: NEGOTIATE, SESSION_SETUP (both NTLMSSP
//! legs), TREE_CONNECT/DISCONNECT, LOGOFF, CREATE, READ, WRITE, CLOSE, FLUSH,
//! LOCK, QUERY_DIRECTORY, QUERY_INFO and SET_INFO. Frames whose magic is
//! `\xFESMB` route here from [`crate::dispatch`].

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use metrics::{counter, gauge};
use tokio::sync::{mpsc, oneshot};

use smb_proto::types::Status;
use smb_proto_smb2::commands as c;
use smb_proto_smb2::consts::{aead, hdr, hdr_flags};
use smb_proto_smb2::info;
use smb_proto_smb2::session_setup as ss;
use smb_transport::Transport;

use crate::state::{ServerShared, Share};

/// MaxTransactSize advertised in our NEGOTIATE response (1 MiB); CHANGE_NOTIFY
/// rejects an OutputBufferLength larger than this ([MS-SMB2] §3.3.5.19).
const MAX_TRANSACT_SIZE: u32 = 1024 * 1024;

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
    /// session enables encryption ([MS-SMB2] §3.1.4.1 labels). AES-128 uses the
    /// first 16 bytes; AES-256 uses all 32.
    pub enc_keys: Option<([u8; 32], [u8; 32])>,
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
    /// Lease key each open handle joined, so a write/open from a co-holder of
    /// the same lease does not break it ([MS-SMB2] §3.3.4.7).
    pub lease_keys: HashMap<[u8; 16], [u8; 16]>,
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
    /// completes the background task with the given status (CANCELLED for a
    /// CANCEL, NOTIFY_CLEANUP when the watched handle is closed).
    pub async_cancels: HashMap<u64, oneshot::Sender<Status>>,
    /// Maps a pending operation's MessageId to its async id, so a CANCEL that
    /// correlates by MessageId (rather than AsyncId) can find it ([MS-SMB2]
    /// §3.2.4.24).
    pub async_msgids: HashMap<u64, u64>,
    /// Pending CHANGE_NOTIFY async ids per watched FileId, so closing the
    /// handle can complete them with STATUS_NOTIFY_CLEANUP ([MS-SMB2]
    /// §3.3.5.10).
    pub async_by_file: HashMap<[u8; 16], Vec<u64>>,
    /// Server-side-copy resume keys → source FileId ([MS-SMB2] §2.2.32.3);
    /// handed out by FSCTL_SRV_REQUEST_RESUME_KEY and consumed by COPYCHUNK.
    pub resume_keys: HashMap<[u8; 24], [u8; 16]>,
    /// Durable handles granted on this connection, keyed by FileId, preserved
    /// into the server table when the connection drops ([MS-SMB2] §3.3.1.10).
    pub durable: HashMap<[u8; 16], crate::state::DurableEntry>,
    /// Negotiated outbound compression algorithm ([MS-SMB2] §2.2.42), if the
    /// client and server share one; `None` disables compressed responses.
    pub compress_algo: Option<u16>,
    /// Set when the current request is a READ carrying
    /// SMB2_READFLAG_REQUEST_COMPRESSED ([MS-SMB2] §2.2.19): the response MUST
    /// be compressed if that shrinks it, regardless of size heuristics.
    pub compress_response: bool,
    /// Client's NEGOTIATE parameters, retained to validate a later
    /// FSCTL_VALIDATE_NEGOTIATE_INFO request ([MS-SMB2] §3.3.5.15.12).
    pub client_guid: [u8; 16],
    /// Client SecurityMode from NEGOTIATE (signing enabled/required bits).
    pub client_security_mode: u16,
    /// Client Capabilities flags from NEGOTIATE.
    pub client_capabilities: u32,
    /// Dialects the client offered in NEGOTIATE.
    pub client_dialects: Vec<u16>,
    /// Set to terminate the transport connection after the current frame
    /// (e.g. a failed VALIDATE_NEGOTIATE_INFO downgrade check).
    pub disconnect: bool,
    /// FileId generated by the most recent CREATE in the current compound
    /// chain, used to resolve the wildcard FileId (0xFF..FF) that a related
    /// follow-up request carries ([MS-SMB2] §3.3.5.2.7.2). Reset per frame.
    pub chain_fid: Option<[u8; 16]>,
    /// Symbolic Link Error Response body built by the last CREATE that stopped
    /// on a symlink ([MS-SMB2] §2.2.2.2.1), consumed when framing the error.
    pub symlink_error: Option<Vec<u8>>,
    /// TreeId a successful TREE_CONNECT installs into its response header
    /// ([MS-SMB2] §3.3.5.7), set by the handler and consumed once when the
    /// reply is framed.
    pub resp_tree_id: Option<u32>,
    /// Force-seal the response to the current frame regardless of session
    /// encryption — set when TREE_CONNECT resolves to an encrypted share so the
    /// tree-connect reply itself is sealed ([MS-SMB2] §3.3.5.7). Reset per frame.
    pub seal_current: bool,
    /// True when the current request arrived inside a transform (encrypted).
    /// Its AEAD tag is the integrity check, so the inner SMB2 signature is not
    /// verified ([MS-SMB2] §3.3.5.2.4). Reset per frame.
    pub req_encrypted: bool,
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
            lease_keys: HashMap::new(),
            pipes: HashMap::new(),
            searches: HashMap::new(),
            outbound,
            next_async_id: 1,
            async_cancels: HashMap::new(),
            async_msgids: HashMap::new(),
            async_by_file: HashMap::new(),
            resume_keys: HashMap::new(),
            durable: HashMap::new(),
            compress_algo: None,
            compress_response: false,
            client_guid: [0u8; 16],
            client_security_mode: 0,
            client_capabilities: 0,
            client_dialects: Vec::new(),
            disconnect: false,
            chain_fid: None,
            symlink_error: None,
            resp_tree_id: None,
            seal_current: false,
            req_encrypted: false,
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
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
fn next_file_id() -> [u8; 16] {
    static F: AtomicU64 = AtomicU64::new(0x2000);
    let mut fid = [0u8; 16];
    fid[..8].copy_from_slice(&F.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    fid
}

/// Allocate a fresh TreeId.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) fn next_tree_id() -> u32 {
    static T: AtomicU64 = AtomicU64::new(1);
    (T.fetch_add(1, Ordering::Relaxed) & 0x7fff_ffff) as u32
}

/// Serve an SMB2 client connection until EOF/error (used when a connection
/// starts life directly in SMB2 rather than upgrading through SMB1).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
            if conn.disconnect {
                break;
            }
        }
    }
    drop(out_tx);
    let _ = writer_task.await;
}

/// Respond to an SMB1 multi-protocol NEGOTIATE that carries the `\xFESMB`
/// dialect marker: builds the SMB2 negotiate response so the client upgrades.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub fn handle_multiprotocol_negotiate(buf: &[u8], guid: &[u8; 16]) -> Option<Vec<u8>> {
    let (hdr, _wc_off) = smb_proto_smb1::header::parse_header(buf)?;
    let _ = hdr;
    // The multi-protocol NEGOTIATE response is MessageId 0 ([MS-SMB2]
    // §3.2.5.2). Offer the wildcard revision when the client listed
    // "SMB 2.???" so it re-negotiates a concrete dialect (up to 3.1.1);
    // otherwise answer the "SMB 2.002"-only case directly.
    let dialect = if buf.windows(5).any(|w| w == b"2.???") {
        smb_proto_smb2::negotiate::DIALECT_WILDCARD
    } else {
        smb_proto_smb2::negotiate::DIALECT_202
    };
    let h2 = smb_proto_smb2::Header2 {
        credit_charge: 0,
        status: 0,
        command: 0,
        credits: 1,
        flags: 1,
        next_command: 0,
        message_id: 0,
        tree_id: 0,
        session_id: 0,
        signature: [0u8; 16],
    };
    Some(response(
        &h2,
        Status::SUCCESS,
        smb_proto_smb2::negotiate::build_response(
            dialect,
            guid,
            smb_proto::types::FileTime::now().0,
        ),
        0,
    ))
}

/// Execute one frame (possibly compound) and build its response (`None` to
/// stay silent). Chained requests ([MS-SMB2] §3.3.5.2) are dispatched in
/// order and their replies concatenated with 8-byte alignment.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
        // A decrypted payload may itself be a compression transform
        // ([MS-SMB2] §3.1.4.4: the client compresses, then encrypts); expand it.
        plaintext = if pt.len() >= 4 && pt[..4] == smb_proto_smb2::compress::PROTOCOL_ID {
            smb_proto_smb2::compress::decompress_message(&pt)?
        } else {
            pt
        };
        buf = &plaintext;
        request_encrypted = true;
        conn.peer_encrypts = true;
    }
    conn.seal_current = false;
    conn.req_encrypted = request_encrypted;

    let mut parts: Vec<(Vec<u8>, bool)> = Vec::new(); // (resp, may_wrap)
    let mut related_flags: Vec<bool> = Vec::new(); // request carried FLAGS_RELATED_OPERATIONS
    // Work on an owned copy so a related follow-up request's wildcard FileId
    // can be patched in place with the chain's last-created handle.
    let mut work: Vec<u8> = buf.to_vec();
    conn.chain_fid = None;
    let mut off = 0usize;
    loop {
        if off + hdr::LEN > work.len() {
            break;
        }
        // A related request ([MS-SMB2] §3.3.5.2.7.2) that carries the wildcard
        // FileId {0xFF..} refers to the FileId produced by the previous CREATE
        // in this chain — substitute it before the handler parses the body.
        let flags = g32(&work, off + hdr::FLAGS);
        if flags & hdr_flags::RELATED_OPERATIONS != 0 {
            if let Some(fid) = conn.chain_fid {
                let cmd = g16(&work, off + hdr::COMMAND);
                if let Some(foff) = file_id_body_offset(cmd) {
                    let abs = off + hdr::LEN + foff;
                    if abs + c::FileId::LEN <= work.len()
                        && work[abs..abs + c::FileId::LEN] == c::FileId::WILDCARD
                    {
                        work[abs..abs + c::FileId::LEN].copy_from_slice(&fid);
                    }
                }
            }
        }
        let rest = &work[off..];
        let Some((single, may_wrap)) = process_single(server, conn, rest).await else {
            return None;
        };
        // Refund the Credits this response grants back to the client's
        // balance ([MS-SMB2] §3.3.1.1) — the field was stamped by
        // response() as max(CreditCharge, 1).
        let granted = g16(&single, hdr::CREDIT) as u32;
        conn.client_credits = conn.client_credits.saturating_add(granted);
        #[cfg(not(feature = "lib"))]
        let may_wrap = false; // sealing unsupported on this backend
        parts.push((single, may_wrap));
        related_flags.push(flags & hdr_flags::RELATED_OPERATIONS != 0);

        let next = g32(&work, off + hdr::NEXT_COMMAND) as usize;
        if next == 0 || next >= work.len() - off {
            break;
        }
        off += next;
    }
    if parts.is_empty() {
        return None;
    }

    // Assemble compound reply: every frame except the last carries
    // NextCommand pointing at the following frame, 8-byte aligned.
    let mut out: Vec<u8> =
        Vec::with_capacity(parts.iter().map(|p| p.0.len() + (hdr::ALIGN - 1)).sum());
    let mut starts = Vec::with_capacity(parts.len());
    for (p, _) in &parts {
        while out.len() % hdr::ALIGN != 0 {
            out.push(0);
        }
        starts.push(out.len());
        out.extend_from_slice(p);
    }
    for w in 0..starts.len().saturating_sub(1) {
        let next = (starts[w + 1] - starts[w]) as u32;
        let bytes = next.to_le_bytes();
        let pos = starts[w] + hdr::NEXT_COMMAND;
        out[pos..pos + bytes.len()].copy_from_slice(&bytes);
    }
    // Echo SMB2_FLAGS_RELATED_OPERATIONS on every chained response whose
    // request carried it, for all responses after the first ([MS-SMB2]
    // §3.3.4.1: the flag marks a response as part of a compounded chain).
    for w in 1..starts.len() {
        if related_flags[w] {
            out[starts[w] + hdr::FLAGS] |= hdr_flags::RELATED_OPERATIONS as u8;
        }
    }

    // Seal the whole reply when the session requires encryption, or when the
    // request itself arrived encrypted ([MS-SMB2] §3.3.5.16 — a sealed request
    // is answered with a sealed response even if the server does not force it).
    // The enabling SESSION_SETUP response itself always travels in the clear.
    let first_tid = if work.len() >= hdr::LEN { g32(&work, hdr::TREE_ID) } else { 0 };
    let tree_requires_seal = conn.seal_current
        || conn
            .trees
            .get(&first_tid)
            .and_then(|n| server.shares.get(n))
            .is_some_and(|s| s.encrypt);
    if (conn.encrypt_data || request_encrypted || tree_requires_seal)
        && parts.iter().all(|(_, w)| *w)
    {
        // Compress before sealing when the peer negotiated compression and the
        // READ asked for it ([MS-SMB2] §3.1.4.4: compress, then encrypt).
        let mut payload = out;
        if let Some(algo) = conn.compress_algo {
            if conn.compress_response {
                if let Some(packed) = smb_proto_smb2::compress::compress_message(&payload, algo) {
                    payload = packed;
                }
            }
        }
        let sealed = encrypt_response(conn, &payload)?;
        return Some(sealed);
    }
    Some(out)
}

/// Body-relative offset of the 16-byte FileId within a request that carries
/// one, used to resolve the wildcard FileId in a related compound follow-up
/// ([MS-SMB2] §3.3.5.2.7.2). `None` for commands with no FileId field.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
fn file_id_body_offset(command: u16) -> Option<usize> {
    use smb_proto_smb2::session_setup::cmd as c;
    match command {
        c::CLOSE | c::FLUSH | c::LOCK | c::IOCTL | c::QUERY_DIRECTORY | c::CHANGE_NOTIFY => Some(8),
        c::READ | c::WRITE | c::SET_INFO => Some(16),
        c::QUERY_INFO => Some(24),
        _ => None,
    }
}

/// True for the GCM cipher variants ([MS-SMB2] §2.2.3.1.2).
fn cipher_is_gcm(cipher: u16) -> bool {
    use smb_proto_smb2::negotiate::ctx_type::{AES128_GCM, AES256_GCM};
    matches!(cipher, AES128_GCM | AES256_GCM)
}

/// True for the AES-256 cipher variants (32-byte keys).
fn cipher_is_256(cipher: u16) -> bool {
    use smb_proto_smb2::negotiate::ctx_type::{AES256_CCM, AES256_GCM};
    matches!(cipher, AES256_GCM | AES256_CCM)
}

/// Key length in bytes for a negotiated cipher.
fn cipher_key_len(cipher: u16) -> usize {
    if cipher_is_256(cipher) {
        32
    } else {
        16
    }
}

/// Wrap an assembled response into a transform frame ([MS-SMB2] §2.2.41)
/// using the S2C cipher key.
#[cfg(not(feature = "lib"))]
fn encrypt_response(conn: &Smb2Conn, msg: &[u8]) -> Option<Vec<u8>> {
    let _ = (conn, msg);
    None
}
#[cfg(not(feature = "lib"))]
fn seal_pdu(
    session_id: u64,
    enc_keys: ([u8; 32], [u8; 32]),
    cipher: u16,
    msg: &[u8],
) -> Option<Vec<u8>> {
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
fn seal_pdu(
    session_id: u64,
    enc_keys: ([u8; 32], [u8; 32]),
    cipher: u16,
    msg: &[u8],
) -> Option<Vec<u8>> {
    let (_c2s, s2c) = enc_keys;
    let gcm = cipher_is_gcm(cipher);
    let iv_size = if gcm {
        aead::GCM_NONCE_LEN
    } else {
        aead::CCM_NONCE_LEN
    };

    let mut nonce_field = [0u8; 16];
    nonce_field[..iv_size].copy_from_slice(&crate::dispatch::rand_bytes(iv_size));

    let mut tf = smb_proto_smb2::commands::build_transform(session_id, &nonce_field, msg.len());
    // AAD region: everything after the Nonce field ([MS-SMB2] §3.1.4.2).
    let aad = &tf[smb_proto_smb2::commands::tf_off::NONCE..];
    let sealed = match (gcm, cipher_is_256(cipher)) {
        (true, true) => smb_auth::crypto::aes256gcm_seal(
            &s2c,
            nonce_field[..aead::GCM_NONCE_LEN].try_into().ok()?,
            aad,
            msg,
        ),
        (true, false) => smb_auth::crypto::aes128gcm_seal(
            s2c[..16].try_into().ok()?,
            nonce_field[..aead::GCM_NONCE_LEN].try_into().ok()?,
            aad,
            msg,
        ),
        (false, true) => smb_auth::crypto::aes256ccm_seal(
            &s2c,
            nonce_field[..aead::CCM_NONCE_LEN].try_into().ok()?,
            aad,
            msg,
        ),
        (false, false) => smb_auth::crypto::aes128ccm_seal(
            s2c[..16].try_into().ok()?,
            nonce_field[..aead::CCM_NONCE_LEN].try_into().ok()?,
            aad,
            msg,
        ),
    };
    // Tag lands in the Signature field; ciphertext follows the header.
    let tag_at = smb_proto_smb2::commands::tf_off::SIGNATURE;
    tf[tag_at..tag_at + aead::TAG_LEN].copy_from_slice(&sealed[sealed.len() - aead::TAG_LEN..]);
    let mut frame = tf;
    frame.extend_from_slice(&sealed[..sealed.len() - aead::TAG_LEN]);
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
        tracing::warn!(
            sid = format!("{:#x}", tf.session_id),
            "transform sid mismatch"
        );
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
    let gcm = cipher_is_gcm(cipher);
    let is256 = cipher_is_256(cipher);
    let aad = frame
        .get(smb_proto_smb2::commands::tf_off::NONCE..smb_proto_smb2::commands::tf_off::HDR_SIZE)?;
    let payload =
        frame.get(smb_proto_smb2::commands::tf_off::HDR_SIZE..tf_off_end(tf.original_len))?;
    // The GCM/CCM tag travels in the TF Signature field ([MS-SMB2]
    // §2.2.41), detached from the ciphertext; re-attach it for the AEAD
    // open, which expects ct||tag.
    let tag_at = smb_proto_smb2::commands::tf_off::SIGNATURE;
    let mut sealed = payload.to_vec();
    sealed.extend_from_slice(frame.get(tag_at..tag_at + aead::TAG_LEN)?);
    let nonce = &frame[smb_proto_smb2::commands::tf_off::NONCE..];
    let opened = match (gcm, is256) {
        (true, true) => smb_auth::crypto::aes256gcm_open(
            &c2s,
            nonce.get(..aead::GCM_NONCE_LEN)?.try_into().ok()?,
            aad,
            &sealed,
        ),
        (true, false) => smb_auth::crypto::aes128gcm_open(
            c2s[..16].try_into().ok()?,
            nonce.get(..aead::GCM_NONCE_LEN)?.try_into().ok()?,
            aad,
            &sealed,
        ),
        (false, true) => smb_auth::crypto::aes256ccm_open(
            &c2s,
            nonce.get(..aead::CCM_NONCE_LEN)?.try_into().ok()?,
            aad,
            &sealed,
        ),
        (false, false) => smb_auth::crypto::aes128ccm_open(
            c2s[..16].try_into().ok()?,
            nonce.get(..aead::CCM_NONCE_LEN)?.try_into().ok()?,
            aad,
            &sealed,
        ),
    };
    let pt = match opened {
        Some(p) => p,
        None => {
            tracing::warn!(cipher = cipher, aad_len = aad.len(), "aead open failed");
            return None;
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

/// Route a request through the typestate pipeline (io::dispatch) and return the
/// `(status, body)` the legacy framing still wraps. Used by commands migrated
/// onto `io::Command` (typestate_plan.md Phases 2–3).
/// How a typestate dispatch resolves for `process_single`: a body that still
/// flows the common signing/sealing tail, a pre-framed async PDU to send
/// verbatim (the STATUS_PENDING interim), or nothing at all.
enum Routed {
    Framed(Status, Vec<u8>),
    Raw(Vec<u8>),
    Silent,
}

async fn via_typestate(
    hdr: &smb_proto_smb2::Header2,
    conn: &mut Smb2Conn,
    server: &Arc<ServerShared>,
    buf: &[u8],
) -> Routed {
    let reply = crate::io::ReplyHeader {
        command: hdr.command,
        message_id: hdr.message_id,
        session_id: conn.session_id,
        tree_id: hdr.tree_id,
        credits: 0,
        seal: crate::io::SealIntent::default(),
    };
    let req = match crate::io::SmbRequest::parse(hdr.command, buf) {
        Ok(req) => req,
        Err(status) => return Routed::Framed(status, Vec::new()),
    };
    let ctx = crate::io::IoContext::accept(reply, req);
    let outcome = {
        let mut res = crate::io::Resources {
            conn,
            server,
            frame: buf,
        };
        crate::io::dispatch(ctx, &mut res).await
    };
    match outcome {
        crate::io::Outcome::Final(r) => Routed::Framed(r.status, r.body),
        // Silent: the handler asked for no reply (e.g. a CANCEL, or a
        // connection termination), so nothing is sent.
        crate::io::Outcome::Silent => Routed::Silent,
        // Interim: frame the STATUS_PENDING async reply now ([MS-SMB2]
        // §3.3.4.2); the parked async worker sends the final reply later on
        // the outbound queue.
        crate::io::Outcome::Interim { parked, interim } => {
            let mut frame = build_async_frame(
                interim.reply.session_id,
                interim.reply.message_id,
                parked.async_id(),
                interim.reply.command,
                interim.status,
                &interim.body,
            );
            if hdr.is_signed() {
                if let Some(key) = conn.signing_key.clone().or(conn.session_key) {
                    sign_pdu(&mut frame, &key, conn.dialect);
                }
            }
            Routed::Raw(frame)
        }
    }
}

/// Process exactly one SMB2 request starting at `buf` (its own header).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
    // SMB2_READFLAG_REQUEST_COMPRESSED (0x02) in a READ Flags byte (body off 3)
    // asks the server to compress the read response ([MS-SMB2] §2.2.19/§3.3.5.12).
    conn.compress_response = hdr.command == ss::cmd::READ
        && buf.get(hdr::LEN + 3).map(|f| f & 0x02 != 0).unwrap_or(false);
    // Request half of the 3.1.1 pre-auth integrity hash ([MS-SMB2] §3.3.4.1.1):
    // every NEGOTIATE / SESSION_SETUP message updates it before processing.
    let is_preauth_msg = matches!(hdr.command, ss::cmd::NEGOTIATE | ss::cmd::SESSION_SETUP);
    if is_preauth_msg {
        let mut joined = Vec::with_capacity(hdr::LEN + buf.len());
        joined.extend_from_slice(&conn.preauth_hash);
        joined.extend_from_slice(buf);
        conn.preauth_hash = smb_auth::crypto::sha512(&joined);
    }
    let sid = hdr.session_id;

    // Commands valid without an authenticated session.
    let pre_session = matches!(
        hdr.command,
        ss::cmd::NEGOTIATE | ss::cmd::SESSION_SETUP | ss::cmd::ECHO
    );
    if !pre_session && (!conn.authenticated || sid != conn.session_id) {
        return Some((response(&hdr, Status::ACCESS_DENIED, Vec::new(), 0), false));
    }

    // A tree-scoped command must carry a TreeId that names a live tree connect
    // ([MS-SMB2] §3.3.5.2.11); a stale/unknown one is STATUS_NETWORK_NAME_DELETED.
    // Related compound follow-ups inherit the chain's tree, so exempt them.
    let needs_tree = matches!(
        hdr.command,
        ss::cmd::CREATE
            | ss::cmd::CLOSE
            | ss::cmd::FLUSH
            | ss::cmd::READ
            | ss::cmd::WRITE
            | ss::cmd::LOCK
            | ss::cmd::IOCTL
            | ss::cmd::QUERY_DIRECTORY
            | ss::cmd::CHANGE_NOTIFY
            | ss::cmd::QUERY_INFO
            | ss::cmd::SET_INFO
    );
    if needs_tree
        && hdr.flags & hdr_flags::RELATED_OPERATIONS == 0
        && !conn.trees.contains_key(&hdr.tree_id)
    {
        return Some((
            response(&hdr, Status::NETWORK_NAME_DELETED, Vec::new(), conn.session_id),
            true,
        ));
    }

    // A handle force-closed by an application-instance failover ([MS-SMB2]
    // §3.3.5.9.13): the owner's next operation on it fails STATUS_FILE_CLOSED.
    if let Some(foff) = file_id_body_offset(hdr.command) {
        let abs = hdr::LEN + foff;
        if let Some(fid) = buf
            .get(abs..abs + 16)
            .and_then(|s| <[u8; 16]>::try_from(s).ok())
        {
            if server.app_instances.take_forced((conn.session_id, fid)) {
                conn.handles.remove(&fid);
                return Some((
                    response(&hdr, Status::FILE_CLOSED, Vec::new(), conn.session_id),
                    true,
                ));
            }
        }
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

    // Signing policy ([MS-SMB2] §3.3.5.2.3). Two independent rules:
    //  1. A request that carries a signature MUST verify against the
    //     session's signing key, regardless of the server signing policy —
    //     a bad signature is a tamper/forgery attempt. This holds for every
    //     dialect: the 3.1.1 signing key binds to the pre-auth integrity hash,
    //     which we now reproduce bit-for-bit (canonical negotiate-context
    //     framing), so honest 3.1.1 traffic verifies and a forged signature
    //     is rejected.
    //  2. Unsigned traffic from real accounts is rejected only when
    //     --require-signing is set. Sealed (encrypted) sessions carry their
    //     own AEAD integrity guarantee, so signatures are not required there.
    if hdr.command != ss::cmd::NEGOTIATE
        && hdr.command != ss::cmd::SESSION_SETUP
        && !conn.guest
        && !conn.encrypt_data
        && !conn.req_encrypted
        && conn.signing_key.is_some()
    {
        let key = conn.signing_key.unwrap();
        if hdr.is_signed() {
            if !verify_pdu_signature(buf, &key, conn.dialect) {
                counter!("smb_reject_bad_signature_total").increment(1);
                return Some((
                    response(&hdr, Status::ACCESS_DENIED, Vec::new(), conn.session_id),
                    true,
                ));
            }
        } else if server.require_signing {
            counter!("smb_reject_unsigned_total").increment(1);
            return Some((
                response(&hdr, Status::ACCESS_DENIED, Vec::new(), conn.session_id),
                true,
            ));
        }
    }

    // Encrypted-share enforcement ([MS-SMB2] §3.3.5.2.9): once a tree that
    // requires encryption is connected, every request on it (other than the
    // negotiate/session/tree-connect handshake) MUST be encrypted.
    if !conn.req_encrypted
        && hdr.command != ss::cmd::NEGOTIATE
        && hdr.command != ss::cmd::SESSION_SETUP
        && hdr.command != ss::cmd::TREE_CONNECT
        && conn
            .trees
            .get(&hdr.tree_id)
            .and_then(|n| server.shares.get(n))
            .map(|s| s.encrypt)
            .unwrap_or(false)
    {
        return Some((
            response(&hdr, Status::ACCESS_DENIED, Vec::new(), conn.session_id),
            true,
        ));
    }

    // TREE_CONNECT installs a fresh TreeId into its reply via conn.resp_tree_id.

    // Route a command through the typestate pipeline: a framed body flows the
    // common signing/sealing tail below, a pre-framed async interim is sent
    // verbatim, and a silent outcome sends nothing.
    macro_rules! route {
        () => {
            match via_typestate(&hdr, conn, server, buf).await {
                Routed::Framed(s, b) => (s, b),
                Routed::Raw(frame) => return Some((frame, true)),
                Routed::Silent => return None,
            }
        };
    }

    let (status, mut body): (Status, Vec<u8>) = match hdr.command {
        ss::cmd::NEGOTIATE => route!(),
        ss::cmd::SESSION_SETUP => route!(),
        ss::cmd::TREE_CONNECT => route!(),
        ss::cmd::TREE_DISCONNECT => route!(),
        ss::cmd::LOGOFF => route!(),
        ss::cmd::CREATE => route!(),
        ss::cmd::READ => route!(),
        ss::cmd::WRITE => route!(),
        ss::cmd::CLOSE => route!(),
        ss::cmd::FLUSH => route!(),
        ss::cmd::IOCTL => route!(),
        ss::cmd::LOCK => route!(),
        ss::cmd::CHANGE_NOTIFY => route!(),
        ss::cmd::QUERY_DIRECTORY => route!(),
        ss::cmd::QUERY_INFO => route!(),
        ss::cmd::SET_INFO => route!(),
        ss::cmd::CANCEL => route!(),
        ss::cmd::ECHO => route!(),
        ss::cmd::OPLOCK_BREAK => route!(),
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
            Some(
                smb_proto_smb2::negotiate::DIALECT_300 | smb_proto_smb2::negotiate::DIALECT_302,
            ) => {
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
                Some(smb_proto_smb2::negotiate::DIALECT_311) => (
                    b"SMBC2SCipherKey\0".as_slice(),
                    b"SMBS2CCipherKey\0".as_slice(),
                ),
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
            // AES-128 derives a 16-byte key; AES-256 derives 32 bytes (the KDF
            // encodes the requested length as L in bits per [SP800-108]).
            let klen = cipher_key_len(conn.cipher.unwrap());
            let kdf = |label: &[u8], context: &[u8]| -> [u8; 32] {
                let derived =
                    smb_auth::crypto::kdf_counter_mode_hmac_sha256(&key, label, context, klen);
                let mut k = [0u8; 32];
                k[..klen].copy_from_slice(&derived);
                k
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
    if let Some(new_tid) = conn.resp_tree_id.take() {
        resp[hdr::TREE_ID..hdr::SESSION_ID].copy_from_slice(&new_tid.to_le_bytes()); // TreeId
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
        let mut joined = Vec::with_capacity(hdr::LEN + resp.len());
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
    resp[hdr::FLAGS] |= hdr_flags::SIGNED as u8;
    let mut msg = Vec::with_capacity(resp.len());
    msg.extend_from_slice(&resp[..hdr::SIGNATURE]);
    msg.extend_from_slice(&[0u8; 16]); // zeroed Signature field
    msg.extend_from_slice(&resp[hdr::LEN..]);
    let sig = if matches!(
        dialect,
        Some(
            smb_proto_smb2::negotiate::DIALECT_300
                | smb_proto_smb2::negotiate::DIALECT_302
                | smb_proto_smb2::negotiate::DIALECT_311
        )
    ) {
        let t = smb_auth::crypto::aes128_cmac(key, &msg);
        let mut s = [0u8; 16];
        s.copy_from_slice(&t);
        s
    } else {
        let t = smb_auth::crypto::hmac_sha256(key, &msg);
        let mut s = [0u8; 16];
        s.copy_from_slice(&t[..hdr::SIGNATURE_LEN]);
        s
    };
    resp[hdr::SIGNATURE..hdr::LEN].copy_from_slice(&sig);
}

/// Verify a request PDU's signature against `key` for `dialect`: recompute the
/// AES-CMAC (3.x) / HMAC-SHA256 (2.x) over the PDU with the signature field
/// zeroed and compare to the header's Signature ([MS-SMB2] §3.3.5.2.4).
fn verify_pdu_signature(buf: &[u8], key: &[u8; 16], dialect: Option<u16>) -> bool {
    if buf.len() < hdr::LEN {
        return false;
    }
    let mut msg = Vec::with_capacity(buf.len());
    msg.extend_from_slice(&buf[..hdr::SIGNATURE]);
    msg.extend_from_slice(&[0u8; 16]); // zeroed Signature field
    msg.extend_from_slice(&buf[hdr::LEN..]);
    let expected: [u8; 16] = if matches!(
        dialect,
        Some(
            smb_proto_smb2::negotiate::DIALECT_300
                | smb_proto_smb2::negotiate::DIALECT_302
                | smb_proto_smb2::negotiate::DIALECT_311
        )
    ) {
        smb_auth::crypto::aes128_cmac(key, &msg)[..hdr::SIGNATURE_LEN]
            .try_into()
            .unwrap()
    } else {
        smb_auth::crypto::hmac_sha256(key, &msg)[..hdr::SIGNATURE_LEN]
            .try_into()
            .unwrap()
    };
    expected == buf[hdr::SIGNATURE..hdr::LEN]
}

/// Per-session crypto material an async completion needs to sign/seal a frame
/// off the request path (snapshotted at request time so the background task
/// never borrows the connection).
#[derive(Clone)]
struct AsyncCrypto {
    dialect: Option<u16>,
    signing_key: Option<[u8; 16]>,
    enc_keys: Option<([u8; 32], [u8; 32])>,
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
    let mut f = Vec::with_capacity(hdr::LEN + body.len());
    f.extend_from_slice(&smb_proto_smb2::SMB2_MAGIC);
    f.extend_from_slice(&(hdr::LEN as u16).to_le_bytes()); // StructureSize
    f.extend_from_slice(&1u16.to_le_bytes()); // CreditCharge
    f.extend_from_slice(&status.raw().to_le_bytes());
    f.extend_from_slice(&command.to_le_bytes());
    f.extend_from_slice(&1u16.to_le_bytes()); // CreditResponse
    f.extend_from_slice(&(hdr_flags::SERVER_TO_REDIR | hdr_flags::ASYNC_COMMAND).to_le_bytes());
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
/// How an async-capable command (LOCK / CHANGE_NOTIFY) starts: either an
/// immediate reply, or a deferral parked under an async id whose final reply a
/// background worker sends later ([MS-SMB2] §3.3.4.2).
pub(crate) enum AsyncStart {
    Reply(Status, Vec<u8>),
    Pending(u64),
}

/// Begin a LOCK ([MS-SMB2] §3.3.5.14): apply unlocks, try acquisitions, and
/// either answer immediately or (for a blocking lock) spawn a waiter and defer.
pub(crate) fn begin_lock(
    conn: &mut Smb2Conn,
    server: &Arc<ServerShared>,
    hdr: &smb_proto_smb2::Header2,
    buf: &[u8],
) -> AsyncStart {
    let Some(req) = c::LockReq::parse(buf) else {
        return AsyncStart::Reply(Status::INVALID_PARAMETER, Vec::new());
    };
    let Some(h) = conn.handles.get(&req.file_id.0) else {
        return AsyncStart::Reply(Status::INVALID_HANDLE, Vec::new());
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
        return AsyncStart::Reply(Status::SUCCESS, c::build_lock_resp());
    }
    if req.locks.iter().any(|l| l.fail_immediately) {
        return AsyncStart::Reply(Status::LOCK_NOT_GRANTED, Vec::new());
    }
    // Blocking lock: interim STATUS_PENDING, then retry as conflicting locks
    // are released.
    let async_id = conn.alloc_async_id();
    let crypto = AsyncCrypto::snapshot(conn, hdr.is_signed());
    let (cancel_tx, cancel_rx) = oneshot::channel();
    conn.async_cancels.insert(async_id, cancel_tx);
    conn.async_msgids.insert(hdr.message_id, async_id);
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
    AsyncStart::Pending(async_id)
}

/// Begin a CHANGE_NOTIFY ([MS-SMB2] §3.3.5.19): validate the directory open,
/// register the watch, and defer with an interim STATUS_PENDING.
pub(crate) fn begin_change_notify(
    conn: &mut Smb2Conn,
    hdr: &smb_proto_smb2::Header2,
    buf: &[u8],
) -> AsyncStart {
    let Some(req) = c::ChangeNotifyReq::parse(buf) else {
        return AsyncStart::Reply(Status::INVALID_PARAMETER, Vec::new());
    };
    let Some(open) = conn.handles.get(&req.file_id.0) else {
        return AsyncStart::Reply(Status::INVALID_HANDLE, Vec::new());
    };
    // Validate before registering the watch ([MS-SMB2] §3.3.5.19).
    if !open.is_dir {
        return AsyncStart::Reply(Status::INVALID_PARAMETER, Vec::new());
    }
    if !open.can_read {
        return AsyncStart::Reply(Status::ACCESS_DENIED, Vec::new());
    }
    if req.output_len > MAX_TRANSACT_SIZE {
        return AsyncStart::Reply(Status::INVALID_PARAMETER, Vec::new());
    }
    let dir_path = open.path.clone();

    let async_id = conn.alloc_async_id();
    let crypto = AsyncCrypto::snapshot(conn, hdr.is_signed());
    let (cancel_tx, cancel_rx) = oneshot::channel();
    conn.async_cancels.insert(async_id, cancel_tx);
    conn.async_msgids.insert(hdr.message_id, async_id);
    conn.async_by_file
        .entry(req.file_id.0)
        .or_default()
        .push(async_id);
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
    AsyncStart::Pending(async_id)
}

/// Handle a CANCEL ([MS-SMB2] §3.3.5.16): find the pending op by AsyncId (async
/// CANCEL) or MessageId (sync CANCEL) and signal it to complete with
/// STATUS_CANCELLED. CANCEL itself carries no response.
pub(crate) fn cancel(conn: &mut Smb2Conn, hdr: &smb_proto_smb2::Header2, buf: &[u8]) {
    counter!("smb_cancels_total").increment(1);
    let async_id = if hdr.is_async() && buf.len() >= hdr::ASYNC_ID + size_of::<u64>() {
        Some(u64::from_le_bytes(
            buf[hdr::ASYNC_ID..hdr::SESSION_ID].try_into().unwrap(),
        ))
    } else {
        conn.async_msgids.get(&hdr.message_id).copied()
    };
    if let Some(aid) = async_id {
        conn.async_msgids.retain(|_, v| *v != aid);
        conn.async_by_file
            .values_mut()
            .for_each(|v| v.retain(|x| *x != aid));
        if let Some(tx) = conn.async_cancels.remove(&aid) {
            let _ = tx.send(Status::CANCELLED);
        }
    }
}

async fn run_lock_wait(
    locks: Arc<crate::state::LockManager>,
    path: String,
    ranges: Vec<(u64, u64, bool)>,
    owner: crate::state::LockOwner,
    crypto: AsyncCrypto,
    message_id: u64,
    async_id: u64,
    outbound: mpsc::Sender<Vec<u8>>,
    mut cancel: oneshot::Receiver<Status>,
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
        build_async_frame(
            crypto.session_id,
            message_id,
            async_id,
            ss::cmd::LOCK,
            status,
            &body,
        ),
    );
    let _ = outbound.send(frame).await;
    gauge!("smb_async_pending").decrement(1.0);
}

/// Watch `dir_path` for one filesystem change (or cancellation) and emit the
/// final CHANGE_NOTIFY response ([MS-SMB2] §2.2.36) on the outbound queue.
async fn run_change_notify(
    dir_path: String,
    watch_tree: bool,
    filter: u32,
    crypto: AsyncCrypto,
    message_id: u64,
    async_id: u64,
    outbound: mpsc::Sender<Vec<u8>>,
    mut cancel: oneshot::Receiver<Status>,
) {
    let frame = match watch_one_event(&dir_path, watch_tree, filter, &mut cancel).await {
        Ok(entries) => {
            let pairs: Vec<(u32, &str)> = entries.iter().map(|(a, n)| (*a, n.as_str())).collect();
            let buf = c::build_file_notify_information(&pairs);
            let body = c::build_change_notify_resp(&buf);
            counter!("smb_notifies_sent").increment(1);
            build_async_frame(
                crypto.session_id,
                message_id,
                async_id,
                ss::cmd::CHANGE_NOTIFY,
                Status::SUCCESS,
                &body,
            )
        }
        Err(status) => {
            // NOTIFY_CLEANUP is severity-success: clients parse it as a normal
            // (empty) CHANGE_NOTIFY response. A genuine CANCEL is an error and
            // must carry the SMB2 error-response body.
            let body = if status == Status::NOTIFY_CLEANUP {
                c::build_change_notify_resp(&[])
            } else {
                error_resp()
            };
            build_async_frame(
                crypto.session_id,
                message_id,
                async_id,
                ss::cmd::CHANGE_NOTIFY,
                status,
                &body,
            )
        }
    };
    let _ = outbound.send(finalize_async(&crypto, frame)).await;
    gauge!("smb_async_pending").decrement(1.0);
}

/// Await the first inotify event on `dir_path` (mapped from the SMB completion
/// filter) or a cancellation. When `watch_tree` is set, subdirectories are
/// watched too and the reported name is relative to `dir_path`. Returns the
/// `(action, name)` list on an event, or `Err(status)` carrying the completion
/// status on cancel/handle-close/setup error.
async fn watch_one_event(
    dir_path: &str,
    watch_tree: bool,
    filter: u32,
    cancel: &mut oneshot::Receiver<Status>,
) -> Result<Vec<(u32, String)>, Status> {
    use futures_util::StreamExt;
    use inotify::Inotify;
    use std::collections::HashMap;

    let inotify = Inotify::init().map_err(|_| Status::CANCELLED)?;
    let mask = filter_to_mask(filter);
    // Map each watch descriptor to its path relative to the watched root so a
    // recursive event names the file as `subdir\name`.
    let mut wd_rel: HashMap<inotify::WatchDescriptor, String> = HashMap::new();
    let root_wd = inotify
        .watches()
        .add(dir_path, mask)
        .map_err(|_| Status::CANCELLED)?;
    wd_rel.insert(root_wd, String::new());
    if watch_tree {
        for (abs, rel) in collect_subdirs(std::path::Path::new(dir_path)) {
            if let Ok(wd) = inotify.watches().add(&abs, mask) {
                wd_rel.insert(wd, rel);
            }
        }
    }
    let mut buf = [0u8; 4096];
    let mut stream = inotify
        .into_event_stream(&mut buf)
        .map_err(|_| Status::CANCELLED)?;

    tokio::select! {
        ev = stream.next() => {
            let ev = ev.ok_or(Status::CANCELLED)?.map_err(|_| Status::CANCELLED)?;
            let name = ev
                .name
                .as_ref()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let prefix = wd_rel.get(&ev.wd).cloned().unwrap_or_default();
            let full = if prefix.is_empty() { name } else { format!("{prefix}\\{name}") };
            Ok(vec![(mask_to_action(ev.mask), full)])
        }
        status = cancel => Err(status.unwrap_or(Status::CANCELLED)),
    }
}

/// Collect subdirectories under `root` as `(absolute_path, backslash_relative)`
/// pairs for recursive CHANGE_NOTIFY, capped to bound very deep trees.
fn collect_subdirs(root: &std::path::Path) -> Vec<(std::path::PathBuf, String)> {
    const CAP: usize = 4096;
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let name = e.file_name().to_string_lossy().into_owned();
                let child = if rel.is_empty() {
                    name
                } else {
                    format!("{rel}\\{name}")
                };
                out.push((e.path(), child.clone()));
                stack.push((e.path(), child));
                if out.len() >= CAP {
                    return out;
                }
            }
        }
    }
    out
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
    // Attribute and timestamp changes are delivered as inotify IN_ATTRIB on
    // Linux (utimensat / chmod), so map every metadata filter there.
    if filter & (nf::ATTRIBUTES | nf::LAST_WRITE | nf::LAST_ACCESS | nf::CREATION | nf::EA) != 0 {
        m |= M::ATTRIB;
    }
    if filter & (nf::SIZE | nf::LAST_WRITE | nf::STREAM_SIZE | nf::STREAM_WRITE | nf::STREAM_NAME)
        != 0
    {
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
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
/// How a NEGOTIATE resolves: an immediate reply, or silence because a repeat
/// NEGOTIATE on an already-negotiated connection terminates it ([MS-SMB2]
/// §3.3.5.4).
pub(crate) enum NegotiateReply {
    Reply(Status, Vec<u8>),
    Silent,
}

/// Negotiate a dialect ([MS-SMB2] §3.3.5.3-4): answer probes with the wildcard
/// response, pick a common dialect, validate 3.1.1 pre-auth contexts, and choose
/// cipher/compression. The response is framed and pre-auth-hashed by the shared
/// tail in `process_single`.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) fn negotiate(
    conn: &mut Smb2Conn,
    server: &Arc<ServerShared>,
    hdr: &smb_proto_smb2::Header2,
    buf: &[u8],
) -> NegotiateReply {
    let body_start = hdr::LEN;
    // A NEGOTIATE received after the connection already negotiated a dialect is
    // invalid: the server MUST disconnect and not reply ([MS-SMB2] §3.3.5.4).
    if conn.dialect.is_some() {
        conn.disconnect = true;
        return NegotiateReply::Silent;
    }
    // Clients probing for SMB2 support send either a header-only NEGOTIATE or one
    // carrying Status = STATUS_INVALID_PARAMETER ([MS-SMB2] §3.3.5.3). Answer
    // both with the wildcard-dialect response so they retry a real negotiation.
    let parsed = smb_proto_smb2::negotiate::Request::parse(buf.get(body_start..).unwrap_or(&[]));
    tracing::debug!(
        status = hdr.status,
        parsed_ok = parsed.is_some(),
        len = buf.len(),
        "negotiate probe check"
    );
    if hdr.status == Status::INVALID_PARAMETER.raw() || parsed.is_none() {
        if parsed.is_none() {
            tracing::debug!(len = buf.len(), body = %hex_str(buf.get(body_start..).unwrap_or(&[])), "negotiate parse failed");
        }
        return NegotiateReply::Reply(Status::INVALID_PARAMETER, probe_negotiate_resp());
    }
    let req = parsed.expect("validated above");
    let Some(dialect) = smb_proto_smb2::negotiate::pick(&req.dialects) else {
        return NegotiateReply::Reply(Status::INVALID_PARAMETER, Vec::new());
    };
    conn.dialect = Some(dialect);
    // Retain the client's NEGOTIATE fields for a later
    // FSCTL_VALIDATE_NEGOTIATE_INFO downgrade check ([MS-SMB2] §3.3.5.15.12).
    conn.client_guid = req.client_guid;
    conn.client_dialects = req.dialects.clone();
    conn.client_security_mode = g16(buf, body_start + 4);
    conn.client_capabilities = buf
        .get(body_start + 8..body_start + 12)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
        .unwrap_or(0);
    // SMB 3.1.1 negotiate-context validation ([MS-SMB2] §3.3.5.4): exactly one
    // PREAUTH_INTEGRITY context is required, and it must offer a hash algorithm
    // the server supports (SHA-512).
    if dialect == smb_proto_smb2::negotiate::DIALECT_311 {
        let preauth: Vec<_> = req
            .contexts
            .iter()
            .filter(|c| c.kind == smb_proto_smb2::negotiate::ctx_type::PREAUTH_INTEGRITY)
            .collect();
        if preauth.len() != 1 {
            return NegotiateReply::Reply(Status::INVALID_PARAMETER, Vec::new());
        }
        // HashAlgorithmCount(2) SaltLength(2) HashAlgorithms[] ([MS-SMB2] §2.2.3.1.1).
        let pd = &preauth[0].data;
        let count = pd
            .get(0..2)
            .map(|s| u16::from_le_bytes([s[0], s[1]]) as usize)
            .unwrap_or(0);
        let algos: Vec<u16> = pd
            .get(4..)
            .map(|d| {
                d.chunks_exact(2)
                    .take(count)
                    .map(|w| u16::from_le_bytes([w[0], w[1]]))
                    .collect()
            })
            .unwrap_or_default();
        if !algos.contains(&smb_proto_smb2::negotiate::ctx_type::SHA512) {
            return NegotiateReply::Reply(
                Status::SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP,
                Vec::new(),
            );
        }
    }
    // SMB2_COMPRESSION_CAPABILITIES validation ([MS-SMB2] §3.3.5.4): a present
    // context must be at least the fixed structure size (8 bytes) and advertise
    // a non-zero CompressionAlgorithmCount, else the negotiate fails with
    // STATUS_INVALID_PARAMETER.
    if dialect == smb_proto_smb2::negotiate::DIALECT_311 {
        if let Some(c) = req
            .contexts
            .iter()
            .find(|c| c.kind == smb_proto_smb2::negotiate::ctx_type::COMPRESSION)
        {
            let count = c
                .data
                .get(0..2)
                .map(|s| u16::from_le_bytes([s[0], s[1]]))
                .unwrap_or(0);
            if c.data.len() < 8 || count == 0 {
                return NegotiateReply::Reply(Status::INVALID_PARAMETER, Vec::new());
            }
        }
    }
    // Must match the Capabilities word written by build_response_full below so
    // VALIDATE_NEGOTIATE_INFO echoes it.
    conn.advertised_caps = if dialect >= smb_proto_smb2::negotiate::DIALECT_300 {
        smb_proto_smb2::negotiate::caps::LARGE_MTU
            | smb_proto_smb2::negotiate::caps::MULTI_CHANNEL
            | smb_proto_smb2::negotiate::caps::LEASING
    } else if dialect >= smb_proto_smb2::negotiate::DIALECT_210 {
        smb_proto_smb2::negotiate::caps::LARGE_MTU | smb_proto_smb2::negotiate::caps::LEASING
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
        // GCM preferred by default ([MS-SMB2] §3.1.4.1). RUSTSMB_CIPHER pins a
        // preference to exercise a specific cipher live: ccm, 256gcm, 256ccm.
        let pref = std::env::var("RUSTSMB_CIPHER")
            .unwrap_or_default()
            .to_lowercase();
        use smb_proto_smb2::negotiate::ctx_type::{
            AES128_CCM, AES128_GCM, AES256_CCM, AES256_GCM,
        };
        let order = match pref.as_str() {
            "ccm" | "128ccm" => [AES128_CCM, AES256_CCM, AES128_GCM, AES256_GCM],
            "256" | "256gcm" => [AES256_GCM, AES128_GCM, AES256_CCM, AES128_CCM],
            "256ccm" => [AES256_CCM, AES128_CCM, AES256_GCM, AES128_GCM],
            _ => [AES128_GCM, AES256_GCM, AES128_CCM, AES256_CCM],
        };
        order.into_iter().find(|ours| client_ciphers.contains(ours))
    };
    // Dialects without negotiate contexts (or clients that did not offer
    // ENCRYPTION_CAPABILITIES) must leave conn.cipher unset — otherwise
    // --encrypt would seal sessions the peer cannot read.
    if dialect == smb_proto_smb2::negotiate::DIALECT_311 && !client_ciphers.is_empty() {
        conn.cipher = chosen;
    }
    // Compression: intersect the client's advertised algorithms with ours; a
    // common set enables compressed transforms both ways.
    let comp_algos = req
        .contexts
        .iter()
        .find(|c| c.kind == smb_proto_smb2::negotiate::ctx_type::COMPRESSION)
        .map(|c| {
            smb_proto_smb2::compress::negotiate_algos(
                &smb_proto_smb2::compress::parse_compression_caps(&c.data),
            )
        })
        .unwrap_or_default();
    if dialect == smb_proto_smb2::negotiate::DIALECT_311
        && comp_algos.contains(&smb_proto_smb2::compress::algo::LZNT1)
    {
        conn.compress_algo = Some(smb_proto_smb2::compress::algo::LZNT1);
    }
    NegotiateReply::Reply(
        Status::SUCCESS,
        smb_proto_smb2::negotiate::build_response_full(
            dialect,
            &server.guid,
            smb_proto::types::FileTime::now().0,
            &salt,
            // Echo ENCRYPTION/SIGNING only when the client offered them
            // ([MS-SMB2] §3.3.5.4). With no common cipher, echo ENCRYPTION_NONE
            // (0) so the client clears Connection.CipherId.
            (!client_ciphers.is_empty()).then(|| chosen.unwrap_or(0)),
            req.contexts
                .iter()
                .any(|c| c.kind == smb_proto_smb2::negotiate::ctx_type::SIGNING),
            &comp_algos,
            server.require_signing,
        ),
    )
}

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) fn session_setup(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Result<(Status, Vec<u8>), Status> {
    let req = ss::Request::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    // Channel binding ([MS-SMB2] §3.3.5.5.2): the setup carries the binding
    // flag and the header names an existing session to attach this new
    // connection (channel) to.
    let hdr_session = buf
        .get(hdr::SESSION_ID..hdr::SIGNATURE)
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
            conn.session_id = if binding {
                hdr_session
            } else {
                next_session_id()
            };
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
            // Per-client dialect consistency ([MS-SMB2] §3.3.5.5.3): a client
            // that authenticates under a ClientGuid already seen with a
            // different negotiated dialect has its new session closed with
            // STATUS_USER_SESSION_DELETED. Skipped for SMB 2.0.2 (no ClientGuid
            // table) and guest/anonymous sessions.
            if let Some(dialect) = conn.dialect.filter(|&d| d != smb_proto_smb2::negotiate::DIALECT_202) {
                use std::sync::LazyLock;
                static CLIENT_DIALECTS: LazyLock<std::sync::Mutex<std::collections::HashMap<[u8; 16], u16>>> =
                    LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));
                let mut table = CLIENT_DIALECTS.lock().unwrap();
                match table.get(&conn.client_guid) {
                    Some(&seen) if seen != dialect => return Err(Status::USER_SESSION_DELETED),
                    Some(_) => {}
                    None => {
                        table.insert(conn.client_guid, dialect);
                    }
                }
            }
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
                && req.blob[MIC_OFFSET..MIC_OFFSET + MIC_SIZE]
                    .iter()
                    .any(|&b| b != 0);
            // A guest/anonymous session has no session key, so it cannot echo a
            // mechListMIC; it completes with a plain accept-complete instead of
            // failing ([MS-SMB2] §3.3.5.5: anonymous/guest sessions are unsigned).
            let wrapped = if client_mic_nonzero && conn.session_key.is_some() {
                let key = conn.session_key.unwrap();
                let init = conn
                    .ntlm_blobs
                    .as_ref()
                    .map(|b| b.0.clone())
                    .unwrap_or_default();
                // Locate MechTypes: smbclient's token nests as
                //   60{ OID, A0{ 30{ A0{ 30<OIDs> }, A2{ntlm} } } }
                // and samba signs exactly the bare `30<OIDs>` SEQUENCE
                // (spnego_write_mech_types: ASN1_SEQUENCE(0) of OIDs).
                // Walk: outer A0 (negTokenInit) -> its 30 SEQUENCE ->
                // first inner A0 (mechTypes wrapper) -> that 30 SEQUENCE.
                #[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
                let mic =
                    smb_auth::crypto::ntlm_mech_list_mic(&key, true, key_exch, 0, &mech_types);
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

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) fn tree_connect(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Result<(String, u8, bool, bool, bool), Status> {
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
    Ok((name, share_type, share.encrypt, share.compress, share.ca))
}

// ---------------- CREATE ----------------

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) async fn create(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    server: &Arc<ServerShared>,
    req_signed: bool,
    is_ca: bool,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::CreateReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;

    const OPT_DIRECTORY_FILE: u32 = 0x1;
    const OPT_NON_DIRECTORY_FILE: u32 = 0x40;
    const OPT_DELETE_ON_CLOSE: u32 = 0x1000;

    // Durable reconnect ([MS-SMB2] §3.3.5.9.7/§3.3.5.9.12): reclaim a preserved
    // handle instead of opening fresh.
    if let Some((id, guid)) = durable_reconnect_ids(&req.durable) {
        return durable_reconnect(conn, vfs, server, &req, id, guid).await;
    }

    // Reject a path that walks upward from a real component ([MS-SMB2]
    // §3.3.5.9 — e.g. "x\..\y.txt"); bare "." / leading ".." are normalized.
    {
        let mut seen_real = false;
        for c in req.name.split(['\\', '/']).filter(|c| !c.is_empty()) {
            if c == ".." && seen_real {
                return Err(Status::INVALID_PARAMETER);
            }
            if c != "." && c != ".." {
                seen_real = true;
            }
        }
    }
    // FILE_DELETE_ON_CLOSE requires DELETE or GENERIC_ALL access ([MS-SMB2]
    // §3.3.5.9).
    if req.options & OPT_DELETE_ON_CLOSE != 0
        && req.desired_access & (0x0001_0000 | 0x1000_0000) == 0
    {
        return Err(Status::ACCESS_DENIED);
    }

    let rel = req.name.trim_start_matches(['\\', '/']).to_string();
    let want_dir = req.options & OPT_DIRECTORY_FILE != 0;

    let (mut open, meta, action) = match vfs
        .create(
            &rel,
            want_dir,
            req.desired_access,
            req.disposition,
            req.options,
            req.attrs,
        )
        .await
    {
        Ok(v) => v,
        // Traversal hit a symlink: build the Symbolic Link Error Response from
        // the target and unparsed path ([MS-SMB2] §2.2.2.2.1) for the caller to
        // frame with STATUS_STOPPED_ON_SYMLINK.
        Err(smb_vfs::VfsError::StoppedOnSymlink {
            target,
            unparsed_len,
            relative,
        }) => {
            conn.symlink_error = Some(c::build_symlink_error_response(
                &target,
                &target,
                unparsed_len,
                relative,
            ));
            return Err(Status::STOPPED_ON_SYMLINK);
        }
        Err(e) => return Err(vfs_err(e)),
    };

    if req.options & OPT_NON_DIRECTORY_FILE != 0 && open.is_dir {
        return Err(Status::FILE_IS_A_DIRECTORY);
    }
    open.delete_on_close |= req.options & OPT_DELETE_ON_CLOSE != 0;

    let fid_bytes = next_file_id();
    let path = open.path.clone();
    let is_dir = open.is_dir;
    // Application-instance failover ([MS-SMB2] §3.3.5.9.13): a CREATE carrying
    // the same AppInstanceId from a different client force-closes the prior
    // open (or is rejected when the existing open's version is newer/equal).
    // Durable reconnect is handled earlier and skips this path.
    if let Some(app_id) = req.app_instance_id {
        let is_311 = conn.dialect == Some(smb_proto_smb2::negotiate::DIALECT_311);
        match server
            .app_instances
            .resolve(app_id, &path, conn.client_guid, is_311, req.app_instance_version)
        {
            crate::state::AppInstanceMatch::Reject => {
                let _ = vfs.close(open).await;
                return Err(Status::FILE_FORCED_CLOSED);
            }
            crate::state::AppInstanceMatch::ForceClose { path: vpath, owner } => {
                server.share_modes.close(&vpath, owner);
                server.oplocks.take(&vpath);
                server.locks.release_owner(owner);
                server.leases.release(&vpath, owner);
            }
            crate::state::AppInstanceMatch::None => {}
        }
    }
    // Sharing-violation check ([MS-FSA] §2.1.5.1): reject an open whose access
    // or share flags conflict with an existing open on the same path. On a
    // directory, an incompatible open first revokes HANDLE caching on any
    // directory lease ([MS-SMB2] §3.3.1.4). Undo the just-opened handle on
    // rejection.
    if !server.share_modes.try_open(
        &path,
        req.desired_access,
        req.share_access,
        (conn.session_id, fid_bytes),
    ) {
        if is_dir {
            break_dir_lease_wait(server, conn, &path, fid_bytes, c::lease::HANDLE_CACHING).await;
        }
        let _ = vfs.close(open).await;
        counter!("smb_sharing_violations_total").increment(1);
        return Err(Status::SHARING_VIOLATION);
    }

    let fid = c::FileId(fid_bytes);
    conn.searches.remove(&fid_bytes);
    conn.handles.insert(fid_bytes, open);
    // Record this handle so a related follow-up in the compound chain that
    // carries the wildcard FileId resolves to it ([MS-SMB2] §3.3.5.2.7.2).
    conn.chain_fid = Some(fid_bytes);
    if let Some(app_id) = req.app_instance_id {
        server.app_instances.register(
            app_id,
            path.clone(),
            conn.client_guid,
            (conn.session_id, fid_bytes),
            req.app_instance_version,
        );
    }

    // A non-lease open conflicting with another holder's lease breaks its
    // write caching (RWH -> RH) ([MS-SMB2] §3.3.4.7); lease-context opens are
    // handled by arbitrate_lease below.
    if req.lease.is_none() && !is_dir {
        if let Some((k, old, new, ep, out, crypto)) = server.leases.break_conflict(
            &path,
            (conn.session_id, fid_bytes),
            None,
            c::lease::WRITE_CACHING,
        ) {
            send_lease_break(&out, &crypto, k, old, new, ep);
        }
    }

    // Adding a new file or directory revokes READ caching on a directory lease
    // held on the parent ([MS-SMB2] §3.3.1.4). A directory lease supports only
    // {None, Read, Read+Handle}, so losing READ also drops HANDLE (to NONE).
    const FILE_ACTION_CREATED: u32 = 2;
    if action == FILE_ACTION_CREATED {
        break_dir_lease(server, conn, parent_dir(&path), fid_bytes, c::lease::RH);
    }

    // Oplock arbitration ([MS-SMB2] §2.2.23): grant an exclusive oplock only
    // to the sole opener of a file. A contending open first breaks the current
    // holder to NONE, then gets no oplock itself. A LEASE request without an
    // RqLs context is treated as an ordinary oplock request ([MS-SMB2]
    // §3.3.5.9 "Oplock Acquisition": any non-NONE level acquires an oplock).
    let lease_context = req.oplock_level == c::oplock::LEASE && req.lease.is_some();
    let wants_oplock = matches!(
        req.oplock_level,
        c::oplock::LEVEL_II | c::oplock::EXCLUSIVE | c::oplock::BATCH
    ) || (req.oplock_level == c::oplock::LEASE && req.lease.is_none());
    // A lease request (RequestedOplockLevel = LEASE + an RqLs context) uses the
    // lease path; leases and oplocks are arbitrated independently.
    let mut lease_grant: Option<c::LeaseResp> = None;
    // Directory leasing ([MS-SMB2] §3.3.1.4) is an SMB 3.x feature; a directory
    // lease supports only READ + HANDLE caching.
    let dir_leasing = is_dir && conn.dialect.map(|d| d >= smb_proto_smb2::negotiate::DIALECT_300).unwrap_or(false);
    let granted = if lease_context && (!is_dir || dir_leasing) {
        if let Some(lr) = req.lease {
            lease_grant = Some(arbitrate_lease(
                server, conn, &path, fid_bytes, &lr, req_signed, is_dir,
            ));
            conn.lease_keys.insert(fid_bytes, lr.key);
            c::oplock::LEASE
        } else {
            c::oplock::NONE
        }
    } else if is_dir {
        c::oplock::NONE
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

    // Grant a durable handle when the client requested one. Persistence is
    // granted only on a continuously-available share ([MS-SMB2] §3.3.5.9.11);
    // a lease present must include handle caching for durable.
    let durable_grant = grant_durable(
        conn,
        &req,
        fid_bytes,
        &rel,
        is_dir,
        lease_grant.as_ref().map(|l| l.state),
        is_ca,
    );

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
        [
            meta.times[0].0,
            meta.times[1].0,
            meta.times[2].0,
            meta.times[3].0,
        ],
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
        Some(c::DurableReq::ReconnectV2 {
            file_id,
            create_guid,
        }) => Some((*file_id, Some(*create_guid))),
        Some(c::DurableReq::ReconnectV1 { file_id }) => Some((*file_id, None)),
        _ => None,
    }
}

/// Reclaim a preserved durable handle and re-open the file under its persistent
/// id (single-node durable model: the on-disk file, not a live fd, is durable).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
async fn durable_reconnect(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    server: &Arc<ServerShared>,
    req: &c::CreateReq,
    id: [u8; 16],
    guid: Option<[u8; 16]>,
) -> Result<Vec<u8>, Status> {
    // A reconnect must not be combined with a conflicting durable context
    // ([MS-SMB2] §3.3.5.9.7/§3.3.5.9.12). A v1 reconnect (DHnC) rejects any V2
    // durable context with STATUS_INVALID_PARAMETER; a v2 reconnect (DH2C)
    // rejects any other durable context with STATUS_OBJECT_NAME_NOT_FOUND.
    let tags = req.durable_ctx_tags;
    if guid.is_none() {
        if tags & (c::durable::tag::REQ_V2 | c::durable::tag::RECONNECT_V2) != 0 {
            return Err(Status::INVALID_PARAMETER);
        }
    } else if tags
        & (c::durable::tag::REQ_V1 | c::durable::tag::RECONNECT_V1 | c::durable::tag::REQ_V2)
        != 0
    {
        return Err(Status::OBJECT_NAME_NOT_FOUND);
    }

    // Peek the preserved record to validate the reconnect against the original
    // open's lease and client before consuming it.
    let peeked = server
        .durables
        .get(&id)
        .await
        .ok()
        .flatten()
        .ok_or(Status::OBJECT_NAME_NOT_FOUND)?;
    if guid.is_some() && peeked.match_guid != guid {
        return Err(Status::OBJECT_NAME_NOT_FOUND);
    }
    // Lease-bound reconnect validation ([MS-SMB2] §3.3.5.9.7): when the original
    // open held a lease, the reconnect must target the same file name, come from
    // the same client, present a lease context, and use the same lease key.
    if let Some(orig_key) = peeked.lease_key {
        if req.name.trim_start_matches(['\\', '/']) != peeked.path {
            // Name mismatch: v1 -> INVALID_PARAMETER, v2 -> OBJECT_NAME_NOT_FOUND.
            return Err(if guid.is_some() {
                Status::OBJECT_NAME_NOT_FOUND
            } else {
                Status::INVALID_PARAMETER
            });
        }
        if peeked.client_guid != conn.client_guid {
            return Err(Status::OBJECT_NAME_NOT_FOUND);
        }
        match &req.lease {
            None => return Err(Status::OBJECT_NAME_NOT_FOUND),
            Some(l) if l.key != orig_key => return Err(Status::OBJECT_NAME_NOT_FOUND),
            Some(_) => {}
        }
    }

    // Durable-owner check ([MS-SMB2] §3.3.5.9.7 rule 17): a reconnect by a user
    // other than the one that created the handle fails with STATUS_ACCESS_DENIED
    // and leaves the preserved handle intact for its real owner.
    if !peeked.owner_user.eq_ignore_ascii_case(&conn.user) {
        return Err(Status::ACCESS_DENIED);
    }

    let record = server
        .durables
        .take(&id, guid, crate::state::now_ms())
        .await
        .ok()
        .flatten()
        .ok_or(Status::OBJECT_NAME_NOT_FOUND)?;
    let persistent = record.flags & c::durable::FLAG_PERSISTENT != 0;
    let timeout = record.timeout_ms as u32;
    // FILE_OPEN (disposition 1): the file already exists.
    let (mut open, meta, _action) = vfs
        .create(
            &record.path,
            record.is_dir,
            record.access,
            1,
            record.create_options,
            0,
        )
        .await
        .map_err(vfs_err)?;
    open.delete_on_close = false;
    conn.handles.insert(id, open);
    conn.durable.insert(
        id,
        crate::state::DurableEntry {
            persistent_id: id,
            create_guid: record.match_guid.unwrap_or([0u8; 16]),
            rel: record.path.clone(),
            is_dir: record.is_dir,
            access: record.access,
            options: record.create_options,
            session_id: conn.session_id,
            owner_user: record.owner_user.clone(),
            client_guid: record.client_guid,
            lease_key: record.lease_key,
            persistent,
            timeout,
            deadline: std::time::Instant::now(),
        },
    );
    counter!("smb_durable_reconnects_total").increment(1);

    let (name, data): (&[u8], Vec<u8>) = if guid.is_some() {
        let flags = if persistent {
            c::durable::FLAG_PERSISTENT
        } else {
            0
        };
        (c::durable::REQ_V2, c::durable_v2_resp_data(timeout, flags))
    } else {
        (c::durable::REQ_V1, c::durable_v1_resp_data())
    };
    let contexts = c::encode_create_contexts(&[(name, data)]);
    Ok(c::build_create_resp(
        c::FileId(id),
        1, // FILE_OPENED
        [
            meta.times[0].0,
            meta.times[1].0,
            meta.times[2].0,
            meta.times[3].0,
        ],
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
/// A durable open also requires a batch oplock or a handle-caching lease, so
/// `lease_state` (the granted lease bits, if any) gates the grant; persistence
/// is only granted on a continuous-availability share (`is_ca`).
fn grant_durable(
    conn: &mut Smb2Conn,
    req: &c::CreateReq,
    fid: [u8; 16],
    rel: &str,
    is_dir: bool,
    lease_state: Option<u32>,
    is_ca: bool,
) -> Option<(&'static [u8], Vec<u8>)> {
    // A durable open requires a batch oplock or a handle-caching lease
    // ([MS-SMB2] §3.3.5.9.6/§3.3.5.9.10), except a persistent handle on a
    // continuous-availability share, which is granted regardless.
    let persistent_eligible = is_ca
        && matches!(req.durable, Some(c::DurableReq::RequestV2 { flags, .. }) if flags & c::durable::FLAG_PERSISTENT != 0);
    if !persistent_eligible {
        match lease_state {
            Some(state) if state & c::lease::HANDLE_CACHING != 0 => {}
            None if req.oplock_level == c::oplock::BATCH => {}
            _ => return None,
        }
    }
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
        owner_user: conn.user.clone(),
        client_guid: conn.client_guid,
        lease_key: req.lease.as_ref().map(|l| l.key),
        persistent,
        timeout,
        deadline: std::time::Instant::now(),
    };
    match req.durable {
        Some(c::DurableReq::RequestV2 {
            timeout,
            flags,
            create_guid,
        }) => {
            // Persistence requires a CA share ([MS-SMB2] §3.3.5.9.11); otherwise
            // the persistent bit is ignored and a plain durable handle granted.
            let persistent = is_ca && flags & c::durable::FLAG_PERSISTENT != 0;
            let to = if timeout == 0 {
                DEFAULT_TIMEOUT_MS
            } else {
                timeout
            };
            conn.durable.insert(fid, make(create_guid, persistent, to));
            counter!("smb_durables_granted_total").increment(1);
            Some((
                c::durable::REQ_V2,
                c::durable_v2_resp_data(
                    to,
                    if persistent {
                        c::durable::FLAG_PERSISTENT
                    } else {
                        0
                    },
                ),
            ))
        }
        Some(c::DurableReq::RequestV1) => {
            conn.durable
                .insert(fid, make([0u8; 16], false, DEFAULT_TIMEOUT_MS));
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
    is_dir: bool,
) -> c::LeaseResp {
    // A directory lease supports only READ + HANDLE caching; a file lease also
    // supports WRITE caching ([MS-SMB2] §3.3.1.4).
    let allowed = if is_dir { c::lease::RH } else { c::lease::RWH };
    let requested = lr.state & allowed;
    if let Some((key, state, epoch, v2)) = server.leases.peek(path) {
        if key == lr.key {
            return c::LeaseResp {
                key: lr.key,
                state,
                flags: 0,
                epoch,
                v2,
            };
        }
        let new_state = state & c::lease::RH;
        if let Some((hkey, old, nepoch, outbound, crypto)) =
            server.leases.downgrade(path, new_state)
        {
            send_lease_break(&outbound, &crypto, hkey, old, new_state, nepoch);
        }
        let grant = requested & c::lease::RH;
        return c::LeaseResp {
            key: lr.key,
            state: grant,
            flags: 0,
            epoch: lr.epoch,
            v2: lr.v2,
        };
    }
    // A newly established lease initializes its epoch from the request and
    // increments it by one for a LeaseV2 grant ([MS-SMB2] §3.3.5.9.11); V1
    // leases have no epoch (reported as zero).
    let granted_epoch = if lr.v2 { lr.epoch.wrapping_add(1) } else { 0 };
    let holder = crate::state::LeaseHolder {
        key: lr.key,
        state: requested,
        epoch: granted_epoch,
        v2: lr.v2,
        session_id: conn.session_id,
        file_id: fid,
        outbound: conn.outbound.clone(),
        crypto: break_crypto(conn, signed),
        client_guid: conn.client_guid,
        breaking: false,
        break_to: requested,
    };
    server.leases.grant(path, holder);
    counter!("smb_leases_granted_total").increment(1);
    c::LeaseResp {
        key: lr.key,
        state: requested,
        flags: 0,
        epoch: granted_epoch,
        v2: lr.v2,
    }
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
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
    let frame = finalize_break(crypto, build_break_frame(&body));
    if outbound.try_send(frame).is_ok() {
        counter!("smb_lease_breaks_total").increment(1);
    }
}

/// Revoke caching bits (`clear`) on a directory lease held on `dir` when its
/// contents or state change, unless the change originates from the lease holder
/// itself ([MS-SMB2] §3.3.1.4). `owner` is the file id of the open performing
/// the change, used to suppress a self-break.
pub(crate) fn break_dir_lease(server: &Arc<ServerShared>, conn: &Smb2Conn, dir: &str, owner: [u8; 16], clear: u32) {
    let req_key = conn.lease_keys.get(&owner).copied();
    if let Some((key, old, new, epoch, outbound, crypto)) =
        server
            .leases
            .break_conflict(dir, (conn.session_id, owner), req_key, clear)
    {
        send_lease_break(&outbound, &crypto, key, old, new, epoch);
    }
}

/// Break a directory lease and wait (briefly) for the holder to acknowledge,
/// as a HANDLE-caching break requires before the conflicting operation may
/// proceed ([MS-SMB2] §3.3.1.4).
pub(crate) async fn break_dir_lease_wait(
    server: &Arc<ServerShared>,
    conn: &Smb2Conn,
    dir: &str,
    owner: [u8; 16],
    clear: u32,
) {
    let req_key = conn.lease_keys.get(&owner).copied();
    if let Some((key, old, new, epoch, outbound, crypto)) =
        server
            .leases
            .break_conflict(dir, (conn.session_id, owner), req_key, clear)
    {
        let rx = server.leases.register_ack_wait(key);
        send_lease_break(&outbound, &crypto, key, old, new, epoch);
        const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let _ = tokio::time::timeout(ACK_TIMEOUT, rx).await;
    }
}

/// The parent directory portion of a normalized share-relative path, or the
/// share root (`""`) when the path has no parent component.
pub(crate) fn parent_dir(path: &str) -> &str {
    path.rsplit_once(['/', '\\']).map(|(p, _)| p).unwrap_or("")
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
    let frame = finalize_break(&holder.crypto, build_break_frame(&body));
    if holder.outbound.try_send(frame).is_ok() {
        counter!("smb_oplock_breaks_total").increment(1);
    }
}

/// Build a server-initiated OPLOCK_BREAK frame (unsolicited: MessageId all-ones,
/// sync header). Returned unsigned and unsealed.
fn build_break_frame(body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(hdr::LEN + body.len());
    f.extend_from_slice(&smb_proto_smb2::SMB2_MAGIC);
    f.extend_from_slice(&(hdr::LEN as u16).to_le_bytes()); // StructureSize
    f.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    f.extend_from_slice(&0u32.to_le_bytes()); // Status
    f.extend_from_slice(&ss::cmd::OPLOCK_BREAK.to_le_bytes());
    f.extend_from_slice(&0u16.to_le_bytes()); // CreditResponse
    f.extend_from_slice(&hdr_flags::SERVER_TO_REDIR.to_le_bytes()); // Flags
    f.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    f.extend_from_slice(&u64::MAX.to_le_bytes()); // MessageId (unsolicited)
    f.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    f.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    // Break notifications carry SessionId 0 ([MS-SMB2] §3.3.4.6/§3.3.4.7).
    f.extend_from_slice(&0u64.to_le_bytes());
    f.extend_from_slice(&[0u8; 16]); // Signature
    f.extend_from_slice(body);
    f
}

/// Seal an oplock/lease break for its holder. Break notifications carry
/// SessionId 0 and are sent unsigned ([MS-SMB2] §3.3.4.6); encrypted sessions
/// still wrap them in a transform header.
fn finalize_break(crypto: &crate::state::BreakCrypto, frame: Vec<u8>) -> Vec<u8> {
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

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) async fn read(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    server: &Arc<ServerShared>,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::ReadReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let len = (req.length as usize).min(1 << 20); // clamp to 1 MiB
    let (path, is_dir, can_read) = {
        let h = conn
            .handles
            .get(&req.file_id.0)
            .ok_or(Status::INVALID_HANDLE)?;
        (h.path.clone(), h.is_dir, h.can_read)
    };
    if is_dir || !can_read {
        return Err(Status::ACCESS_DENIED);
    }
    // An exclusive byte-range lock from another open blocks reads ([MS-FSA]).
    if server.locks.read_conflict(
        &path,
        req.offset,
        len as u64,
        (conn.session_id, req.file_id.0),
    ) {
        return Err(Status::FILE_LOCK_CONFLICT);
    }
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

pub(crate) async fn write(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    server: &Arc<ServerShared>,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::WriteReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let (path, is_dir, can_write) = {
        let h = conn
            .handles
            .get(&req.file_id.0)
            .ok_or(Status::INVALID_HANDLE)?;
        (h.path.clone(), h.is_dir, h.can_write)
    };
    if is_dir || !can_write {
        return Err(Status::ACCESS_DENIED);
    }
    // Byte-range lock enforcement ([MS-SMB2] §2.2.26 / [MS-FSA]).
    if server.locks.write_conflict(
        &path,
        req.offset,
        req.payload.len() as u64,
        (conn.session_id, req.file_id.0),
    ) {
        return Err(Status::FILE_LOCK_CONFLICT);
    }
    let Some(h) = conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) else {
        return Err(Status::INVALID_HANDLE);
    };
    if h.is_dir || !h.can_write {
        return Err(Status::ACCESS_DENIED);
    }
    let written = vfs
        .write(h, req.offset, &req.payload, false)
        .await
        .map_err(vfs_err)?;
    counter!("smb_bytes_written_total").increment(written);
    tracing::trace!(offset = req.offset, wrote = written, "write");
    // A write from a non-holder invalidates cached reads: break the lease to
    // NONE ([MS-SMB2] §3.3.4.7). A co-holder of the same lease key is exempt.
    let req_key = conn.lease_keys.get(&req.file_id.0).copied();
    if let Some((k, old, new, ep, out, crypto)) = server.leases.break_conflict(
        &path,
        (conn.session_id, req.file_id.0),
        req_key,
        c::lease::RWH,
    ) {
        send_lease_break(&out, &crypto, k, old, new, ep);
    }
    // Modifying a child updates directory metadata: revoke READ caching on any
    // directory lease held on the parent ([MS-SMB2] §3.3.1.4).
    break_dir_lease(server, conn, parent_dir(&path), req.file_id.0, c::lease::RH);
    Ok(c::build_write_resp(written as u32))
}

/// The outcome of an IOCTL: either a reply body to encode, or silence because
/// the connection is being terminated ([MS-SMB2] §3.3.5.15.12).
pub(crate) enum IoctlReply {
    Reply(Status, Vec<u8>),
    Silent,
}

/// IOCTL / FSCTL dispatch ([MS-SMB2] §3.3.5.15). Kept as a free function so the
/// typestate handler and its private FSCTL helpers all live in this module.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) async fn ioctl(
    conn: &mut Smb2Conn,
    server: &Arc<ServerShared>,
    tid: u32,
    buf: &[u8],
) -> IoctlReply {
    let Some(req) = c::IoctlReq::parse(buf) else {
        tracing::debug!("ioctl parse failed");
        return IoctlReply::Reply(Status::INVALID_PARAMETER, Vec::new());
    };
    tracing::debug!(ctl = format!("{:#010x}", req.ctl_code), "ioctl");
    let (status, body) = match req.ctl_code {
        // Echo the negotiated parameters back ([MS-SMB2] §3.3.5.15):
        // capabilities, server GUID, security mode and dialect.
        // Validate against the original NEGOTIATE and terminate the
        // connection on any mismatch — a downgrade attempt ([MS-SMB2]
        // §3.3.5.15.12). The request is invalid on 3.1.1, where
        // pre-auth integrity supersedes this exchange.
        c::fsctl::VALIDATE_NEGOTIATE_INFO => {
            let input = &req.input;
            let terminate = 'v: {
                if conn.dialect == Some(smb_proto_smb2::negotiate::DIALECT_311) {
                    break 'v true;
                }
                if input.len() < 24 || (req.max_output as usize) < 24 {
                    break 'v true;
                }
                let req_caps = u32::from_le_bytes(input[0..4].try_into().unwrap());
                if req_caps != conn.client_capabilities {
                    break 'v true;
                }
                if input[4..20] != conn.client_guid {
                    break 'v true;
                }
                let req_secmode = u16::from_le_bytes(input[20..22].try_into().unwrap());
                if req_secmode != conn.client_security_mode {
                    break 'v true;
                }
                let count = u16::from_le_bytes(input[22..24].try_into().unwrap()) as usize;
                let mut dialects = Vec::with_capacity(count);
                for i in 0..count {
                    match input.get(24 + i * 2..26 + i * 2) {
                        Some(s) => dialects.push(u16::from_le_bytes(s.try_into().unwrap())),
                        None => break 'v true,
                    }
                }
                const SUPPORTED: [u16; 5] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
                let gcd = dialects
                    .iter()
                    .copied()
                    .filter(|d| SUPPORTED.contains(d))
                    .max();
                gcd != conn.dialect
            };
            if terminate {
                conn.disconnect = true;
                return IoctlReply::Silent;
            }
            let mut out = Vec::with_capacity(24);
            // Echo the exact values from our NEGOTIATE response —
            // the client fails the exchange on any mismatch
            // ([MS-SMB2] §3.3.5.15).
            out.extend_from_slice(&conn.advertised_caps.to_le_bytes());
            out.extend_from_slice(&server.guid);
            let sec_mode = smb_proto_smb2::negotiate::SIGNING_ENABLED
                | if server.require_signing {
                    smb_proto_smb2::negotiate::SIGNING_REQUIRED
                } else {
                    0
                };
            out.extend_from_slice(&sec_mode.to_le_bytes()); // SecurityMode
            out.extend_from_slice(
                &conn
                    .dialect
                    .unwrap_or(smb_proto_smb2::negotiate::DIALECT_210)
                    .to_le_bytes(),
            );
            (
                Status::SUCCESS,
                c::build_ioctl_resp(req.file_id, req.ctl_code, &out),
            )
        }
        // Resiliency handshake carries no output data. Preserve the
        // handle like a durable open ([MS-SMB2] §3.3.5.15.9) so a later
        // SMB2_CREATE_DURABLE_HANDLE_RECONNECT can reclaim it.
        c::fsctl::LMR_REQUEST_RESILIENCY => {
            if let Some(open) = conn.handles.get(&req.file_id.0) {
                let timeout = req
                    .input
                    .get(0..4)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .filter(|t| *t != 0)
                    .unwrap_or(60_000);
                let access = if open.can_write {
                    0x001F_01FF
                } else {
                    0x0012_0089
                };
                let options = if open.is_dir { 0x1 } else { 0x40 };
                let entry = crate::state::DurableEntry {
                    persistent_id: req.file_id.0,
                    create_guid: [0u8; 16],
                    rel: open.rel.clone(),
                    is_dir: open.is_dir,
                    access,
                    options,
                    session_id: conn.session_id,
                    owner_user: conn.user.clone(),
                    client_guid: conn.client_guid,
                    lease_key: None,
                    persistent: false,
                    timeout,
                    deadline: std::time::Instant::now(),
                };
                conn.durable.insert(req.file_id.0, entry);
            }
            (
                Status::SUCCESS,
                c::build_ioctl_resp(req.file_id, req.ctl_code, &[]),
            )
        }
        // FSCTL_PIPE_TRANSACT (0x0011C017): the DCERPC PDU arrives
        // in the input buffer and the reply leaves in the output
        // buffer — this is how SMB2 clients speak RPC over named
        // pipes.
        c::fsctl::PIPE_TRANSACT => {
            let Some(pipe) = conn.pipes.get_mut(&req.file_id.0) else {
                tracing::debug!(pipes = conn.pipes.len(), "transact on non-pipe fid");
                return IoctlReply::Reply(Status::NOT_IMPLEMENTED, Vec::new());
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
            (
                Status::SUCCESS,
                c::build_ioctl_resp(req.file_id, req.ctl_code, &out),
            )
        }
        // Server-side copy: hand the client a resume key naming this
        // open so a later COPYCHUNK can use it as the source.
        c::fsctl::SRV_REQUEST_RESUME_KEY => {
            if !conn.handles.contains_key(&req.file_id.0) {
                return IoctlReply::Reply(Status::INVALID_HANDLE, Vec::new());
            }
            let mut key = [0u8; 24];
            key[..16].copy_from_slice(&req.file_id.0);
            key[16..24].copy_from_slice(&next_resume_nonce().to_le_bytes());
            conn.resume_keys.insert(key, req.file_id.0);
            (
                Status::SUCCESS,
                c::build_ioctl_resp(req.file_id, req.ctl_code, &c::build_resume_key_resp(&key)),
            )
        }
        // Server-side copy: read from the source open (named by the
        // resume key in the input) and write into this target handle.
        c::fsctl::SRV_COPYCHUNK | c::fsctl::SRV_COPYCHUNK_WRITE => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return IoctlReply::Reply(Status::INVALID_HANDLE, Vec::new()),
            };
            match do_copychunk(conn, vfs, &req).await {
                Ok(out) => {
                    counter!("smb_copychunk_bytes_total").increment(copychunk_total(&out) as u64);
                    (
                        Status::SUCCESS,
                        c::build_ioctl_resp(req.file_id, req.ctl_code, &out),
                    )
                }
                Err((status, out)) => {
                    let body = c::build_ioctl_resp(req.file_id, req.ctl_code, &out);
                    return IoctlReply::Reply(status, body);
                }
            }
        }
        // Linux files are implicitly sparse; accept the hint.
        c::fsctl::SET_SPARSE => (
            Status::SUCCESS,
            c::build_ioctl_resp(req.file_id, req.ctl_code, &[]),
        ),
        // FSCTL_FILE_LEVEL_TRIM ([MS-FSCC] §2.3.73): deallocate byte ranges. The
        // Key field MUST be zero; the trim is advisory, so every requested range
        // is reported as processed (§2.3.74).
        c::fsctl::FILE_LEVEL_TRIM => match c::parse_file_level_trim(&req.input) {
            Some((0, num_ranges)) => (
                Status::SUCCESS,
                c::build_ioctl_resp(
                    req.file_id,
                    req.ctl_code,
                    &c::build_file_level_trim_resp(num_ranges),
                ),
            ),
            _ => return IoctlReply::Reply(Status::INVALID_PARAMETER, Vec::new()),
        },
        // FSCTL_PIPE_WAIT ([MS-SMB2] §2.2.31.2): our named pipes are
        // always instantiable, so the wait completes immediately.
        c::fsctl::PIPE_WAIT => (
            Status::SUCCESS,
            c::build_ioctl_resp(req.file_id, req.ctl_code, &[]),
        ),
        // DFS is not offered on this standalone server: a referral
        // query for any path is answered STATUS_NOT_FOUND so the client
        // treats the path as non-DFS ([MS-DFSC] §3.1.5.4.2).
        c::fsctl::DFS_GET_REFERRALS => {
            return IoctlReply::Reply(Status::NOT_FOUND, Vec::new());
        }
        // Multichannel interface discovery ([MS-SMB2] §3.3.5.15.4):
        // report the server's network interfaces so the client may open
        // additional channels for the session.
        c::fsctl::QUERY_NETWORK_INTERFACE_INFO => {
            let out = network_interface_info();
            (
                Status::SUCCESS,
                c::build_ioctl_resp(req.file_id, req.ctl_code, &out),
            )
        }
        // Zero a byte range in the target handle ([MS-FSCC] §2.3.79).
        c::fsctl::SET_ZERO_DATA => {
            let vfs = match share_vfs(server, conn, tid) {
                Some(v) => v,
                None => return IoctlReply::Reply(Status::INVALID_HANDLE, Vec::new()),
            };
            let Some((start, end)) = c::parse_zero_data(&req.input).filter(|(s, e)| e >= s) else {
                return IoctlReply::Reply(Status::INVALID_PARAMETER, Vec::new());
            };
            let Some(h) = conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) else {
                return IoctlReply::Reply(Status::INVALID_HANDLE, Vec::new());
            };
            match vfs.zero_range(h, start, end - start).await {
                Ok(()) => {
                    counter!("smb_zeroed_bytes_total").increment(end - start);
                    (
                        Status::SUCCESS,
                        c::build_ioctl_resp(req.file_id, req.ctl_code, &[]),
                    )
                }
                Err(e) => (vfs_err(e), Vec::new()),
            }
        }
        _ => (Status::NOT_IMPLEMENTED, Vec::new()),
    };
    IoctlReply::Reply(status, body)
}

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) async fn close(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Vec<u8>, Status> {
    let req = c::CloseReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let Some(mut h) = conn.handles.remove(&req.file_id.0) else {
        return Err(Status::INVALID_HANDLE);
    };
    conn.searches.remove(&req.file_id.0);
    conn.lease_keys.remove(&req.file_id.0);
    let meta = vfs.stat(&h.path).await.ok().unwrap_or_default();
    vfs.close(h).await.map_err(vfs_err)?;
    counter!("smb_closes_total").increment(1);
    Ok(c::build_close_resp(
        [
            meta.times[0].0,
            meta.times[1].0,
            meta.times[2].0,
            meta.times[3].0,
        ],
        meta.alloc,
        meta.eof,
        meta.attrs.0,
    ))
}

pub(crate) fn close_all_handles(conn: &mut Smb2Conn) {
    conn.handles.clear();
    conn.pipes.clear();
}

// ---------------- Named pipes (IPC$) ----------------

/// True when the tree behind `tid` is the virtual IPC$ share.
pub(crate) fn share_is_ipc(server: &Arc<ServerShared>, conn: &Smb2Conn, tid: u32) -> bool {
    conn.trees
        .get(&tid)
        .and_then(|n| server.shares.get(n))
        .map(|s| s.is_ipc)
        .unwrap_or(false)
}

/// True when the tree behind `tid` is a continuously-available share, which may
/// grant persistent handles ([MS-SMB2] §3.3.5.9.11).
pub(crate) fn share_is_ca(server: &Arc<ServerShared>, conn: &Smb2Conn, tid: u32) -> bool {
    conn.trees
        .get(&tid)
        .and_then(|n| server.shares.get(n))
        .map(|s| s.ca)
        .unwrap_or(false)
}

/// Known pipe names served on IPC$.
const KNOWN_PIPES: &[&str] = &["srvsvc", "wkssvc", "lanman", "netlogon"];

/// Open a virtual pipe; `Err(FILE_NOT_FOUND)` for unknown names.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) fn pipe_create(conn: &mut Smb2Conn, buf: &[u8]) -> Result<Vec<u8>, Status> {
    let req = c::CreateReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    let name = req.name.trim_start_matches(['\\', '/']).to_lowercase();
    if !KNOWN_PIPES.contains(&name.as_str()) {
        return Err(Status::OBJECT_PATH_NOT_FOUND);
    }
    let fid_bytes = next_file_id();
    let fid = c::FileId(fid_bytes);
    conn.pipes
        .insert(fid_bytes, crate::srvsvc::Pipe::new(&name));
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
pub(crate) fn pipe_read(conn: &mut Smb2Conn, buf: &[u8]) -> Option<Vec<u8>> {
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
pub(crate) fn pipe_write(
    server: &Arc<ServerShared>,
    conn: &mut Smb2Conn,
    buf: &[u8],
) -> Option<Vec<u8>> {
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
pub(crate) fn pipe_close(conn: &mut Smb2Conn, buf: &[u8]) -> bool {
    c::CloseReq::parse(buf)
        .map(|r| conn.pipes.remove(&r.file_id.0).is_some())
        .unwrap_or(false)
}

// ---------------- QUERY_DIRECTORY ----------------

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) async fn query_directory(
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
            & (c::find_flags::RESTART_SCANS
                | c::find_flags::REOPEN
                | c::find_flags::SCAN
                | c::find_flags::INDEX_SPECIFIED)
            != 0;

    if restart {
        let dir_rel = {
            let h = conn
                .handles
                .get(&req.file_id.0)
                .ok_or(Status::INVALID_HANDLE)?;
            if !h.is_dir {
                // QUERY_DIRECTORY on a non-directory open ([MS-SMB2] §3.3.5.18).
                return Err(Status::INVALID_PARAMETER);
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

        let (_, name_pat) =
            crate::cmds::dir_cmds_split(&req.pattern.trim_start_matches(['\\', '/']));
        let entries = vfs.list(&dir_rel).await.map_err(vfs_err)?;
        // Windows precedes real children with "." (the directory itself) and
        // ".." (its parent) on a wildcard scan ([MS-FSCC] §2.4), so even an
        // empty directory yields these two entries. They pass through the same
        // pattern filter, so a non-matching pattern still excludes them.
        let dot_meta = vfs.stat(&dir_rel).await.map_err(vfs_err)?;
        let dots = [".", ".."].into_iter().map(|n| info::FindEntry {
            name: n.to_string(),
            meta: info::QueryMeta::from_vfs(&dot_meta),
        });
        let mut matched: Vec<info::FindEntry> = dots
            .chain(entries.into_iter().map(|e| info::FindEntry {
                name: e.name,
                meta: info::QueryMeta::from_vfs(&e.meta),
            }))
            .filter(|e| {
                name_pat.is_empty()
                    || crate::cmds::wildcard(&e.name.to_lowercase(), &name_pat.to_lowercase())
            })
            .collect();
        // Resume-by-index ([MS-SMB2] §2.2.33): skip to the requested ordinal.
        if req.flags & c::find_flags::INDEX_SPECIFIED != 0 && req.file_index > 0 {
            let skip = (req.file_index as usize).min(matched.len());
            matched.drain(..skip);
        }
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
    let out: Vec<info::FindEntry> = (0..take).filter_map(|_| queue.pop_front()).collect();

    if out.is_empty() {
        return Ok(None); // STATUS_NO_MORE_FILES
    }
    Ok(Some(info::encode_find_entries(&out, req.class)))
}

// ---------------- QUERY_INFO ----------------

pub(crate) async fn query_info(
    conn: &mut Smb2Conn,
    vfs: Arc<dyn smb_vfs::Vfs>,
    buf: &[u8],
) -> Result<Option<Vec<u8>>, Status> {
    let req = c::QueryInfoReq::parse(buf).ok_or(Status::INVALID_PARAMETER)?;
    match req.info_type {
        c::info_type::FILE => {
            let h = conn
                .handles
                .get(&req.file_id.0)
                .ok_or(Status::INVALID_HANDLE)?;
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
            let name = if req.class == info::file_class::NORMALIZED_NAME {
                // Normalized name is the full share-relative path ([MS-FSCC]
                // §2.4.NormalizedName): no leading separator, backslash-joined.
                h.rel.trim_start_matches(['\\', '/']).replace('/', "\\")
            } else {
                h.rel.rsplit(['\\', '/']).next().unwrap_or("").to_string()
            };
            info::encode_file_info(req.class, &qm, &name)
                .map(Some)
                .ok_or(Status::NOT_IMPLEMENTED)
        }
        c::info_type::FS => info::encode_fs_info(req.class)
            .map(Some)
            .ok_or(Status::NOT_IMPLEMENTED),
        c::info_type::SECURITY => {
            let h = conn
                .handles
                .get(&req.file_id.0)
                .ok_or(Status::INVALID_HANDLE)?;
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
        // Disk quotas are not tracked on this volume ([MS-FSCC] §2.4.33):
        // report the standard "quotas not enabled" status.
        c::info_type::QUOTA => Err(Status::INVALID_DEVICE_REQUEST),
        _ => Ok(None),
    }
}

// ---------------- SET_INFO ----------------

pub(crate) async fn set_info(
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
            let h = conn
                .handles
                .get(&req.file_id.0)
                .ok_or(Status::INVALID_HANDLE)?;
            vfs.set_security(&h.path, &req.buffer)
                .await
                .map_err(vfs_err)
        }
        // Disk quotas are not tracked on this volume ([MS-FSCC] §2.4.33).
        c::info_type::QUOTA => Err(Status::INVALID_DEVICE_REQUEST),
        _ => Err(Status::NOT_IMPLEMENTED),
    }
}

// ---------------- helpers ----------------

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn g16(b: &[u8], o: usize) -> u16 {
    b.get(o..o + size_of::<u16>())
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .unwrap_or(0)
}

fn g32(b: &[u8], o: usize) -> u32 {
    b.get(o..o + size_of::<u32>())
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

/// Resolve the VFS backing `tid`, mirroring the SMB1 path (share by name,
/// unknown trees rejected before handlers run).
pub(crate) fn share_vfs(
    server: &Arc<ServerShared>,
    conn: &Smb2Conn,
    tid: u32,
) -> Option<Arc<dyn smb_vfs::Vfs>> {
    conn.trees
        .get(&tid)
        .and_then(|n| server.shares.get(n))
        .map(|s| s.vfs.clone())
}

/// Server-side-copy nonce appended to a resume key so repeated keys on one
/// open stay distinct.
fn next_resume_nonce() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0x5253_554d_4b45_5900);
    N.fetch_add(1, Ordering::Relaxed)
}

/// Read the TotalBytesWritten field out of a SRV_COPYCHUNK_RESPONSE body.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
        let limits =
            c::build_copychunk_resp(lim::MAX_CHUNKS, lim::MAX_CHUNK_SIZE, lim::MAX_TOTAL_SIZE);
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
            let src = conn
                .handles
                .get_mut(&src_fid)
                .ok_or((Status::INVALID_HANDLE, Vec::new()))?;
            vfs.read(src, k.source_offset, k.length as usize)
                .await
                .map_err(|e| (vfs_err(e), Vec::new()))?
        };
        let tgt = conn
            .handles
            .get_mut(&tgt_fid)
            .ok_or((Status::INVALID_HANDLE, Vec::new()))?;
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

pub(crate) fn vfs_err(e: smb_vfs::VfsError) -> Status {
    use smb_vfs::VfsError as E;
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

/// Build the generic ERROR response body ([MS-SMB2] §2.2.2): StructureSize
/// 9 with no error data. Every failed command carries this so clients can
/// parse the frame (a bare header breaks their compound parser). The body
/// is padded to the structure's declared 8-byte footprint.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
pub(crate) fn error_resp() -> Vec<u8> {
    let mut b = Vec::with_capacity(8);
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.push(0); // Reserved
    b.push(0); // ByteCount
    b.resize(8, 0); // ErrorData area (empty, padded)
    b
}

/// Build a 64-byte SMB2 response header + body, echoing MessageId/TreeId
/// and stamping the effective session id ([MS-SMB2] §3.3.4.1).
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 wire serialization
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
    // Honor the client's CreditRequest ([MS-SMB2] §3.3.1.2) so it can build a
    // credit window large enough for multi-credit (>64 KiB) reads/writes; the
    // grant is floored at the charge and capped to bound outstanding credits.
    let grant = req.credits.max(req.credit_charge).max(1).min(512);
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
        let f = build_async_frame(
            0xABCD,
            42,
            7,
            ss::cmd::CHANGE_NOTIFY,
            Status::PENDING,
            &[0u8; 8],
        );
        assert_eq!(&f[0..4], &smb_proto_smb2::SMB2_MAGIC);
        let flags = u32::from_le_bytes(f[16..20].try_into().unwrap());
        assert_eq!(flags & 0x2, 0x2, "ASYNC_COMMAND set");
        assert_eq!(flags & 0x1, 0x1, "SERVER_TO_REDIR set");
        assert_eq!(
            u64::from_le_bytes(f[24..32].try_into().unwrap()),
            42,
            "MessageId"
        );
        assert_eq!(
            u64::from_le_bytes(f[32..40].try_into().unwrap()),
            7,
            "AsyncId"
        );
        assert_eq!(
            u64::from_le_bytes(f[40..48].try_into().unwrap()),
            0xABCD,
            "SessionId"
        );
        assert_eq!(
            u32::from_le_bytes(f[8..12].try_into().unwrap()),
            Status::PENDING.raw()
        );
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
                watch_one_event(
                    &path,
                    false,
                    smb_proto_smb2::commands::notify_filter::FILE_NAME,
                    &mut rx,
                )
                .await
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

    /// A tree watch (`watch_tree`) fires on a file created in a subdirectory and
    /// names it relative to the watched root.
    #[test]
    fn recursive_watch_reports_subdir_file() {
        tokio_uring::start(async {
            let dir =
                std::env::temp_dir().join(format!("rustsmb_notify_rec_{}", std::process::id()));
            let sub = dir.join("nested");
            std::fs::create_dir_all(&sub).unwrap();
            let path = dir.to_string_lossy().into_owned();

            let (_tx, mut rx) = oneshot::channel();
            let watch = tokio_uring::spawn(async move {
                watch_one_event(
                    &path,
                    true,
                    smb_proto_smb2::commands::notify_filter::FILE_NAME,
                    &mut rx,
                )
                .await
            });
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            std::fs::write(sub.join("deep.txt"), b"hi").unwrap();

            let events = watch.await.unwrap().expect("subdir event fired");
            assert_eq!(events[0].0, smb_proto_smb2::commands::notify_action::ADDED);
            assert_eq!(
                events[0].1, "nested\\deep.txt",
                "named relative to watch root"
            );
            std::fs::remove_dir_all(&dir).ok();
        });
    }

    /// Cancelling the watch resolves the watcher with no events.
    #[test]
    fn cancel_stops_watch() {
        tokio_uring::start(async {
            let dir =
                std::env::temp_dir().join(format!("rustsmb_notify_cancel_{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.to_string_lossy().into_owned();

            let (tx, mut rx) = oneshot::channel();
            let watch = tokio_uring::spawn(async move {
                watch_one_event(
                    &path,
                    false,
                    smb_proto_smb2::commands::notify_filter::FILE_NAME,
                    &mut rx,
                )
                .await
            });
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            tx.send(Status::CANCELLED).unwrap();
            assert!(
                watch.await.unwrap().is_err(),
                "cancelled watch yields no events"
            );
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
            let (src, _m, _a) = vfs
                .create("src.txt", false, 0x8000_0000, 1, 0, 0)
                .await
                .unwrap();
            let (dst, _m, _a) = vfs
                .create("dst.txt", false, 0x4000_0000, 1, 0, 0)
                .await
                .unwrap();
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
            let out = do_copychunk(&mut conn, vfs.clone(), &req)
                .await
                .expect("copychunk");
            assert_eq!(&out[0..4], &1u32.to_le_bytes(), "ChunksWritten");
            assert_eq!(&out[8..12], &21u32.to_le_bytes(), "TotalBytesWritten");

            let dst = conn.handles.remove(&dst_fid).unwrap();
            vfs.close(dst).await.unwrap();
            assert_eq!(
                std::fs::read(dir.join("dst.txt")).unwrap(),
                b"hello copychunk world"
            );
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
            assert_eq!(
                &err.1[4..8],
                &lim::MAX_CHUNK_SIZE.to_le_bytes(),
                "limits echoed"
            );
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
            let (f, _m, _a) = vfs
                .create("z.bin", false, 0x4000_0000, 1, 0, 0)
                .await
                .unwrap();
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
            Share {
                name: "public".into(),
                root: dir.to_path_buf(),
                vfs,
                is_ipc: false,
                encrypt: false,
                compress: false,
                ca: false,
            },
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
            durables: Arc::new(smb_handle_store::MemStore::new()),
            sessions: Arc::new(SessionTable::new()),
            app_instances: Arc::new(AppInstanceTable::new()),
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
                false,
                &create_request("shared.bin", c::oplock::BATCH, access, share),
            )
            .await
            .unwrap();
            assert_eq!(
                resp_a[2],
                c::oplock::EXCLUSIVE,
                "sole opener granted exclusive"
            );

            let (tx_b, _rx_b) = mpsc::channel(8);
            let mut conn_b = Smb2Conn::new([0u8; 8], tx_b);
            conn_b.session_id = 2;
            let resp_b = create(
                &mut conn_b,
                vfs.clone(),
                &server,
                false,
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
            Share {
                name: "public".into(),
                root: dir.to_path_buf(),
                vfs,
                is_ipc: false,
                encrypt: false,
                compress: false,
                ca: false,
            },
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
            durables: Arc::new(smb_handle_store::MemStore::new()),
            sessions: Arc::new(SessionTable::new()),
            app_instances: Arc::new(AppInstanceTable::new()),
        })
    }

    /// Build a CREATE request that requests a v1 lease via an `RqLs` context.
    fn create_request_lease(
        name: &str,
        key: [u8; 16],
        state: u32,
        access: u32,
        share: u32,
    ) -> Vec<u8> {
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
                false,
                &create_request_lease("leased.bin", k1, c::lease::RWH, access, share),
            )
            .await
            .unwrap();
            assert_eq!(resp_a[2], c::oplock::LEASE, "response is a lease grant");
            assert_eq!(
                granted_state(&resp_a),
                c::lease::RWH,
                "sole opener gets RWH"
            );

            let (tx_b, _rx_b) = mpsc::channel(8);
            let mut conn_b = Smb2Conn::new([0u8; 8], tx_b);
            conn_b.session_id = 2;
            let resp_b = create(
                &mut conn_b,
                vfs.clone(),
                &server,
                false,
                false,
                &create_request_lease("leased.bin", k2, c::lease::RWH, access, share),
            )
            .await
            .unwrap();
            assert_eq!(
                granted_state(&resp_b),
                c::lease::RH,
                "contender gets read+handle"
            );

            let brk = rx_a.try_recv().expect("lease break delivered to A");
            assert_eq!(
                u16::from_le_bytes([brk[12], brk[13]]),
                ss::cmd::OPLOCK_BREAK,
                "break rides the OPLOCK_BREAK command",
            );
            assert_eq!(
                u16::from_le_bytes([brk[64], brk[65]]),
                44,
                "lease-break StructureSize"
            );
            assert_eq!(&brk[72..88], &k1, "names holder A's lease key");
            assert_eq!(
                u32::from_le_bytes(brk[88..92].try_into().unwrap()),
                c::lease::RWH,
                "current"
            );
            assert_eq!(
                u32::from_le_bytes(brk[92..96].try_into().unwrap()),
                c::lease::RH,
                "new"
            );

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
            let _ = create(
                &mut conn_a,
                vfs.clone(),
                &server,
                false,
                false,
                &create_request_lease("f.bin", key, c::lease::RWH, access, share),
            )
            .await
            .unwrap();

            let (tx_b, _rx_b) = mpsc::channel(8);
            let mut conn_b = Smb2Conn::new([0u8; 8], tx_b);
            conn_b.session_id = 2;
            let resp_b = create(
                &mut conn_b,
                vfs.clone(),
                &server,
                false,
                false,
                &create_request_lease("f.bin", key, c::lease::RWH, access, share),
            )
            .await
            .unwrap();

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

    fn query_info_frame(
        info_type: u8,
        class: u8,
        output_len: u32,
        additional: u32,
        fid: [u8; 16],
    ) -> Vec<u8> {
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

    fn set_info_frame(
        info_type: u8,
        class: u8,
        additional: u32,
        fid: [u8; 16],
        buffer: &[u8],
    ) -> Vec<u8> {
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
            let q = query_info_frame(
                c::info_type::SECURITY,
                0,
                4096,
                crate::security::sec_info::DEFAULT,
                fid,
            );
            let out = query_info(&mut conn, vfs.clone(), &q)
                .await
                .unwrap()
                .unwrap();
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
            set_info(&mut conn, vfs.clone(), &s)
                .await
                .expect("set security");

            let q2 = query_info_frame(
                c::info_type::SECURITY,
                0,
                4096,
                crate::security::sec_info::OWNER,
                fid,
            );
            let out2 = query_info(&mut conn, vfs.clone(), &q2)
                .await
                .unwrap()
                .unwrap();
            let sd2 = SecurityDescriptor::from_bytes(&out2).expect("stored parse");
            assert_eq!(
                sd2.owner(),
                Some(&Sid::local_system()),
                "stored owner round-trips"
            );

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
            let (open, _m, _a) = vfs
                .create("s.bin", false, 0x8000_0000, 1, 0, 0)
                .await
                .unwrap();
            let fid = [2u8; 16];
            conn.handles.insert(fid, open);

            let q = query_info_frame(
                c::info_type::SECURITY,
                0,
                8,
                crate::security::sec_info::DEFAULT,
                fid,
            );
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
            Share {
                name: "public".into(),
                root: dir.to_path_buf(),
                vfs,
                is_ipc: false,
                encrypt: false,
                compress: false,
                ca: false,
            },
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
            durables: Arc::new(smb_handle_store::MemStore::new()),
            sessions: Arc::new(SessionTable::new()),
            app_instances: Arc::new(AppInstanceTable::new()),
        })
    }

    /// Build a CREATE frame carrying a single create-context (name, data).
    fn create_req_ctx(
        name: &str,
        access: u32,
        disp: u32,
        ctx_name: &[u8],
        ctx_data: &[u8],
    ) -> Vec<u8> {
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
            let mut frame = frame;
            frame[67] = c::oplock::BATCH; // durable requires a batch oplock
            let resp = create(&mut conn, vfs.clone(), &server, false, false, &frame)
                .await
                .unwrap();
            assert_ne!(
                u32::from_le_bytes(resp[80..84].try_into().unwrap()),
                0,
                "durable resp ctx"
            );
            assert_eq!(conn.durable.len(), 1, "durable handle recorded");
            let pid: [u8; 16] = resp[64..80].try_into().unwrap();

            // Simulate the connection dropping: preserve into the server table.
            for (_f, e) in conn.durable.drain() {
                let _ = server
                    .durables
                    .put(e.into_record(crate::state::now_ms()))
                    .await;
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
            let resp2 = create(&mut conn2, vfs.clone(), &server, false, false, &rframe)
                .await
                .expect("reconnect");
            let rid: [u8; 16] = resp2[64..80].try_into().unwrap();
            assert_eq!(rid, pid, "reconnect returns the persistent id");
            assert!(
                conn2.handles.contains_key(&pid),
                "handle reinstated on new connection"
            );

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
            let err = create(&mut conn, vfs.clone(), &server, false, false, &rframe)
                .await
                .unwrap_err();
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
        assert_eq!(
            u16::from_le_bytes(buf[24..26].try_into().unwrap()),
            2,
            "AF_INET"
        );
        assert_eq!(&buf[28..32], &[10, 0, 0, 5], "sin_addr");
        // Second entry terminates the chain and carries AF_INET6.
        assert_eq!(u32::from_le_bytes(buf[152..156].try_into().unwrap()), 0);
        assert_eq!(
            u16::from_le_bytes(buf[152 + 24..152 + 26].try_into().unwrap()),
            23,
            "AF_INET6"
        );
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;

    #[test]
    fn sign_then_verify_round_trips_and_detects_tamper() {
        let key = [0x42u8; 16];
        let dialect = Some(smb_proto_smb2::negotiate::DIALECT_311);
        let mut pdu = vec![0u8; 96];
        pdu[0..4].copy_from_slice(&smb_proto_smb2::SMB2_MAGIC);
        for (i, b) in pdu[64..].iter_mut().enumerate() {
            *b = i as u8; // arbitrary body bytes
        }
        sign_pdu(&mut pdu, &key, dialect);
        assert!(
            verify_pdu_signature(&pdu, &key, dialect),
            "valid signature verifies"
        );
        // Tamper with the body: verification must fail.
        pdu[70] ^= 0xFF;
        assert!(
            !verify_pdu_signature(&pdu, &key, dialect),
            "tampered body rejected"
        );
        // Wrong key: fails.
        pdu[70] ^= 0xFF;
        assert!(
            !verify_pdu_signature(&pdu, &[0u8; 16], dialect),
            "wrong key rejected"
        );
    }
}

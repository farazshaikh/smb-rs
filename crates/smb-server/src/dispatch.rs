//! Per-connection request context and async frame loop.
//!
//! [`IoContext`] bundles the refcounted server metadata a handler needs —
//! server config plus connection bookkeeping — together with the SMB command
//! currently being served. Command routing lives in [`crate::cmds`].

use std::sync::Arc;

use smb_proto::types::Status;
use smb_proto_smb1::consts;
use smb_proto_smb1::header::{build_response, parse_header, Header, RespBody, HDR_LEN};

use smb_transport::Transport;
use smb_proto_smb1::consts::flags2;

use metrics::{counter, histogram};

use crate::state::{next_uid, ServerShared, ConnState, Session};

/// Short alias used by command handlers.
pub type IoCtx<'a> = IoContext<'a>;

/// Bundled per-request context handed to every command handler.
pub struct IoContext<'a> {
    /// Refcounted global configuration and user database.
    pub server: Arc<ServerShared>,
    /// Connection bookkeeping (challenge, session, trees, handles…).
    pub conn: &'a mut ConnState,
}

/// A parsed view over one request body inside the received frame.
#[derive(Debug)]
pub struct ReqView<'a> {
    /// Request header (echoed into the response).
    pub hdr: Header,
    /// WordCount value.
    pub wct: usize,
    /// Parameter words as raw bytes.
    pub words: &'a [u8],
    /// ByteCount data section.
    pub data: &'a [u8],
    /// Absolute frame offset of ByteCount.
    pub bc_off_abs: usize,
    /// The complete received frame (needed by commands whose payloads are
    /// addressed with absolute offsets, e.g. WRITE_ANDX).
    pub frame: &'a [u8],
}

impl<'a> ReqView<'a> {
    /// True when FLAGS2_UNICODE is set on the request header.
    pub fn unicode(&self) -> bool {
        self.hdr.flags2 & flags2::UNICODE != 0
    }

    /// AndX successor command byte when chaining continues past this request.
    pub fn andx_command(&self) -> Option<u8> {
        if self.wct < 2 {
            return None;
        }
        self.words.first().copied().filter(|c| *c != 0xFF)
    }

    /// AndXOffset of the successor body relative to the SMB header start.
    pub fn andx_offset(&self) -> Option<usize> {
        if self.wct < 3 || self.andx_command().is_none() {
            return None;
        }
        Some(u16::from_le_bytes([
            *self.words.get(2)?,
            *self.words.get(3)?,
        ]) as usize)
    }
}

/// Serve one client connection until EOF or transport error.
pub async fn serve_client(server: Arc<crate::state::ServerShared>, mut transport: Box<dyn Transport>) {
    let challenge = rand_challenge();
    let mut conn = ConnState::new(challenge);

    let mut smb2_conn: Option<crate::smb2::Smb2Conn> = None;

    loop {
        let Some(frame) = (match transport.recv().await {
            Ok(Some(f)) => Some(f),
            Ok(None) | Err(_) => return,
        }) else {
            return;
        };
        if frame.0.len() < 4 {
            continue;
        }

        counter!("smb_nbss_frames_total").increment(1);

        // SMB2/3 frames (\xFESMB magic) and encrypted transform frames
        // (\xFD"SMB" — [MS-SMB2] §2.2.41).
        if frame.0[0] == 0xFE || frame.0[0] == 0xFD || conn.upgraded_smb2 {
            if smb2_conn.is_none() {
                smb2_conn = Some(crate::smb2::Smb2Conn::new(rand_challenge()));
            }
            let c2 = smb2_conn.as_mut().unwrap();
            let start = std::time::Instant::now();
            if let Some(resp) =
                crate::smb2::process_frame(&server, c2, &frame.0).await
            {
                histogram!("smb_frame_duration_us").record(start.elapsed().as_micros() as f64);
                counter!("smb_responses_total").increment(1);
                if transport.send(&resp).await.is_err() {
                    return;
                }
            }
            continue;
        }

        // SMB1 frames.
        if let Some(resp) = process_frame(&server, &mut conn, &frame.0).await {
            if transport.send(&resp).await.is_err() {
                return;
            }
        }
    }
}

/// Cryptographically random per-connection NTLM challenge.
pub fn rand_challenge_pub() -> [u8; 8] {
    rand_challenge()
}

/// Cryptographically random bytes (urandom with time fallback).
pub fn rand_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = nanos[i % 16];
    }
    buf
}

/// Cryptographically random per-connection NTLM challenge.
fn rand_challenge() -> [u8; 8] {
    use std::io::Read;
    let mut b = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut b).is_ok() {
            return b;
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_le_bytes();
    b.copy_from_slice(&nanos[..8]);
    b
}

/// Execute one frame and build its response (`None` to stay silent).
pub(crate) async fn process_frame(
    server: &Arc<crate::state::ServerShared>,
    conn: &mut ConnState,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let (hdr, wc_off) = parse_header(buf)?;

    // NT_CANCEL never produces a normal body exchange.
    if hdr.command == consts::COM_NT_CANCEL {
        return Some(build_response(&hdr, Status::CANCELLED, Vec::new()));
    }

    // Multi-protocol upgrade: only when client offers \xFESMB dialects.
    // Marks the connection so serve_client routes later frames through the
    // persistent SMB2 processor.
    if hdr.command == consts::COM_NEGOTIATE
        && !conn.upgraded_smb2
        && buf.windows(4).any(|w| w == [0xFE, b'S', b'M', b'B'])
    {
        if let Some(resp) = crate::smb2::handle_multiprotocol_negotiate(buf, &server.guid) {
            conn.upgraded_smb2 = true;
            tracing::info!("client upgraded to SMB2 via multi-protocol negotiate");
            return Some(resp);
        }
    }

    let wct = buf[wc_off] as usize;
    let bc_off_abs = wc_off + 1 + wct * 2;

    // Build the AndX chain view over this single frame buffer.
    let mut views: Vec<ReqView> = Vec::new();
    let mut off = wc_off;
    while off + 1 <= buf.len() {
        let cwct = buf[off] as usize;
        let cbc = off + 1 + cwct * 2;
        if cbc + 2 > buf.len() {
            break;
        }
        let words = &buf[off + 1..off + 1 + cwct * 2];
        views.push(ReqView {
            hdr: hdr.clone(),
            wct: cwct,
            words,
            data: &buf[cbc + 2..],
            bc_off_abs: cbc,
            frame: buf,
        });
        let next_cmd = words.first().copied().unwrap_or(0xFF);
        let next_off =
            u16::from_le_bytes([*words.get(2).unwrap_or(&0), *words.get(3).unwrap_or(&0)])
                as usize;
        off = if next_cmd != 0xFF && next_off > off && next_off < buf.len() {
            next_off
        } else {
            break;
        };
    }

    let mut io = IoContext { server: server.clone(), conn };
    let mut bodies: Vec<RespBody> = Vec::new();
    let mut last_status = Status::SUCCESS;
    let mut final_hdr = hdr.clone();

    for req in &views {
        match crate::cmds::dispatch_one(&mut io, req, &mut bodies).await {
            Ok(st) => last_status = st,
            Err(status) => {
                tracing::warn!(
                    cmd = format!("{:#06x}", req.hdr.command),
                    tid = format!("{:#06x}", req.hdr.tid),
                    uid = format!("{:#06x}", req.hdr.uid),
                    status = format!("{:08x}", status.raw()),
                    "handler error"
                );
                counter!("smb_handler_errors_total").increment(1);
                final_hdr = req.hdr.clone();
                last_status = status;
                bodies.clear();
                break;
            }
        }
    }

    Some(build_response(&final_hdr, last_status, bodies))
}


/// Record the authenticated session on the SMB1-side connection state.
fn io_conn_set_session(conn: &mut ConnState, user: String, guest: bool) {
    conn.session = Some(Session { user, guest, trees: Vec::new() });
}

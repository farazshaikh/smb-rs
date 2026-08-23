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

use crate::state::{next_uid, ServerShared, ConnState};

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

    loop {
        let Some(frame) = (match transport.recv().await {
            Ok(Some(f)) => Some(f),
            Ok(None) | Err(_) => return,
        }) else {
            return;
        };
        if frame.0.is_empty() {
            continue;
        }
        if let Some(resp) = process_frame(&server, &mut conn, &frame.0).await {
            if transport.send(&resp).await.is_err() {
                return;
            }
        }
    }
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
async fn process_frame(
    server: &Arc<crate::state::ServerShared>,
    conn: &mut ConnState,
    buf: &[u8],
) -> Option<Vec<u8>> {
    let (hdr, wc_off) = parse_header(buf)?;

    // NT_CANCEL never produces a normal body exchange.
    if hdr.command == consts::COM_NT_CANCEL {
        return Some(build_response(&hdr, Status::CANCELLED, Vec::new()));
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
                eprintln!(
                    "handler error: cmd=0x{:02x} tid={:#06x} uid={:#06x} -> {:08x}",
                    req.hdr.command, req.hdr.tid, req.hdr.uid, status.raw()
                );
                final_hdr = req.hdr.clone();
                last_status = status;
                bodies.clear();
                break;
            }
        }
    }

    Some(build_response(&final_hdr, last_status, bodies))
}


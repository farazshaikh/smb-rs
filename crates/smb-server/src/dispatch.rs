//! Per-connection request context and async frame loop.
//!
//! [`IoContext`] bundles the refcounted server metadata a handler needs —
//! server config plus connection bookkeeping — together with the SMB command
//! currently being served. Command routing lives in [`crate::cmds`].

use std::sync::Arc;

use smb_proto::types::Status;
use smb_proto_smb1::consts;
use smb_proto_smb1::header::{build_response, parse_header, Header, RespBody, HDR_LEN};

use smb_transport::{FrameSink, Transport};
use smb_proto_smb1::consts::flags2;

use metrics::{counter, histogram};
use tokio::sync::mpsc;

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
/// Drain the outbound frame queue into the connection's write half. Runs as a
/// dedicated task so background work can emit unsolicited frames (async
/// STATUS_PENDING completions, oplock/lease breaks, CHANGE_NOTIFY) while the
/// reader blocks on `recv`. Ends when every [`mpsc::Sender`] clone is dropped.
pub(crate) async fn writer_loop(
    mut writer: Box<dyn FrameSink>,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(frame) = out_rx.recv().await {
        if writer.send(&frame).await.is_err() {
            break;
        }
    }
}

pub async fn serve_client(server: Arc<crate::state::ServerShared>, transport: Box<dyn Transport>) {
    let (mut reader, writer) = transport.split();
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
    let writer_task = tokio_uring::spawn(writer_loop(writer, out_rx));

    {
        let challenge = rand_challenge();
        let mut conn = ConnState::new(challenge);
        let mut smb2_conn: Option<crate::smb2::Smb2Conn> = None;

        loop {
            let Some(frame) = (match reader.recv().await {
                Ok(Some(f)) => Some(f),
                Ok(None) | Err(_) => break,
            }) else {
                break;
            };
            if frame.0.len() < 4 {
                continue;
            }

            counter!("smb_nbss_frames_total").increment(1);

            // SMB2/3 frames (\xFESMB magic), encrypted transform frames
            // (\xFD"SMB" — [MS-SMB2] §2.2.41) and compressed transform frames
            // (\xFC"SMB" — §2.2.42).
            if frame.0[0] == 0xFE || frame.0[0] == 0xFD || frame.0[0] == 0xFC || conn.upgraded_smb2 {
                if smb2_conn.is_none() {
                    smb2_conn = Some(crate::smb2::Smb2Conn::new(rand_challenge(), out_tx.clone()));
                }
                let c2 = smb2_conn.as_mut().unwrap();
                // Decompress an SMB3 compressed transform before dispatch.
                let decompressed;
                let msg: &[u8] = if frame.0[0] == 0xFC {
                    match smb_proto_smb2::compress::decompress_message(&frame.0) {
                        Some(d) => {
                            decompressed = d;
                            &decompressed
                        }
                        None => continue,
                    }
                } else {
                    &frame.0
                };
                let start = std::time::Instant::now();
                if let Some(mut resp) = crate::smb2::process_frame(&server, c2, msg).await {
                    // Opportunistically compress large plaintext responses when
                    // the peer negotiated compression (never a sealed frame).
                    if let Some(algo) = c2.compress_algo {
                        if resp.len() > 1024 && resp.first() != Some(&0xFD) {
                            if let Some(packed) = smb_proto_smb2::compress::compress_message(&resp, algo) {
                                resp = packed;
                            }
                        }
                    }
                    histogram!("smb_frame_duration_us").record(start.elapsed().as_micros() as f64);
                    counter!("smb_responses_total").increment(1);
                    if out_tx.send(resp).await.is_err() {
                        break;
                    }
                }
                // A handler may ask to terminate the connection (e.g. a failed
                // FSCTL_VALIDATE_NEGOTIATE_INFO downgrade check, [MS-SMB2]
                // §3.3.5.15.12).
                if c2.disconnect {
                    break;
                }
                continue;
            }

            // SMB1 frames.
            if let Some(resp) = process_frame(&server, &mut conn, &frame.0).await {
                if out_tx.send(resp).await.is_err() {
                    break;
                }
            }
        }

        // Connection closing: drop any byte-range locks this session held.
        if let Some(c2) = &mut smb2_conn {
            if c2.session_id != 0 {
                server.locks.release_session(c2.session_id);
                server.share_modes.close_session(c2.session_id);
                server.oplocks.release_session(c2.session_id);
                server.leases.release_session(c2.session_id);
            }
            // Preserve durable handles so a later connection can reclaim them
            // ([MS-SMB2] §3.3.7.1).
            let now_ms = crate::state::now_ms();
            for (_fid, entry) in c2.durable.drain() {
                let _ = server.durables.put(entry.into_record(now_ms)).await;
            }
        }
    }

    // The read loop has ended: drop our sender so the writer task sees every
    // clone gone and shuts down, then join it.
    drop(out_tx);
    let _ = writer_task.await;
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

    // Multi-protocol upgrade ([MS-SMB2] §3.2.4.2): a client may send an SMB1
    // NEGOTIATE whose dialect list carries the "SMB 2.002"/"SMB 2.???" strings
    // (Windows clients do this), or embed the \xFESMB id. Either way, answer
    // with an SMB2 NEGOTIATE and route later frames through the SMB2 processor.
    if hdr.command == consts::COM_NEGOTIATE
        && !conn.upgraded_smb2
        && (buf.windows(4).any(|w| w == [0xFE, b'S', b'M', b'B'])
            || buf.windows(6).any(|w| w == b"SMB 2."))
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

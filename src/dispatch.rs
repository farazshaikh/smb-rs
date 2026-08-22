// Connection dispatcher: NBSS loop, AndX chain handling, command routing.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use crate::dirops;
use crate::files;
use crate::handlers;
use crate::message::*;
use crate::nbss;
use crate::smb::*;
use crate::state::*;

pub struct ConnCtx {
    pub server: Arc<ServerShared>,
    pub conn: Mutex<ConnState>,
}

fn rand_challenge() -> [u8; 8] {
    use std::io::Read;
    let mut b = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut b).is_ok() {
            return b;
        }
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos().to_le_bytes();
    b.copy_from_slice(&t[..8]);
    b
}

pub fn serve_client(server: Arc<ServerShared>, mut stream: TcpStream) {
    let ctx = Arc::new(ConnCtx {
        server,
        conn: Mutex::new(ConnState::new(rand_challenge())),
    });

    loop {
        use nbss::Frame;
        let frame = match nbss::read_frame(&mut stream) {
            Ok(Some(f)) => f,
            Ok(None) | Err(_) => {
                eprintln!("nbss: eof/err");
                return;
            }
        };
        let frame = match frame {
            Frame::SessionRequest => {
                eprintln!("nbss: session request -> positive response");
                if stream.write_all(&[0x82, 0, 0, 0]).is_err() {
                    return;
                }
                let _ = stream.flush();
                continue;
            }
            Frame::Keepalive => {
                eprintln!("nbss: keepalive");
                continue;
            }
            Frame::Message(m) => m,
        };

        let response = process_message(&ctx, &frame);
        if let Some(resp) = response {
            if nbss::write_frame(&mut stream, &resp).is_err() {
                return;
            }
        }
    }
}

fn process_message(ctx: &Arc<ConnCtx>, buf: &[u8]) -> Option<Vec<u8>> {
    // Parse header.
    let (hdr, wc_off) = match parse_header(buf) {
        Some(v) => v,
        None => return None,
    };
    let wct = buf[wc_off] as usize;
    let bc_off = wc_off + 1 + wct * 2;

    // NT_CANCEL is special-cased.
    if hdr.command == COM_NT_CANCEL {
        let req = Request { hdr, buf, wc_off, wct, bc_off };
        let resp = build_response(&req.hdr, Status::CANCELLED, Vec::new());
        return Some(resp);
    }

    // Execute first request and any AndX-chained requests.
    let mut chain: Vec<Request> = Vec::new();
    {
        let first = Request { hdr: hdr.clone(), buf, wc_off, wct, bc_off };
        chain.push(first);
        loop {
            let cur = chain.last().unwrap();
            match (cur.andx_command(), cur.andx_offset()) {
                (Some(cmd), Some(off)) if cmd != 0xFF && off > wc_off && off < buf.len() => {
                    match chained_request(buf, off) {
                        Some(next_req) => {
                            if next_req.wct == 0 && next_req.data().is_empty() && off >= buf.len() - 4 {
                                break;
                            }
                            chain.push(next_req);
                        }
                        None => break,
                    }
                }
                _ => break,
            }
        }
    }

    let mut bodies: Vec<RespBody> = Vec::new();
    let mut last_status = Status::SUCCESS;
    let mut final_hdr = hdr.clone();

    for req in &chain {
        let result = dispatch_one(ctx, req, &mut bodies);
        match result {
            Ok(status) => last_status = status,
            Err(status) => {
                eprintln!(
                    "handler error: cmd=0x{:02x} tid={:#06x} uid={:#06x} -> {:08x}",
                    req.hdr.command,
                    req.hdr.tid,
                    req.hdr.uid,
                    status.0
                );
                // Emit a bare error response for the failing command only.
                final_hdr = req.hdr.clone();
                last_status = status;
                bodies.clear();
                break;
            }
        }
    }
    // NOTE: the NEGOTIATE challenge is patched into the body before assembly.
    Some(build_response(&final_hdr, last_status, bodies))
}


/// Returns Ok(status_of_response) or Err(error status).
fn dispatch_one(
    ctx: &Arc<ConnCtx>,
    req: &Request,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let mut conn = ctx.conn.lock().map_err(|_| Status::UNSUCCESSFUL)?;
    let server = ctx.server.clone();

    // Session enforcement: most commands need an established session+tree.
    let needs_session = !matches!(
        req.hdr.command,
        COM_NEGOTIATE | COM_SESSION_SETUP_ANDX | COM_ECHO | COM_PROCESS_EXIT | COM_NT_CANCEL
    );
    // Null-session / unauthenticated client: map to guest when allowed
    // (mirrors "map to guest = bad user").
    if conn.session.is_none()
        && !conn.auth_pending
        && server.allow_guest
        && needs_session
    {
        let uid = if conn.uid != 0 { conn.uid } else { next_uid() };
        conn.uid = uid;
        conn.session = Some(Session {
            user: "nobody".to_string(),
            guest: true,
            trees: Vec::new(),
        });
    }
    if needs_session && conn.session.is_none() && !conn.auth_pending {
        return Err(Status::ACCESS_DENIED);
    }
    let needs_tree = !matches!(
        req.hdr.command,
        COM_NEGOTIATE
            | COM_SESSION_SETUP_ANDX
            | COM_ECHO
            | COM_LOGOFF_ANDX
            | COM_TREE_CONNECT_ANDX
            | COM_PROCESS_EXIT
            | COM_NT_CANCEL
    );

    if needs_tree && !conn.trees.contains_key(&req.hdr.tid) {
        return Err(Status::INVALID_HANDLE);
    }

    match req.hdr.command {
        COM_NEGOTIATE => {
            conn.negotiated = true;
            *bodies = {
                let guid = server.guid;
                handlers::handle_negotiate(req, &guid)
            };
            Ok(Status::SUCCESS)
        }
        COM_SESSION_SETUP_ANDX => {
            let (bs, _uid, _guest, st) = handlers::session_setup(&server, &mut conn, req)?;
            *bodies = bs;
            Ok(st)
        }
        COM_TREE_CONNECT_ANDX => {
            let bs = handlers::tree_connect(&server, &mut conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_TREE_DISCONNECT => {
            *bodies = handlers::tree_disconnect(&mut conn, req.hdr.tid);
            Ok(Status::SUCCESS)
        }
        COM_LOGOFF_ANDX => {
            // Close all handles/trees of this session.
            let fids: Vec<u16> = conn.handles.keys().copied().collect();
            for fid in fids {
                let _ = conn.close_fid(fid);
            }
            conn.session = None;
            *bodies = handlers::logoff(req);
            Ok(Status::SUCCESS)
        }
        COM_ECHO => {
            // Echo uses TID but not session.
            *bodies = handlers::echo(req);
            Ok(Status::SUCCESS)
        }
        COM_QUERY_INFORMATION_DISK => {
            let bs = handlers::query_disk(req, &conn).map_err(|e| e)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_NT_CREATE_ANDX => {
            let bs = files::nt_create(&server, &mut conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_READ_ANDX => {
            let bs = files::read_andx(&mut conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_WRITE_ANDX => {
            let bs = files::write_andx(&mut conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_CLOSE => {
            let bs = files::close(&mut conn, req);
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_FLUSH => {
            let bs = files::flush(&mut conn, req);
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_SEEK => {
            let bs = files::seek(&mut conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_LOCKING_ANDX => {
            let bs = files::locking_andx(&mut conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_LOCK_BYTE_RANGE | COM_UNLOCK_BYTE_RANGE => {
            *bodies = vec![RespBody::new(req.hdr.command, Vec::new(), Vec::new())];
            Ok(Status::SUCCESS)
        }
        COM_CREATE_DIRECTORY => {
            let bs = dirops::create_directory(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_DELETE_DIRECTORY => {
            let bs = dirops::delete_directory(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_CHECK_DIRECTORY => {
            let bs = dirops::check_directory(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_DELETE => {
            let bs = dirops::delete(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_RENAME => {
            let bs = dirops::rename(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_NT_RENAME => {
            let bs = dirops::nt_rename(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_QUERY_INFORMATION => {
            let bs = dirops::query_information(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_SET_INFORMATION => {
            let bs = dirops::set_information(&server, &conn, req)?;
            *bodies = bs;
            Ok(Status::SUCCESS)
        }
        COM_PROCESS_EXIT => {
            let fids: Vec<u16> = conn.handles.keys().copied().collect();
            for fid in fids {
                let _ = conn.close_fid(fid);
            }
            *bodies = vec![RespBody::new(COM_PROCESS_EXIT, Vec::new(), Vec::new())];
            Ok(Status::SUCCESS)
        }
        COM_TRANSACTION2 => handle_trans2(&server, &mut conn, req, bodies),
        COM_TRANSACTION | COM_OPEN_ANDX | COM_SEARCH | COM_READ | COM_WRITE | COM_OPEN | COM_CREATE | COM_NT_TRANSACT => {
            Err(Status::NOT_IMPLEMENTED)
        }
        _ => Err(Status::INVALID_DEVICE_REQUEST),
    }
}


fn handle_trans2(
    server: &Arc<ServerShared>,
    conn: &mut std::sync::MutexGuard<'_, ConnState>,
    req: &Request,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {
    let w = req.word_bytes();
    if w.len() < 30 {
        return Err(Status::INVALID_PARAMETER);
    }
    // TRANS2 request words (MS-CIFS 2.2.4.46):
    // vwv9 ParameterCount, vwv10 ParameterOffset, vwv12 DataCount, vwv13 DataOffset
    let pcount = u16::from_le_bytes([w[18], w[19]]) as usize;
    let poff = u16::from_le_bytes([w[20], w[21]]) as usize;
    let mut dcount = u16::from_le_bytes([w[24], w[25]]) as usize;
    let mut doff = u16::from_le_bytes([w[26], w[27]]) as usize;
    // Some clients (impacket) emit oversized/odd Data sections; clamp safely.
    if poff > req.buf.len() {
        return Err(Status::INVALID_PARAMETER);
    }
    if poff + pcount > req.buf.len() {
        return Err(Status::INVALID_PARAMETER);
    }
    if doff > req.buf.len() || doff + dcount > req.buf.len() {
        dcount = req.buf.len().saturating_sub(doff).min(dcount);
        let _ = dcount;
        // Keep going: request data is only needed for SET_FILE_INFO, where
        // bounds are re-checked by the handler.
    }
    let params_all = &req.buf[poff..poff + pcount];
    if params_all.is_empty() && w[26] == 0 {
        return Err(Status::INVALID_PARAMETER);
    }
    // Two client styles exist:
    //  A) SetupCount=0: subcommand is the first byte of the params buffer,
    //     followed by a pad byte.
    //  B) SetupCount>=1 (impacket): subcommand rides in Setup[0]; the params
    //     buffer contains only the fixed fields.
    let setup_count = w[26] as usize;
    let (subcmd, fixed, param_base) = if setup_count >= 1 {
        (
            w[28],
            params_all,
            poff,
        )
    } else {
        let sc = params_all[0];
        let rest = if params_all.len() > 1 && pcount >= 2 {
            &params_all[2..]
        } else {
            &params_all[1..]
        };
        (sc, rest, poff + 2)
    };
    let data_end = doff + dcount;
    let data: &[u8] = if dcount > 0 && data_end <= req.buf.len() && doff >= 32 {
        &req.buf[doff..data_end]
    } else {
        &[]
    };

    let subreq = SubReq {
        subcmd,
        params: fixed,
        data,
        param_base,
        data_base: doff,
        unicode: req.unicode(),
    };

    eprintln!("t2req: subcmd={:#06x} params={:02x?}", subcmd, &params_all[..pcount.min(28)]);
    let body = match subcmd as u16 {
        TRANS2_FIND_FIRST2 => crate::trans2::find_first2(server, conn, req.hdr.tid, &subreq)?,
        TRANS2_FIND_NEXT2 => crate::trans2::find_next2(conn, &subreq)?,
        TRANS2_QUERY_FS_INFO => crate::trans2::query_fs_info(server, conn, req.hdr.tid, &subreq)?,
        TRANS2_QUERY_PATH_INFO => {
            crate::trans2::query_path_info(server, conn, req.hdr.tid, &subreq)?
        }
        TRANS2_QUERY_FILE_INFO => crate::trans2::query_file_info(conn, &subreq)?,
        TRANS2_SET_FILE_INFO => crate::trans2::set_file_info(server, conn, req.hdr.tid, &subreq)?,
        TRANS2_SET_PATH_INFO => crate::trans2::set_path_info(server, conn, req.hdr.tid, &subreq)?,
        other => {
            eprintln!(
                "trans2: unsupported subcmd {:#06x} params={:02x?}",
                other,
                subreq.params
            );
            return Err(Status::INVALID_PARAMETER);
        }
    };
    *bodies = vec![body];
    Ok(Status::SUCCESS)
}

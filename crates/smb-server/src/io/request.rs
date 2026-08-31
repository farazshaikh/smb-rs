//! The command table (single source of truth) and the commands migrated onto the
//! typestate pipeline so far. Phase 0 wires only ECHO end to end to prove the
//! machinery; later phases add one line per command here.

use metrics::{counter, gauge};
use smb_proto::types::Status;
use smb_proto_smb2::commands::{
    self as c, ChangeNotifyReq, CloseReq, CreateReq, FlushReq, IoctlReq, LockReq, QueryDirReq,
    QueryInfoReq, ReadReq, SetInfoReq, WriteReq,
};
use smb_proto_smb2::session_setup::cmd;

use super::context::{Command, IoContext, Outcome, Resources};
use super::origin::{Bare, Solicited};
use super::state::Accepted;
use super::wire::Decode;

/// SMB2 ECHO request ([MS-SMB2] §2.2.28): no meaningful body.
#[derive(Debug)]
pub struct EchoReq;
impl Decode for EchoReq {
    const COMMAND: u16 = cmd::ECHO;
    fn decode(_frame: &[u8]) -> Result<Self, Status> {
        Ok(EchoReq)
    }
}

/// SMB2 TREE_DISCONNECT request ([MS-SMB2] §2.2.11): no fields we act on.
#[derive(Debug)]
pub struct TreeDisconnectReq;
impl Decode for TreeDisconnectReq {
    const COMMAND: u16 = cmd::TREE_DISCONNECT;
    fn decode(_frame: &[u8]) -> Result<Self, Status> {
        Ok(TreeDisconnectReq)
    }
}

/// SMB2 TREE_CONNECT request ([MS-SMB2] §2.2.9): the share path is parsed from
/// the frame by the handler, so the marker itself decodes nothing.
#[derive(Debug)]
pub struct TreeConnectReq;
impl Decode for TreeConnectReq {
    const COMMAND: u16 = cmd::TREE_CONNECT;
    fn decode(_frame: &[u8]) -> Result<Self, Status> {
        Ok(TreeConnectReq)
    }
}

/// SMB2 LOGOFF request ([MS-SMB2] §2.2.7): no fields we act on.
#[derive(Debug)]
pub struct LogoffReq;
impl Decode for LogoffReq {
    const COMMAND: u16 = cmd::LOGOFF;
    fn decode(_frame: &[u8]) -> Result<Self, Status> {
        Ok(LogoffReq)
    }
}

/// SMB2 CANCEL request ([MS-SMB2] §2.2.30): correlated by MessageId/AsyncId from
/// the header, so the body carries nothing we decode.
#[derive(Debug)]
pub struct CancelReq;
impl Decode for CancelReq {
    const COMMAND: u16 = cmd::CANCEL;
    fn decode(_frame: &[u8]) -> Result<Self, Status> {
        Ok(CancelReq)
    }
}

/// SMB2 OPLOCK_BREAK acknowledgement ([MS-SMB2] §2.2.24): command 18 carries an
/// oplock (StructureSize 24) or lease (StructureSize 36) ack, dispatched on the
/// size in the handler, so the marker itself decodes nothing.
#[derive(Debug)]
pub struct OplockBreakReq;
impl Decode for OplockBreakReq {
    const COMMAND: u16 = cmd::OPLOCK_BREAK;
    fn decode(_frame: &[u8]) -> Result<Self, Status> {
        Ok(OplockBreakReq)
    }
}

/// ECHO handler: a keep-alive, always answered SUCCESS ([MS-SMB2] §3.3.5.17).
pub struct EchoCmd;
impl Command for EchoCmd {
    type Request = EchoReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: EchoReq, _res: &mut Resources<'_>) -> Outcome {
        Outcome::Final(ctx.respond(Status::SUCCESS, c::build_echo_resp()))
    }
}

/// FLUSH handler ([MS-SMB2] §3.3.5.11): flush the open's backing file.
pub struct FlushCmd;
impl Command for FlushCmd {
    type Request = FlushReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, req: FlushReq, res: &mut Resources<'_>) -> Outcome {
        let tid = ctx.reply.tree_id;
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, tid) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        if let Some(h) = res.conn.handles.get_mut(&req.file_id.0).map(|b| &mut **b) {
            if let Err(e) = vfs.flush(h).await {
                return Outcome::Final(ctx.respond(crate::smb2::vfs_err(e), Vec::new()));
            }
        }
        Outcome::Final(ctx.respond(Status::SUCCESS, c::build_flush_resp()))
    }
}

/// TREE_DISCONNECT handler ([MS-SMB2] §3.3.5.8): idempotent tree teardown.
pub struct TreeDisconnectCmd;
impl Command for TreeDisconnectCmd {
    type Request = TreeDisconnectReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: TreeDisconnectReq, res: &mut Resources<'_>) -> Outcome {
        res.conn.trees.remove(&ctx.reply.tree_id);
        Outcome::Final(ctx.respond(Status::SUCCESS, c::build_tree_disconnect_resp()))
    }
}

/// LOGOFF handler ([MS-SMB2] §3.3.5.6): release the session's resources but keep
/// the session id and keys so this reply still frames/seals correctly.
pub struct LogoffCmd;
impl Command for LogoffCmd {
    type Request = LogoffReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: LogoffReq, res: &mut Resources<'_>) -> Outcome {
        let sid = res.conn.session_id;
        crate::smb2::close_all_handles(res.conn);
        res.server.locks.release_session(sid);
        res.server.share_modes.close_session(sid);
        res.server.oplocks.release_session(sid);
        res.server.leases.release_session(sid);
        res.server.sessions.remove(sid);
        res.conn.trees.clear();
        res.conn.searches.clear();
        if res.conn.authenticated {
            gauge!("smb_sessions_active").decrement(1.0);
        }
        res.conn.authenticated = false;
        counter!("smb_logoffs_total").increment(1);
        Outcome::Final(ctx.respond(Status::SUCCESS, c::build_logoff_resp()))
    }
}

/// READ handler ([MS-SMB2] §3.3.5.12): a pipe read on IPC$, else a file read.
pub struct ReadCmd;
impl Command for ReadCmd {
    type Request = ReadReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: ReadReq, res: &mut Resources<'_>) -> Outcome {
        if let Some(body) = crate::smb2::pipe_read(res.conn, res.frame) {
            return Outcome::Final(ctx.respond(Status::SUCCESS, body));
        }
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, ctx.reply.tree_id) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        match crate::smb2::read(res.conn, vfs, res.server, res.frame).await {
            Ok(body) => Outcome::Final(ctx.respond(Status::SUCCESS, body)),
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

/// WRITE handler ([MS-SMB2] §3.3.5.13): a pipe write on IPC$, else a file write.
pub struct WriteCmd;
impl Command for WriteCmd {
    type Request = WriteReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: WriteReq, res: &mut Resources<'_>) -> Outcome {
        if let Some(body) = crate::smb2::pipe_write(res.server, res.conn, res.frame) {
            return Outcome::Final(ctx.respond(Status::SUCCESS, body));
        }
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, ctx.reply.tree_id) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        match crate::smb2::write(res.conn, vfs, res.server, res.frame).await {
            Ok(body) => Outcome::Final(ctx.respond(Status::SUCCESS, body)),
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

/// CLOSE handler ([MS-SMB2] §3.3.5.10): closes a pipe handle, else a file handle
/// and tears down that open's notifies, byte-range locks, share mode, oplock,
/// lease, and durable-handle state.
pub struct CloseCmd;
impl Command for CloseCmd {
    type Request = CloseReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: CloseReq, res: &mut Resources<'_>) -> Outcome {
        if crate::smb2::pipe_close(res.conn, res.frame) {
            let body = c::build_close_resp([0u64; 4], 0, 0, 0);
            return Outcome::Final(ctx.respond(Status::SUCCESS, body));
        }
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, ctx.reply.tree_id) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        let close_path = CloseReq::parse(res.frame)
            .and_then(|r| res.conn.handles.get(&r.file_id.0).map(|h| (r.file_id.0, h.path.clone())));
        match crate::smb2::close(res.conn, vfs, res.frame).await {
            Ok(body) => {
                if let Some((fid, path)) = close_path {
                    complete_pending_notifies(res.conn, fid);
                    res.server.locks.release_owner((res.conn.session_id, fid));
                    res.server.share_modes.close(&path, (res.conn.session_id, fid));
                    res.server.oplocks.release(&path, (res.conn.session_id, fid));
                    res.server.leases.release(&path, (res.conn.session_id, fid));
                    res.conn.durable.remove(&fid);
                    let _ = res.server.durables.remove(&fid).await;
                }
                Outcome::Final(ctx.respond(Status::SUCCESS, body))
            }
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

/// Complete any pending CHANGE_NOTIFY on this handle with STATUS_NOTIFY_CLEANUP
/// ([MS-SMB2] §3.3.5.10) when its open is closed.
fn complete_pending_notifies(conn: &mut crate::smb2::Smb2Conn, fid: [u8; 16]) {
    let Some(ids) = conn.async_by_file.remove(&fid) else {
        return;
    };
    for aid in ids {
        conn.async_msgids.retain(|_, v| *v != aid);
        if let Some(tx) = conn.async_cancels.remove(&aid) {
            let _ = tx.send(Status::NOTIFY_CLEANUP);
        }
    }
}

/// QUERY_DIRECTORY handler ([MS-SMB2] §3.3.5.18): enumerates a directory handle.
pub struct QueryDirCmd;
impl Command for QueryDirCmd {
    type Request = QueryDirReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: QueryDirReq, res: &mut Resources<'_>) -> Outcome {
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, ctx.reply.tree_id) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        match crate::smb2::query_directory(res.conn, vfs, res.frame).await {
            Ok(Some(buffer)) => Outcome::Final(ctx.respond(Status::SUCCESS, c::build_info_resp(&buffer))),
            Ok(None) => Outcome::Final(ctx.respond(Status::NO_MORE_FILES, Vec::new())),
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

/// QUERY_INFO handler ([MS-SMB2] §3.3.5.20): file/filesystem/security info.
pub struct QueryInfoCmd;
impl Command for QueryInfoCmd {
    type Request = QueryInfoReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: QueryInfoReq, res: &mut Resources<'_>) -> Outcome {
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, ctx.reply.tree_id) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        match crate::smb2::query_info(res.conn, vfs, res.frame).await {
            Ok(Some(buffer)) => Outcome::Final(ctx.respond(Status::SUCCESS, c::build_info_resp(&buffer))),
            Ok(None) => Outcome::Final(ctx.respond(Status::NOT_IMPLEMENTED, Vec::new())),
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

/// SET_INFO handler ([MS-SMB2] §3.3.5.21): applies file/filesystem info changes.
pub struct SetInfoCmd;
impl Command for SetInfoCmd {
    type Request = SetInfoReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: SetInfoReq, res: &mut Resources<'_>) -> Outcome {
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, ctx.reply.tree_id) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        match crate::smb2::set_info(res.conn, vfs, res.frame).await {
            Ok(()) => Outcome::Final(ctx.respond(Status::SUCCESS, c::build_set_info_resp())),
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

/// CREATE handler ([MS-SMB2] §3.3.5.9): opens a named pipe on IPC$, else a file
/// or directory. A symlink in the path yields a Symbolic Link Error Response
/// ([MS-SMB2] §2.2.2.2.1); the heavy share-mode/oplock/lease/durable logic lives
/// in the existing create().
pub struct CreateCmd;
impl Command for CreateCmd {
    type Request = CreateReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: CreateReq, res: &mut Resources<'_>) -> Outcome {
        if crate::smb2::share_is_ipc(res.server, res.conn, ctx.reply.tree_id) {
            return match crate::smb2::pipe_create(res.conn, res.frame) {
                Ok(body) => Outcome::Final(ctx.respond(Status::SUCCESS, body)),
                Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
            };
        }
        let Some(vfs) = crate::smb2::share_vfs(res.server, res.conn, ctx.reply.tree_id) else {
            return Outcome::Final(ctx.respond(Status::INVALID_HANDLE, Vec::new()));
        };
        let signed = smb_proto_smb2::Header2::parse(res.frame)
            .map(|h| h.is_signed())
            .unwrap_or(false);
        match crate::smb2::create(res.conn, vfs, res.server, signed, res.frame).await {
            Ok(body) => Outcome::Final(ctx.respond(Status::SUCCESS, body)),
            Err(status) if status == Status::STOPPED_ON_SYMLINK => {
                let body = res.conn.symlink_error.take().unwrap_or_else(crate::smb2::error_resp);
                Outcome::Final(ctx.respond(status, body))
            }
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

/// IOCTL handler ([MS-SMB2] §3.3.5.15): FSCTL dispatch (validate-negotiate,
/// resiliency, pipe transact, server-side copy, zero-data, interface info, ...).
/// A downgrade-detected VALIDATE_NEGOTIATE_INFO terminates the connection and
/// yields no reply.
pub struct IoctlCmd;
impl Command for IoctlCmd {
    type Request = IoctlReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: IoctlReq, res: &mut Resources<'_>) -> Outcome {
        match crate::smb2::ioctl(res.conn, res.server, ctx.reply.tree_id, res.frame).await {
            crate::smb2::IoctlReply::Reply(status, body) => Outcome::Final(ctx.respond(status, body)),
            crate::smb2::IoctlReply::Silent => Outcome::Silent,
        }
    }
}

/// LOCK handler ([MS-SMB2] §3.3.5.14): a byte-range lock/unlock. A conflicting
/// blocking lock defers as [`Outcome::Interim`]; the parked waiter completes it
/// on the outbound queue when the range frees.
pub struct LockCmd;
impl Command for LockCmd {
    type Request = LockReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: LockReq, res: &mut Resources<'_>) -> Outcome {
        let Some(hdr) = smb_proto_smb2::Header2::parse(res.frame) else {
            return Outcome::Final(ctx.respond(Status::INVALID_PARAMETER, Vec::new()));
        };
        match crate::smb2::begin_lock(res.conn, res.server, &hdr, res.frame) {
            crate::smb2::AsyncStart::Reply(status, body) => Outcome::Final(ctx.respond(status, body)),
            crate::smb2::AsyncStart::Pending(async_id) => {
                let parked = ctx.defer(async_id);
                let interim = parked.interim(Status::PENDING, crate::smb2::error_resp());
                Outcome::Interim { parked, interim }
            }
        }
    }
}

/// CHANGE_NOTIFY handler ([MS-SMB2] §3.3.5.19): registers a directory watch and
/// defers as [`Outcome::Interim`]; the background watcher completes it when the
/// first change (or cancellation) arrives.
pub struct ChangeNotifyCmd;
impl Command for ChangeNotifyCmd {
    type Request = ChangeNotifyReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: ChangeNotifyReq, res: &mut Resources<'_>) -> Outcome {
        let Some(hdr) = smb_proto_smb2::Header2::parse(res.frame) else {
            return Outcome::Final(ctx.respond(Status::INVALID_PARAMETER, Vec::new()));
        };
        match crate::smb2::begin_change_notify(res.conn, &hdr, res.frame) {
            crate::smb2::AsyncStart::Reply(status, body) => Outcome::Final(ctx.respond(status, body)),
            crate::smb2::AsyncStart::Pending(async_id) => {
                let parked = ctx.defer(async_id);
                let interim = parked.interim(Status::PENDING, crate::smb2::error_resp());
                Outcome::Interim { parked, interim }
            }
        }
    }
}

/// CANCEL handler ([MS-SMB2] §3.3.5.16): signals the targeted pending op to
/// complete with STATUS_CANCELLED. CANCEL itself yields no reply.
pub struct CancelCmd;
impl Command for CancelCmd {
    type Request = CancelReq;
    async fn serve(_ctx: IoContext<Accepted, Bare>, _req: CancelReq, res: &mut Resources<'_>) -> Outcome {
        if let Some(hdr) = smb_proto_smb2::Header2::parse(res.frame) {
            crate::smb2::cancel(res.conn, &hdr, res.frame);
        }
        Outcome::Silent
    }
}

/// OPLOCK_BREAK handler ([MS-SMB2] §3.3.5.22): acknowledges an oplock or lease
/// break. Command 18 dispatches on StructureSize — 36 is a lease-break ack
/// (record the settled state), otherwise an oplock-break ack (echo the level).
pub struct OplockBreakCmd;
impl Command for OplockBreakCmd {
    type Request = OplockBreakReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: OplockBreakReq, res: &mut Resources<'_>) -> Outcome {
        let frame = res.frame;
        let structure_size = u16::from_le_bytes([*frame.get(64).unwrap_or(&0), *frame.get(65).unwrap_or(&0)]);
        if structure_size == 36 {
            return match c::LeaseBreakAck::parse(frame) {
                Some(ack) => {
                    res.server.leases.set_state(ack.key, ack.state);
                    Outcome::Final(ctx.respond(Status::SUCCESS, c::build_lease_break_resp(ack.key, ack.state)))
                }
                None => Outcome::Final(ctx.respond(Status::INVALID_PARAMETER, Vec::new())),
            };
        }
        match c::OplockBreakAck::parse(frame) {
            // The holder acknowledges a break; we already downgraded on our
            // side, so echo the settled level ([MS-SMB2] §3.3.5.22.2).
            Some(ack) => Outcome::Final(ctx.respond(Status::SUCCESS, c::build_oplock_break_resp(ack.file_id, ack.level))),
            None => Outcome::Final(ctx.respond(Status::INVALID_PARAMETER, Vec::new())),
        }
    }
}

/// TREE_CONNECT handler ([MS-SMB2] §3.3.5.7): resolves the share, installs a
/// fresh TreeId (surfaced to the reply header via conn.resp_tree_id), and
/// answers with the share's type.
pub struct TreeConnectCmd;
impl Command for TreeConnectCmd {
    type Request = TreeConnectReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: TreeConnectReq, res: &mut Resources<'_>) -> Outcome {
        match crate::smb2::tree_connect(res.server, res.conn, res.frame) {
            Ok((name, share_type)) => {
                let new_tid = crate::smb2::next_tree_id();
                res.conn.trees.insert(new_tid, name);
                res.conn.resp_tree_id = Some(new_tid);
                counter!("smb_tcons_total").increment(1);
                gauge!("smb_trees_active").increment(1.0);
                Outcome::Final(ctx.respond(Status::SUCCESS, c::build_tree_connect_resp(share_type)))
            }
            Err(status) => Outcome::Final(ctx.respond(status, Vec::new())),
        }
    }
}

// The command table (single source of truth). A row makes a command decodable;
// a row in `smb_dispatch!` (plus a Command impl) makes it handled.
smb_request_table! {
    Echo           = cmd::ECHO            => EchoReq;
    TreeConnect    = cmd::TREE_CONNECT    => TreeConnectReq;
    TreeDisconnect = cmd::TREE_DISCONNECT => TreeDisconnectReq;
    Logoff         = cmd::LOGOFF          => LogoffReq;
    Create         = cmd::CREATE          => CreateReq;
    Close          = cmd::CLOSE           => CloseReq;
    Flush          = cmd::FLUSH           => FlushReq;
    Read           = cmd::READ            => ReadReq;
    Write          = cmd::WRITE           => WriteReq;
    Lock           = cmd::LOCK            => LockReq;
    Ioctl          = cmd::IOCTL           => IoctlReq;
    QueryDir       = cmd::QUERY_DIRECTORY => QueryDirReq;
    ChangeNotify   = cmd::CHANGE_NOTIFY   => ChangeNotifyReq;
    QueryInfo      = cmd::QUERY_INFO      => QueryInfoReq;
    SetInfo        = cmd::SET_INFO        => SetInfoReq;
    Cancel         = cmd::CANCEL          => CancelReq;
    OplockBreak    = cmd::OPLOCK_BREAK    => OplockBreakReq;
}

smb_dispatch! {
    Echo           => EchoCmd;
    TreeConnect    => TreeConnectCmd;
    Flush          => FlushCmd;
    TreeDisconnect => TreeDisconnectCmd;
    Logoff         => LogoffCmd;
    Read           => ReadCmd;
    Write          => WriteCmd;
    Close          => CloseCmd;
    QueryDir       => QueryDirCmd;
    QueryInfo      => QueryInfoCmd;
    SetInfo        => SetInfoCmd;
    Ioctl          => IoctlCmd;
    Create         => CreateCmd;
    Lock           => LockCmd;
    ChangeNotify   => ChangeNotifyCmd;
    Cancel         => CancelCmd;
    OplockBreak    => OplockBreakCmd;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::wire::{ReplyHeader, SealIntent};

    fn reply(command: u16, message_id: u64) -> ReplyHeader {
        ReplyHeader {
            command,
            message_id,
            session_id: 1,
            tree_id: 1,
            credits: 1,
            seal: SealIntent::default(),
        }
    }

    #[test]
    fn accept_split_respond_moves_through_states() {
        // The pure typestate path: accept a request, split it out for a handler,
        // and produce a response — no server resources needed. Handlers that use
        // resources are covered by the MS suite / conformance integration.
        let req = SmbRequest::parse(cmd::ECHO, &[]).expect("decode echo");
        assert_eq!(req.command(), cmd::ECHO);
        let ctx = IoContext::accept(reply(cmd::ECHO, 7), req);
        let (ctx, req) = ctx.split();
        assert!(matches!(req, SmbRequest::Echo(_)));
        let resp = ctx.respond(Status::SUCCESS, vec![1, 2, 3]);
        assert_eq!(resp.status, Status::SUCCESS);
        assert_eq!(resp.reply.message_id, 7);
        assert_eq!(resp.body, vec![1, 2, 3]);
    }

    #[test]
    fn unknown_command_is_not_implemented() {
        assert_eq!(SmbRequest::parse(0xBEEF, &[]).unwrap_err(), Status::NOT_IMPLEMENTED);
    }

    #[test]
    fn every_migrated_command_routes_to_its_decoder() {
        // A command in the table routes to a decoder: on an empty frame the body
        // decoders reject with INVALID_PARAMETER; the body-less commands accept.
        for &code in &[
            cmd::CREATE, cmd::CLOSE, cmd::FLUSH, cmd::READ, cmd::WRITE, cmd::LOCK,
            cmd::IOCTL, cmd::QUERY_DIRECTORY, cmd::CHANGE_NOTIFY, cmd::QUERY_INFO, cmd::SET_INFO,
        ] {
            assert_eq!(
                SmbRequest::parse(code, &[]).unwrap_err(),
                Status::INVALID_PARAMETER,
                "command {code} should route to a decoder, not fall through",
            );
        }
        for &code in &[cmd::ECHO, cmd::TREE_DISCONNECT, cmd::LOGOFF] {
            assert!(SmbRequest::parse(code, &[]).is_ok());
        }
    }

    #[test]
    fn decode_command_codes_match_the_table() {
        assert_eq!(<CreateReq as Decode>::COMMAND, cmd::CREATE);
        assert_eq!(<ReadReq as Decode>::COMMAND, cmd::READ);
        assert_eq!(<WriteReq as Decode>::COMMAND, cmd::WRITE);
        assert_eq!(<LockReq as Decode>::COMMAND, cmd::LOCK);
        assert_eq!(<IoctlReq as Decode>::COMMAND, cmd::IOCTL);
        assert_eq!(<SetInfoReq as Decode>::COMMAND, cmd::SET_INFO);
    }
}

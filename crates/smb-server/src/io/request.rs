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

/// SMB2 LOGOFF request ([MS-SMB2] §2.2.7): no fields we act on.
#[derive(Debug)]
pub struct LogoffReq;
impl Decode for LogoffReq {
    const COMMAND: u16 = cmd::LOGOFF;
    fn decode(_frame: &[u8]) -> Result<Self, Status> {
        Ok(LogoffReq)
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

// The command table (single source of truth). A row makes a command decodable;
// a row in `smb_dispatch!` (plus a Command impl) makes it handled.
smb_request_table! {
    Echo           = cmd::ECHO            => EchoReq;
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
}

smb_dispatch! {
    Echo           => EchoCmd;
    Flush          => FlushCmd;
    TreeDisconnect => TreeDisconnectCmd;
    Logoff         => LogoffCmd;
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

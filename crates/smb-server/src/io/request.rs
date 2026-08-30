//! The command table (single source of truth) and the commands migrated onto the
//! typestate pipeline so far. Phase 0 wires only ECHO end to end to prove the
//! machinery; later phases add one line per command here.

use smb_proto::types::Status;
use smb_proto_smb2::session_setup::cmd;

use super::context::{Command, IoContext, Outcome};
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

/// ECHO handler: a keep-alive, always answered SUCCESS ([MS-SMB2] §3.3.5.17).
pub struct EchoCmd;

impl Command for EchoCmd {
    type Request = EchoReq;
    async fn serve(ctx: IoContext<Accepted, Bare>, _req: EchoReq) -> Outcome {
        Outcome::Final(ctx.respond(Status::SUCCESS, smb_proto_smb2::commands::build_echo_resp()))
    }
}

smb_commands! {
    Echo = cmd::ECHO => EchoReq, EchoCmd;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::wire::{ReplyHeader, SealIntent};

    /// Minimal executor: our Phase 0 handlers never truly pend, so a busy poll
    /// with the no-op waker resolves them immediately.
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll};
        let mut fut = std::pin::pin!(fut);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

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
    fn echo_flows_through_the_typestate() {
        let req = SmbRequest::parse(cmd::ECHO, &[]).expect("decode echo");
        assert_eq!(req.command(), cmd::ECHO);

        let ctx = IoContext::accept(reply(cmd::ECHO, 7), req);
        match block_on(dispatch(ctx)) {
            Outcome::Final(resp) => {
                assert_eq!(resp.status, Status::SUCCESS);
                assert_eq!(resp.reply.message_id, 7);
                assert!(!resp.body.is_empty(), "echo response carries a body");
            }
            other => panic!("expected Final, got {other:?}"),
        }
    }

    #[test]
    fn unknown_command_is_not_implemented() {
        assert_eq!(SmbRequest::parse(0xBEEF, &[]).unwrap_err(), Status::NOT_IMPLEMENTED);
    }
}

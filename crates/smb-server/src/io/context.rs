//! The [`IoContext`] typestate and the [`Command`] handler trait.
//!
//! `IoContext<S, O>` is the server's per-request work item, generic over its
//! lifecycle state `S` and origin `O`. Transitions consume `self` by value, so
//! the previous state becomes unusable — the borrow checker enforces the
//! request lifecycle. Everything here is static dispatch (see the plan's §12).

use smb_server_proto::types::Status;

use super::origin::{Bare, Origin, Solicited, Unsolicited};
use super::state::{Accepted, Pending};
use super::wire::{ReplyHeader, SmbResponse};
use super::SmbRequest;

/// Per-request access to the mutable connection and shared server state a
/// handler needs. Borrowed for the duration of one dispatch on the connection's
/// single thread, so no locking is required for the per-connection half.
pub struct Resources<'r> {
    /// Per-connection state (handles, session, credits, durable table…).
    pub conn: &'r mut crate::smb2::Smb2Conn,
    /// Server-wide shared state (shares, lock/oplock/lease tables, sessions…).
    pub server: &'r std::sync::Arc<crate::state::ServerShared>,
    /// The complete single-command frame, for handlers that read the raw body
    /// (e.g. WRITE payload) zero-copy.
    pub frame: &'r [u8],
}

/// The server's work item for one request (or one server event). Owns the reply
/// header and — while `Solicited` — the parsed request; parameterized by the
/// lifecycle state `S` and origin `O`.
#[derive(Debug)]
pub struct IoContext<S: super::IoState, O: Origin = Solicited> {
    /// Header the eventual reply is framed with.
    pub reply: ReplyHeader,
    /// Owned request payload for this origin (`SmbRequest` for `Solicited`,
    /// `()` otherwise). Accessed only through the state-appropriate methods.
    request: O::Request,
    /// Lifecycle state value (a ZST for data-less states; carries data for
    /// `Pending`).
    state: S,
}

impl IoContext<Accepted, Solicited> {
    /// Accept a parsed request for processing; the [`SmbRequest`] is moved in
    /// and owned by the context from here on.
    pub fn accept(reply: ReplyHeader, request: SmbRequest) -> Self {
        IoContext { reply, request, state: Accepted }
    }

    /// Split the request out to hand it to its concrete [`Command`] handler; the
    /// context keeps the reply header and becomes request-neutral (`Bare`).
    pub(crate) fn split(self) -> (IoContext<Accepted, Bare>, SmbRequest) {
        let ctx = IoContext { reply: self.reply, request: (), state: Accepted };
        (ctx, self.request)
    }
}

impl IoContext<Accepted, Unsolicited> {
    /// Build a request-less context for a server-initiated response.
    pub fn from_event(reply: ReplyHeader) -> Self {
        IoContext { reply, request: (), state: Accepted }
    }
}

impl<O: Origin> IoContext<Accepted, O> {
    /// Produce the terminal reply, consuming the context (the request payload is
    /// dropped). Reachable in the `Accepted` state for any origin.
    pub fn respond(self, status: Status, body: Vec<u8>) -> SmbResponse {
        SmbResponse { status, reply: self.reply, body }
    }
}

impl IoContext<Accepted, Bare> {
    /// Defer this request: park it as [`Pending`] so an async worker owns it and
    /// completes it later; the reader loop is never blocked.
    pub fn defer(self, async_id: u64) -> IoContext<Pending, Bare> {
        IoContext { reply: self.reply, request: (), state: Pending { async_id } }
    }
}

impl IoContext<Pending, Bare> {
    /// The async correlation id this deferred op was parked under.
    pub fn async_id(&self) -> u64 {
        self.state.async_id
    }

    /// Build the immediate interim reply for this deferred op without consuming
    /// the parked context ([MS-SMB2] §3.3.4.2). The worker still owns `self` and
    /// completes it later.
    pub fn interim(&self, status: Status, body: Vec<u8>) -> SmbResponse {
        SmbResponse { status, reply: self.reply.clone(), body }
    }

    /// Complete a deferred op with its final reply, consuming the parked context.
    /// Only callable in the `Pending` state, so a request cannot be completed
    /// unless it was actually deferred.
    pub fn complete(self, status: Status, body: Vec<u8>) -> SmbResponse {
        SmbResponse { status, reply: self.reply, body }
    }
}

/// The result of serving one accepted request. Encodes the final-vs-interim
/// distinction in the type system.
#[derive(Debug)]
pub enum Outcome {
    /// Terminal reply; the context was consumed.
    Final(SmbResponse),
    /// Interim STATUS_PENDING reply now; the final reply is owed later and the
    /// work is parked in the returned [`Pending`] context ([MS-SMB2] §3.3.4.2).
    Interim {
        /// The parked context the async worker will `complete`.
        parked: IoContext<Pending, Bare>,
        /// The interim reply to send immediately.
        interim: SmbResponse,
    },
    /// No reply at all (e.g. CANCEL of an unknown id, or a terminating check).
    Silent,
}

/// One command's server-side behaviour: map its owned request to an [`Outcome`],
/// using the connection/server [`Resources`]. Dispatched by a concrete `match`
/// (never as a trait object), so it uses native `async fn` and needs no boxed
/// future.
#[allow(async_fn_in_trait)]
pub trait Command {
    /// The request type this command decodes and consumes.
    type Request: super::Decode;
    /// Serve the request. The context is request-neutral (`Bare`) and owns
    /// everything except the request and the shared resources, passed alongside.
    async fn serve(
        ctx: IoContext<Accepted, Bare>,
        req: Self::Request,
        res: &mut Resources<'_>,
    ) -> Outcome;
}

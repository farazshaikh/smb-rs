//! Origin of an [`IoContext`](super::IoContext): whether it was triggered by a
//! client request or by a server event, which decides if it carries a request
//! payload and how its reply header is filled.

mod sealed {
    pub trait Sealed {}
}

/// Where an [`IoContext`](super::IoContext) came from. Sealed: the set of
/// origins is closed to this crate. `Request` is the owned payload the context
/// carries (`()` when there is none).
pub trait Origin: sealed::Sealed {
    /// The owned request payload for this origin.
    type Request;
}

/// Triggered by a client frame; carries the parsed [`SmbRequest`](super::SmbRequest)
/// and echoes the client's MessageId/SessionId/TreeId on reply.
#[derive(Debug)]
pub struct Solicited;

/// A request-neutral context: the request has been split out to its handler, so
/// the context carries only the shared bits and the reply header.
#[derive(Debug)]
pub struct Bare;

/// Triggered by a server event (oplock/lease break, CHANGE_NOTIFY cleanup); has
/// no request, and header fields are server-chosen ([MS-SMB2] §3.3.4.6).
#[derive(Debug)]
pub struct Unsolicited;

impl sealed::Sealed for Solicited {}
impl sealed::Sealed for Bare {}
impl sealed::Sealed for Unsolicited {}

impl Origin for Solicited {
    type Request = super::SmbRequest;
}
impl Origin for Bare {
    type Request = ();
}
impl Origin for Unsolicited {
    type Request = ();
}

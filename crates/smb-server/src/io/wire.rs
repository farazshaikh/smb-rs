//! Wire codecs and the response value: `Decode` (frame → typed request),
//! `Encode` (typed body → bytes), and the `SmbResponse`/`ReplyHeader` a handler
//! produces. Every response — solicited, interim, or unsolicited — is serialized
//! through one place so signing/sealing lives in a single site.

use smb_proto::types::Status;

/// Decode one single-command SMB2 frame into a typed request. Implemented per
/// command; dispatched statically by [`SmbRequest::parse`](super::SmbRequest).
pub trait Decode: Sized {
    /// The SMB2 command code this request decodes.
    const COMMAND: u16;
    /// Parse the request from its complete frame (header + body); the frame is
    /// borrowed, so payloads stay zero-copy.
    fn decode(frame: &[u8]) -> Result<Self, Status>;
}

/// Serialize a typed response body against a reply header.
pub trait Encode {
    /// Encode the response body (without the 64-byte SMB2 header).
    fn encode(&self, hdr: &ReplyHeader) -> Vec<u8>;
}

/// Whether a response must be signed and/or sealed. Computed once at `accept`
/// from the session/request so it is never threaded by hand.
#[derive(Debug, Clone, Copy, Default)]
pub struct SealIntent {
    /// Sign the response ([MS-SMB2] §3.3.4.1.1).
    pub sign: bool,
    /// Encrypt (seal) the response ([MS-SMB2] §3.3.4.1.4).
    pub seal: bool,
}

/// The header fields a reply echoes or sets, captured when the context is built.
#[derive(Debug, Clone)]
pub struct ReplyHeader {
    /// SMB2 command code.
    pub command: u16,
    /// MessageId echoed from the request (0 for some server events).
    pub message_id: u64,
    /// SessionId echoed (0 for e.g. a lease break, [MS-SMB2] §3.3.4.6).
    pub session_id: u64,
    /// TreeId echoed.
    pub tree_id: u32,
    /// Credits granted on this reply.
    pub credits: u16,
    /// Signing/sealing intent.
    pub seal: SealIntent,
}

/// A finished response: the status, the header it replies under, and the encoded
/// body. Solicited, interim, and unsolicited replies all converge on this type.
#[derive(Debug)]
pub struct SmbResponse {
    /// NT status of the reply.
    pub status: Status,
    /// Header this reply is framed with.
    pub reply: ReplyHeader,
    /// Encoded response body (without the 64-byte SMB2 header).
    pub body: Vec<u8>,
}

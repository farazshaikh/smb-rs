//! Async SMB message transport abstraction.
//!
//! A [`Transport`] moves complete SMB frames (the bytes between NBSS
//! headers, i.e. starting at the `\xFFSMB` / `\xFESMB` magic) over some
//! network or in-memory channel. The server dispatch is written against this
//! trait so it can be exercised without real sockets.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod mem;
#[cfg(test)]
mod tests;
pub mod tcp;

use async_trait::async_trait;

/// One complete SMB frame received from the wire.
#[derive(Debug)]
pub struct Frame(pub Vec<u8>);

/// Errors surfaced by transports.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Underlying I/O failure.
    #[error("transport i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Abstract bidirectional frame transport.
///
/// Implementations must preserve frame boundaries: each value returned by
/// [`Transport::recv`] is exactly one SMB frame.
#[async_trait]
pub trait Transport: Send {
    /// Receive the next frame. `Ok(None)` signals a clean end of stream.
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError>;

    /// Transmit one frame.
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;

    /// Human-readable peer description for logs.
    fn peer(&self) -> String;

    /// Split into independent read and write halves.
    ///
    /// The server drives the read half from its accept loop while a dedicated
    /// writer task drains an outbound queue into the write half. This lets
    /// background work (async STATUS_PENDING completions, oplock/lease breaks,
    /// CHANGE_NOTIFY) emit unsolicited frames without cancelling the blocking
    /// `recv` — critical because `recv` is not cancel-safe.
    fn split(self: Box<Self>) -> (Box<dyn FrameSource>, Box<dyn FrameSink>);
}

/// Read half of a split [`Transport`].
#[async_trait]
pub trait FrameSource: Send {
    /// Receive the next frame. `Ok(None)` signals a clean end of stream.
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError>;

    /// Human-readable peer description for logs.
    fn peer(&self) -> String;
}

/// Write half of a split [`Transport`]. Owned by the per-connection writer task.
#[async_trait]
pub trait FrameSink: Send {
    /// Transmit one frame.
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
}

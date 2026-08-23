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
}

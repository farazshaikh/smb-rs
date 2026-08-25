//! NBSS-over-TCP transport ([RFC 1002] session service, direct hosting on
//! port 445), built on `tokio_uring` for zero-copy io_uring networking.
//!
//! io_uring socket reads deliver *owned* buffers of arbitrary length, so the
//! reader keeps a carry-over buffer and hands out exact-length header/body
//! slices for NBSS framing. Because `TcpStream::read`/`write_all` take `&self`,
//! the read and write halves share one [`Rc<TcpStream>`]; concurrent read and
//! write on the same fd is safe under io_uring.

use async_trait::async_trait;
use std::io;
use std::rc::Rc;
use tokio_uring::net::TcpStream;

use crate::{Frame, FrameSink, FrameSource, Transport, TransportError};

/// NetBIOS session-service message types we care about ([RFC 1002] §4).
mod nb_type {
    /// Session message carrying an SMB PDU.
    pub const SESSION_MESSAGE: u8 = 0x00;
    /// Session request handshake (port 139 style; answered positively).
    pub const SESSION_REQUEST: u8 = 0x81;
    /// Positive session response.
    pub const POSITIVE_RESPONSE: u8 = 0x82;
}

/// Largest NBSS session-message payload we accept (2 MiB).
const MAX_FRAME: usize = 0x20_0000;
/// Per-read socket scratch size handed to io_uring.
const READ_CHUNK: usize = 64 * 1024;

/// Buffered NBSS reader over an io_uring TCP stream.
struct NbssReader {
    stream: Rc<TcpStream>,
    /// Bytes already read from the socket but not yet consumed by framing.
    carry: Vec<u8>,
}

impl std::fmt::Debug for NbssReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NbssReader").field("carry", &self.carry.len()).finish()
    }
}

impl NbssReader {
    fn new(stream: Rc<TcpStream>) -> Self {
        Self { stream, carry: Vec::new() }
    }

    /// Pull one more chunk from the socket into `carry`. Returns `false` at EOF.
    async fn fill(&mut self) -> Result<bool, TransportError> {
        let (res, chunk) = self.stream.read(vec![0u8; READ_CHUNK]).await;
        let n = res?;
        if n == 0 {
            return Ok(false);
        }
        self.carry.extend_from_slice(&chunk[..n]);
        Ok(true)
    }

    /// Take exactly `n` bytes, reading more as needed. `Ok(None)` at clean EOF.
    async fn take(&mut self, n: usize) -> Result<Option<Vec<u8>>, TransportError> {
        while self.carry.len() < n {
            if !self.fill().await? {
                return Ok(None);
            }
        }
        let rest = self.carry.split_off(n);
        Ok(Some(std::mem::replace(&mut self.carry, rest)))
    }

    /// Read one NBSS session-message frame, skipping control frames. When
    /// `answer` is `Some`, a legacy SESSION_REQUEST is answered positively
    /// (unified transport only; the split read half passes `None`).
    async fn next_frame(
        &mut self,
        mut answer: Option<&Rc<TcpStream>>,
    ) -> Result<Option<Frame>, TransportError> {
        loop {
            let hdr = match self.take(4).await? {
                Some(h) => h,
                None => return Ok(None),
            };
            let len = ((hdr[1] as usize & 0x01) << 16)
                | ((hdr[2] as usize) << 8)
                | hdr[3] as usize;
            match hdr[0] {
                nb_type::SESSION_MESSAGE => {
                    if len > MAX_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "oversized NBSS frame",
                        )
                        .into());
                    }
                    return Ok(self.take(len).await?.map(Frame));
                }
                nb_type::SESSION_REQUEST => {
                    if len > 0 && self.take(len).await?.is_none() {
                        return Ok(None);
                    }
                    if let Some(s) = answer.take() {
                        write_nbss(s, &[nb_type::POSITIVE_RESPONSE, 0, 0, 0]).await?;
                    }
                }
                _ => {
                    // Keepalive / unknown control: drain payload and continue.
                    if len > 0 && self.take(len).await?.is_none() {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

/// Frame `data` in an NBSS session message and write it via io_uring.
async fn write_nbss(stream: &TcpStream, data: &[u8]) -> Result<(), TransportError> {
    // 3-byte big-endian length: frames above 64 KiB (multi-credit
    // reads/writes, sealed transform payloads) need the middle byte.
    let mut frame = Vec::with_capacity(4 + data.len());
    frame.push(nb_type::SESSION_MESSAGE);
    frame.push((data.len() >> 16) as u8);
    frame.push((data.len() >> 8) as u8);
    frame.push((data.len() & 0xff) as u8);
    frame.extend_from_slice(data);
    let (res, _buf) = stream.write_all(frame).await;
    res.map_err(Into::into)
}

/// TCP transport speaking RFC 1002 session protocol over io_uring.
pub struct TcpTransport {
    reader: NbssReader,
    stream: Rc<TcpStream>,
    peer: String,
}

impl std::fmt::Debug for TcpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTransport").field("peer", &self.peer).finish()
    }
}

impl TcpTransport {
    /// Wrap an already-accepted connection. `peer` is the remote address
    /// reported by `accept` (io_uring `TcpStream` exposes no `peer_addr`).
    pub fn new(stream: TcpStream, peer: String) -> Self {
        let stream = Rc::new(stream);
        Self {
            reader: NbssReader::new(stream.clone()),
            stream,
            peer,
        }
    }
}

#[async_trait(?Send)]
impl Transport for TcpTransport {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        self.reader.next_frame(Some(&self.stream)).await
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        write_nbss(&self.stream, data).await
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }

    fn split(self: Box<Self>) -> (Box<dyn FrameSource>, Box<dyn FrameSink>) {
        (
            Box::new(TcpSource {
                reader: self.reader,
                peer: self.peer,
            }),
            Box::new(TcpSink {
                stream: self.stream,
            }),
        )
    }
}

/// Read half of a split [`TcpTransport`].
pub struct TcpSource {
    reader: NbssReader,
    peer: String,
}

impl std::fmt::Debug for TcpSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpSource").field("peer", &self.peer).finish()
    }
}

#[async_trait(?Send)]
impl FrameSource for TcpSource {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        // Split read half cannot write, so legacy SESSION_REQUEST is skipped.
        self.reader.next_frame(None).await
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// Write half of a split [`TcpTransport`]. Owned by the per-connection writer.
pub struct TcpSink {
    stream: Rc<TcpStream>,
}

impl std::fmt::Debug for TcpSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpSink").finish()
    }
}

#[async_trait(?Send)]
impl FrameSink for TcpSink {
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        write_nbss(&self.stream, data).await
    }
}

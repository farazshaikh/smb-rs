//! NBSS-over-TCP transport ([RFC 1002] session service, direct hosting on
//! port 445).

use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

use crate::{Frame, FrameSink, FrameSource, Transport, TransportError};

/// NetBIOS session-service message types we care about ([RFC 1002] §4).
mod nb_type {
    /// Session message carrying an SMB PDU.
    pub const SESSION_MESSAGE: u8 = 0x00;
    /// Session request handshake (port 139 style; answered positively).
    pub const SESSION_REQUEST: u8 = 0x81;
    /// Positive session response.
    pub const POSITIVE_RESPONSE: u8 = 0x82;
    /// Session keepalive.
    pub const KEEPALIVE: u8 = 0x85;
}

/// TCP transport speaking RFC 1002 session protocol.
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
    peer: String,
}

impl TcpTransport {
    /// Wrap an already-accepted connection.
    pub fn new(stream: TcpStream) -> Self {
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Self { stream, peer }
    }

    /// Bind a listener on `addr`.
    pub fn bind(
        addr: &str,
    ) -> impl std::future::Future<Output = io::Result<TcpListener>> + Send {
        TcpListener::bind(addr.to_string())
    }
}

async fn read_exact_or_none<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut [u8],
) -> Result<Option<()>, TransportError> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(Some(())),
        Err(e) if matches!(
            e.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Read one NBSS session-message frame from a read half, skipping control
/// frames (keepalive, legacy session-request). Returns `Ok(None)` at EOF.
/// Unlike [`TcpTransport::recv`] this never writes, so it is safe to own in a
/// split read half; legacy port-139 SESSION_REQUEST handshakes (unused on the
/// 445 direct-hosting path) are logged and skipped rather than answered.
async fn read_nbss_frame<R: AsyncRead + Unpin>(
    rd: &mut R,
) -> Result<Option<Frame>, TransportError> {
    loop {
        let mut hdr = [0u8; 4];
        if read_exact_or_none(rd, &mut hdr).await?.is_none() {
            return Ok(None);
        }
        let len = ((hdr[1] as usize & 0x01) << 16)
            | ((hdr[2] as usize) << 8)
            | hdr[3] as usize;
        match hdr[0] {
            nb_type::SESSION_MESSAGE => {
                if len > 0x20_0000 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "oversized NBSS frame",
                    )
                    .into());
                }
                let mut body = vec![0u8; len];
                if read_exact_or_none(rd, &mut body).await?.is_none() {
                    return Ok(None);
                }
                return Ok(Some(Frame(body)));
            }
            other => {
                // Control frame (keepalive, legacy port-139 session-request):
                // drain any payload and keep reading. SESSION_REQUEST is not
                // answered here — the split read half cannot write, and the
                // 445 direct-hosting path we serve never sends it.
                let _ = other;
                if len > 0 {
                    let mut junk = vec![0u8; len];
                    if read_exact_or_none(rd, &mut junk).await?.is_none() {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

/// Write one NBSS session-message frame to a write half.
async fn write_nbss_frame<W: AsyncWrite + Unpin>(
    wr: &mut W,
    data: &[u8],
) -> Result<(), TransportError> {
    let mut hdr = [0u8; 4];
    hdr[0] = nb_type::SESSION_MESSAGE;
    // 3-byte big-endian length: frames above 64 KiB (multi-credit
    // reads/writes, sealed transform payloads) need the middle byte.
    hdr[1] = (data.len() >> 16) as u8;
    hdr[2] = (data.len() >> 8) as u8;
    hdr[3] = (data.len() & 0xff) as u8;
    wr.write_all(&hdr).await?;
    wr.write_all(data).await?;
    wr.flush().await?;
    Ok(())
}

#[async_trait]
impl Transport for TcpTransport {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        loop {
            // NBSS header: type, flags, 16-bit length (17th bit in flags).
            let mut hdr = [0u8; 4];
            if read_exact_or_none(&mut self.stream, &mut hdr).await?.is_none() {
                return Ok(None);
            }

            let len = ((hdr[1] as usize & 0x01) << 16)
                | ((hdr[2] as usize) << 8)
                | hdr[3] as usize;

            match hdr[0] {
                nb_type::SESSION_MESSAGE => {
                    if len > 0x20_0000 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "oversized NBSS frame",
                        )
                        .into());
                    }
                    let mut body = vec![0u8; len];
                    if read_exact_or_none(&mut self.stream, &mut body).await?.is_none() {
                        return Ok(None);
                    }
                    return Ok(Some(Frame(body)));
                }
                nb_type::SESSION_REQUEST => {
                    // Answer legacy port-139 style handshakes positively.
                    let mut junk = vec![0u8; len];
                    if len > 0 && read_exact_or_none(&mut self.stream, &mut junk).await?.is_none()
                    {
                        return Ok(None);
                    }
                    self.send(&[nb_type::POSITIVE_RESPONSE, 0, 0, 0]).await?;
                }
                nb_type::KEEPALIVE => { /* nothing to answer */ }
                _ => { /* unknown control type: ignore */ }
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        write_nbss_frame(&mut self.stream, data).await
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }

    fn split(self: Box<Self>) -> (Box<dyn FrameSource>, Box<dyn FrameSink>) {
        let (rd, wr) = self.stream.into_split();
        (
            Box::new(TcpSource { rd, peer: self.peer }),
            Box::new(TcpSink { wr }),
        )
    }
}

/// Read half of a split [`TcpTransport`].
#[derive(Debug)]
pub struct TcpSource {
    rd: OwnedReadHalf,
    peer: String,
}

#[async_trait]
impl FrameSource for TcpSource {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        read_nbss_frame(&mut self.rd).await
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// Write half of a split [`TcpTransport`].
#[derive(Debug)]
pub struct TcpSink {
    wr: OwnedWriteHalf,
}

#[async_trait]
impl FrameSink for TcpSink {
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        write_nbss_frame(&mut self.wr, data).await
    }
}

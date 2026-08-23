//! NBSS-over-TCP transport ([RFC 1002] session service, direct hosting on
//! port 445).

use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{Frame, Transport, TransportError};

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

async fn read_exact_or_none(
    stream: &mut TcpStream,
    buf: &mut [u8],
) -> Result<Option<()>, TransportError> {
    match stream.read_exact(buf).await {
        Ok(()) => Ok(Some(())),
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
        let mut hdr = [0u8; 4];
        hdr[0] = nb_type::SESSION_MESSAGE;
        hdr[2] = (data.len() >> 8) as u8;
        hdr[3] = (data.len() & 0xff) as u8;
        self.stream.write_all(&hdr).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;
        Ok(())
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

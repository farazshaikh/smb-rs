//! In-memory transport for testing protocol layers without sockets.
//!
//! A [`mem::Duplex`] pair behaves like a crossed wire: frames written into
//! one side are returned by the other side's [`Transport::recv`].

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{Frame, FrameSink, FrameSource, Transport, TransportError};

/// One end of an in-memory transport pair.
pub struct MemTransport {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    peer: String,
}

/// Create two connected transports. Frames sent on one are received by the
/// other; dropping a sender closes that direction.
pub fn duplex(buffer: usize) -> (MemTransport, MemTransport) {
    let (tx_a, rx_a) = mpsc::channel(buffer);
    let (tx_b, rx_b) = mpsc::channel(buffer);
    (
        MemTransport { rx: rx_a, tx: tx_b, peer: "mem:a".into() },
        MemTransport { rx: rx_b, tx: tx_a, peer: "mem:b".into() },
    )
}

#[async_trait]
impl Transport for MemTransport {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        Ok(self.rx.recv().await.map(Frame))
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "peer dropped",
            )))
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }

    fn split(self: Box<Self>) -> (Box<dyn FrameSource>, Box<dyn FrameSink>) {
        (
            Box::new(MemSource { rx: self.rx, peer: self.peer }),
            Box::new(MemSink { tx: self.tx }),
        )
    }
}

/// Read half of a split [`MemTransport`].
#[derive(Debug)]
pub struct MemSource {
    rx: mpsc::Receiver<Vec<u8>>,
    peer: String,
}

#[async_trait]
impl FrameSource for MemSource {
    async fn recv(&mut self) -> Result<Option<Frame>, TransportError> {
        Ok(self.rx.recv().await.map(Frame))
    }

    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// Write half of a split [`MemTransport`].
#[derive(Debug)]
pub struct MemSink {
    tx: mpsc::Sender<Vec<u8>>,
}

#[async_trait]
impl FrameSink for MemSink {
    async fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.tx
            .send(data.to_vec())
            .await
            .map_err(|_| TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "peer dropped",
            )))
    }
}

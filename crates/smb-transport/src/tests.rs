//! Transport abstraction tests.

use crate::{mem, Transport};

#[tokio::test]
async fn duplex_roundtrip() {
    let (mut a, mut b) = mem::duplex(8);
    a.send(&[1, 2, 3]).await.unwrap();
    let f = b.recv().await.unwrap().unwrap();
    assert_eq!(f.0, vec![1, 2, 3]);

    b.send(&[9]).await.unwrap();
    let f = a.recv().await.unwrap().unwrap();
    assert_eq!(f.0, vec![9]);
}

#[tokio::test]
async fn closed_peer_returns_none() {
    let (mut a, b) = mem::duplex(4);
    drop(b);
    assert!(a.recv().await.unwrap().is_none());
}

/// The split read and write halves operate independently: a writer task can
/// emit an unsolicited frame while the read half is parked on `recv`. This is
/// the foundation for async STATUS_PENDING completions and oplock/lease breaks.
#[tokio::test]
async fn split_halves_write_while_reader_parked() {
    let (a, mut b) = mem::duplex(8);
    let (mut src, mut sink) = Box::new(a).split();

    // Reader parks on `a`'s read half with nothing queued yet.
    let reader = tokio::spawn(async move { src.recv().await.unwrap().map(|f| f.0) });

    // Writer half pushes an unsolicited frame to the peer independently.
    sink.send(&[0xAA, 0xBB]).await.unwrap();
    assert_eq!(b.recv().await.unwrap().unwrap().0, vec![0xAA, 0xBB]);

    // The parked reader wakes once the peer sends.
    b.send(&[0x01]).await.unwrap();
    assert_eq!(reader.await.unwrap(), Some(vec![0x01]));
}


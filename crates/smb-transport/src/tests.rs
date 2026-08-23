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

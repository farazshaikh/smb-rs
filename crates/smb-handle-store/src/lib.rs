//! Pluggable store for durable and persistent SMB handles ([MS-SMB2] §3.3.1.10).
//!
//! A durable/persistent handle survives a client disconnect (and, for the
//! replicated backends, a server node failing over) so the client can reclaim
//! it with `DH2C`. This crate abstracts *where* that handle state lives behind
//! one async [`HandleStore`] trait so the server code is backend-agnostic:
//!
//! - [`MemStore`] — in-process, non-durable (single node, dev/tests).
//! - `RedbStore` (feature `redb-backend`) — embedded durable KV; survives a
//!   process restart on one node.
//! - Replicated backends (openraft / etcd) plug in behind the same trait for
//!   multi-node continuous availability without touching the SMB code.
//!
//! Only handle *lifecycle* state lives here (open/close/reclaim/lock), never
//! the file data path — values stay small and writes are infrequent.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[cfg(feature = "redb-backend")]
mod redb_store;
#[cfg(feature = "redb-backend")]
pub use redb_store::RedbStore;

/// SMB create GUID identifying a durable handle ([MS-SMB2] §2.2.13.2.3).
pub type Guid = [u8; 16];

/// Persisted state for one durable/persistent handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleRecord {
    pub create_guid: Guid,
    /// Share-relative path of the open, used to re-open on reclaim.
    pub path: String,
    /// Share name the handle belongs to.
    pub share: String,
    pub session_id: u64,
    pub access: u32,
    pub share_access: u32,
    pub create_options: u32,
    /// Durable flags (v2 request / persistent).
    pub flags: u32,
    /// Node currently owning the handle; empty when free for reclaim.
    pub owner_node: String,
    pub lease_key: Option<Guid>,
    /// Requested durable timeout in milliseconds (0 = persistent, no timeout).
    pub timeout_ms: u64,
    /// Absolute expiry (ms since epoch); 0 means persistent / never expires.
    pub deadline_ms: u64,
    pub delete_on_close: bool,
}

impl HandleRecord {
    /// A persistent handle has no timeout and is never swept.
    pub fn is_persistent(&self) -> bool {
        self.deadline_ms == 0
    }

    fn expired_at(&self, now_ms: u64) -> bool {
        !self.is_persistent() && self.deadline_ms <= now_ms
    }
}

/// Errors surfaced by a [`HandleStore`] backend.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("handle store backend error: {0}")]
    Backend(String),
    #[error("handle store serialization error: {0}")]
    Serde(String),
}

/// Backend-agnostic durable/persistent handle registry.
///
/// Implementations must make [`reclaim`](HandleStore::reclaim) atomic so two
/// nodes cannot both win the same handle during failover.
#[async_trait]
pub trait HandleStore: Send + Sync {
    /// Insert or replace a handle record (durable grant).
    async fn put(&self, record: HandleRecord) -> Result<(), StoreError>;

    /// Fetch a handle record by its create GUID.
    async fn get(&self, create_guid: &Guid) -> Result<Option<HandleRecord>, StoreError>;

    /// Atomically claim a handle for `owner` when it is free, already owned by
    /// `owner`, or expired. Returns the (now owned) record, or `None` if it is
    /// still validly owned by another node. Reclaim renews the deadline.
    async fn reclaim(
        &self,
        create_guid: &Guid,
        owner: &str,
        now_ms: u64,
    ) -> Result<Option<HandleRecord>, StoreError>;

    /// Remove a handle record (close or durable expiry).
    async fn remove(&self, create_guid: &Guid) -> Result<(), StoreError>;

    /// Drop every non-persistent handle whose deadline has passed; returns the
    /// GUIDs removed so the caller can release their backing resources.
    async fn sweep_expired(&self, now_ms: u64) -> Result<Vec<Guid>, StoreError>;

    /// All live handle records (diagnostics / reconciliation).
    async fn list(&self) -> Result<Vec<HandleRecord>, StoreError>;
}

/// In-process, non-durable store — the default single-node/dev backend.
#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<Guid, HandleRecord>>,
}

impl MemStore {
    pub fn new() -> MemStore {
        MemStore { map: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Guid, HandleRecord>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait]
impl HandleStore for MemStore {
    async fn put(&self, record: HandleRecord) -> Result<(), StoreError> {
        self.lock().insert(record.create_guid, record);
        Ok(())
    }

    async fn get(&self, create_guid: &Guid) -> Result<Option<HandleRecord>, StoreError> {
        Ok(self.lock().get(create_guid).cloned())
    }

    async fn reclaim(
        &self,
        create_guid: &Guid,
        owner: &str,
        now_ms: u64,
    ) -> Result<Option<HandleRecord>, StoreError> {
        let mut map = self.lock();
        let Some(record) = map.get_mut(create_guid) else {
            return Ok(None);
        };
        if !record.owner_node.is_empty() && record.owner_node != owner && !record.expired_at(now_ms) {
            return Ok(None);
        }
        record.owner_node = owner.to_string();
        if record.timeout_ms > 0 {
            record.deadline_ms = now_ms + record.timeout_ms;
        }
        Ok(Some(record.clone()))
    }

    async fn remove(&self, create_guid: &Guid) -> Result<(), StoreError> {
        self.lock().remove(create_guid);
        Ok(())
    }

    async fn sweep_expired(&self, now_ms: u64) -> Result<Vec<Guid>, StoreError> {
        let mut map = self.lock();
        let expired: Vec<Guid> =
            map.values().filter(|r| r.expired_at(now_ms)).map(|r| r.create_guid).collect();
        for guid in &expired {
            map.remove(guid);
        }
        Ok(expired)
    }

    async fn list(&self) -> Result<Vec<HandleRecord>, StoreError> {
        Ok(self.lock().values().cloned().collect())
    }
}

#[cfg(test)]
pub(crate) fn sample(guid_byte: u8, timeout_ms: u64) -> HandleRecord {
    HandleRecord {
        create_guid: [guid_byte; 16],
        path: "dir/file.bin".into(),
        share: "public".into(),
        session_id: 0x1234,
        access: 0x0012_019f,
        share_access: 0x7,
        create_options: 0x40,
        flags: 0x2,
        owner_node: String::new(),
        lease_key: None,
        timeout_ms,
        deadline_ms: if timeout_ms == 0 { 0 } else { timeout_ms },
        delete_on_close: false,
    }
}

#[cfg(test)]
mod mem_tests {
    use super::*;

    #[tokio::test]
    async fn put_get_remove_roundtrip() {
        let store = MemStore::new();
        let rec = sample(1, 1000);
        store.put(rec.clone()).await.unwrap();
        assert_eq!(store.get(&rec.create_guid).await.unwrap().as_ref(), Some(&rec));
        store.remove(&rec.create_guid).await.unwrap();
        assert!(store.get(&rec.create_guid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn reclaim_is_exclusive_until_expiry() {
        let store = MemStore::new();
        store.put(sample(2, 1000)).await.unwrap();
        let guid = [2u8; 16];
        // Node A claims it.
        assert!(store.reclaim(&guid, "nodeA", 0).await.unwrap().is_some());
        // Node B cannot steal it while A's lease is valid.
        assert!(store.reclaim(&guid, "nodeB", 500).await.unwrap().is_none());
        // After the deadline, B reclaims it.
        let claimed = store.reclaim(&guid, "nodeB", 2000).await.unwrap();
        assert_eq!(claimed.unwrap().owner_node, "nodeB");
    }

    #[tokio::test]
    async fn sweep_drops_expired_but_keeps_persistent() {
        let store = MemStore::new();
        store.put(sample(3, 1000)).await.unwrap(); // expires at 1000
        store.put(sample(4, 0)).await.unwrap(); // persistent
        let dropped = store.sweep_expired(2000).await.unwrap();
        assert_eq!(dropped, vec![[3u8; 16]]);
        assert!(store.get(&[3u8; 16]).await.unwrap().is_none());
        assert!(store.get(&[4u8; 16]).await.unwrap().is_some());
    }
}

//! Embedded single-node durable backend for [`HandleStore`], built on `redb`.
//!
//! Handle records survive a process restart, which is what the single-node
//! persistent-handle reclaim path ([MS-SMB2] §3.3.5.9.7) needs. redb calls are
//! blocking, so they run on the blocking pool to keep the async reactor free.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use redb::{Database, ReadableTable, TableDefinition};

use crate::{Guid, HandleRecord, HandleStore, StoreError};

const HANDLES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("handles");

/// Durable handle store backed by an embedded redb database file.
pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    /// Open (creating if needed) the database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<RedbStore, StoreError> {
        let db = Database::create(path).map_err(be)?;
        let wtx = db.begin_write().map_err(be)?;
        wtx.open_table(HANDLES).map_err(be)?;
        wtx.commit().map_err(be)?;
        Ok(RedbStore { db: Arc::new(db) })
    }
}

fn be<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Backend(e.to_string())
}

fn se<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Serde(e.to_string())
}

/// Run a blocking redb closure off the async reactor.
async fn blocking<T, F>(f: F) -> Result<T, StoreError>
where
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(be)?
}

#[async_trait]
impl HandleStore for RedbStore {
    async fn put(&self, record: HandleRecord) -> Result<(), StoreError> {
        let db = self.db.clone();
        blocking(move || {
            let value = serde_json::to_vec(&record).map_err(se)?;
            let wtx = db.begin_write().map_err(be)?;
            {
                let mut table = wtx.open_table(HANDLES).map_err(be)?;
                table.insert(record.create_guid.as_slice(), value.as_slice()).map_err(be)?;
            }
            wtx.commit().map_err(be)
        })
        .await
    }

    async fn get(&self, create_guid: &Guid) -> Result<Option<HandleRecord>, StoreError> {
        let db = self.db.clone();
        let guid = *create_guid;
        blocking(move || {
            let rtx = db.begin_read().map_err(be)?;
            let table = rtx.open_table(HANDLES).map_err(be)?;
            match table.get(guid.as_slice()).map_err(be)? {
                Some(v) => Ok(Some(serde_json::from_slice(v.value()).map_err(se)?)),
                None => Ok(None),
            }
        })
        .await
    }

    async fn take(
        &self,
        create_guid: &Guid,
        match_guid: Option<Guid>,
        now_ms: u64,
    ) -> Result<Option<HandleRecord>, StoreError> {
        let db = self.db.clone();
        let guid = *create_guid;
        blocking(move || {
            let wtx = db.begin_write().map_err(be)?;
            let taken = {
                let mut table = wtx.open_table(HANDLES).map_err(be)?;
                let current = table.get(guid.as_slice()).map_err(be)?.map(|v| v.value().to_vec());
                match current {
                    None => None,
                    Some(bytes) => {
                        let record: HandleRecord = serde_json::from_slice(&bytes).map_err(se)?;
                        let expired = !record.is_persistent() && record.deadline_ms <= now_ms;
                        let guid_ok = match match_guid {
                            Some(g) => record.match_guid == Some(g),
                            None => true,
                        };
                        if expired || !guid_ok {
                            if expired {
                                table.remove(guid.as_slice()).map_err(be)?;
                            }
                            None
                        } else {
                            table.remove(guid.as_slice()).map_err(be)?;
                            Some(record)
                        }
                    }
                }
            };
            wtx.commit().map_err(be)?;
            Ok(taken)
        })
        .await
    }

    async fn reclaim(
        &self,
        create_guid: &Guid,
        owner: &str,
        now_ms: u64,
    ) -> Result<Option<HandleRecord>, StoreError> {
        let db = self.db.clone();
        let guid = *create_guid;
        let owner = owner.to_string();
        blocking(move || {
            let wtx = db.begin_write().map_err(be)?;
            let claimed = {
                let mut table = wtx.open_table(HANDLES).map_err(be)?;
                let current = table.get(guid.as_slice()).map_err(be)?.map(|v| v.value().to_vec());
                match current {
                    None => None,
                    Some(bytes) => {
                        let mut record: HandleRecord = serde_json::from_slice(&bytes).map_err(se)?;
                        let expired = !record.is_persistent() && record.deadline_ms <= now_ms;
                        if !record.owner_node.is_empty() && record.owner_node != owner && !expired {
                            None
                        } else {
                            record.owner_node = owner.clone();
                            if record.timeout_ms > 0 {
                                record.deadline_ms = now_ms + record.timeout_ms;
                            }
                            let value = serde_json::to_vec(&record).map_err(se)?;
                            table.insert(guid.as_slice(), value.as_slice()).map_err(be)?;
                            Some(record)
                        }
                    }
                }
            };
            wtx.commit().map_err(be)?;
            Ok(claimed)
        })
        .await
    }

    async fn remove(&self, create_guid: &Guid) -> Result<(), StoreError> {
        let db = self.db.clone();
        let guid = *create_guid;
        blocking(move || {
            let wtx = db.begin_write().map_err(be)?;
            {
                let mut table = wtx.open_table(HANDLES).map_err(be)?;
                table.remove(guid.as_slice()).map_err(be)?;
            }
            wtx.commit().map_err(be)
        })
        .await
    }

    async fn sweep_expired(&self, now_ms: u64) -> Result<Vec<Guid>, StoreError> {
        let db = self.db.clone();
        blocking(move || {
            let wtx = db.begin_write().map_err(be)?;
            let mut expired: Vec<Guid> = Vec::new();
            {
                let mut table = wtx.open_table(HANDLES).map_err(be)?;
                {
                    let iter = table.iter().map_err(be)?;
                    for entry in iter {
                        let (_k, v) = entry.map_err(be)?;
                        let record: HandleRecord = serde_json::from_slice(v.value()).map_err(se)?;
                        if !record.is_persistent() && record.deadline_ms <= now_ms {
                            expired.push(record.create_guid);
                        }
                    }
                }
                for guid in &expired {
                    table.remove(guid.as_slice()).map_err(be)?;
                }
            }
            wtx.commit().map_err(be)?;
            Ok(expired)
        })
        .await
    }

    async fn list(&self) -> Result<Vec<HandleRecord>, StoreError> {
        let db = self.db.clone();
        blocking(move || {
            let rtx = db.begin_read().map_err(be)?;
            let table = rtx.open_table(HANDLES).map_err(be)?;
            let mut out = Vec::new();
            for entry in table.iter().map_err(be)? {
                let (_k, v) = entry.map_err(be)?;
                out.push(serde_json::from_slice(v.value()).map_err(se)?);
            }
            Ok(out)
        })
        .await
    }
}

#[cfg(test)]
mod redb_tests {
    use super::*;
    use crate::sample;

    fn temp_db() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("smb-hs-{}-{}.redb", std::process::id(), nanos))
    }

    #[tokio::test]
    async fn survives_reopen() {
        let path = temp_db();
        let rec = sample(9, 5000);
        {
            let store = RedbStore::open(&path).unwrap();
            store.put(rec.clone()).await.unwrap();
        }
        // Re-open the same file: the record must still be there.
        let store = RedbStore::open(&path).unwrap();
        assert_eq!(store.get(&rec.create_guid).await.unwrap().as_ref(), Some(&rec));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn reclaim_and_sweep() {
        let path = temp_db();
        let store = RedbStore::open(&path).unwrap();
        store.put(sample(10, 1000)).await.unwrap();
        let guid = [10u8; 16];
        assert!(store.reclaim(&guid, "nodeA", 0).await.unwrap().is_some());
        assert!(store.reclaim(&guid, "nodeB", 500).await.unwrap().is_none());
        let dropped = store.sweep_expired(2000).await.unwrap();
        assert_eq!(dropped, vec![guid]);
        assert!(store.get(&guid).await.unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }
}

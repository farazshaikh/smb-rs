//! Server-side state: configuration, sessions, tree connects, open handles
//! and directory-search contexts.
//!
//! Per the architecture, shared metadata is refcounted (`Arc`) so an
//! [`IoContext`](crate::dispatch::IoContext) can carry it for the lifetime of
//! one request without borrowing the connection lock.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

/// Durable-handle flag marking a persistent handle ([MS-SMB2] §2.2.14.2.12).
const DHANDLE_FLAG_PERSISTENT: u32 = 0x0000_0002;
/// Share type for a hidden IPC$ pipe share: STYPE_IPC | STYPE_SPECIAL
/// ([MS-SRVS] §2.2.2.4).
const STYPE_IPC_SPECIAL: u32 = 0x8000_0003;

use smb_vfs::OpenFile;
use smb_vfs::Vfs;

use smb_handle_store::HandleStore;

/// Milliseconds since the Unix epoch, used for durable-handle deadlines.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A published share backed by a VFS instance.
#[derive(Clone)]
pub struct Share {
    /// Share name as clients request it (lowercased).
    pub name: String,
    /// Physical root directory of the share.
    pub root: PathBuf,
    /// Backend serving this share.
    pub vfs: Arc<dyn Vfs>,
    /// True for the virtual `IPC$` pipe share.
    pub is_ipc: bool,
    /// True when the share requires SMB3 encryption (SMB2_SHAREFLAG_ENCRYPT_DATA):
    /// its TREE_CONNECT response advertises the flag and every message on the
    /// tree is sealed ([MS-SMB2] §3.3.5.7).
    pub encrypt: bool,
    /// True when the share advertises SMB2_SHAREFLAG_COMPRESS_DATA in its
    /// TREE_CONNECT response ([MS-SMB2] §2.2.10).
    pub compress: bool,
    /// True for a continuously-available share ([MS-SMB2] §2.2.10): its
    /// TREE_CONNECT response advertises SMB2_SHAREFLAG_CONTINUOUSLY_AVAILABLE
    /// and SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY, and it may grant persistent
    /// handles ([MS-SMB2] §3.3.5.9.11).
    pub ca: bool,
}

/// Global (per-process) server configuration and user database.
#[derive(Clone)]
pub struct ServerShared {
    /// Published shares keyed by lowercase name.
    pub shares: HashMap<String, Share>,
    /// Server GUID used by extended-security negotiate.
    pub guid: [u8; 16],
    /// NT domain / workgroup name.
    pub domain: String,
    /// NetBIOS server name.
    pub server_name: String,
    /// Configured accounts: lowercased username → password.
    pub users: HashMap<String, String>,
    /// When no users are configured every principal maps to guest.
    pub allow_guest: bool,
    /// Reject traffic from authenticated sessions that does not carry a
    /// valid signature ([MS-SMB2] §3.3.5.2.3 signing policy).
    pub require_signing: bool,
    /// Seal sessions when the client supports encryption
    /// (SMB2_SESSION_FLAG_ENCRYPT_DATA, [MS-SMB2] §2.2.5.2).
    pub encrypt: bool,
    /// Server-wide byte-range lock table ([MS-SMB2] §2.2.26) shared across
    /// connections so conflicting locks from different clients are detected.
    pub locks: Arc<LockManager>,
    /// Server-wide open share-mode table for sharing-violation detection
    /// ([MS-FSA] §2.1.5.1).
    pub share_modes: Arc<ShareModeTable>,
    /// Server-wide oplock table ([MS-SMB2] §2.2.23) — at most one exclusive
    /// oplock per file, broken when a second open contends.
    pub oplocks: Arc<OplockTable>,
    /// Server-wide lease table ([MS-SMB2] §2.2.23.2) — one caching lease per
    /// file path, broken down when an open with a different lease key contends.
    pub leases: Arc<LeaseTable>,
    /// Durable handles preserved across connection drops ([MS-SMB2] §3.3.1.10),
    /// behind a pluggable store (in-memory, redb, or a replicated backend).
    pub durables: Arc<dyn HandleStore>,
    /// Established sessions, shared so channels can bind ([MS-SMB2] §3.3.5.5.3).
    pub sessions: Arc<SessionTable>,
    /// Application-instance opens for client failover ([MS-SMB2] §3.3.5.9.13).
    pub app_instances: Arc<AppInstanceTable>,
}

/// Identifies the open that owns a byte-range lock: `(session_id, file_id)`.
pub type LockOwner = (u64, [u8; 16]);

#[derive(Clone, Copy)]
struct HeldLock {
    offset: u64,
    length: u64,
    exclusive: bool,
    owner: LockOwner,
}

/// Whether `[off, off+len)` overlaps the held lock's range.
fn overlaps(h: &HeldLock, off: u64, len: u64) -> bool {
    off < h.offset.saturating_add(h.length) && h.offset < off.saturating_add(len)
}

/// Server-wide byte-range lock manager ([MS-SMB2] §2.2.26 / [MS-FSA]
/// §2.1.4.10). Locks are keyed by the file's on-disk path so opens from
/// different connections contend correctly.
pub struct LockManager {
    held: std::sync::Mutex<HashMap<String, Vec<HeldLock>>>,
    released: tokio::sync::Notify,
}

impl Default for LockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LockManager {
    /// Create an empty lock manager.
    pub fn new() -> Self {
        Self {
            held: std::sync::Mutex::new(HashMap::new()),
            released: tokio::sync::Notify::new(),
        }
    }

    /// A new lock on `[off, off+len)` conflicts with `existing` when the ranges
    /// overlap and either lock is exclusive. An exclusive lock conflicts even
    /// with the same open's overlapping lock ([MS-FSA] §2.1.5.9); two shared
    /// locks never conflict.
    fn conflicts(existing: &HeldLock, off: u64, len: u64, excl: bool) -> bool {
        let overlap = off < existing.offset.saturating_add(existing.length)
            && existing.offset < off.saturating_add(len);
        overlap && (excl || existing.exclusive)
    }

    /// Atomically acquire every range, or acquire none. `ranges` are
    /// `(offset, length, exclusive)`. Returns true on success.
    pub fn try_acquire(&self, path: &str, ranges: &[(u64, u64, bool)], owner: LockOwner) -> bool {
        let mut held = self.held.lock().unwrap();
        let list = held.entry(path.to_string()).or_default();
        let clash = ranges
            .iter()
            .any(|&(off, len, excl)| list.iter().any(|h| Self::conflicts(h, off, len, excl)));
        if clash {
            return false;
        }
        for &(off, len, excl) in ranges {
            list.push(HeldLock { offset: off, length: len, exclusive: excl, owner });
        }
        true
    }

    /// A write to `[off, off+len)` is blocked when it overlaps any shared lock
    /// (a read lock forbids writes by every open, [MS-FSA] §2.1.5.9) or an
    /// exclusive lock held by a different open.
    pub fn write_conflict(&self, path: &str, off: u64, len: u64, owner: LockOwner) -> bool {
        let held = self.held.lock().unwrap();
        let Some(list) = held.get(path) else { return false };
        list.iter().any(|h| overlaps(h, off, len) && (!h.exclusive || h.owner != owner))
    }

    /// A read overlaps a conflicting lock only when another open holds an
    /// exclusive lock on the range.
    pub fn read_conflict(&self, path: &str, off: u64, len: u64, owner: LockOwner) -> bool {
        let held = self.held.lock().unwrap();
        let Some(list) = held.get(path) else { return false };
        list.iter().any(|h| overlaps(h, off, len) && h.exclusive && h.owner != owner)
    }

    /// Release specific `(offset, length)` ranges held by `owner`.
    pub fn release(&self, path: &str, ranges: &[(u64, u64)], owner: LockOwner) {
        let mut held = self.held.lock().unwrap();
        if let Some(list) = held.get_mut(path) {
            for &(off, len) in ranges {
                if let Some(pos) = list
                    .iter()
                    .position(|h| h.owner == owner && h.offset == off && h.length == len)
                {
                    list.swap_remove(pos);
                }
            }
            if list.is_empty() {
                held.remove(path);
            }
        }
        drop(held);
        self.released.notify_waiters();
    }

    /// Drop every lock held by `owner` (on handle close or session teardown).
    pub fn release_owner(&self, owner: LockOwner) {
        let mut held = self.held.lock().unwrap();
        held.retain(|_, list| {
            list.retain(|h| h.owner != owner);
            !list.is_empty()
        });
        drop(held);
        self.released.notify_waiters();
    }

    /// Drop every lock held by any open of `session_id` (logoff/disconnect).
    pub fn release_session(&self, session_id: u64) {
        let mut held = self.held.lock().unwrap();
        held.retain(|_, list| {
            list.retain(|h| h.owner.0 != session_id);
            !list.is_empty()
        });
        drop(held);
        self.released.notify_waiters();
    }

    /// Notified when any lock is released, so blocked waiters can retry.
    pub fn released(&self) -> &tokio::sync::Notify {
        &self.released
    }
}

/// One recorded open on a file: its granted access and the sharing it permits.
#[derive(Clone, Copy)]
struct OpenMode {
    access: u32,
    share: u32,
    owner: LockOwner,
}

/// Server-wide table of open share modes, keyed by on-disk path, used to
/// detect sharing violations ([MS-FSA] §2.1.5.1) across all connections.
#[derive(Default)]
pub struct ShareModeTable {
    opens: std::sync::Mutex<HashMap<String, Vec<OpenMode>>>,
}

impl ShareModeTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self { opens: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Record a new open if it is compatible with every existing open on the
    /// same file; returns false (registering nothing) on a sharing violation.
    pub fn try_open(&self, path: &str, access: u32, share: u32, owner: LockOwner) -> bool {
        let mut opens = self.opens.lock().unwrap();
        let list = opens.entry(path.to_string()).or_default();
        if list.iter().any(|e| !compatible(e, access, share)) {
            if list.is_empty() {
                opens.remove(path);
            }
            return false;
        }
        list.push(OpenMode { access, share, owner });
        true
    }

    /// Drop the open recorded for `owner` on `path`.
    pub fn close(&self, path: &str, owner: LockOwner) {
        let mut opens = self.opens.lock().unwrap();
        if let Some(list) = opens.get_mut(path) {
            if let Some(pos) = list.iter().position(|e| e.owner == owner) {
                list.swap_remove(pos);
            }
            if list.is_empty() {
                opens.remove(path);
            }
        }
    }

    /// Drop every open recorded for any handle of `session_id`.
    pub fn close_session(&self, session_id: u64) {
        let mut opens = self.opens.lock().unwrap();
        opens.retain(|_, list| {
            list.retain(|e| e.owner.0 != session_id);
            !list.is_empty()
        });
    }

    /// Number of opens currently recorded for `path`.
    pub fn open_count(&self, path: &str) -> usize {
        self.opens.lock().unwrap().get(path).map_or(0, |l| l.len())
    }
}

/// A recorded application-instance open ([MS-SMB2] §3.3.5.9.13).
struct AppOpen {
    app_instance_id: [u8; 16],
    path: String,
    client_guid: [u8; 16],
    owner: LockOwner,
    version: Option<(u64, u64)>,
}

/// Outcome of matching a CREATE's AppInstanceId against existing opens.
pub enum AppInstanceMatch {
    /// No matching prior open; proceed normally.
    None,
    /// A prior open was force-closed; drop its share-mode entry for `owner`.
    ForceClose {
        /// On-disk path of the force-closed open.
        path: String,
        /// Owner (session id, file id) of the force-closed open.
        owner: LockOwner,
    },
    /// The prior open is newer or equal; the new CREATE must be rejected.
    Reject,
}

/// Server-wide registry of application-instance opens: a later CREATE with the
/// same AppInstanceId from a different client force-closes the prior open,
/// enabling client failover ([MS-SMB2] §3.3.5.9.13).
#[derive(Default)]
pub struct AppInstanceTable {
    opens: std::sync::Mutex<Vec<AppOpen>>,
    forced: std::sync::Mutex<HashSet<LockOwner>>,
}

impl AppInstanceTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a CREATE carrying `id` against existing opens. A match from a
    /// different client force-closes the prior open unless the 3.1.1 version
    /// rules say the existing open is newer/equal (then Reject).
    pub fn resolve(
        &self,
        id: [u8; 16],
        path: &str,
        client_guid: [u8; 16],
        is_311: bool,
        req_version: Option<(u64, u64)>,
    ) -> AppInstanceMatch {
        let mut opens = self.opens.lock().unwrap();
        let Some(pos) = opens
            .iter()
            .position(|o| o.app_instance_id == id && o.path == path && o.client_guid != client_guid)
        else {
            return AppInstanceMatch::None;
        };
        if let Some((eh, el)) = opens[pos].version {
            match req_version {
                // Version-comparison rule: applies only when the reopening
                // connection negotiated 3.1.1. The prior open wins on an equal
                // or higher version.
                Some((rh, rl)) if is_311 && (eh > rh || (eh == rh && el >= rl)) => {
                    return AppInstanceMatch::Reject;
                }
                // No-version rule: the server implements 3.1.1, so a request
                // that omits a version against a versioned open is rejected
                // regardless of the reopening connection's dialect.
                None => return AppInstanceMatch::Reject,
                _ => {}
            }
        }
        let victim = opens.remove(pos);
        self.forced.lock().unwrap().insert(victim.owner);
        AppInstanceMatch::ForceClose { path: victim.path, owner: victim.owner }
    }

    /// Record a new application-instance open.
    pub fn register(
        &self,
        id: [u8; 16],
        path: String,
        client_guid: [u8; 16],
        owner: LockOwner,
        version: Option<(u64, u64)>,
    ) {
        self.opens.lock().unwrap().push(AppOpen {
            app_instance_id: id,
            path,
            client_guid,
            owner,
            version,
        });
    }

    /// Consume and report the force-closed flag for `owner`.
    pub fn take_forced(&self, owner: LockOwner) -> bool {
        self.forced.lock().unwrap().remove(&owner)
    }

    /// Drop the registry entry for a closed open.
    pub fn close(&self, owner: LockOwner) {
        self.opens.lock().unwrap().retain(|o| o.owner != owner);
        self.forced.lock().unwrap().remove(&owner);
    }

    /// Drop every entry belonging to `session_id` (logoff/disconnect).
    pub fn close_session(&self, session_id: u64) {
        self.opens.lock().unwrap().retain(|o| o.owner.0 != session_id);
        self.forced.lock().unwrap().retain(|o| o.0 != session_id);
    }
}

/// Crypto material needed to sign/seal an unsolicited oplock break for a
/// holder, snapshotted at grant time (mirrors the async completion path).
#[derive(Clone)]
pub struct BreakCrypto {
    /// Negotiated dialect.
    pub dialect: Option<u16>,
    /// Signing key, if the session signs.
    pub signing_key: Option<[u8; 16]>,
    /// (c2s, s2c) cipher keys, if a cipher is negotiated.
    pub enc_keys: Option<([u8; 32], [u8; 32])>,
    /// Negotiated cipher id.
    pub cipher: Option<u16>,
    /// Session id for the transform header.
    pub session_id: u64,
    /// Seal the break notification.
    pub encrypt: bool,
    /// Sign the break notification.
    pub signed: bool,
}

/// A granted exclusive oplock and the means to break it.
pub struct OplockHolder {
    /// Session that holds the oplock.
    pub session_id: u64,
    /// File id the oplock is bound to (named in the break notification).
    pub file_id: [u8; 16],
    /// Outbound queue of the holder's connection, to push the break.
    pub outbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Crypto material to protect the break notification.
    pub crypto: BreakCrypto,
}

/// Server-wide oplock table: at most one exclusive oplock per file path.
#[derive(Default)]
pub struct OplockTable {
    held: std::sync::Mutex<HashMap<String, OplockHolder>>,
}

impl OplockTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self { held: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Grant an exclusive oplock on `path` if none is held.
    pub fn grant(&self, path: &str, holder: OplockHolder) -> bool {
        let mut held = self.held.lock().unwrap();
        if held.contains_key(path) {
            return false;
        }
        held.insert(path.to_string(), holder);
        true
    }

    /// Remove and return the current holder of `path`, if any.
    pub fn take(&self, path: &str) -> Option<OplockHolder> {
        self.held.lock().unwrap().remove(path)
    }

    /// Drop the oplock held by `owner` on `path` (on close), returning it.
    pub fn release(&self, path: &str, owner: LockOwner) -> Option<OplockHolder> {
        let mut held = self.held.lock().unwrap();
        if held.get(path).map(|h| (h.session_id, h.file_id)) == Some(owner) {
            held.remove(path)
        } else {
            None
        }
    }

    /// Drop every oplock held by any open of `session_id`.
    pub fn release_session(&self, session_id: u64) {
        self.held.lock().unwrap().retain(|_, h| h.session_id != session_id);
    }
}

/// A granted caching lease and the means to break it ([MS-SMB2] §2.2.23.2).
pub struct LeaseHolder {
    /// Client-chosen lease key identifying the shared caching state.
    pub key: [u8; 16],
    /// Currently granted lease state (caching bits).
    pub state: u32,
    /// Lease epoch (v2), bumped on each downgrade.
    pub epoch: u16,
    /// True when the holder negotiated the v2 lease form.
    pub v2: bool,
    /// Session that holds the lease.
    pub session_id: u64,
    /// File id the lease was granted on (for per-open release).
    pub file_id: [u8; 16],
    /// Outbound queue of the holder's connection, to push the break.
    pub outbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Crypto material to protect the break notification.
    pub crypto: BreakCrypto,
    /// Client GUID that owns the lease, to validate a break acknowledgment.
    pub client_guid: [u8; 16],
    /// True while a break is outstanding and awaiting acknowledgment.
    pub breaking: bool,
    /// The lease state the holder is being broken to (ack must be a subset).
    pub break_to: u32,
}

/// Why a lease-break acknowledgment was rejected ([MS-SMB2] §3.3.5.22.1).
pub enum LeaseAckError {
    /// No lease matches the key/client GUID.
    NotFound,
    /// The lease is not currently breaking.
    NotBreaking,
    /// The acknowledged state is not a subset of the break-to state.
    StateNotAccepted,
}

/// Server-wide lease table: the set of caching-lease holders per file path.
///
/// Simplified relative to [MS-SMB2] §3.3.1.10 (leases are managed independently
/// of oplocks), but READ and HANDLE caching are shareable, so multiple clients
/// may hold a lease on the same path with distinct lease keys — notably several
/// directory-lease holders that must each be broken on a conflicting access.
#[derive(Default)]
pub struct LeaseTable {
    held: std::sync::Mutex<HashMap<String, Vec<LeaseHolder>>>,
    /// One-shot signals delivered when a lease key's break is acknowledged, so
    /// a conflicting open can wait for a HANDLE-caching break ([MS-SMB2] §3.3.1.4).
    ack_waiters: std::sync::Mutex<HashMap<[u8; 16], Vec<tokio::sync::oneshot::Sender<()>>>>,
}

impl LeaseTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            held: std::sync::Mutex::new(HashMap::new()),
            ack_waiters: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Record a lease holder on `path`. Multiple clients may hold shareable
    /// (READ / HANDLE) caching on the same path with distinct lease keys
    /// ([MS-SMB2] §3.3.1.4); a duplicate of an existing key+open is ignored.
    pub fn grant(&self, path: &str, holder: LeaseHolder) -> bool {
        let mut held = self.held.lock().unwrap();
        let holders = held.entry(path.to_string()).or_default();
        if holders
            .iter()
            .any(|h| h.key == holder.key && h.file_id == holder.file_id)
        {
            return false;
        }
        holders.push(holder);
        true
    }

    /// Snapshot a co-holder's state on `path` sharing lease key `key`, if any:
    /// `(state, epoch, v2)`. A CREATE reusing an existing lease key shares that
    /// caching state rather than establishing a new grant ([MS-SMB2]
    /// §3.3.5.9.11).
    pub fn peek_key(&self, path: &str, key: [u8; 16]) -> Option<(u32, u16, bool)> {
        self.held
            .lock()
            .unwrap()
            .get(path)?
            .iter()
            .find(|h| h.key == key)
            .map(|h| (h.state, h.epoch, h.v2))
    }

    /// True when any lease is currently held on `path`.
    pub fn has_holders(&self, path: &str) -> bool {
        self.held
            .lock()
            .unwrap()
            .get(path)
            .is_some_and(|h| !h.is_empty())
    }

    /// Break every conflicting holder on `path` by clearing the `clear` caching
    /// bits, skipping the caller's own open (`owner`) and any co-holder sharing
    /// `req_key`. Returns one notification tuple `(key, old_state, new_state,
    /// epoch, outbound, crypto)` per holder that must be broken ([MS-SMB2]
    /// §3.3.4.7); READ / HANDLE caching is shareable, so multiple directory
    /// holders may each require a break.
    pub fn break_conflict(
        &self,
        path: &str,
        owner: LockOwner,
        req_key: Option<[u8; 16]>,
        clear: u32,
    ) -> Vec<(
        [u8; 16],
        u32,
        u32,
        u16,
        tokio::sync::mpsc::Sender<Vec<u8>>,
        BreakCrypto,
    )> {
        let mut held = self.held.lock().unwrap();
        let mut breaks = Vec::new();
        let Some(holders) = held.get_mut(path) else {
            return breaks;
        };
        for h in holders.iter_mut() {
            if (h.session_id, h.file_id) == owner || req_key == Some(h.key) {
                continue;
            }
            let new_state = h.state & !clear;
            if new_state == h.state {
                continue;
            }
            let old = h.state;
            h.state = new_state;
            h.epoch = h.epoch.wrapping_add(1);
            h.breaking = true;
            h.break_to = new_state;
            breaks.push((
                h.key,
                old,
                new_state,
                h.epoch,
                h.outbound.clone(),
                h.crypto.clone(),
            ));
        }
        breaks
    }

    /// Record the state a holder settled on after acknowledging a break.
    pub fn set_state(&self, key: [u8; 16], state: u32) {
        let mut held = self.held.lock().unwrap();
        if let Some(h) = held.values_mut().flatten().find(|h| h.key == key) {
            h.state = state;
        }
    }

    /// Validate and apply a client lease-break acknowledgment ([MS-SMB2]
    /// §3.3.5.22.1): the lease must exist under this client GUID, be breaking,
    /// and `acked` must be a subset of the break-to state.
    pub fn acknowledge(
        &self,
        client_guid: [u8; 16],
        key: [u8; 16],
        acked: u32,
    ) -> Result<u32, LeaseAckError> {
        let mut held = self.held.lock().unwrap();
        let h = held
            .values_mut()
            .flatten()
            .find(|h| h.key == key && h.client_guid == client_guid)
            .ok_or(LeaseAckError::NotFound)?;
        if !h.breaking {
            return Err(LeaseAckError::NotBreaking);
        }
        if acked & !h.break_to != 0 {
            return Err(LeaseAckError::StateNotAccepted);
        }
        h.state = acked;
        h.breaking = false;
        Ok(acked)
    }

    /// Drop the lease held by `owner` on `path` (on close), returning it.
    pub fn release(&self, path: &str, owner: LockOwner) -> Option<LeaseHolder> {
        let mut held = self.held.lock().unwrap();
        let holders = held.get_mut(path)?;
        let idx = holders
            .iter()
            .position(|h| (h.session_id, h.file_id) == owner)?;
        let removed = holders.remove(idx);
        if holders.is_empty() {
            held.remove(path);
        }
        Some(removed)
    }

    /// Register interest in a lease key's break acknowledgment; the returned
    /// receiver fires when the holder acknowledges ([MS-SMB2] §3.3.1.4).
    pub fn register_ack_wait(&self, key: [u8; 16]) -> tokio::sync::oneshot::Receiver<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.ack_waiters.lock().unwrap().entry(key).or_default().push(tx);
        rx
    }

    /// Wake any opens waiting on a lease key's break acknowledgment.
    pub fn signal_ack(&self, key: [u8; 16]) {
        if let Some(waiters) = self.ack_waiters.lock().unwrap().remove(&key) {
            for w in waiters {
                let _ = w.send(());
            }
        }
    }

    /// Drop every lease held by any open of `session_id`.
    pub fn release_session(&self, session_id: u64) {
        let mut held = self.held.lock().unwrap();
        for holders in held.values_mut() {
            holders.retain(|h| h.session_id != session_id);
        }
        held.retain(|_, holders| !holders.is_empty());
    }
}

/// A durable file handle preserved across a connection drop so the client can
/// reclaim it ([MS-SMB2] §3.3.1.10). Stored as `Send` metadata; on reconnect
/// the file is re-opened (single-node model), so no live fd is held here.
#[derive(Clone)]
pub struct DurableEntry {
    /// Persistent handle id the client reconnects with (the original FileId).
    pub persistent_id: [u8; 16],
    /// Client create-guid (v2 handles); zero for v1.
    pub create_guid: [u8; 16],
    /// Share-relative path to re-open on reconnect.
    pub rel: String,
    /// Whether the handle was a directory.
    pub is_dir: bool,
    /// Original desired-access mask, replayed on re-open.
    pub access: u32,
    /// Original create options, replayed on re-open.
    pub options: u32,
    /// Session that owned the handle.
    pub session_id: u64,
    /// User (SecurityContext) that owns the handle; a reconnect by a different
    /// user is rejected with STATUS_ACCESS_DENIED ([MS-SMB2] §3.3.5.9.7).
    pub owner_user: String,
    /// Client GUID that opened the handle (validated on a lease reconnect).
    pub client_guid: [u8; 16],
    /// Lease key associated with the open, if it held a lease.
    pub lease_key: Option<[u8; 16]>,
    /// Granted lease state, recreated on a persistent resume ([MS-SMB2] §3.3.5.9.12).
    pub lease_state: u32,
    /// Persistent (survives server restart intent) vs. plain durable.
    pub persistent: bool,
    /// Requested handle timeout in milliseconds (0 = server default).
    pub timeout: u32,
    /// Absolute expiry after which the preserved handle may be evicted.
    pub deadline: std::time::Instant,
}

impl DurableEntry {
    /// Project into a store record, computing the absolute deadline from
    /// `now_ms`. Persistent handles get deadline 0 (never swept).
    pub fn into_record(self, now_ms: u64) -> smb_handle_store::HandleRecord {
        smb_handle_store::HandleRecord {
            create_guid: self.persistent_id,
            path: self.rel,
            share: String::new(),
            session_id: self.session_id,
            owner_user: self.owner_user,
            access: self.access,
            share_access: 0,
            create_options: self.options,
            is_dir: self.is_dir,
            flags: if self.persistent { DHANDLE_FLAG_PERSISTENT } else { 0 },
            match_guid: if self.create_guid == [0u8; 16] { None } else { Some(self.create_guid) },
            owner_node: String::new(),
            lease_key: self.lease_key,
            lease_state: self.lease_state,
            client_guid: self.client_guid,
            timeout_ms: self.timeout as u64,
            deadline_ms: if self.persistent { 0 } else { now_ms + self.timeout as u64 },
            delete_on_close: false,
        }
    }
}

/// Established-session crypto material, shared server-wide so a new connection
/// can bind another channel to the session ([MS-SMB2] §3.3.5.5.3 multichannel).
#[derive(Clone)]
pub struct SessionEntry {
    /// Exported NTLM session key.
    pub session_key: Option<[u8; 16]>,
    /// Dialect-specific signing key.
    pub signing_key: Option<[u8; 16]>,
    /// Negotiated dialect.
    pub dialect: Option<u16>,
    /// Authenticated user name.
    pub user: String,
    /// Whether the session mapped to guest.
    pub guest: bool,
    /// Negotiated cipher id.
    pub cipher: Option<u16>,
    /// (client-to-server, server-to-client) cipher keys.
    pub enc_keys: Option<([u8; 32], [u8; 32])>,
    /// Whether the session forces encryption.
    pub encrypt_data: bool,
}

/// Server-wide table of established sessions, keyed by session id.
#[derive(Default)]
pub struct SessionTable {
    sessions: std::sync::Mutex<HashMap<u64, SessionEntry>>,
}

impl SessionTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self { sessions: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Register or refresh an established session.
    pub fn insert(&self, id: u64, entry: SessionEntry) {
        self.sessions.lock().unwrap().insert(id, entry);
    }

    /// Look up a session's crypto material for channel binding.
    pub fn get(&self, id: u64) -> Option<SessionEntry> {
        self.sessions.lock().unwrap().get(&id).cloned()
    }

    /// Forget a session (on logoff).
    pub fn remove(&self, id: u64) {
        self.sessions.lock().unwrap().remove(&id);
    }
}


/// Windows share-mode access bits ([MS-SMB2] §2.2.13).
mod amask {
    pub const FILE_READ_DATA: u32 = 0x0000_0001;
    pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
    pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
    pub const FILE_EXECUTE: u32 = 0x0000_0020;
    pub const DELETE: u32 = 0x0001_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_READ: u32 = 0x8000_0000;
}

/// Share flags ([MS-SMB2] §2.2.13).
mod share {
    pub const READ: u32 = 0x0000_0001;
    pub const WRITE: u32 = 0x0000_0002;
    pub const DELETE: u32 = 0x0000_0004;
}

fn wants_read(access: u32) -> bool {
    access & (amask::FILE_READ_DATA | amask::FILE_EXECUTE | amask::GENERIC_READ | amask::GENERIC_ALL) != 0
}
fn wants_write(access: u32) -> bool {
    access & (amask::FILE_WRITE_DATA | amask::FILE_APPEND_DATA | amask::GENERIC_WRITE | amask::GENERIC_ALL) != 0
}
fn wants_delete(access: u32) -> bool {
    access & (amask::DELETE | amask::GENERIC_ALL) != 0
}

/// A new `(access, share)` open is compatible with an `existing` open when each
/// side permits the other's access through its share flags ([MS-FSA] §2.1.5.1).
fn compatible(existing: &OpenMode, access: u32, share: u32) -> bool {
    (!wants_read(access) || existing.share & share::READ != 0)
        && (!wants_read(existing.access) || share & share::READ != 0)
        && (!wants_write(access) || existing.share & share::WRITE != 0)
        && (!wants_write(existing.access) || share & share::WRITE != 0)
        && (!wants_delete(access) || existing.share & share::DELETE != 0)
        && (!wants_delete(existing.access) || share & share::DELETE != 0)
}

impl ServerShared {
    /// Share table as advertised through srvsvc NetShareEnum level 1
    /// ([MS-SRVS] §2.2.4.26): disk shares carry STYPE_DISK, the virtual
    /// IPC$ share carries STYPE_IPC|STYPE_SPECIAL.
    pub fn share_infos(&self) -> Vec<crate::srvsvc::ShareInfo> {
        let mut v: Vec<crate::srvsvc::ShareInfo> = self
            .shares
            .values()
            .map(|s| crate::srvsvc::ShareInfo {
                netname: s.name.clone(),
                shi_type: if s.is_ipc { STYPE_IPC_SPECIAL } else { 0 },
                remark: String::new(),
            })
            .collect();
        v.sort_by(|a, b| a.netname.cmp(&b.netname));
        v
    }
}

/// An authenticated SMB session (one UID).
#[derive(Debug, Clone)]
pub struct Session {
    /// Authenticated principal name (`nobody` for guests).
    pub user: String,
    /// True when mapped to guest rather than a configured account.
    pub guest: bool,
    /// Tree connects opened under this session.
    pub trees: Vec<u16>,
}

/// Directory search continuation state keyed by search SID.
pub struct SearchCtx {
    /// Names still to be returned.
    pub queue: std::vec::IntoIter<String>,
    /// Information level requested at FIND_FIRST2 time.
    pub level: u16,
    /// Directory the search runs against.
    pub base_dir: PathBuf,
}

/// Per-connection state machine.
pub struct ConnState {
    /// NTLM challenge generated per connection at negotiate.
    pub challenge: [u8; 8],
    /// NEGOTIATE completed.
    pub negotiated: bool,
    /// Current UID (0 until first session setup allocates one).
    pub uid: u16,
    /// Multi-leg authentication in progress.
    pub auth_pending: bool,
    /// Client upgraded from SMB1 multi-protocol negotiate to SMB2.
    pub upgraded_smb2: bool,
    /// Client initiated SPNEGO-wrapped NTLMSSP.
    pub spnego: bool,
    /// Session once authenticated (None during null-session setup).
    pub session: Option<Session>,
    /// TID → share-name map.
    pub trees: HashMap<u16, String>,
    /// FID → open handle table.
    pub handles: HashMap<u16, Box<OpenFile>>,
    /// Active directory searches keyed by SID.
    pub searches: HashMap<u16, SearchCtx>,
}

impl ConnState {
    /// New connection state with the supplied per-connection challenge.
    pub fn new(challenge: [u8; 8]) -> Self {
        ConnState {
            challenge,
            negotiated: false,
            uid: 0,
            auth_pending: false,
            upgraded_smb2: false,
            spnego: false,
            session: None,
            trees: HashMap::new(),
            handles: HashMap::new(),
            searches: HashMap::new(),
        }
    }
}

static UID: AtomicU16 = AtomicU16::new(0x0400);
static TID: AtomicU16 = AtomicU16::new(0x1000);
static FID: AtomicU16 = AtomicU16::new(0x2000);
static SID: AtomicU16 = AtomicU16::new(1);

fn next_id(counter: &AtomicU16) -> u16 {
    loop {
        let v = counter.fetch_add(1, Ordering::Relaxed);
        if v != 0 && v != u16::MAX {
            return v;
        }
    }
}

/// Allocate a fresh UID.
pub fn next_uid() -> u16 {
    next_id(&UID)
}
/// Allocate a fresh TID.
pub fn next_tid() -> u16 {
    next_id(&TID)
}
/// Allocate a fresh FID.
pub fn next_fid() -> u16 {
    let v = FID.fetch_add(1, Ordering::Relaxed);
    if v == u16::MAX {
        FID.fetch_add(1, Ordering::Relaxed)
    } else {
        v
    }
}
/// Allocate a fresh search SID.
pub fn next_sid() -> u16 {
    SID.fetch_add(1, Ordering::Relaxed)
}

/// Convenience alias: refcounted shared server config.
pub type SharedServer = Arc<ServerShared>;

#[cfg(test)]
mod lock_tests {
    use super::*;

    fn owner(n: u8) -> LockOwner {
        (1, [n; 16])
    }

    #[test]
    fn exclusive_lock_blocks_other_owner() {
        let m = LockManager::new();
        assert!(m.try_acquire("f", &[(0, 10, true)], owner(1)));
        // Different owner, overlapping exclusive → denied.
        assert!(!m.try_acquire("f", &[(5, 10, true)], owner(2)));
        // Non-overlapping → allowed.
        assert!(m.try_acquire("f", &[(100, 10, true)], owner(2)));
    }

    #[test]
    fn shared_locks_coexist_but_block_exclusive() {
        let m = LockManager::new();
        assert!(m.try_acquire("f", &[(0, 10, false)], owner(1)));
        assert!(m.try_acquire("f", &[(0, 10, false)], owner(2)), "shared+shared ok");
        assert!(!m.try_acquire("f", &[(0, 10, true)], owner(3)), "shared blocks exclusive");
    }

    #[test]
    fn exclusive_conflicts_even_for_same_owner() {
        let m = LockManager::new();
        assert!(m.try_acquire("f", &[(0, 10, true)], owner(1)));
        // An exclusive lock conflicts with an overlapping lock held by the same
        // open ([MS-FSA] §2.1.5.9); a non-overlapping range still succeeds.
        assert!(!m.try_acquire("f", &[(0, 10, true)], owner(1)), "overlapping exclusive conflicts");
        assert!(m.try_acquire("f", &[(10, 10, true)], owner(1)), "adjacent range ok");
    }

    #[test]
    fn release_frees_the_range() {
        let m = LockManager::new();
        assert!(m.try_acquire("f", &[(0, 10, true)], owner(1)));
        assert!(!m.try_acquire("f", &[(0, 10, true)], owner(2)));
        m.release("f", &[(0, 10)], owner(1));
        assert!(m.try_acquire("f", &[(0, 10, true)], owner(2)), "range freed");
    }

    #[test]
    fn release_session_drops_all() {
        let m = LockManager::new();
        assert!(m.try_acquire("a", &[(0, 10, true)], (7, [1; 16])));
        assert!(m.try_acquire("b", &[(0, 10, true)], (7, [2; 16])));
        m.release_session(7);
        assert!(m.try_acquire("a", &[(0, 10, true)], (9, [3; 16])));
        assert!(m.try_acquire("b", &[(0, 10, true)], (9, [4; 16])));
    }
}

#[cfg(test)]
mod share_mode_tests {
    use super::*;

    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const SHARE_READ: u32 = 0x1;
    const SHARE_WRITE: u32 = 0x2;

    #[test]
    fn two_shared_readers_are_compatible() {
        let t = ShareModeTable::new();
        assert!(t.try_open("f", GENERIC_READ, SHARE_READ, (1, [1; 16])));
        assert!(t.try_open("f", GENERIC_READ, SHARE_READ, (1, [2; 16])));
    }

    #[test]
    fn writer_without_share_write_blocks_second_writer() {
        let t = ShareModeTable::new();
        assert!(t.try_open("f", GENERIC_WRITE, SHARE_READ, (1, [1; 16])));
        // Second writer: first open did not permit FILE_SHARE_WRITE → violation.
        assert!(!t.try_open("f", GENERIC_WRITE, SHARE_READ | SHARE_WRITE, (1, [2; 16])));
    }

    #[test]
    fn exclusive_open_blocks_everyone() {
        let t = ShareModeTable::new();
        assert!(t.try_open("f", GENERIC_READ, 0, (1, [1; 16])), "first open ok");
        assert!(!t.try_open("f", GENERIC_READ, SHARE_READ, (1, [2; 16])), "no-share open blocks");
    }

    #[test]
    fn close_reopens_share() {
        let t = ShareModeTable::new();
        assert!(t.try_open("f", GENERIC_WRITE, 0, (1, [1; 16])));
        assert!(!t.try_open("f", GENERIC_READ, SHARE_READ, (1, [2; 16])));
        t.close("f", (1, [1; 16]));
        assert!(t.try_open("f", GENERIC_READ, SHARE_READ, (1, [2; 16])), "freed after close");
    }

    #[test]
    fn session_table_binds_and_forgets() {
        let t = SessionTable::new();
        assert!(t.get(7).is_none(), "unknown session");
        t.insert(
            7,
            SessionEntry {
                session_key: Some([9u8; 16]),
                signing_key: Some([8u8; 16]),
                dialect: Some(0x0311),
                user: "faraz".into(),
                guest: false,
                cipher: Some(2),
                enc_keys: None,
                encrypt_data: false,
            },
        );
        let e = t.get(7).expect("session present for binding");
        assert_eq!(e.signing_key, Some([8u8; 16]), "bound channel reuses signing key");
        assert_eq!(e.dialect, Some(0x0311));
        t.remove(7);
        assert!(t.get(7).is_none(), "forgotten on logoff");
    }
}

//! Server-side state: configuration, sessions, tree connects, open handles
//! and directory-search contexts.
//!
//! Per the architecture, shared metadata is refcounted (`Arc`) so an
//! [`IoContext`](crate::dispatch::IoContext) can carry it for the lifetime of
//! one request without borrowing the connection lock.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use smb_vfs::OpenFile;
use smb_vfs::Vfs;

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

    /// A new lock on `[off, off+len)` conflicts with `existing` when they are
    /// held by different opens, overlap, and either side is exclusive.
    fn conflicts(existing: &HeldLock, off: u64, len: u64, excl: bool, owner: LockOwner) -> bool {
        if existing.owner == owner {
            return false;
        }
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
            .any(|&(off, len, excl)| list.iter().any(|h| Self::conflicts(h, off, len, excl, owner)));
        if clash {
            return false;
        }
        for &(off, len, excl) in ranges {
            list.push(HeldLock { offset: off, length: len, exclusive: excl, owner });
        }
        true
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

/// Crypto material needed to sign/seal an unsolicited oplock break for a
/// holder, snapshotted at grant time (mirrors the async completion path).
#[derive(Clone)]
pub struct BreakCrypto {
    /// Negotiated dialect.
    pub dialect: Option<u16>,
    /// Signing key, if the session signs.
    pub signing_key: Option<[u8; 16]>,
    /// (c2s, s2c) cipher keys, if a cipher is negotiated.
    pub enc_keys: Option<([u8; 16], [u8; 16])>,
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
}

/// Server-wide lease table: at most one primary lease holder per file path.
///
/// Simplified relative to [MS-SMB2] §3.3.1.10: a single holder is tracked per
/// path (the one that may need breaking), and leases are managed independently
/// of oplocks. This is sufficient for the common single-writer caching case.
#[derive(Default)]
pub struct LeaseTable {
    held: std::sync::Mutex<HashMap<String, LeaseHolder>>,
}

impl LeaseTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self { held: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Grant a lease on `path` if none is held; returns false if one exists.
    pub fn grant(&self, path: &str, holder: LeaseHolder) -> bool {
        let mut held = self.held.lock().unwrap();
        if held.contains_key(path) {
            return false;
        }
        held.insert(path.to_string(), holder);
        true
    }

    /// Snapshot the current holder's identity/state on `path`, if any:
    /// `(key, state, epoch, v2)`.
    pub fn peek(&self, path: &str) -> Option<([u8; 16], u32, u16, bool)> {
        self.held
            .lock()
            .unwrap()
            .get(path)
            .map(|h| (h.key, h.state, h.epoch, h.v2))
    }

    /// Break the write-caching bit of the holder on `path` down to `new_state`,
    /// returning a clone of the notification-relevant fields when a break is
    /// actually needed (state changed). Bumps the stored epoch and state.
    pub fn downgrade(
        &self,
        path: &str,
        new_state: u32,
    ) -> Option<(
        [u8; 16],
        u32,
        u16,
        tokio::sync::mpsc::Sender<Vec<u8>>,
        BreakCrypto,
    )> {
        let mut held = self.held.lock().unwrap();
        let h = held.get_mut(path)?;
        if h.state == new_state {
            return None;
        }
        let old = h.state;
        h.state = new_state;
        h.epoch = h.epoch.wrapping_add(1);
        Some((h.key, old, h.epoch, h.outbound.clone(), h.crypto.clone()))
    }

    /// Record the state a holder settled on after acknowledging a break.
    pub fn set_state(&self, key: [u8; 16], state: u32) {
        let mut held = self.held.lock().unwrap();
        if let Some(h) = held.values_mut().find(|h| h.key == key) {
            h.state = state;
        }
    }

    /// Drop the lease held by `owner` on `path` (on close), returning it.
    pub fn release(&self, path: &str, owner: LockOwner) -> Option<LeaseHolder> {
        let mut held = self.held.lock().unwrap();
        if held.get(path).map(|h| (h.session_id, h.file_id)) == Some(owner) {
            held.remove(path)
        } else {
            None
        }
    }

    /// Drop every lease held by any open of `session_id`.
    pub fn release_session(&self, session_id: u64) {
        self.held.lock().unwrap().retain(|_, h| h.session_id != session_id);
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
                shi_type: if s.is_ipc { 0x8000_0003 } else { 0 },
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
        if v != 0 && v != 0xFFFF {
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
    if v == 0xFFFF {
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
    fn same_owner_does_not_self_conflict() {
        let m = LockManager::new();
        assert!(m.try_acquire("f", &[(0, 10, true)], owner(1)));
        assert!(m.try_acquire("f", &[(0, 10, true)], owner(1)), "same owner re-lock ok");
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
}

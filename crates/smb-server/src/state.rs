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

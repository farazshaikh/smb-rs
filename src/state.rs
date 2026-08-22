// Server-side state: shares, sessions (UIDs), tree connects (TIDs),
// open file handles (FIDs) and directory-search contexts.

use std::collections::HashMap;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

#[derive(Clone)]
pub struct Share {
    pub name: String,
    pub root: PathBuf,
    pub is_ipc: bool,
}

pub fn build_shares(specs: &[(String, String)]) -> HashMap<String, Share> {
    let mut map = HashMap::new();
    for (name, path) in specs {
        let lname = name.to_lowercase();
        let is_ipc = lname == "ipc$";
        map.insert(
            lname.clone(),
            Share {
                name: name.clone(),
                root: PathBuf::from(path),
                is_ipc,
            },
        );
    }
    if !map.contains_key("ipc$") {
        map.insert(
            "ipc$".to_string(),
            Share {
                name: "IPC$".to_string(),
                root: PathBuf::from("/"),
                is_ipc: true,
            },
        );
    }
    map
}

pub static UID_COUNTER: AtomicU16 = AtomicU16::new(0x0400);
pub static TID_COUNTER: AtomicU16 = AtomicU16::new(0x1000);
pub static FID_COUNTER: AtomicU16 = AtomicU16::new(0x2000);
pub static SID_COUNTER: AtomicU16 = AtomicU16::new(1);

#[derive(Debug)]
pub struct FileHandle {
    pub path: PathBuf,
    pub is_dir: bool,
    pub file: Option<File>,
    pub pos: u64,
    pub access_read: bool,
    pub access_write: bool,
    pub delete_on_close: bool,
    pub delete_pending: bool,
}

impl FileHandle {
    pub fn metadata(&self) -> std::io::Result<Metadata> {
        match &self.file {
            Some(f) => f.metadata(),
            None => std::fs::metadata(&self.path),
        }
    }
}

pub struct SearchCtx {
    /// Remaining entries to return (file names relative to share root dir).
    pub queue: std::vec::IntoIter<String>,
    pub info_level: u16,
    pub pattern: String,
    pub base_dir: PathBuf,
}

#[derive(Default)]
pub struct Session {
    pub user: String,
    pub guest: bool,
    /// TIDs connected under this session.
    pub trees: Vec<u16>,
}

pub struct ConnState {
    /// Per-connection NTLM challenge issued at NEGOTIATE.
    pub challenge: [u8; 8],
    pub negotiated: bool,
    pub uid: u16,
    pub auth_pending: bool,
    /// Client initiated SPNEGO-wrapped NTLMSSP.
    pub spnego: bool,
    pub session: Option<Session>,
    /// All tree connects on this VC: TID -> share name.
    pub trees: HashMap<u16, String>,
    pub handles: HashMap<u16, FileHandle>,
    pub searches: HashMap<u16, SearchCtx>,
}

impl ConnState {
    pub fn new(challenge: [u8; 8]) -> Self {
        ConnState {
            challenge,
            negotiated: false,
            uid: 0,
            auth_pending: false,
            spnego: false,
            session: None,
            trees: HashMap::new(),
            handles: HashMap::new(),
            searches: HashMap::new(),
        }
    }

    pub fn close_fid(&mut self, fid: u16) -> Result<(), ()> {
        let h = self.handles.remove(&fid);
        if let Some(mut h) = h {
            // flush
            if let Some(f) = h.file.as_mut() {
                let _ = f.sync_all();
            }
            if h.delete_on_close || h.delete_pending {
                if h.is_dir {
                    let _ = std::fs::remove_dir_all(&h.path);
                } else {
                    let _ = std::fs::remove_file(&h.path);
                }
            }
        }
        Ok(())
    }
}

pub struct ServerShared {
    pub shares: HashMap<String, Share>,
    pub guid: [u8; 16],
    /// Optional user database: username -> password
    pub users: HashMap<String, String>,
    /// If true, accept any credentials as guest when no users configured.
    pub allow_guest: bool,
    pub server_name: String,
    pub domain: String,
}

/// Resolve a share-relative path securely (no escaping the share root).
/// Performs case-insensitive resolution of existing components.
pub fn resolve_path(root: &Path, rel: &str) -> PathBuf {
    let mut cur = root.to_path_buf();
    for comp in rel.split(['\\', '/']) {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp.contains(':') || comp == ".." {
            continue; // refuse traversal / drive letters
        }
        cur.push(comp);
    }
    // Case-insensitive fixup of existing components.
    let mut fixed = PathBuf::from(root);
    let suffix = cur.strip_prefix(root).unwrap_or(Path::new(""));
    for comp in suffix.components() {
        let candidate = fixed.join(comp.as_os_str());
        if candidate.exists() {
            fixed.push(comp.as_os_str());
        } else if let Some(actual) = find_case_insensitive(&fixed, &comp.as_os_str().to_string_lossy()) {
            fixed.push(actual);
        } else {
            fixed.push(comp.as_os_str());
        }
    }
    fixed
}

fn find_case_insensitive(dir: &Path, name: &str) -> Option<String> {
    let rd = std::fs::read_dir(dir).ok()?;
    let lower = name.to_lowercase();
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().to_lowercase() == lower {
            return Some(e.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

pub fn next_uid() -> u16 {
    loop {
        let v = UID_COUNTER.fetch_add(1, Ordering::Relaxed);
        if v != 0 && v != 0xFFFF {
            return v;
        }
    }
}

pub fn next_tid() -> u16 {
    loop {
        let v = TID_COUNTER.fetch_add(1, Ordering::Relaxed);
        if v != 0 && v != 0xFFFF {
            return v;
        }
    }
}

pub fn next_fid() -> u16 {
    loop {
        let v = FID_COUNTER.fetch_add(1, Ordering::Relaxed);
        if v != 0xFFFF {
            return v;
        }
    }
}

pub fn next_sid() -> u16 {
    SID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

//! Per-session state shared across the channels bound to one session
//! ([MS-SMB2] §3.3.5.5.3 multichannel): the Session.TreeConnectTable and
//! Session.OpenTable ([MS-SMB2] §3.3.1.8).
//!
//! The server runs on a single `tokio_uring` thread, so channels share this
//! state through a thread-local registry of `Rc<RefCell<SessionScope>>` keyed
//! by session id. This avoids a `Send`/`Sync` bound — io_uring open handles are
//! `!Send` — and needs no cross-thread locking.
//!
//! Handlers must never hold a `RefCell` borrow across an `.await`; async file
//! I/O checks an `OpenFile` out of the map, awaits on the owned value, then
//! checks it back in (see [`Smb2Conn`](crate::smb2::Smb2Conn) helpers).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// State shared by every channel bound to one session.
#[derive(Default)]
pub struct SessionScope {
    /// TreeId -> share name (Session.TreeConnectTable).
    pub trees: HashMap<u32, String>,
    /// Open handles keyed by 16-byte SMB2 FileId (Session.OpenTable).
    pub handles: HashMap<[u8; 16], Box<smb_vfs::OpenFile>>,
}

/// Shared, per-thread handle to a session's [`SessionScope`].
pub type ScopeRef = Rc<RefCell<SessionScope>>;

thread_local! {
    static SCOPES: RefCell<HashMap<u64, ScopeRef>> = RefCell::new(HashMap::new());
}

/// Return the scope for `session_id`, creating and registering it if absent.
/// The first channel of a session creates it; a binding channel reuses it.
pub fn get_or_create(session_id: u64) -> ScopeRef {
    SCOPES.with(|s| {
        s.borrow_mut()
            .entry(session_id)
            .or_insert_with(|| Rc::new(RefCell::new(SessionScope::default())))
            .clone()
    })
}

/// Drop the scope when the session is torn down (LOGOFF or last channel gone).
pub fn remove(session_id: u64) {
    SCOPES.with(|s| {
        s.borrow_mut().remove(&session_id);
    });
}

/// Create a fresh, unregistered scope. A new connection starts with one so
/// pre-session state is isolated; session setup replaces it with the session's
/// shared scope from the registry.
pub fn detached() -> ScopeRef {
    Rc::new(RefCell::new(SessionScope::default()))
}

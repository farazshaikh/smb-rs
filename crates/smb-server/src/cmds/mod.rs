//! SMB1 command routing and handlers.

pub mod dir_cmds;
pub mod file_cmds;
pub mod session;
pub mod trans2_cmds;

use smb_server_proto::types::Status;
use smb_server_proto_smb1::consts;
use smb_server_proto_smb1::header::{Header, RespBody};

pub use crate::dispatch::IoCtx;
use crate::dispatch::{IoContext, ReqView};
use crate::state::{next_uid, Session};

/// Route one request: fills `bodies` and returns the response status.
pub async fn dispatch_one<'a>(
    io: &mut IoContext<'a>,
    req: &ReqView<'a>,
    bodies: &mut Vec<RespBody>,
) -> Result<Status, Status> {

    // Pre-session commands: negotiate/setup/echo/exit/cancel.
    let needs_session = !matches!(
        req.hdr.command,
        consts::COM_NEGOTIATE
            | consts::COM_SESSION_SETUP_ANDX
            | consts::COM_ECHO
            | consts::COM_PROCESS_EXIT
            | consts::COM_NT_CANCEL
    );

    // Map unauthenticated clients to guest when no user DB is configured
    // (mirrors Samba's "map to guest = bad user").
    if io.conn.session.is_none() && !io.conn.auth_pending && io.server.allow_guest && needs_session {
        let uid = if io.conn.uid != 0 { io.conn.uid } else { next_uid() };
        io.conn.uid = uid;
        io.conn.session = Some(Session { user: "nobody".into(), guest: true, trees: Vec::new() });
    }
    if needs_session && io.conn.session.is_none() && !io.conn.auth_pending {
        return Err(Status::ACCESS_DENIED);
    }

    let needs_tree = needs_session
        && !matches!(req.hdr.command, consts::COM_TREE_CONNECT_ANDX | consts::COM_LOGOFF_ANDX);
    if needs_tree && !io.conn.trees.contains_key(&req.hdr.tid) {
        return Err(Status::INVALID_HANDLE);
    }

    match req.hdr.command {
        consts::COM_NEGOTIATE => session::negotiate(io, req, bodies),
        consts::COM_SESSION_SETUP_ANDX => session::setup(io, req, bodies),
        consts::COM_TREE_CONNECT_ANDX => session::tree_connect(io, req, bodies),
        consts::COM_TREE_DISCONNECT => {
            let tid = req.hdr.tid;
            io.conn.trees.remove(&tid);
            if let Some(s) = io.conn.session.as_mut() {
                s.trees.retain(|t| *t != tid);
            }
            *bodies = vec![RespBody::new(consts::COM_TREE_DISCONNECT, Vec::new(), Vec::new())];
            Ok(Status::SUCCESS)
        }
        consts::COM_LOGOFF_ANDX => {
            for fid in io.conn.handles.keys().copied().collect::<Vec<_>>() {
                if let Some(h) = io.conn.handles.remove(&fid) {
                    let vfs = share_vfs(io, req.hdr.tid);
                    let _ = vfs.close(h);
                }
            }
            io.conn.session = None;
            io.conn.auth_pending = false;
            *bodies =
                vec![RespBody::new(consts::COM_LOGOFF_ANDX, vec![consts::ANDX_NONE, 0, 0, 0], Vec::new())];
            Ok(Status::SUCCESS)
        }
        consts::COM_ECHO => session::echo(req, bodies),
        consts::COM_QUERY_INFORMATION_DISK => file_cmds::query_disk(io, req, bodies).await,
        consts::COM_NT_CREATE_ANDX => file_cmds::nt_create(io, req, bodies).await,
        consts::COM_READ_ANDX => file_cmds::read_andx(io, req, bodies).await,
        consts::COM_WRITE_ANDX => file_cmds::write_andx(io, req, bodies).await,
        consts::COM_CLOSE => file_cmds::close(io, req, bodies).await,
        consts::COM_FLUSH => file_cmds::flush(io, req, bodies).await,
        consts::COM_SEEK => file_cmds::seek(io, req, bodies).await,
        consts::COM_LOCKING_ANDX
        | consts::COM_LOCK_BYTE_RANGE
        | consts::COM_UNLOCK_BYTE_RANGE => file_cmds::locking(io, req, bodies).await,
        consts::COM_CREATE_DIRECTORY => dir_cmds::mkdir(io, req, bodies).await,
        consts::COM_DELETE_DIRECTORY => dir_cmds::rmdir(io, req, bodies).await,
        consts::COM_CHECK_DIRECTORY => dir_cmds::check_dir(io, req, bodies).await,
        consts::COM_DELETE => dir_cmds::delete(io, req, bodies).await,
        consts::COM_RENAME => dir_cmds::rename(io, req, bodies).await,
        consts::COM_NT_RENAME => dir_cmds::rename(io, req, bodies).await,
        consts::COM_QUERY_INFORMATION => dir_cmds::query_info_legacy(io, req, bodies).await,
        consts::COM_SET_INFORMATION => dir_cmds::set_info_legacy(io, req, bodies).await,
        consts::COM_PROCESS_EXIT => {
            for (_, h) in std::mem::take(&mut io.conn.handles) {
                let vfs = share_vfs_any(io);
                let _ = vfs.close(h);
            }
            *bodies = vec![RespBody::new(consts::COM_PROCESS_EXIT, Vec::new(), Vec::new())];
            Ok(Status::SUCCESS)
        }
        consts::COM_TRANSACTION2 => trans2_cmds::dispatch_trans2(io, req, bodies).await,
        _ => Err(Status::INVALID_DEVICE_REQUEST),
    }
}

/// Split a find pattern into directory + filename parts.
pub fn dir_cmds_split(pattern: &str) -> (String, String) {
    crate::cmds::dir_cmds::split_pattern_pub(pattern)
}

pub use crate::cmds::dir_cmds::split_pattern_pub as split_pattern;

/// DOS wildcard match.
pub fn wildcard(name: &str, pat: &str) -> bool {
    smb_server_backend_posix::wildcard_match(name, pat)
}

/// Resolve the VFS for the request's tree; IPC$ yields a stub that rejects.
/// Clone the VFS handle for the request's tree (Arc so handlers can hold it
    /// across mutable connection access).
    pub fn share_vfs(io: &IoContext<'_>, tid: u16) -> std::sync::Arc<dyn smb_server_vfs::Vfs> {
        static IPC: std::sync::OnceLock<smb_server_vfs_stub::IpcVfs> = std::sync::OnceLock::new();
        match io.conn.trees.get(&tid).and_then(|n| io.server.shares.get(n)) {
            Some(share) => share.vfs.clone(),
            None => std::sync::Arc::new(IPC.get_or_init(smb_server_vfs_stub::IpcVfs::default).clone())
                as std::sync::Arc<dyn smb_server_vfs::Vfs>,
        }
    }

fn share_vfs_any(_io: &IoContext) -> &'static dyn smb_server_vfs::Vfs {
    static IPC: std::sync::OnceLock<smb_server_vfs_stub::IpcVfs> = std::sync::OnceLock::new();
    IPC.get_or_init(smb_server_vfs_stub::IpcVfs::default) as &dyn smb_server_vfs::Vfs
}

/// Stub namespace so `share_vfs` can always return something.
mod smb_server_vfs_stub {
    /// Rejecting backend used for unknown trees.
    #[derive(Debug, Default, Clone)]
    pub struct IpcVfs;

    #[async_trait::async_trait(?Send)]
    impl smb_server_vfs::Vfs for IpcVfs {
        async fn create(
            &self,
            _: &str,
            _: bool,
            _: u32,
            _: u32,
            _: u32,
            _: u32,
        ) -> smb_server_vfs::VfsResult<(Box<smb_server_vfs::OpenFile>, smb_server_vfs::FileMeta, u32)> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn read(
            &self,
            _: &mut smb_server_vfs::OpenFile,
            _: u64,
            _: usize,
        ) -> smb_server_vfs::VfsResult<Vec<u8>> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn write(
            &self,
            _: &mut smb_server_vfs::OpenFile,
            _: u64,
            _: &[u8],
            _: bool,
        ) -> smb_server_vfs::VfsResult<u64> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn seek(
            &self,
            _: &mut smb_server_vfs::OpenFile,
            _: u16,
            _: i64,
        ) -> smb_server_vfs::VfsResult<u64> {
            Err(smb_server_vfs::VfsError::NotSupported)
        }
        async fn flush(&self, _: &mut smb_server_vfs::OpenFile) -> smb_server_vfs::VfsResult<()> {
            Ok(())
        }
        async fn flush_all(&self) -> smb_server_vfs::VfsResult<()> {
            Ok(())
        }
        async fn close(&self, _: Box<smb_server_vfs::OpenFile>) -> smb_server_vfs::VfsResult<()> {
            Ok(())
        }
        async fn mkdir(&self, _: &str) -> smb_server_vfs::VfsResult<()> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn rmdir(&self, _: &str) -> smb_server_vfs::VfsResult<()> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn check_dir(&self, _: &str) -> smb_server_vfs::VfsResult<()> {
            Err(smb_server_vfs::VfsError::NotFound)
        }
        async fn unlink(&self, _: &str) -> smb_server_vfs::VfsResult<()> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn delete_pattern(&self, _: &str, _: &str) -> smb_server_vfs::VfsResult<bool> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn rename(&self, _: &str, _: &str) -> smb_server_vfs::VfsResult<()> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn list(&self, _: &str) -> smb_server_vfs::VfsResult<Vec<smb_server_vfs::Entry>> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn stat(&self, _: &str) -> smb_server_vfs::VfsResult<smb_server_vfs::FileMeta> {
            Err(smb_server_vfs::VfsError::NotFound)
        }
        async fn set_info_open(
            &self,
            _: &mut smb_server_vfs::OpenFile,
            _: &smb_server_vfs::SetOp,
        ) -> smb_server_vfs::VfsResult<()> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn set_info_path(
            &self,
            _: &str,
            _: &smb_server_vfs::SetOp,
        ) -> smb_server_vfs::VfsResult<()> {
            Err(smb_server_vfs::VfsError::AccessDenied)
        }
        async fn query_disk(&self) -> smb_server_vfs::VfsResult<(u32, u32, u16, u16)> {
            Err(smb_server_vfs::VfsError::NotSupported)
        }
    }
}

//! rustsmb binary entry point: CLI parsing, async accept loop, observability.

mod auth;
pub mod cmds;
pub mod dispatch;
pub mod io;
pub mod security;
pub mod smb2;
pub mod srvsvc;
pub mod state;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser as _;

/// Default TCP listen port when `--port` is not supplied.
const DEFAULT_PORT: u16 = 4450;
/// Interval between durable-handle expiry sweeps.
const DURABLE_SWEEP_INTERVAL_SECS: u64 = 30;
/// Bytes drained from a stray HTTP probe before replying.
const HTTP_PROBE_READ_LEN: usize = 1024;

/// Command-line interface.
#[derive(Debug, clap::Parser)]
#[command(
    name = "rustsmb",
    version,
    about = "An SMB1/SMB2/SMB3 file server in pure Rust",
    long_about = None
)]
struct Args {
    /// TCP port to listen on (direct hosting on 445 by tradition).
    #[arg(short = 'p', long = "port", default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Publish a share: NAME=PATH (repeatable; defaults to public=$PWD).
    #[arg(short = 's', long = "share", value_name = "NAME=PATH")]
    shares: Vec<String>,

    /// Add an account USER:PASSWORD (repeatable; empty DB maps all users to guest).
    #[arg(short = 'u', long = "user", value_name = "USER:PASSWORD")]
    users: Vec<String>,

    /// Log filter (tracing EnvFilter syntax); RUST_LOG overrides this value.
    #[arg(long = "log", default_value = "info")]
    log_filter: String,

    /// Serve Prometheus metrics at http://ADDR/metrics (e.g. 127.0.0.1:9449).
    #[arg(long = "metrics-bind", value_name = "ADDR")]
    metrics_bind: Option<SocketAddr>,

    /// Reject clients that do not sign their traffic.
    #[arg(long = "require-signing")]
    require_signing: bool,

    /// Seal authenticated sessions that offer an encryption cipher
    /// (SMB2_SESSION_FLAG_ENCRYPT_DATA).
    #[arg(long = "encrypt")]
    encrypt: bool,

    /// Mark a share as requiring SMB3 encryption by NAME (repeatable). Its
    /// TREE_CONNECT response sets SMB2_SHAREFLAG_ENCRYPT_DATA and all traffic
    /// on the tree is sealed.
    #[arg(long = "encrypt-share", value_name = "NAME")]
    encrypt_shares: Vec<String>,

    /// Advertise SMB2_SHAREFLAG_COMPRESS_DATA on a share by NAME (repeatable):
    /// its TREE_CONNECT response signals the client may compress traffic.
    #[arg(long = "compress-share", value_name = "NAME")]
    compress_shares: Vec<String>,

    /// Durable-handle store backend: `mem` (non-durable) or `redb` (survives
    /// a server restart, enabling persistent-handle reclaim).
    #[arg(long = "handle-store", default_value = "mem")]
    handle_store: String,

    /// Path for the `redb` handle-store database.
    #[arg(long = "handle-store-path", default_value = "rustsmb-handles.redb")]
    handle_store_path: String,
}

/// Entry point.
fn main() {
    let args = Args::parse();

    // Observability: tracing subscriber honours RUST_LOG, else --log filter.
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| args.log_filter.clone());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_target(false)
        .init();

    if args.shares.is_empty() {
        let cwd = std::env::current_dir().unwrap_or_default();
        tracing::warn!(path = %cwd.display(), "no --share given; publishing cwd as 'public'");
    }

    let share_map = build_shares(&args);
    let users = build_users(&args);

    let guid = random_guid();
    let shared = Arc::new(state::ServerShared {
        shares: share_map,
        guid,
        domain: "WORKGROUP".into(),
        server_name: "RUSTSMB".into(),
        users,
        allow_guest: true,
        require_signing: args.require_signing,
        encrypt: args.encrypt,
        locks: Arc::new(state::LockManager::new()),
        share_modes: Arc::new(state::ShareModeTable::new()),
        oplocks: Arc::new(state::OplockTable::new()),
        leases: Arc::new(state::LeaseTable::new()),
        durables: build_handle_store(&args),
        sessions: Arc::new(state::SessionTable::new()),
        app_instances: Arc::new(state::AppInstanceTable::new()),
    });

    // Single-threaded io_uring runtime: all networking and file I/O run on
    // one thread via io_uring, so per-connection state stays `!Send` and never
    // crosses threads. (Per-core scaling with SO_REUSEPORT comes later.)
    tokio_uring::start(async move {
        let listener = match tokio_uring::net::TcpListener::bind(SocketAddr::from((
            [0, 0, 0, 0],
            args.port,
        ))) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(port = args.port, error = %e, "failed to bind");
                std::process::exit(1);
            }
        };
        tracing::info!(
            port = args.port,
            build = "B7",
            shares = ?shared.shares.keys().collect::<Vec<_>>(),
            auth = if shared.users.is_empty() { "guest(any)" } else { "users" },
            "rustsmb listening"
        );

        if let Some(addr) = args.metrics_bind {
            spawn_metrics_endpoint(addr);
        }

        // Periodically evict expired durable handles awaiting reconnect.
        {
            let durables = shared.durables.clone();
            tokio_uring::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(DURABLE_SWEEP_INTERVAL_SECS)).await;
                    let _ = durables.sweep_expired(state::now_ms()).await;
                }
            });
        }

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let srv = shared.clone();
                    tokio_uring::spawn(async move {
                        let _ = stream.set_nodelay(true);
                        let span = tracing::info_span!("conn", peer = %peer);
                        let _g = span.enter();
                        tracing::debug!("client connected");
                        let transport = Box::new(smb_transport::tcp::TcpTransport::new(
                            stream,
                            peer.to_string(),
                        )) as Box<dyn smb_transport::Transport>;
                        dispatch::serve_client(srv, transport).await;
                        tracing::debug!("client disconnected");
                    });
                }
                Err(e) => tracing::warn!(error = %e, "accept error"),
            }
        }
    });
}

/// Build the published share table plus the virtual IPC$ share.
fn build_shares(args: &Args) -> HashMap<String, state::Share> {
    let mut shares: Vec<(String, String)> = Vec::new();
    for spec in &args.shares {
        match spec.split_once('=') {
            Some((name, path)) => shares.push((name.to_string(), path.to_string())),
            None => shares.push(("public".into(), spec.clone())),
        }
    }
    if shares.is_empty() {
        let cwd = std::env::current_dir().unwrap_or_default();
        shares.push(("public".into(), cwd.to_string_lossy().into_owned()));
    }

    let mut map = HashMap::new();
    let encrypt_set: std::collections::HashSet<String> =
        args.encrypt_shares.iter().map(|s| s.to_lowercase()).collect();
    let compress_set: std::collections::HashSet<String> =
        args.compress_shares.iter().map(|s| s.to_lowercase()).collect();
    for (name, root) in shares {
        let lname = name.to_lowercase();
        let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(root.clone()));
        let encrypt = encrypt_set.contains(&lname);
        let compress = compress_set.contains(&lname);
        map.insert(
            lname.clone(),
            state::Share { name, root: root.into(), vfs, is_ipc: false, encrypt, compress },
        );
    }
    // Virtual IPC$ share for named-pipe traffic.
    map.insert(
        "ipc$".into(),
        state::Share {
            name: "IPC$".into(),
            root: "/".into(),
            vfs: Arc::new(smb_backend_posix::PosixVfs::new("/")),
            is_ipc: true,
            encrypt: false,
            compress: false,
        },
    );
    map
}

/// Parse USER:PASSWORD account specs into the user database.
fn build_users(args: &Args) -> HashMap<String, String> {
    let mut users = HashMap::new();
    for spec in &args.users {
        if let Some((user, pass)) = spec.split_once(':') {
            users.insert(user.to_lowercase(), pass.to_string());
        } else {
            tracing::warn!(spec = %spec, "ignoring malformed --user (expected USER:PASSWORD)");
        }
    }
    users
}

/// Build the durable-handle store from `--handle-store`. `redb` persists across
/// a restart (persistent-handle reclaim); anything else is the in-memory store.
fn build_handle_store(args: &Args) -> Arc<dyn smb_handle_store::HandleStore> {
    match args.handle_store.as_str() {
        "redb" => match smb_handle_store::RedbStore::open(&args.handle_store_path) {
            Ok(store) => {
                tracing::info!(path = %args.handle_store_path, "durable handle store: redb");
                Arc::new(store)
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to open redb handle store; using memory");
                Arc::new(smb_handle_store::MemStore::new())
            }
        },
        _ => Arc::new(smb_handle_store::MemStore::new()),
    }
}

/// Serve /metrics over a minimal HTTP/1.0 responder — no framework needed
/// for a single static endpoint, and scrape latency stays negligible.
fn spawn_metrics_endpoint(addr: SocketAddr) {
    use metrics_exporter_prometheus::PrometheusBuilder;
    match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => {
            tokio_uring::spawn(async move {
                let listener = match tokio_uring::net::TcpListener::bind(addr) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(%addr, error = %e, "metrics bind failed");
                        return;
                    }
                };
                tracing::info!(%addr, "prometheus metrics on http://{addr}/metrics");
                loop {
                    let Ok((sock, _)) = listener.accept().await else { continue };
                    let text = handle.render();
                    tokio_uring::spawn(async move {
                        // Drain the request line/headers before responding.
                        let (_read, _scratch) = sock.read(vec![0u8; HTTP_PROBE_READ_LEN]).await;
                        let resp = format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            text.len(),
                            text
                        );
                        let (_wrote, _buf) = sock.write_all(resp.into_bytes()).await;
                        let _ = sock.shutdown(std::net::Shutdown::Write);
                    });
                }
            });
        }
        Err(e) => tracing::error!(error = %e, "prometheus recorder install failed"),
    }
}

fn random_guid() -> [u8; 16] {
    use std::io::Read;
    let mut g = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut g);
    }
    g
}

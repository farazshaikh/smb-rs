//! rustsmb binary entry point: CLI parsing, async accept loop, observability.

mod auth;
pub mod cmds;
pub mod dispatch;
pub mod smb2;
pub mod srvsvc;
pub mod state;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser as _;

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
    #[arg(short = 'p', long = "port", default_value_t = 4450)]
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
    for (name, root) in shares {
        let lname = name.to_lowercase();
        let vfs: Arc<dyn smb_vfs::Vfs> = Arc::new(smb_backend_posix::PosixVfs::new(root.clone()));
        map.insert(
            lname.clone(),
            state::Share { name, root: root.into(), vfs, is_ipc: false },
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
                        let (_read, _scratch) = sock.read(vec![0u8; 1024]).await;
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

//! rustsmb binary entry point: CLI parsing, async accept loop.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod auth;
pub mod cmds;
pub mod dispatch;
pub mod smb2;
pub mod state;

use std::collections::HashMap;
use std::sync::Arc;

/// Entry point.
#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let mut port: u16 = 4450;
    let mut shares: Vec<(String, String)> = Vec::new();
    let mut users: HashMap<String, String> = HashMap::new();

    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" | "-p" => port = args.next().and_then(|v| v.parse().ok()).unwrap_or(4450),
            "--share" | "-s" => {
                if let Some(spec) = args.next() {
                    if let Some(eq) = spec.find('=') {
                        shares.push((spec[..eq].to_string(), spec[eq + 1..].to_string()));
                    } else {
                        shares.push(("public".to_string(), spec));
                    }
                }
            }
            "--user" | "-u" => {
                if let Some(spec) = args.next() {
                    if let Some(c) = spec.find(':') {
                        users.insert(spec[..c].to_lowercase(), spec[c + 1..].to_string());
                    }
                }
            }
            _ => {}
        }
    }

    if shares.is_empty() {
        let cwd = std::env::current_dir().unwrap_or_default();
        shares.push(("public".into(), cwd.to_string_lossy().into_owned()));
    }

    let mut share_map = HashMap::new();
    for (name, root) in shares {
        let lname = name.to_lowercase();
        let vfs: Arc<dyn smb_vfs::Vfs> =
            Arc::new(smb_backend_posix::PosixVfs::new(root.clone()));
        share_map.insert(
            lname.clone(),
            state::Share { name, root: root.into(), vfs, is_ipc: false },
        );
    }
    // Virtual IPC$ share.
    share_map.insert(
        "ipc$".into(),
        state::Share {
            name: "IPC$".into(),
            root: "/".into(),
            vfs: Arc::new(smb_backend_posix::PosixVfs::new("/")),
            is_ipc: true,
        },
    );

    let guid = random_guid();
    let shared = Arc::new(state::ServerShared {
        shares: share_map,
        guid,
        domain: "WORKGROUP".into(),
        server_name: "RUSTSMB".into(),
        users,
        allow_guest: true,
    });

    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind port {port}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "rustsmb listening on :{port} shares: {:?} auth: {}",
        shared.shares.keys().collect::<Vec<_>>(),
        if shared.users.is_empty() { "guest(any)" } else { "users" }
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let srv = shared.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    eprintln!("client connected: {peer}");
                    let transport = Box::new(smb_transport::tcp::TcpTransport::new(stream))
                        as Box<dyn smb_transport::Transport>;
                    dispatch::serve_client(srv, transport).await;
                    eprintln!("client disconnected: {peer}");
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
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

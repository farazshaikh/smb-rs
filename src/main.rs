mod crypto;
mod dirops;
mod dispatch;
mod files;
mod handlers;
mod message;
mod ntlm;
mod nbss;
mod smb;
mod state;
mod trans2;

use std::collections::HashMap;
use std::net::TcpListener;
use state::{ServerShared};
use std::sync::Arc;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut port: u16 = 4450;
    let mut shares: Vec<(String, String)> = Vec::new();
    let mut users: HashMap<String, String> = HashMap::new();

    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" | "-p" => {
                port = args.next().and_then(|v| v.parse().ok()).unwrap_or(4450);
            }
            "--share" | "-s" => {
                // --share name=path (repeatable)
                if let Some(spec) = args.next() {
                    if let Some(eq) = spec.find('=') {
                        shares.push((spec[..eq].to_string(), spec[eq + 1..].to_string()));
                    } else {
                        shares.push(("public".to_string(), spec));
                    }
                }
            }
            "--user" | "-u" => {
                // --user name:password (repeatable)
                if let Some(spec) = args.next() {
                    if let Some(colon) = spec.find(':') {
                        users.insert(
                            spec[..colon].to_lowercase(),
                            spec[colon + 1..].to_string(),
                        );
                    }
                }
            }
            "--help" | "-h" => {
                println!(
                    "rustsmb - an SMB1 file server\n\n\
                     USAGE:\n\
                       rustsmb [--port N] [--share name=path]... [--user name:pass]...\n\n\
                     Defaults: port 4450, share public=<cwd>, no users (guest-only access)"
                );
                return;
            }
            _ => {}
        }
    }

    if shares.is_empty() {
        let cwd = std::env::current_dir().unwrap_or_else(|_| "/tmp".into());
        shares.push(("public".to_string(), cwd.to_string_lossy().into_owned()));
    }

    let allow_guest = users.is_empty();
    let mut guid = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut guid);
    }
    let shared = Arc::new(ServerShared {
        shares: state::build_shares(&shares),
        guid,
        users,
        allow_guest,
        server_name: "RUSTSMB".to_string(),
        domain: "WORKGROUP".to_string(),
    });

    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind port {}: {}", port, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "rustsmb listening on :{} shares: {:?} auth: {}",
        port,
        shared.shares.keys().collect::<Vec<_>>(),
        if allow_guest { "guest(any)" } else { "users" }
    );

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let srv = shared.clone();
                let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                std::thread::spawn(move || {
                    let _ = s.set_nodelay(true);
                    eprintln!("client connected: {}", peer);
                    dispatch::serve_client(srv, s);
                    eprintln!("client disconnected: {}", peer);
                });
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}

//! A tiny, dependency-free HTTP server that serves MS-SMB2 test results.
//!
//! It reads a CSV (the source of truth for pass/fail state), exposes a REST API
//! over it, and serves a static single-page dashboard that renders progress.
//! It listens on the SMB port plus one so it sits next to the server under test.

mod csv;
mod http;
mod json;

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

/// Default SMB port the dashboard sits next to (it listens on this plus one).
const DEFAULT_SMB_PORT: u16 = 4450;
/// Exit code for a command-line usage error.
const EXIT_USAGE: i32 = 2;

/// Runtime configuration resolved from the command line.
struct Config {
    port: u16,
    csv_path: PathBuf,
}

fn main() {
    let config = parse_args();
    serve(config);
}

/// Parse `--smb-port`, `--port` and `--csv`. The dashboard defaults to the SMB
/// port (4450) plus one; an explicit `--port` overrides that.
fn parse_args() -> Config {
    let mut smb_port: u16 = DEFAULT_SMB_PORT;
    let mut explicit_port: Option<u16> = None;
    let mut csv_path = PathBuf::from("test_status.csv");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--smb-port" => smb_port = next_u16(&mut args, "--smb-port"),
            "--port" => explicit_port = Some(next_u16(&mut args, "--port")),
            "--csv" => csv_path = PathBuf::from(next_value(&mut args, "--csv")),
            "-h" | "--help" => print_help_and_exit(),
            other => fail(&format!("unknown argument: {other}")),
        }
    }

    Config { port: explicit_port.unwrap_or(smb_port + 1), csv_path }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next().unwrap_or_else(|| fail(&format!("{flag} needs a value")))
}

fn next_u16(args: &mut impl Iterator<Item = String>, flag: &str) -> u16 {
    next_value(args, flag)
        .parse()
        .unwrap_or_else(|_| fail(&format!("{flag} needs a number")))
}

fn print_help_and_exit() -> ! {
    println!(
        "smb-server-test-dashboard [--smb-port <n>] [--port <n>] [--csv <path>]\n\
         \n\
         Serves the MS-SMB2 test dashboard. Defaults to SMB port + 1 (4451) and\n\
         reads/writes test_status.csv in the working directory."
    );
    std::process::exit(0);
}

fn fail(msg: &str) -> ! {
    eprintln!("smb-server-test-dashboard: {msg}");
    std::process::exit(EXIT_USAGE);
}

/// Bind the listener and hand each connection to a worker thread. The CSV path
/// is shared read-only; every request re-reads the file so external test runs
/// are reflected immediately.
fn serve(config: Config) {
    let addr = ("0.0.0.0", config.port);
    let listener = TcpListener::bind(addr)
        .unwrap_or_else(|e| fail(&format!("cannot bind port {}: {e}", config.port)));
    let csv_path = Arc::new(config.csv_path);
    println!(
        "smb-server-test-dashboard listening on http://0.0.0.0:{} (csv: {})",
        config.port,
        csv_path.display()
    );

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let csv_path = Arc::clone(&csv_path);
        thread::spawn(move || http::handle_connection(stream, &csv_path));
    }
}

//! `smb-testrunner` — automated/interactive driver for the conformance suite.
//!
//! Runs the shared case registry against a live server, prints a summary, and
//! (optionally) records results under `test/data/` for the history UI. Can
//! start a local `rustsmb` itself so a single command builds a full report.
//!
//! Examples:
//!   smb-testrunner --list
//!   smb-testrunner --host 127.0.0.1 --port 4450 --user faraz --pass pass
//!   smb-testrunner --start-server --server-bin target/debug/rustsmb --record

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use clap::Parser;
use smb_server_testsuite::recorder::{self, RunReport};
use smb_server_testsuite::{cases, run_case, Ctx, Driver, Endpoint, Status, DEFAULT_PORT};

/// Exit code for a command-line usage error.
const EXIT_USAGE: i32 = 2;
/// Grace period for a freshly spawned server to bind its port.
const SERVER_BIND_DELAY_MS: u64 = 1500;

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "smb-testrunner",
    version,
    about = "smb-server-rs conformance suite runner",
    long_about = None
)]
struct Args {
    /// List cases and exit.
    #[arg(long = "list")]
    list: bool,

    /// Run only cases whose id/category contains this substring.
    #[arg(long = "filter", value_name = "SUBSTR")]
    filter: Option<String>,

    /// Write results under --data-dir.
    #[arg(long = "record")]
    record: bool,

    /// Results directory.
    #[arg(long = "data-dir", default_value = "test/data")]
    data_dir: PathBuf,

    /// Server host (default env or 127.0.0.1).
    #[arg(long = "host")]
    host: Option<String>,

    /// Server port (default env or 445).
    #[arg(long = "port")]
    port: Option<u16>,

    /// Username (default env or faraz).
    #[arg(long = "user")]
    user: Option<String>,

    /// Password (default env or pass).
    #[arg(long = "pass")]
    pass: Option<String>,

    /// Share name (default env or public).
    #[arg(long = "share")]
    share: Option<String>,

    /// Python interpreter override.
    #[arg(long = "python")]
    python: Option<String>,

    /// Driver script override.
    #[arg(long = "driver")]
    driver: Option<String>,

    /// Spawn --server-bin on --port before running.
    #[arg(long = "start-server")]
    start_server: bool,

    /// Server binary to spawn with --start-server.
    #[arg(long = "server-bin", default_value = "target/debug/rustsmb")]
    server_bin: String,

    /// Directory to publish when starting the server.
    #[arg(long = "share-dir", value_name = "PATH")]
    share_dir: Option<String>,

    /// Always exit 0 (do not fail CI on test failures).
    #[arg(long = "no-fail")]
    no_fail: bool,
}

fn main() {
    let args = Args::parse();

    let cases = cases::all();
    if args.list {
        for c in &cases {
            println!("{:<34} {:<12} {}", c.id, c.category, c.about);
        }
        println!("\n{} cases", cases.len());
        return;
    }

    let mut server = args.start_server.then(|| start_server(&args));

    let endpoint = resolve_endpoint(&args);
    let driver = resolve_driver(&args);

    let selected: Vec<_> = cases
        .iter()
        .filter(|c| match &args.filter {
            Some(f) => {
                let f = f.to_lowercase();
                c.id.to_lowercase().contains(&f) || c.category.to_lowercase().contains(&f)
            }
            None => true,
        })
        .collect();

    println!(
        "running {} case(s) against {}:{} (share {})\n",
        selected.len(),
        endpoint.host,
        endpoint.port,
        endpoint.share
    );

    let ctx = Ctx { ep: &endpoint, driver: &driver };
    let mut results = Vec::with_capacity(selected.len());
    for case in &selected {
        let r = run_case(case, &ctx);
        println!(
            "  {} {:<34} {:>6} ms  {}",
            badge(&r.status),
            r.id,
            r.duration_ms,
            if r.message.is_empty() { String::new() } else { format!("- {}", r.message) }
        );
        results.push(r);
    }

    let passed = results.iter().filter(|r| r.status == Status::Pass).count();
    let failed = results.iter().filter(|r| r.status == Status::Fail).count();
    let errored = results.iter().filter(|r| r.status == Status::Error).count();
    let skipped = results.iter().filter(|r| r.status == Status::Skip).count();
    println!(
        "\n{passed} passed, {failed} failed, {errored} errored, {skipped} skipped ({} total)",
        results.len()
    );

    if args.record {
        let report = RunReport::build(results, git_commit(), env!("CARGO_PKG_VERSION").to_string(), endpoint.host.clone());
        match recorder::record(&report, &args.data_dir) {
            Ok(path) => println!("recorded {} -> {}", report.run_id, path.display()),
            Err(e) => eprintln!("failed to record results: {e}"),
        }
    }

    if let Some(child) = server.as_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }

    let exit = if !args.no_fail && (failed > 0 || errored > 0) { 1 } else { 0 };
    std::process::exit(exit);
}

fn badge(s: &Status) -> &'static str {
    match s {
        Status::Pass => "PASS",
        Status::Fail => "FAIL",
        Status::Error => "ERR ",
        Status::Skip => "SKIP",
    }
}

fn resolve_endpoint(args: &Args) -> Endpoint {
    let mut ep = Endpoint::from_env().unwrap_or(Endpoint {
        host: "127.0.0.1".into(),
        port: DEFAULT_PORT,
        user: "faraz".into(),
        pass: "pass".into(),
        share: "public".into(),
    });
    if let Some(h) = &args.host { ep.host = h.clone(); }
    if let Some(p) = args.port { ep.port = p; }
    if let Some(u) = &args.user { ep.user = u.clone(); }
    if let Some(p) = &args.pass { ep.pass = p.clone(); }
    if let Some(s) = &args.share { ep.share = s.clone(); }
    if args.start_server {
        ep.host = "127.0.0.1".into();
    }
    ep
}

fn resolve_driver(args: &Args) -> Driver {
    let mut d = Driver::from_env();
    if let Some(p) = &args.python { d.python = p.clone(); }
    if let Some(s) = &args.driver { d.script = s.clone(); }
    d
}

/// Spawn a local server and give it a moment to bind before tests run.
fn start_server(args: &Args) -> Child {
    let port = args.port.unwrap_or(DEFAULT_PORT);
    let share_dir = args
        .share_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("smb-server-testsuite-share").to_string_lossy().into_owned());
    // Always ensure the published directory exists, or root opens fail with
    // STATUS_OBJECT_PATH_NOT_FOUND.
    std::fs::create_dir_all(&share_dir).ok();
    println!("starting {} on :{port} publishing {share_dir}", args.server_bin);
    let child = Command::new(&args.server_bin)
        .args([
            "-p",
            &port.to_string(),
            "-s",
            &format!("public={share_dir}"),
            "-u",
            "faraz:pass",
            "--log",
            "warn",
        ])
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("failed to start server {}: {e}", args.server_bin);
            std::process::exit(EXIT_USAGE);
        });
    std::thread::sleep(Duration::from_millis(SERVER_BIND_DELAY_MS));
    child
}

fn git_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

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

use smb_testsuite::recorder::{self, RunReport};
use smb_testsuite::{cases, run_case, Ctx, Driver, Endpoint, Status};

struct Args {
    list: bool,
    filter: Option<String>,
    record: bool,
    data_dir: PathBuf,
    host: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    pass: Option<String>,
    share: Option<String>,
    python: Option<String>,
    driver: Option<String>,
    start_server: bool,
    server_bin: String,
    share_dir: Option<String>,
    no_fail: bool,
}

impl Args {
    fn parse() -> Args {
        let mut a = Args {
            list: false,
            filter: None,
            record: false,
            data_dir: PathBuf::from("test/data"),
            host: None,
            port: None,
            user: None,
            pass: None,
            share: None,
            python: None,
            driver: None,
            start_server: false,
            server_bin: "target/debug/rustsmb".into(),
            share_dir: None,
            no_fail: false,
        };
        let mut it = std::env::args().skip(1);
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--list" => a.list = true,
                "--record" => a.record = true,
                "--start-server" => a.start_server = true,
                "--no-fail" => a.no_fail = true,
                "--filter" => a.filter = it.next(),
                "--data-dir" => a.data_dir = PathBuf::from(next(&mut it, "--data-dir")),
                "--host" => a.host = it.next(),
                "--port" => a.port = it.next().and_then(|p| p.parse().ok()),
                "--user" => a.user = it.next(),
                "--pass" => a.pass = it.next(),
                "--share" => a.share = it.next(),
                "--python" => a.python = it.next(),
                "--driver" => a.driver = it.next(),
                "--server-bin" => a.server_bin = next(&mut it, "--server-bin"),
                "--share-dir" => a.share_dir = it.next(),
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                other => {
                    eprintln!("unknown argument: {other}");
                    print_help();
                    std::process::exit(2);
                }
            }
        }
        a
    }
}

fn next(it: &mut impl Iterator<Item = String>, flag: &str) -> String {
    it.next().unwrap_or_else(|| {
        eprintln!("{flag} requires a value");
        std::process::exit(2);
    })
}

fn print_help() {
    eprintln!(
        "smb-testrunner — smb-rs conformance suite\n\n\
         --list                 list cases and exit\n\
         --filter <substr>      run only cases whose id/category contains substr\n\
         --record               write results under --data-dir\n\
         --data-dir <path>      results directory (default test/data)\n\
         --host/--port          server endpoint (default env or 127.0.0.1:445)\n\
         --user/--pass/--share  credentials and share (default faraz/pass/public)\n\
         --python/--driver      python interpreter and driver script overrides\n\
         --start-server         spawn --server-bin on --port before running\n\
         --server-bin <path>    server binary (default target/debug/rustsmb)\n\
         --share-dir <path>     directory to publish when starting the server\n\
         --no-fail              always exit 0 (do not fail CI on test failures)"
    );
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
        port: 445,
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
    let port = args.port.unwrap_or(445);
    let share_dir = args.share_dir.clone().unwrap_or_else(|| {
        let dir = std::env::temp_dir().join("smb-testsuite-share");
        std::fs::create_dir_all(&dir).ok();
        dir.to_string_lossy().into_owned()
    });
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
            std::process::exit(2);
        });
    std::thread::sleep(Duration::from_millis(1500));
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

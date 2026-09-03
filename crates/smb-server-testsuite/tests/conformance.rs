//! Interactive conformance tests: `cargo test -p smb-server-testsuite`.
//!
//! These require a live server; point them at one with:
//!   SMB_TEST_HOST=127.0.0.1 SMB_TEST_PORT=4450 \
//!   SMB_TEST_USER=faraz SMB_TEST_PASS=pass SMB_TEST_SHARE=public \
//!   SMB_TEST_PYTHON=/path/to/python-with-smbprotocol \
//!   cargo test -p smb-server-testsuite
//!
//! The driver script is located relative to the crate, so `SMB_TEST_DRIVER`
//! is optional. With `SMB_TEST_HOST` unset the tests skip cleanly (they pass
//! without a server) so a bare `cargo test --workspace` stays green. The
//! automated path with result recording is the `smb-testrunner` binary.

use smb_server_testsuite::{cases, run_case, Ctx, Driver, Endpoint, Status};

fn run_category(category: &str) {
    let Some(ep) = Endpoint::from_env() else {
        eprintln!("SMB_TEST_HOST unset — skipping {category} conformance cases");
        return;
    };
    let driver = Driver::from_env();
    let ctx = Ctx { ep: &ep, driver: &driver };

    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases::all().iter().filter(|c| c.category == category) {
        ran += 1;
        let r = run_case(case, &ctx);
        if r.status != Status::Pass {
            failures.push(format!("{} [{:?}]: {}", r.id, r.status, r.message));
        }
    }
    assert!(ran > 0, "no cases registered for category {category}");
    assert!(failures.is_empty(), "{category} failures:\n{}", failures.join("\n"));
}

#[test]
fn negotiate() {
    run_category("Negotiate");
}

#[test]
fn session() {
    run_category("Session");
}

#[test]
fn encryption() {
    run_category("Encryption");
}

#[test]
fn tree_connect() {
    run_category("TreeConnect");
}

#[test]
fn create() {
    run_category("Create");
}

#[test]
fn read_write() {
    run_category("ReadWrite");
}

#[test]
fn directory() {
    run_category("Directory");
}

#[test]
fn ioctl() {
    run_category("Ioctl");
}

#[test]
fn query_info() {
    run_category("QueryInfo");
}

#[test]
fn set_info() {
    run_category("SetInfo");
}

#[test]
fn locking() {
    run_category("Locking");
}

#[test]
fn streams() {
    run_category("Streams");
}

#[test]
fn security() {
    run_category("Security");
}

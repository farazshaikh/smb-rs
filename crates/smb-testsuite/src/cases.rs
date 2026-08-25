//! The conformance case registry.
//!
//! Categories mirror Microsoft's WindowsProtocolTestSuites FileServer family
//! (MS-SMB2 / MS-FSCC). Each case drives the server through the Python
//! `smbprotocol` actuator and asserts on the returned JSON. Cases must leave
//! no residue on the share (created files use delete-on-close).

use serde_json::{json, Value};

use crate::{Ctx, Metrics, Opts, TestCase};

/// The full catalog, in a stable order.
pub fn all() -> Vec<TestCase> {
    vec![
        // ---- Negotiate ([MS-SMB2] §2.2.3/4) ----
        TestCase {
            id: "negotiate.default",
            category: "Negotiate",
            spec: "MS-SMB2 3.1.1 §2.2.3",
            about: "Connects with the highest common dialect and reaches the share",
            run: |c| { probe(c, &Opts::default())?; Ok(Metrics::new()) },
        },
        TestCase {
            id: "negotiate.smb_3_1_1",
            category: "Negotiate",
            spec: "MS-SMB2 §2.2.3.1.1",
            about: "Pins dialect 3.1.1 and verifies it is negotiated",
            run: |c| { expect_dialect(c, "3.1.1")?; Ok(Metrics::new()) },
        },
        TestCase {
            id: "negotiate.smb_2_1_0",
            category: "Negotiate",
            spec: "MS-SMB2 §2.2.3",
            about: "Pins dialect 2.1.0 and verifies it is negotiated",
            run: |c| { expect_dialect(c, "2.1.0")?; Ok(Metrics::new()) },
        },
        TestCase {
            id: "negotiate.smb_2_0_2",
            category: "Negotiate",
            spec: "MS-SMB2 §2.2.3",
            about: "Pins dialect 2.0.2 and verifies it is negotiated",
            run: |c| { expect_dialect(c, "2.0.2")?; Ok(Metrics::new()) },
        },
        // ---- Session ([MS-SMB2] §2.2.5, [MS-NLMP]) ----
        TestCase {
            id: "session.ntlm_auth",
            category: "Session",
            spec: "MS-SMB2 §2.2.5 / MS-NLMP",
            about: "SPNEGO/NTLMSSP session setup reaches the share",
            run: |c| { probe(c, &Opts::default())?; Ok(Metrics::new()) },
        },
        TestCase {
            id: "session.signed",
            category: "Session",
            spec: "MS-SMB2 §3.2.5.3",
            about: "Signed session (require_signing) completes an op",
            run: |c| { probe(c, &Opts::signed())?; Ok(Metrics::new()) },
        },
        // ---- Encryption ([MS-SMB2] §3.3.5.16) ----
        TestCase {
            id: "encryption.aes_roundtrip",
            category: "Encryption",
            spec: "MS-SMB2 §2.2.41",
            about: "Encrypted session write+read roundtrip preserves data",
            run: |c| { roundtrip(c, &Opts::encrypted(), "enc_probe.bin", 4096)?; Ok(Metrics::new()) },
        },
        // ---- Tree connect ([MS-SMB2] §2.2.9) ----
        TestCase {
            id: "tree.connect_share",
            category: "TreeConnect",
            spec: "MS-SMB2 §2.2.9/10",
            about: "TREE_CONNECT to the configured share succeeds",
            run: |c| { probe(c, &Opts::default())?; Ok(Metrics::new()) },
        },
        // ---- Create ([MS-SMB2] §2.2.13) ----
        TestCase {
            id: "create.create_new",
            category: "Create",
            spec: "MS-SMB2 §2.2.13",
            about: "FILE_CREATE makes a new file (delete-on-close cleans up)",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"ct_create_new.bin",
                     "disposition":"create","delete_on_close":true},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)
            },
        },
        TestCase {
            id: "create.overwrite_if",
            category: "Create",
            spec: "MS-SMB2 §2.2.13",
            about: "FILE_OVERWRITE_IF opens-or-truncates and writes",
            run: |c| { roundtrip(c, &Opts::default(), "ct_overwrite_if.bin", 1024)?; Ok(Metrics::new()) },
        },
        TestCase {
            id: "create.open_missing_fails",
            category: "Create",
            spec: "MS-SMB2 §3.3.5.9",
            about: "FILE_OPEN of a missing file is refused",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"ct_definitely_absent_9271.bin",
                     "disposition":"open"}
                ]))?;
                if r.ok {
                    return Err("opening a missing file unexpectedly succeeded".into());
                }
                Ok(Metrics::new())
            },
        },
        TestCase {
            id: "create.directory_open",
            category: "Create",
            spec: "MS-SMB2 §2.2.13",
            about: "Opens the share root as a directory handle",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"d","path":"","directory":true,"disposition":"open"},
                    {"op":"close","handle":"d"}
                ]))?;
                ok(&r)
            },
        },
        // ---- Read / Write ([MS-SMB2] §2.2.19/21) ----
        TestCase {
            id: "readwrite.roundtrip_small",
            category: "ReadWrite",
            spec: "MS-SMB2 §2.2.19/21",
            about: "Small write then read returns identical bytes",
            run: |c| { roundtrip(c, &Opts::default(), "rw_small.bin", 512)?; Ok(Metrics::new()) },
        },
        TestCase {
            id: "readwrite.offset",
            category: "ReadWrite",
            spec: "MS-SMB2 §2.2.19",
            about: "Write at a non-zero offset reads back at that offset",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"rw_offset.bin",
                     "disposition":"overwrite_if","delete_on_close":true},
                    {"op":"write","handle":"f","offset":4096,"fill_size":256,"fill_seed":11},
                    {"op":"read","handle":"f","offset":4096,"length":256},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)?;
                compare_crc(&r, 1, 2)
            },
        },
        TestCase {
            id: "readwrite.large_mtu_256k",
            category: "ReadWrite",
            spec: "MS-SMB2 §2.2.3.1.1 CAP_LARGE_MTU",
            about: "256 KiB single-op write+read (multi-credit) preserves data",
            run: |c| {
                let size = 256 * 1024u64;
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"rw_large.bin",
                     "disposition":"overwrite_if","delete_on_close":true},
                    {"op":"write","handle":"f","offset":0,"fill_size":size,"fill_seed":7},
                    {"op":"read","handle":"f","offset":0,"length":size},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)?;
                compare_crc(&r, 1, 2)?;
                let mut m = Metrics::new();
                // End-to-end throughput incl. client startup; a trend signal.
                m.insert("bytes".into(), (size * 2) as f64);
                Ok(m)
            },
        },
        // ---- Directory query ([MS-SMB2] §2.2.33) ----
        TestCase {
            id: "directory.enumerate",
            category: "Directory",
            spec: "MS-SMB2 §2.2.33/34",
            about: "Created files appear in a directory enumeration",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"a","path":"dir_enum_a.bin","disposition":"overwrite_if"},
                    {"op":"close","handle":"a"},
                    {"op":"open","handle":"b","path":"dir_enum_b.bin","disposition":"overwrite_if"},
                    {"op":"close","handle":"b"},
                    {"op":"list","path":"","pattern":"dir_enum_*"},
                    {"op":"open","handle":"a","path":"dir_enum_a.bin","disposition":"open","delete_on_close":true},
                    {"op":"close","handle":"a"},
                    {"op":"open","handle":"b","path":"dir_enum_b.bin","disposition":"open","delete_on_close":true},
                    {"op":"close","handle":"b"}
                ]))?;
                ok(&r)?;
                let names = list_names(&r, 4)?;
                for want in ["dir_enum_a.bin", "dir_enum_b.bin"] {
                    if !names.iter().any(|n| n == want) {
                        return Err(format!("enumeration missing {want}: got {names:?}"));
                    }
                }
                Ok(Metrics::new())
            },
        },
        TestCase {
            id: "directory.pattern_filter",
            category: "Directory",
            spec: "MS-SMB2 §2.2.33.1 / MS-CIFS wildcard",
            about: "A wildcard pattern only returns matching names",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"m","path":"pat_match.bin","disposition":"overwrite_if"},
                    {"op":"close","handle":"m"},
                    {"op":"open","handle":"o","path":"pat_other.bin","disposition":"overwrite_if"},
                    {"op":"close","handle":"o"},
                    {"op":"list","path":"","pattern":"pat_match*"},
                    {"op":"open","handle":"m","path":"pat_match.bin","disposition":"open","delete_on_close":true},
                    {"op":"close","handle":"m"},
                    {"op":"open","handle":"o","path":"pat_other.bin","disposition":"open","delete_on_close":true},
                    {"op":"close","handle":"o"}
                ]))?;
                ok(&r)?;
                let names = list_names(&r, 4)?;
                if names.iter().any(|n| n == "pat_other.bin") {
                    return Err(format!("pattern leaked a non-match: {names:?}"));
                }
                if !names.iter().any(|n| n == "pat_match.bin") {
                    return Err(format!("pattern dropped the match: {names:?}"));
                }
                Ok(Metrics::new())
            },
        },
        // ---- IOCTL / FSCTL ([MS-SMB2] §2.2.31) ----
        TestCase {
            id: "ioctl.validate_negotiate_info",
            category: "Ioctl",
            spec: "MS-SMB2 §3.3.5.15",
            about: "FSCTL_VALIDATE_NEGOTIATE_INFO echoes 24 bytes",
            run: |c| {
                // 24 zero bytes of input satisfy the server's length guard.
                let r = c.run_with(&Opts::dialect("3.1.1"), json!([
                    {"op":"ioctl","ctl_code":0x00140204,
                     "input_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
                ]))?;
                ok(&r)?;
                let out = b64_len(&r, 0)?;
                if out < 24 {
                    return Err(format!("validate-negotiate output too short: {out}"));
                }
                Ok(Metrics::new())
            },
        },
        TestCase {
            id: "ioctl.query_network_interface_info",
            category: "Ioctl",
            spec: "MS-SMB2 §3.3.5.15.4",
            about: "FSCTL_QUERY_NETWORK_INTERFACE_INFO returns interface data",
            run: |c| {
                let r = c.run_with(&Opts::dialect("3.1.1"), json!([
                    {"op":"ioctl","ctl_code":0x001401FC}
                ]))?;
                ok(&r)?;
                let out = b64_len(&r, 0)?;
                if out < 152 {
                    return Err(format!("interface-info output too short: {out}"));
                }
                Ok(Metrics::new())
            },
        },
    ]
}

/// Open the share root as a directory and close it — a minimal reachability probe.
fn probe(c: &Ctx, opts: &Opts) -> Result<(), String> {
    let r = c.run_with(opts, json!([
        {"op":"open","handle":"d","path":"","directory":true,"disposition":"open"},
        {"op":"close","handle":"d"}
    ]))?;
    ok(&r).map(|_| ())
}

/// Assert the negotiated dialect string matches.
fn expect_dialect(c: &Ctx, want: &str) -> Result<(), String> {
    let r = c.run_with(&Opts::dialect(want), json!([
        {"op":"open","handle":"d","path":"","directory":true,"disposition":"open"},
        {"op":"close","handle":"d"}
    ]))?;
    ok(&r)?;
    if r.dialect != want {
        return Err(format!("negotiated {} but expected {want}", r.dialect));
    }
    Ok(())
}

/// Write a filled pattern and read it back, asserting the crc matches.
fn roundtrip(c: &Ctx, opts: &Opts, path: &str, size: u64) -> Result<(), String> {
    let r = c.run_with(opts, json!([
        {"op":"open","handle":"f","path":path,"disposition":"overwrite_if","delete_on_close":true},
        {"op":"write","handle":"f","offset":0,"fill_size":size,"fill_seed":7},
        {"op":"read","handle":"f","offset":0,"length":size},
        {"op":"close","handle":"f"}
    ]))?;
    ok(&r)?;
    compare_crc(&r, 1, 2).map(|_| ())
}

/// Return `Ok` if the driver reported overall success, else the driver error.
fn ok(r: &crate::DriverResp) -> Result<Metrics, String> {
    if r.ok {
        Ok(Metrics::new())
    } else {
        Err(r.error.clone().unwrap_or_else(|| "driver reported failure".into()))
    }
}

/// Compare the crc32 of a write step against a read step.
fn compare_crc(r: &crate::DriverResp, write_idx: usize, read_idx: usize) -> Result<Metrics, String> {
    let w = step_u64(r, write_idx, "crc32")?;
    let rd = step_u64(r, read_idx, "crc32")?;
    if w != rd {
        return Err(format!("data mismatch: write crc {w:#x} != read crc {rd:#x}"));
    }
    Ok(Metrics::new())
}

/// Names returned by a `list` op at the given step index.
fn list_names(r: &crate::DriverResp, idx: usize) -> Result<Vec<String>, String> {
    let step = r.step(idx).ok_or("missing list step")?;
    let arr = step.get("names").and_then(Value::as_array).ok_or("no names in list step")?;
    Ok(arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
}

/// Length of the base64 output at a step (decoded byte count).
fn b64_len(r: &crate::DriverResp, idx: usize) -> Result<usize, String> {
    let step = r.step(idx).ok_or("missing ioctl step")?;
    let b64 = step.get("output_b64").and_then(Value::as_str).ok_or("no output_b64")?;
    Ok(b64.len() * 3 / 4)
}

fn step_u64(r: &crate::DriverResp, idx: usize, key: &str) -> Result<u64, String> {
    r.step(idx)
        .and_then(|s| s.get(key))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("step {idx} missing {key}"))
}

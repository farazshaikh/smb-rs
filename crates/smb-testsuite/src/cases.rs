//! The conformance case registry.
//!
//! Categories mirror Microsoft's WindowsProtocolTestSuites FileServer family
//! (MS-SMB2 / MS-FSCC). Each case drives the server through the Python
//! `smbprotocol` actuator and asserts on the returned JSON. Cases must leave
//! no residue on the share (created files use delete-on-close).

use serde_json::{json, Value};

use crate::{Ctx, Metrics, Opts, TestCase};

/// The full catalog, in a stable order.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // SMB2 test-fixture sizes/offsets
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
            spec: "MS-SMB2 §3.3.5.15.12",
            about: "FSCTL_VALIDATE_NEGOTIATE_INFO on 3.1.1 terminates the connection",
            run: |c| {
                // On 3.1.1 pre-auth integrity supersedes this exchange, so the
                // server MUST terminate the connection ([MS-SMB2] §3.3.5.15.12).
                let r = c.run_with(&Opts::dialect("3.1.1"), json!([
                    {"op":"ioctl","ctl_code":0x00140204,
                     "input_b64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
                ]))?;
                if r.ok {
                    return Err("expected connection termination on 3.1.1 validate-negotiate".into());
                }
                let err = r.error.clone().unwrap_or_default();
                if err.to_lowercase().contains("clos") {
                    Ok(Metrics::new())
                } else {
                    Err(format!("expected connection closed, got: {err}"))
                }
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
        // ---- Query info ([MS-SMB2] §2.2.37, [MS-FSCC] §2.4) ----
        TestCase {
            id: "queryinfo.standard",
            category: "QueryInfo",
            spec: "MS-FSCC §2.4.41 FileStandardInformation",
            about: "FileStandardInformation reports the written EOF",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"qi_std.bin","disposition":"overwrite_if","delete_on_close":true},
                    {"op":"write","handle":"f","offset":0,"fill_size":1000},
                    {"op":"query_info","handle":"f","info_type":"file","info_class":5},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)?;
                let eof = step_u64(&r, 2, "end_of_file")?;
                if eof != 1000 {
                    return Err(format!("end_of_file {eof} != 1000"));
                }
                Ok(Metrics::new())
            },
        },
        TestCase {
            id: "queryinfo.all_information",
            category: "QueryInfo",
            spec: "MS-FSCC §2.4.2 FileAllInformation",
            about: "FileAllInformation returns a populated buffer",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"qi_all.bin","disposition":"overwrite_if","delete_on_close":true},
                    {"op":"query_info","handle":"f","info_type":"file","info_class":18},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)?;
                if step_u64(&r, 1, "length")? == 0 {
                    return Err("FileAllInformation returned empty buffer".into());
                }
                Ok(Metrics::new())
            },
        },
        TestCase {
            id: "queryinfo.network_open",
            category: "QueryInfo",
            spec: "MS-FSCC §2.4.34 FileNetworkOpenInformation",
            about: "FileNetworkOpenInformation returns a populated buffer",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"qi_netopen.bin","disposition":"overwrite_if","delete_on_close":true},
                    {"op":"query_info","handle":"f","info_type":"file","info_class":34},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)?;
                if step_u64(&r, 1, "length")? == 0 {
                    return Err("FileNetworkOpenInformation returned empty buffer".into());
                }
                Ok(Metrics::new())
            },
        },
        // ---- Set info ([MS-SMB2] §2.2.39, [MS-FSCC] §2.4) ----
        TestCase {
            id: "setinfo.end_of_file",
            category: "SetInfo",
            spec: "MS-FSCC §2.4.13 FileEndOfFileInformation",
            about: "Setting EOF resizes the file (verified via query)",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"si_eof.bin","disposition":"overwrite_if","delete_on_close":true},
                    {"op":"set_info","handle":"f","kind":"eof","size":4096},
                    {"op":"query_info","handle":"f","info_type":"file","info_class":5},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)?;
                let eof = step_u64(&r, 2, "end_of_file")?;
                if eof != 4096 {
                    return Err(format!("end_of_file {eof} != 4096 after set-eof"));
                }
                Ok(Metrics::new())
            },
        },
        TestCase {
            id: "setinfo.rename",
            category: "SetInfo",
            spec: "MS-FSCC §2.4.37 FileRenameInformation",
            about: "Rename moves the file to the new name",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"si_rename_a.bin","disposition":"overwrite_if"},
                    {"op":"set_info","handle":"f","kind":"rename","new_name":"si_rename_b.bin","replace":true},
                    {"op":"close","handle":"f"},
                    {"op":"list","path":"","pattern":"si_rename_*"},
                    {"op":"open","handle":"b","path":"si_rename_b.bin","disposition":"open","delete_on_close":true},
                    {"op":"close","handle":"b"}
                ]))?;
                ok(&r)?;
                let names = list_names(&r, 3)?;
                if names.iter().any(|n| n == "si_rename_a.bin") {
                    return Err("old name still present after rename".into());
                }
                if !names.iter().any(|n| n == "si_rename_b.bin") {
                    return Err(format!("new name missing after rename: {names:?}"));
                }
                Ok(Metrics::new())
            },
        },
        TestCase {
            id: "setinfo.delete_disposition",
            category: "SetInfo",
            spec: "MS-FSCC §2.4.11 FileDispositionInformation",
            about: "Delete-on-close disposition removes the file",
            run: |c| {
                // The final open is expected to fail: the file is gone.
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"si_del.bin","disposition":"overwrite_if"},
                    {"op":"set_info","handle":"f","kind":"delete"},
                    {"op":"close","handle":"f"},
                    {"op":"open","handle":"g","path":"si_del.bin","disposition":"open","expect_fail":true}
                ]))?;
                ok(&r)
            },
        },
        // ---- Locking ([MS-SMB2] §2.2.26) ----
        TestCase {
            id: "locking.exclusive_conflict",
            category: "Locking",
            spec: "MS-SMB2 §2.2.26 / §3.3.5.14",
            about: "An exclusive lock blocks a conflicting lock until released",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"a","path":"lk_conf.bin","disposition":"overwrite_if"},
                    {"op":"write","handle":"a","offset":0,"fill_size":100},
                    {"op":"open","handle":"b","path":"lk_conf.bin","disposition":"open"},
                    {"op":"lock","handle":"a","kind":"exclusive","offset":0,"length":50},
                    {"op":"lock","handle":"b","kind":"exclusive","offset":0,"length":50,"expect_fail":true},
                    {"op":"lock","handle":"a","kind":"unlock","offset":0,"length":50},
                    {"op":"lock","handle":"b","kind":"exclusive","offset":0,"length":50},
                    {"op":"lock","handle":"b","kind":"unlock","offset":0,"length":50},
                    {"op":"close","handle":"b"},
                    {"op":"close","handle":"a","delete":true}
                ]))?;
                ok(&r)
            },
        },
        TestCase {
            id: "locking.unlock_roundtrip",
            category: "Locking",
            spec: "MS-SMB2 §2.2.26",
            about: "Lock then unlock a range on one handle",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"lk_rt.bin","disposition":"overwrite_if","delete_on_close":true},
                    {"op":"write","handle":"f","offset":0,"fill_size":64},
                    {"op":"lock","handle":"f","kind":"exclusive","offset":0,"length":32},
                    {"op":"lock","handle":"f","kind":"unlock","offset":0,"length":32},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)
            },
        },
        // ---- Alternate data streams ([MS-FSCC] §2.6) ----
        TestCase {
            id: "streams.roundtrip",
            category: "Streams",
            spec: "MS-FSCC §2.6 named streams",
            about: "Write and read back a named alternate data stream",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"base","path":"ads_rt.bin","disposition":"overwrite_if"},
                    {"op":"write","handle":"base","offset":0,"data":"base"},
                    {"op":"close","handle":"base"},
                    {"op":"open","handle":"s","path":"ads_rt.bin:alt","disposition":"overwrite_if"},
                    {"op":"write","handle":"s","offset":0,"fill_size":256,"fill_seed":13},
                    {"op":"read","handle":"s","offset":0,"length":256},
                    {"op":"close","handle":"s"},
                    {"op":"open","handle":"base2","path":"ads_rt.bin","disposition":"open","delete_on_close":true},
                    {"op":"close","handle":"base2"}
                ]))?;
                ok(&r)?;
                compare_crc(&r, 4, 5)
            },
        },
        TestCase {
            id: "streams.enumerate",
            category: "Streams",
            spec: "MS-FSCC §2.4.40 FileStreamInformation",
            about: "Stream enumeration lists the named stream",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"base","path":"ads_enum.bin","disposition":"overwrite_if"},
                    {"op":"write","handle":"base","offset":0,"data":"base"},
                    {"op":"close","handle":"base"},
                    {"op":"open","handle":"s","path":"ads_enum.bin:alt","disposition":"overwrite_if"},
                    {"op":"write","handle":"s","offset":0,"data":"streamdata"},
                    {"op":"close","handle":"s"},
                    {"op":"open","handle":"b2","path":"ads_enum.bin","disposition":"open"},
                    {"op":"query_info","handle":"b2","info_type":"file","info_class":22},
                    {"op":"close","handle":"b2","delete":true}
                ]))?;
                ok(&r)?;
                let streams = stream_names(&r, 7)?;
                if !streams.iter().any(|n| n.contains(":alt:")) {
                    return Err(format!("named stream missing from enumeration: {streams:?}"));
                }
                Ok(Metrics::new())
            },
        },
        // ---- Security descriptors ([MS-SMB2] §2.2.37, [MS-FSCC] §2.4.6) ----
        TestCase {
            id: "security.query_descriptor",
            category: "Security",
            spec: "MS-FSCC §2.4.6 / MS-DTYP §2.4.6",
            about: "Query owner/group/DACL returns a security descriptor",
            run: |c| {
                let r = c.run(json!([
                    {"op":"open","handle":"f","path":"sd_q.bin","disposition":"overwrite_if","delete_on_close":true},
                    {"op":"query_info","handle":"f","info_type":"security","info_class":0,"additional":7},
                    {"op":"close","handle":"f"}
                ]))?;
                ok(&r)?;
                if step_u64(&r, 1, "length")? < 20 {
                    return Err("security descriptor too small".into());
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
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // test I/O sizes
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
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // base64 length arithmetic
fn b64_len(r: &crate::DriverResp, idx: usize) -> Result<usize, String> {
    let step = r.step(idx).ok_or("missing ioctl step")?;
    let b64 = step.get("output_b64").and_then(Value::as_str).ok_or("no output_b64")?;
    Ok(b64.len() * 3 / 4)
}

/// Stream names from a `query_info` FileStreamInformation step.
fn stream_names(r: &crate::DriverResp, idx: usize) -> Result<Vec<String>, String> {
    let step = r.step(idx).ok_or("missing query_info step")?;
    let arr = step.get("streams").and_then(Value::as_array).ok_or("no streams in step")?;
    Ok(arr
        .iter()
        .filter_map(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
        .collect())
}

fn step_u64(r: &crate::DriverResp, idx: usize, key: &str) -> Result<u64, String> {
    r.step(idx)
        .and_then(|s| s.get(key))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("step {idx} missing {key}"))
}

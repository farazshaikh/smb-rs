//! Hand-rolled JSON serialization for the REST responses (no dependencies).

use crate::csv::{Summary, TestRow};
use std::collections::BTreeMap;

/// `/api/status`: overall counts plus per-suite and per-category breakdowns.
pub fn status_body(rows: &[TestRow], summary: &Summary) -> String {
    format!(
        "{{\"total\":{},\"passed\":{},\"failed\":{},\"skipped\":{},\"unknown\":{},\
         \"suites\":[{}],\"categories\":[{}]}}",
        summary.total,
        summary.passed,
        summary.failed,
        summary.skipped,
        summary.unknown,
        breakdown(rows, |r| &r.suite, "suite"),
        breakdown(rows, |r| &r.category, "category"),
    )
}

/// Group rows by a key and emit `[{"<label>":..,"passed":..,...}]`.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // pass/fail/skip/error counter slots
fn breakdown(rows: &[TestRow], key: impl Fn(&TestRow) -> &str, label: &str) -> String {
    let mut groups: BTreeMap<&str, [usize; 4]> = BTreeMap::new();
    for row in rows {
        let slot = groups.entry(key(row)).or_insert([0, 0, 0, 0]);
        match row.status.as_str() {
            "pass" => slot[0] += 1,
            "fail" => slot[1] += 1,
            "skip" => slot[2] += 1,
            _ => slot[3] += 1,
        }
    }
    let items: Vec<String> = groups
        .iter()
        .map(|(name, [p, f, s, u])| {
            format!(
                "{{\"{label}\":{},\"passed\":{p},\"failed\":{f},\"skipped\":{s},\
                 \"unknown\":{u},\"total\":{}}}",
                quote(name),
                p + f + s + u
            )
        })
        .collect();
    items.join(",")
}

/// `/api/tests`: the full row list.
pub fn tests_body(rows: &[TestRow]) -> String {
    let items: Vec<String> = rows.iter().map(row_to_json).collect();
    format!("[{}]", items.join(","))
}

fn row_to_json(row: &TestRow) -> String {
    format!(
        "{{\"suite\":{},\"name\":{},\"category\":{},\"status\":{},\
         \"duration_ms\":{},\"timestamp\":{},\"commit\":{}}}",
        quote(&row.suite),
        quote(&row.name),
        quote(&row.category),
        quote(&row.status),
        row.duration_ms,
        quote(&row.timestamp),
        quote(&row.commit)
    )
}

/// Quote and escape a string as a JSON value.
#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // JSON string escaping ([RFC 8259])
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

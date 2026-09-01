//! CSV storage for test results. The schema is a header line followed by rows:
//! `suite,name,category,status,duration_ms,timestamp,commit,note`. `suite` is one
//! of `protocol`/`unit`/`system`; `status` is `pass`/`fail`/`skip`/`unknown`;
//! `commit` is the changeset the test last passed at (empty when not passing);
//! `note` explains a skip/fail reason (empty otherwise).

use std::path::Path;

/// A single test result row.
pub struct TestRow {
    pub suite: String,
    pub name: String,
    pub category: String,
    pub status: String,
    pub duration_ms: u64,
    pub timestamp: String,
    pub commit: String,
    pub note: String,
}

/// Aggregate counts over a set of rows.
pub struct Summary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub unknown: usize,
}

/// Read every result row from the CSV. A missing file yields an empty set so the
/// dashboard renders cleanly before the first test run.
pub fn load(path: &Path) -> Vec<TestRow> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .skip(1) // header
        .filter(|line| !line.trim().is_empty())
        .filter_map(parse_row)
        .collect()
}

#[cfg_attr(dylint_lib = "no_magic_numbers", allow(no_magic_numbers))] // CSV column layout
fn parse_row(line: &str) -> Option<TestRow> {
    let fields = split_csv_line(line);
    if fields.len() < 4 {
        return None;
    }
    Some(TestRow {
        suite: fields[0].clone(),
        name: fields[1].clone(),
        category: fields[2].clone(),
        status: normalize_status(&fields[3]),
        duration_ms: fields.get(4).and_then(|f| f.parse().ok()).unwrap_or(0),
        timestamp: fields.get(5).cloned().unwrap_or_default(),
        commit: fields.get(6).cloned().unwrap_or_default(),
        note: fields.get(7).cloned().unwrap_or_default(),
    })
}

fn normalize_status(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pass" | "passed" | "ok" => "pass",
        "fail" | "failed" | "error" => "fail",
        "skip" | "skipped" | "notexecuted" | "ignored" => "skip",
        _ => "unknown",
    }
    .to_string()
}

/// Split one CSV line, honouring double-quoted fields with `""` escapes.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    fields.push(field);
    fields
}

/// Count pass/fail/skip/unknown across the rows.
pub fn summarize(rows: &[TestRow]) -> Summary {
    let mut summary =
        Summary { total: rows.len(), passed: 0, failed: 0, skipped: 0, unknown: 0 };
    for row in rows {
        match row.status.as_str() {
            "pass" => summary.passed += 1,
            "fail" => summary.failed += 1,
            "skip" => summary.skipped += 1,
            _ => summary.unknown += 1,
        }
    }
    summary
}

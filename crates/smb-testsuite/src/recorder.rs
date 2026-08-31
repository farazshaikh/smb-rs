//! Result persistence: one JSON file per run plus append-only CSVs, and a
//! rebuilt aggregate `results.json` that the static UI renders. Everything
//! lives under `test/data/` and is committed so history is versioned.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::CaseResult;

/// A full run: metadata plus every case result.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunReport {
    /// Unique run identifier (`<epoch>-<short-commit>`).
    pub run_id: String,
    /// Run start time (seconds since the Unix epoch).
    pub timestamp_epoch: u64,
    /// Git commit the server was built from.
    pub commit: String,
    /// Server version string.
    pub server_version: String,
    /// Host the run executed against.
    pub host: String,
    /// Total cases in the run.
    pub total: usize,
    /// Cases that passed.
    pub passed: usize,
    /// Cases that failed an assertion.
    pub failed: usize,
    /// Cases skipped (precondition unmet).
    pub skipped: usize,
    /// Cases that aborted unexpectedly.
    pub errored: usize,
    /// Total wall-clock duration in milliseconds.
    pub duration_ms: u128,
    /// Every case result in the run.
    pub cases: Vec<CaseResult>,
}

impl RunReport {
    /// Build a report from case results, filling in counts and metadata.
    pub fn build(cases: Vec<CaseResult>, commit: String, server_version: String, host: String) -> RunReport {
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut r = RunReport {
            run_id: format!("{epoch}-{}", short(&commit)),
            timestamp_epoch: epoch,
            commit,
            server_version,
            host,
            total: cases.len(),
            passed: 0,
            failed: 0,
            skipped: 0,
            errored: 0,
            duration_ms: cases.iter().map(|c| c.duration_ms).sum(),
            cases,
        };
        for c in &r.cases {
            match c.status {
                crate::Status::Pass => r.passed += 1,
                crate::Status::Fail => r.failed += 1,
                crate::Status::Skip => r.skipped += 1,
                crate::Status::Error => r.errored += 1,
            }
        }
        r
    }

    /// Fraction of non-skipped cases that passed (0.0 when none ran).
    pub fn pass_rate(&self) -> f64 {
        let ran = (self.total - self.skipped) as f64;
        if ran <= 0.0 { 0.0 } else { self.passed as f64 / ran }
    }
}

fn short(commit: &str) -> String {
    commit.chars().take(12).collect()
}

/// Persist a run and rebuild the aggregate the UI reads.
pub fn record(report: &RunReport, data_dir: &Path) -> std::io::Result<PathBuf> {
    let runs_dir = data_dir.join("runs");
    fs::create_dir_all(&runs_dir)?;

    let run_path = runs_dir.join(format!("{}.json", report.run_id));
    fs::write(&run_path, serde_json::to_vec_pretty(report).expect("serialize run"))?;

    append_summary(report, &data_dir.join("summary.csv"))?;
    append_history(report, &data_dir.join("history.csv"))?;
    rebuild_aggregate(&runs_dir, &data_dir.join("results.json"))?;
    Ok(run_path)
}

fn append_summary(report: &RunReport, path: &Path) -> std::io::Result<()> {
    let header = "run_id,timestamp_epoch,commit,server_version,total,passed,failed,skipped,errored,duration_ms,pass_rate\n";
    let mut f = open_with_header(path, header)?;
    writeln!(
        f,
        "{},{},{},{},{},{},{},{},{},{},{:.4}",
        report.run_id,
        report.timestamp_epoch,
        short(&report.commit),
        report.server_version,
        report.total,
        report.passed,
        report.failed,
        report.skipped,
        report.errored,
        report.duration_ms,
        report.pass_rate(),
    )
}

fn append_history(report: &RunReport, path: &Path) -> std::io::Result<()> {
    let header = "run_id,timestamp_epoch,category,id,status,duration_ms\n";
    let mut f = open_with_header(path, header)?;
    for c in &report.cases {
        writeln!(
            f,
            "{},{},{},{},{:?},{}",
            report.run_id,
            report.timestamp_epoch,
            c.category,
            c.id,
            c.status,
            c.duration_ms,
        )?;
    }
    Ok(())
}

fn open_with_header(path: &Path, header: &str) -> std::io::Result<fs::File> {
    let fresh = !path.exists();
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    if fresh {
        f.write_all(header.as_bytes())?;
    }
    Ok(f)
}

#[derive(Serialize)]
struct RunSummary {
    run_id: String,
    timestamp_epoch: u64,
    commit: String,
    server_version: String,
    host: String,
    total: usize,
    passed: usize,
    failed: usize,
    skipped: usize,
    errored: usize,
    duration_ms: u128,
    pass_rate: f64,
}

#[derive(Serialize)]
struct CategorySummary {
    name: String,
    pass: usize,
    fail: usize,
    skip: usize,
    error: usize,
}

#[derive(Serialize)]
struct Aggregate {
    generated_epoch: u64,
    runs: Vec<RunSummary>,
    latest: Option<RunReport>,
    categories: Vec<CategorySummary>,
}

/// Read every per-run JSON and produce the aggregate the UI loads.
fn rebuild_aggregate(runs_dir: &Path, out: &Path) -> std::io::Result<()> {
    let mut reports: Vec<RunReport> = Vec::new();
    for entry in fs::read_dir(runs_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(r) = serde_json::from_slice::<RunReport>(&bytes) {
                reports.push(r);
            }
        }
    }
    reports.sort_by(|a, b| b.timestamp_epoch.cmp(&a.timestamp_epoch));

    let runs = reports
        .iter()
        .map(|r| RunSummary {
            run_id: r.run_id.clone(),
            timestamp_epoch: r.timestamp_epoch,
            commit: short(&r.commit),
            server_version: r.server_version.clone(),
            host: r.host.clone(),
            total: r.total,
            passed: r.passed,
            failed: r.failed,
            skipped: r.skipped,
            errored: r.errored,
            duration_ms: r.duration_ms,
            pass_rate: r.pass_rate(),
        })
        .collect();

    let latest = reports.first().cloned();
    let categories = latest.as_ref().map(category_summaries).unwrap_or_default();

    let aggregate = Aggregate {
        generated_epoch: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        runs,
        latest,
        categories,
    };
    fs::write(out, serde_json::to_vec_pretty(&aggregate).expect("serialize aggregate"))
}

fn category_summaries(report: &RunReport) -> Vec<CategorySummary> {
    let mut order: Vec<String> = Vec::new();
    let mut map: std::collections::BTreeMap<String, CategorySummary> = std::collections::BTreeMap::new();
    for c in &report.cases {
        if !map.contains_key(&c.category) {
            order.push(c.category.clone());
        }
        let e = map.entry(c.category.clone()).or_insert_with(|| CategorySummary {
            name: c.category.clone(),
            pass: 0,
            fail: 0,
            skip: 0,
            error: 0,
        });
        match c.status {
            crate::Status::Pass => e.pass += 1,
            crate::Status::Fail => e.fail += 1,
            crate::Status::Skip => e.skip += 1,
            crate::Status::Error => e.error += 1,
        }
    }
    order.into_iter().filter_map(|k| map.remove(&k)).collect()
}

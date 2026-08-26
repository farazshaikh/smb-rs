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
    pub run_id: String,
    pub timestamp_epoch: u64,
    pub commit: String,
    pub server_version: String,
    pub host: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errored: usize,
    pub duration_ms: u128,
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

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT PRIMARY KEY,
    timestamp_epoch INTEGER NOT NULL,
    git_commit     TEXT NOT NULL,
    server_version TEXT NOT NULL,
    host           TEXT NOT NULL,
    total          INTEGER NOT NULL,
    passed         INTEGER NOT NULL,
    failed         INTEGER NOT NULL,
    skipped        INTEGER NOT NULL,
    errored        INTEGER NOT NULL,
    duration_ms    INTEGER NOT NULL,
    pass_rate      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    run_id      TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    category    TEXT NOT NULL,
    spec        TEXT NOT NULL,
    status      TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    message     TEXT NOT NULL,
    PRIMARY KEY (run_id, case_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id)
);
CREATE TABLE IF NOT EXISTS metrics (
    run_id  TEXT NOT NULL,
    case_id TEXT NOT NULL,
    name    TEXT NOT NULL,
    value   REAL NOT NULL,
    PRIMARY KEY (run_id, case_id, name)
);
CREATE INDEX IF NOT EXISTS idx_runs_commit ON runs(git_commit);
CREATE INDEX IF NOT EXISTS idx_results_status ON results(status);
";

/// Persist a run into the SQLite database (created on first use), keyed by
/// `run_id` and carrying the git revision so results can be queried per commit.
pub fn record_sqlite(report: &RunReport, db_path: &Path) -> rusqlite::Result<()> {
    if let Some(parent) = db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut conn = rusqlite::Connection::open(db_path)?;
    conn.execute_batch(SCHEMA)?;
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO runs (run_id, timestamp_epoch, git_commit, server_version, host, \
         total, passed, failed, skipped, errored, duration_ms, pass_rate) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        rusqlite::params![
            report.run_id,
            report.timestamp_epoch as i64,
            report.commit,
            report.server_version,
            report.host,
            report.total as i64,
            report.passed as i64,
            report.failed as i64,
            report.skipped as i64,
            report.errored as i64,
            report.duration_ms as i64,
            report.pass_rate(),
        ],
    )?;
    for c in &report.cases {
        tx.execute(
            "INSERT OR REPLACE INTO results (run_id, case_id, category, spec, status, duration_ms, message) \
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![
                report.run_id,
                c.id,
                c.category,
                c.spec,
                c.status.as_str(),
                c.duration_ms as i64,
                c.message,
            ],
        )?;
        for (name, value) in &c.metrics {
            tx.execute(
                "INSERT OR REPLACE INTO metrics (run_id, case_id, name, value) VALUES (?1,?2,?3,?4)",
                rusqlite::params![report.run_id, c.id, name, value],
            )?;
        }
    }
    tx.commit()
}

/// One run's headline numbers, for reporting a revision's history.
#[derive(Debug)]
pub struct RunRow {
    pub run_id: String,
    pub timestamp_epoch: i64,
    pub passed: i64,
    pub failed: i64,
    pub errored: i64,
    pub total: i64,
    pub pass_rate: f64,
}

/// All recorded runs for a git revision, newest first.
pub fn runs_for_commit(db_path: &Path, commit: &str) -> rusqlite::Result<Vec<RunRow>> {
    let conn = rusqlite::Connection::open(db_path)?;
    conn.execute_batch(SCHEMA)?;
    let mut stmt = conn.prepare(
        "SELECT run_id, timestamp_epoch, passed, failed, errored, total, pass_rate \
         FROM runs WHERE git_commit = ?1 ORDER BY timestamp_epoch DESC",
    )?;
    let rows = stmt.query_map([commit], |r| {
        Ok(RunRow {
            run_id: r.get(0)?,
            timestamp_epoch: r.get(1)?,
            passed: r.get(2)?,
            failed: r.get(3)?,
            errored: r.get(4)?,
            total: r.get(5)?,
            pass_rate: r.get(6)?,
        })
    })?;
    rows.collect()
}

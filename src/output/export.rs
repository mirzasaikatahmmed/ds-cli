//! CSV / JSON export for `--save`.
//!
//! Files are written to the current working directory with a timestamped
//! name (e.g. `ds-results-2026-08-16-15-30-00.csv`). JSON is the union of all
//! fields; CSV flattens `LookupDetails` into additional columns.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::models::LookupResult;

/// CSV row layout. Each row is one lookup result.
#[derive(Debug, Serialize)]
struct CsvRow<'a> {
    domain: &'a str,
    status: &'a str,
    source: &'a str,
    latency_ms: u64,
    registrar: String,
    creation_date: String,
    expiry_date: String,
    nameservers: String,
    server: String,
    registry: String,
}

impl<'a> From<&'a LookupResult> for CsvRow<'a> {
    fn from(r: &'a LookupResult) -> Self {
        let (registrar, creation_date, expiry_date, nameservers, server, registry) =
            if let Some(d) = &r.details {
                (
                    d.registrar.clone().unwrap_or_default(),
                    d.creation_date.clone().unwrap_or_default(),
                    d.expiry_date.clone().unwrap_or_default(),
                    d.nameservers.join(";"),
                    d.server.clone().unwrap_or_default(),
                    d.registry.clone().unwrap_or_default(),
                )
            } else {
                Default::default()
            };
        Self {
            domain: &r.domain,
            status: match r.status {
                crate::models::DomainStatus::Available => "available",
                crate::models::DomainStatus::Taken => "taken",
                crate::models::DomainStatus::Unknown => "unknown",
            },
            source: &r.source,
            latency_ms: r.latency_ms,
            registrar,
            creation_date,
            expiry_date,
            nameservers,
            server,
            registry,
        }
    }
}

/// Write CSV to `path`. Caller picks the path.
#[allow(dead_code)]
pub fn write_csv(path: &Path, results: &[LookupResult]) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)
        .with_context(|| format!("creating CSV at {}", path.display()))?;
    for r in results {
        wtr.serialize(CsvRow::from(r))?;
    }
    wtr.flush()?;
    Ok(())
}

/// Write JSON (pretty-printed array of `LookupResult`) to `path`.
#[allow(dead_code)]
pub fn write_json(path: &Path, results: &[LookupResult]) -> Result<()> {
    let json = serde_json::to_string_pretty(results).context("serializing results to JSON")?;
    let mut f =
        fs::File::create(path).with_context(|| format!("creating JSON at {}", path.display()))?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

/// Generate a timestamped filename in the current directory, like
/// `ds-results-2026-08-16-15-30-00.csv`.
#[allow(dead_code)]
pub fn timestamped_path(ext: &str) -> PathBuf {
    let (date, time) = utc_date_time_strings();
    PathBuf::from(format!("ds-results-{date}-{time}.{ext}"))
}

/// Returns `(YYYY-MM-DD, HH-MM-SS)` for the current UTC time. Kept inline
/// to avoid pulling in a chrono dep.
fn utc_date_time_strings() -> (String, String) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Days since epoch -> date using a small inline algorithm.
    let days = secs.div_euclid(86_400);
    let secs_in_day = secs.rem_euclid(86_400) as u32;
    let (year, month, day) = days_to_ymd(days);
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    (
        format!("{year:04}-{month:02}-{day:02}"),
        format!("{h:02}-{m:02}-{s:02}"),
    )
}

fn days_to_ymd(days_since_epoch: i64) -> (i32, u32, u32) {
    // Civil-from-days algorithm by Howard Hinnant (public domain).
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DomainStatus, LookupDetails, LookupResult};

    fn sample_results() -> Vec<LookupResult> {
        vec![
            LookupResult {
                domain: "a.com".into(),
                status: DomainStatus::Available,
                source: "rdap".into(),
                latency_ms: 100,
                details: None,
            },
            LookupResult {
                domain: "b.com".into(),
                status: DomainStatus::Taken,
                source: "whois".into(),
                latency_ms: 200,
                details: Some(LookupDetails {
                    registrar: Some("Big Registrar".into()),
                    ..Default::default()
                }),
            },
        ]
    }

    #[test]
    fn write_csv_round_trips_via_serde() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.csv");
        write_csv(&path, &sample_results()).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("a.com"));
        assert!(text.contains("b.com"));
        assert!(text.contains("available"));
        assert!(text.contains("Big Registrar"));
    }

    #[test]
    fn write_json_round_trips_via_serde() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.json");
        write_json(&path, &sample_results()).unwrap();
        let parsed: Vec<LookupResult> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].domain, "a.com");
        assert_eq!(parsed[1].status, DomainStatus::Taken);
    }

    #[test]
    fn timestamped_path_uses_extension() {
        let p = timestamped_path("csv");
        assert!(p.to_string_lossy().starts_with("ds-results-"));
        assert!(p.to_string_lossy().ends_with(".csv"));
    }
}

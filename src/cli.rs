//! CLI parsing (clap derive) + name/TLD expansion.
//!
//! The split between `Cli` (parsed args) and `Inputs` (expanded name + TLD lists)
//! keeps the engine layer simple: it only ever sees a flat list of (name, tld)
//! pairs, never ambiguity about whether `apple,orange` was one name or two.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;

use crate::models::LookupLevel;

/// `ds` — domain availability checker (RDAP first, WHOIS fallback).
#[derive(Debug, Parser, Clone)]
#[command(
    name = "ds",
    version,
    about = "Check domain availability over RDAP with a WHOIS fallback.",
    long_about = "Check domain availability over RDAP with a WHOIS fallback.\n\
                  Examples:\n  \
                  ds apple --tld all\n  \
                  ds apple --tld com,net --details\n  \
                  ds apple,orange,bangla,english --tld com,net\n  \
                  ds @names.txt --tld popular --available-only --save\n  \
                  ds apple --tld all --level second\n  \
                  ds apple --tld com,io --where\n  \
                  ds apple google --tld popular --whois --dns-records\n  \
                  ds apple.com --details --registry",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// One or more base names, comma-separated or space-separated. Use
    /// `@file.txt` to bulk-load names from a file (one per line).
    #[arg(value_name = "NAMES", required = true)]
    pub names: Vec<String>,

    /// TLD list (comma-separated) or named group: `all`, `popular`, `bd`.
    /// The `bd` group expands to common `.bd` SLDs (com.bd, net.bd, etc.).
    /// Dots are allowed in TLD names, so `--tld com.bd,org` parses as two
    /// TLDs: `com.bd` and `org`.
    #[arg(long, value_name = "LIST")]
    pub tld: Option<String>,

    /// Show registrar, creation date, expiry date, nameservers when available.
    #[arg(long)]
    pub details: bool,

    /// Force WHOIS instead of RDAP-first.
    #[arg(long)]
    pub whois: bool,

    /// Resolve and show A/AAAA/MX/NS records for taken domains.
    #[arg(long)]
    pub dns_records: bool,

    /// Show which registry/RDAP server answered.
    #[arg(long)]
    pub registry: bool,

    /// Show which protocol + server were used to answer.
    #[arg(long)]
    pub r#where: bool,

    /// Only print AVAILABLE results, suppress TAKEN/UNKNOWN.
    #[arg(long)]
    pub available_only: bool,

    /// Export results to CSV/JSON in the current directory.
    #[arg(long)]
    pub save: bool,

    /// Domain level to check (e.g. `second` = check `name.co.uk` style).
    #[arg(long, value_name = "LEVEL")]
    pub level: Option<String>,

    /// Override default concurrency.
    #[arg(long, value_name = "N")]
    pub concurrent: Option<usize>,

    /// Per-lookup timeout in milliseconds.
    #[arg(long, value_name = "MS")]
    pub timeout: Option<u64>,

    /// User-supplied RDAP bootstrap JSON (merge with bundled by default).
    #[arg(long, value_name = "PATH")]
    pub rdap_json: Option<String>,

    /// User-supplied WHOIS server JSON (merge with bundled by default).
    #[arg(long, value_name = "PATH")]
    pub whois_json: Option<String>,

    /// When a custom JSON is given, fully replace instead of merge.
    #[arg(long)]
    pub no_merge: bool,

    /// Override the `.bd` lookup endpoint (URL template containing
    /// `{domain}`). Falls back to the `DS_BD_ENDPOINT` env var, then the
    /// built-in default.
    #[arg(long, value_name = "URL")]
    pub bd_endpoint: Option<String>,
}

impl Cli {
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}

/// Fully expanded inputs ready for the engine.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Inputs {
    /// Expanded (name, tld) pairs, deduplicated.
    pub pairs: Vec<(String, String)>,
    /// Resolved domain level.
    pub level: LookupLevel,
}

/// Expand raw CLI args into a flat, deduplicated `(name, tld)` list.
///
/// Rules:
/// * Names may be comma-separated or space-separated. `apple,orange` and
///   `apple orange` both produce two names.
/// * `@file.txt` anywhere in the input expands to one name per line of that
///   file (blank lines and `#` comments are skipped).
/// * A name that already contains a TLD (e.g. `apple.com`, `saikat.com.bd`)
///   is split into `(name, tld)` and the `--tld` flag is ignored for that
///   entry. The split uses `known_tlds` to decide whether the trailing
///   label is actually a TLD we recognise. If it's not a known TLD the
///   whole input is treated as a base name (and the default-TLD logic
///   below applies).
/// * TLDs are comma-separated or space-separated, OR a named group:
///   `all`, `popular`, `bd`.
/// * The default TLD when none is supplied is `com` (matches the common
///   CLI expectation of "just check if my name is available").
pub fn expand_inputs(cli: &Cli, known_tlds: &HashSet<String>) -> Result<Inputs> {
    let raw_names = expand_names(&cli.names)?;
    let tlds = expand_tlds(cli.tld.as_deref().unwrap_or("com"))?;
    let level = parse_level(cli.level.as_deref())?;

    // Build pairs, dedup, preserve order.
    let mut seen = std::collections::HashSet::new();
    let mut pairs = Vec::new();

    for raw in &raw_names {
        // Try to detect a full domain like `apple.com` or `saikat.com.bd`
        // and split it into `(name, tld)`. If the trailing label isn't a
        // known TLD we treat the whole input as a base name and combine it
        // with the --tld list (or default).
        if let Some((name, tld)) = split_full_domain(raw, known_tlds) {
            let key = (name, tld);
            if seen.insert(key.clone()) {
                pairs.push(key);
            }
            continue;
        }

        let base = normalize_name(raw);
        if base.is_empty() {
            continue;
        }
        for tld in &tlds {
            let key = (base.clone(), tld.clone());
            if seen.insert(key.clone()) {
                pairs.push(key);
            }
        }
    }

    Ok(Inputs { pairs, level })
}

/// If `raw` looks like a full domain whose trailing label is a known TLD,
/// return `(name, tld)`. Otherwise return `None`.
///
/// `known_tlds` is a case-insensitive set of TLD labels (without the
/// leading dot), e.g. `{"com", "net", "org", "com.bd", "bd", ...}`.
///
/// Multi-label TLDs like `co.uk` are handled correctly: we walk from the
/// rightmost label leftward, building longer TLD candidates, and accept
/// the **longest** candidate that appears in `known_tlds`. So given
/// `known_tlds = {"uk", "co.uk"}`, `apple.co.uk` splits into
/// `(apple, co.uk)`.
pub fn split_full_domain(raw: &str, known_tlds: &HashSet<String>) -> Option<(String, String)> {
    let raw = raw.trim().trim_start_matches('.');
    if raw.is_empty() {
        return None;
    }
    let lowered = raw.to_ascii_lowercase();
    // Build TLD candidates from the rightmost label, then progressively
    // longer prefixes separated by dots. e.g. for "saikat.com.bd" the
    // candidates are ["bd", "com.bd", "saikat.com.bd"].
    let parts: Vec<&str> = lowered.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    // Try TLD candidates from longest to shortest (i.e. the rightmost
    // label group). For "apple.co.uk" with {uk, co.uk} in the set, we
    // try "co.uk" first (longer match wins) before falling back to "uk".
    // The single-label "whole input" candidate is rejected because it
    // would have an empty name.
    let original_parts: Vec<&str> = raw.split('.').collect();
    // start ranges over the first label of the candidate TLD. start=1
    // gives the full TLD with all labels; start=parts.len()-1 gives
    // just the rightmost label.
    for start in 1..parts.len() {
        let candidate_tld = parts[start..].join(".");
        if known_tlds.contains(&candidate_tld) {
            // Name is everything before this TLD. Must be non-empty.
            if start == 0 {
                continue;
            }
            let original_name = original_parts[..start].join(".");
            return Some((original_name, candidate_tld));
        }
    }
    None
}

/// Build the full set of TLDs `ds` knows about, from well-known lists.
/// Used to decide whether a positional argument like `apple.com` already
/// contains a TLD.
pub fn known_tlds() -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for t in POPULAR_TLDS {
        out.insert(t.to_ascii_lowercase());
    }
    for t in BD_ZONE_TLDS {
        out.insert(t.to_ascii_lowercase());
    }
    out
}

/// Expand `<NAMES>...` into a flat list of raw names.
///
/// Handles comma-separated tokens, `@file.txt` references, and trims
/// whitespace. Empty names are dropped.
pub fn expand_names(raw: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for token in raw {
        for piece in token.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            if let Some(path) = piece.strip_prefix('@') {
                let names = read_names_file(Path::new(path))?;
                out.extend(names);
            } else {
                out.push(piece.to_string());
            }
        }
    }
    Ok(out)
}

/// Read a `@file.txt` style name list. One name per line, `#` comments and
/// blank lines are skipped.
pub fn read_names_file(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("reading names file: {}", path.display()))?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Allow comma-separated names inside a file too.
        for piece in line.split(',') {
            let piece = piece.trim();
            if !piece.is_empty() {
                out.push(piece.to_string());
            }
        }
    }
    Ok(out)
}

/// Expand a `--tld` value into a concrete TLD list.
///
/// Accepts:
/// * `all` — every TLD in the popular + gTLD list (see `POPULAR_TLDS`).
/// * `popular` — a curated list of commonly-checked TLDs.
/// * `bd` — convenience for the `.bd` zone (direct `bd` plus the common
///   second-level SLDs: `com.bd`, `net.bd`, `org.bd`, `edu.bd`, `gov.bd`,
///   `ac.bd`). All of these are handled by the same upstream provider.
/// * `com,net,org` / `com net org` — comma- or space-separated concrete
///   list. Dots are allowed in TLD names so `com.bd` parses as a single
///   SLD rather than as `com` + `bd`.
pub fn expand_tlds(raw: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for piece in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        match piece.to_ascii_lowercase().as_str() {
            "all" => {
                out.extend(POPULAR_TLDS.iter().map(|s| s.to_string()));
            }
            "popular" => {
                out.extend(POPULAR_TLDS.iter().map(|s| s.to_string()));
            }
            "bd" => {
                out.extend(BD_ZONE_TLDS.iter().map(|s| s.to_string()));
            }
            other => {
                out.push(other.to_string());
            }
        }
    }

    // Dedupe while preserving order.
    let mut seen = BTreeSet::new();
    let dedup: Vec<String> = out.into_iter().filter(|t| seen.insert(t.clone())).collect();

    Ok(dedup)
}

/// Common TLDs in the `.bd` zone (second-level `.bd` SLDs plus the
/// direct `bd` TLD itself). All of these route through the dedicated
/// `.bd` resolver.
pub const BD_ZONE_TLDS: &[&str] = &[
    "bd",      // direct .bd
    "com.bd",  // commercial
    "net.bd",  // network
    "org.bd",  // organizations
    "edu.bd",  // educational
    "gov.bd",  // government
    "ac.bd",   // academic
    "co.bd",   // company
    "info.bd", // info
    "name.bd", // personal names
];

/// Curated list of commonly-checked TLDs used by the `popular` and `all`
/// groups. Kept in one place so it's easy to extend.
pub const POPULAR_TLDS: &[&str] = &[
    "com", "net", "org", "io", "app", "dev", "co", "ai", "me", "info", "xyz", "tech", "cloud",
    "store", "shop", "site", "online", "blog", "bd",
];

fn parse_level(raw: Option<&str>) -> Result<LookupLevel> {
    match raw {
        None => Ok(LookupLevel::First),
        Some("first") => Ok(LookupLevel::First),
        Some("second") => Ok(LookupLevel::Second),
        Some(other) => anyhow::bail!("invalid --level: {} (expected 'first' or 'second')", other),
    }
}

/// Normalize a name: strip whitespace, lowercase, drop any leading dot.
fn normalize_name(raw: &str) -> String {
    raw.trim().trim_start_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_names_handles_comma_and_space() {
        let raw = vec!["apple,orange".into(), "banana".into()];
        let out = expand_names(&raw).unwrap();
        assert_eq!(out, vec!["apple", "orange", "banana"]);
    }

    #[test]
    fn expand_names_skips_empty_pieces() {
        let raw = vec![",,apple,,".into()];
        let out = expand_names(&raw).unwrap();
        assert_eq!(out, vec!["apple"]);
    }

    #[test]
    fn expand_names_loads_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("names.txt");
        std::fs::write(&path, "# comment\n\napple\norange, banana\n  cherry  \n").unwrap();

        let raw = vec![format!("@{}", path.display())];
        let out = expand_names(&raw).unwrap();
        assert_eq!(out, vec!["apple", "orange", "banana", "cherry"]);
    }

    #[test]
    fn expand_names_read_file_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("n.txt");
        std::fs::write(&path, "# header\n\nfoo\n# mid\nbar\n").unwrap();
        let out = read_names_file(&path).unwrap();
        assert_eq!(out, vec!["foo", "bar"]);
    }

    #[test]
    fn expand_tlds_popular_group() {
        assert_eq!(expand_tlds("popular").unwrap(), POPULAR_TLDS);
    }

    #[test]
    fn expand_tlds_all_group() {
        assert_eq!(expand_tlds("all").unwrap(), POPULAR_TLDS);
    }

    #[test]
    fn expand_tlds_bd_alias_expands_to_bd_zone() {
        // The `bd` shorthand expands to direct `.bd` plus the common
        // second-level `.bd` SLDs.
        let out = expand_tlds("bd").unwrap();
        assert_eq!(out, BD_ZONE_TLDS);
        // All entries must end in `.bd` (or be exactly `bd`).
        for tld in &out {
            assert!(
                *tld == "bd" || tld.ends_with(".bd"),
                "BD_ZONE_TLDS entry {tld} is not a .bd TLD"
            );
        }
    }

    #[test]
    fn expand_tlds_handles_dot_in_tld_name() {
        // TLDs may contain dots — `com.bd` is a single SLD, not `com` + `bd`.
        assert_eq!(expand_tlds("com.bd,net").unwrap(), vec!["com.bd", "net"]);
        assert_eq!(
            expand_tlds("com.bd net.bd org.bd").unwrap(),
            vec!["com.bd", "net.bd", "org.bd"]
        );
    }

    #[test]
    fn expand_tlds_concrete_list() {
        assert_eq!(
            expand_tlds("com,net,org").unwrap(),
            vec!["com", "net", "org"]
        );
    }

    #[test]
    fn expand_tlds_dedupes() {
        let out = expand_tlds("com,net,com,org,net").unwrap();
        assert_eq!(out, vec!["com", "net", "org"]);
    }

    #[test]
    fn expand_tlds_handles_spaces() {
        assert_eq!(
            expand_tlds("com net org").unwrap(),
            vec!["com", "net", "org"]
        );
    }

    #[test]
    fn split_full_domain_basic_tld() {
        let mut tlds = HashSet::new();
        tlds.insert("com".into());
        tlds.insert("net".into());
        assert_eq!(
            split_full_domain("apple.com", &tlds),
            Some(("apple".into(), "com".into()))
        );
        assert_eq!(
            split_full_domain("Saikat.NET", &tlds),
            Some(("Saikat".into(), "net".into()))
        );
    }

    #[test]
    fn split_full_domain_multi_label_tld() {
        // `co.uk` is a multi-label TLD. Without it in the set, `apple.co.uk`
        // would split as (apple.co, uk). With both `uk` and `co.uk` in the
        // set, it should pick the longest match: (apple, co.uk).
        let mut tlds = HashSet::new();
        tlds.insert("uk".into());
        tlds.insert("co.uk".into());
        assert_eq!(
            split_full_domain("apple.co.uk", &tlds),
            Some(("apple".into(), "co.uk".into()))
        );
    }

    #[test]
    fn split_full_domain_bd_zone() {
        let tlds = known_tlds();
        assert_eq!(
            split_full_domain("saikat.com.bd", &tlds),
            Some(("saikat".into(), "com.bd".into()))
        );
        assert_eq!(
            split_full_domain("saikat.bd", &tlds),
            Some(("saikat".into(), "bd".into()))
        );
        assert_eq!(
            split_full_domain("saikat.net.bd", &tlds),
            Some(("saikat".into(), "net.bd".into()))
        );
    }

    #[test]
    fn split_full_domain_unknown_tld_falls_through() {
        // If the trailing label isn't a known TLD we return None — the
        // input is treated as a base name and combined with --tld.
        let mut tlds = HashSet::new();
        tlds.insert("com".into());
        assert_eq!(split_full_domain("saikat.com.bd", &tlds), None);
        assert_eq!(split_full_domain("saikat.example", &tlds), None);
    }

    #[test]
    fn split_full_domain_no_dot_returns_none() {
        let mut tlds = HashSet::new();
        tlds.insert("com".into());
        assert_eq!(split_full_domain("apple", &tlds), None);
        assert_eq!(split_full_domain("", &tlds), None);
        assert_eq!(split_full_domain(".com", &tlds), None);
    }

    #[test]
    fn expand_inputs_recognises_full_domain() {
        // `ds apple.com` should NOT get `com` appended again — the input
        // already contains a TLD.
        let cli = Cli {
            names: vec!["apple.com".into()],
            tld: None,
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(inputs.pairs, vec![("apple".into(), "com".into())]);
    }

    #[test]
    fn expand_inputs_recognises_full_2ld_bd_domain() {
        // `ds saikat.com.bd` (no --tld flag) should split correctly.
        let cli = Cli {
            names: vec!["saikat.com.bd".into()],
            tld: None,
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(inputs.pairs, vec![("saikat".into(), "com.bd".into())]);
    }

    #[test]
    fn expand_inputs_full_domain_does_not_get_tld_appended() {
        // Regression test for the bug where `ds saikat.com.bd --details`
        // produced `saikat.com.bd.com`. With the fix it produces just
        // (saikat, com.bd) — `com` is not appended because the input
        // already contained a TLD.
        let cli = Cli {
            names: vec!["saikat.com.bd".into()],
            tld: None,
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        // Critical: the result must NOT contain `com.bd.com`.
        for (name, tld) in &inputs.pairs {
            let full = format!("{name}.{tld}");
            assert!(
                !full.ends_with(".com.bd.com"),
                "{full} has the wrong TLD (shouldn't be com.bd.com)"
            );
        }
        assert_eq!(inputs.pairs, vec![("saikat".into(), "com.bd".into())]);
    }

    #[test]
    fn expand_inputs_mixed_full_and_bare_names() {
        // `apple.com` (full domain) and `orange` (base name) together
        // should produce different shapes: apple → (apple, com),
        // orange → (orange, com) from the --tld default.
        let cli = Cli {
            names: vec!["apple.com".into(), "orange".into()],
            tld: None,
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(
            inputs.pairs,
            vec![
                ("apple".into(), "com".into()),
                ("orange".into(), "com".into()),
            ]
        );
    }

    #[test]
    fn expand_inputs_dedupes_pairs() {
        let cli = Cli {
            names: vec!["apple,APPLE".into()],
            tld: Some("com,com".into()),
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(inputs.pairs, vec![("apple".into(), "com".into())]);
    }

    #[test]
    fn expand_inputs_default_level_is_first() {
        let cli = Cli {
            names: vec!["apple".into()],
            tld: Some("com".into()),
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(inputs.level, LookupLevel::First);
    }

    #[test]
    fn expand_inputs_parses_second_level() {
        let cli = Cli {
            names: vec!["apple".into()],
            tld: Some("co.uk".into()),
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: Some("second".into()),
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(inputs.level, LookupLevel::Second);
    }

    #[test]
    fn expand_inputs_defaults_to_com_when_no_tld_flag() {
        let cli = Cli {
            names: vec!["apple".into()],
            tld: None,
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(inputs.pairs, vec![("apple".into(), "com".into())]);
    }

    #[test]
    fn expand_inputs_rejects_bad_level() {
        let cli = Cli {
            names: vec!["apple".into()],
            tld: Some("com".into()),
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: Some("third".into()),
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        assert!(expand_inputs(&cli, &known_tlds()).is_err());
    }

    #[test]
    fn expand_inputs_pairs_intersection() {
        let cli = Cli {
            names: vec!["apple,banana".into()],
            tld: Some("com,net".into()),
            details: false,
            whois: false,
            dns_records: false,
            registry: false,
            r#where: false,
            available_only: false,
            save: false,
            level: None,
            concurrent: None,
            timeout: None,
            rdap_json: None,
            whois_json: None,
            no_merge: false,
            bd_endpoint: None,
        };
        let inputs = expand_inputs(&cli, &known_tlds()).unwrap();
        assert_eq!(
            inputs.pairs,
            vec![
                ("apple".into(), "com".into()),
                ("apple".into(), "net".into()),
                ("banana".into(), "com".into()),
                ("banana".into(), "net".into()),
            ]
        );
    }
}

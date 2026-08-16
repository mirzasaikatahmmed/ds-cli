//! Plain-line output for `ds` results.
//!
//! Format target (from Section 6):
//!
//! ```text
//! + dolkana.app   AVAILABLE  rdap    442ms
//! x dolkana.com   TAKEN      rdap    120ms
//! ? dolkana.bd    UNKNOWN    bd      536ms
//! ```
//!
//! Columns: marker+domain (one column), status, source, latency. Optional
//! indented rows for `--details`, `--where`, `--registry`.
//!
//! Rendering strategy: each column is left-padded to its computed width
//! from the full result set, separated by single spaces. The latency
//! column is right-aligned so digit widths line up. No header row, no
//! box-drawing — just whitespace-aligned columns. ANSI color is applied
//! to the marker and the status cell only.

use owo_colors::OwoColorize;

use crate::models::{DomainStatus, LookupResult};

/// Options that change how the results are rendered.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct RenderOptions {
    pub details: bool,
    pub show_where: bool,
    pub show_registry: bool,
    pub available_only: bool,
}

/// Render results as colored, aligned lines. Returns the formatted string so
/// the caller can print it (or write it to a file for `--save`).
#[allow(dead_code)]
pub fn render(results: &[LookupResult], opts: &RenderOptions) -> String {
    // Filter first (--available-only) before computing widths.
    let visible: Vec<&LookupResult> = results
        .iter()
        .filter(|r| !(opts.available_only && r.status != DomainStatus::Available))
        .collect();

    if visible.is_empty() {
        return String::new();
    }

    // Compute column widths from the raw, uncolored text so columns line up
    // across all rows regardless of result mix.
    // First column = marker (2 chars) + domain, so the widths are computed
    // on the visible prefix.
    let mut prefix_w = 0usize;
    let mut status_w = 0usize;
    let mut source_w = 0usize;
    let mut latency_w = 0usize;
    for r in &visible {
        prefix_w = prefix_w.max(2 + r.domain.chars().count());
        status_w = status_w.max(format_status(r.status).chars().count());
        source_w = source_w.max(r.source.chars().count());
        latency_w = latency_w.max(format!("{}ms", r.latency_ms).chars().count());
    }

    let mut out = String::new();
    for r in &visible {
        out.push_str(&render_row(r, prefix_w, status_w, source_w, latency_w));
        if opts.details || opts.show_where || opts.show_registry {
            let extra = render_extra(r, opts);
            if !extra.is_empty() {
                out.push('\n');
                out.push_str(&extra);
            }
        }
        out.push('\n');
    }
    out
}

fn render_row(r: &LookupResult, prefix_w: usize, s_w: usize, src_w: usize, lat_w: usize) -> String {
    let marker = match r.status {
        DomainStatus::Available => "+ ",
        DomainStatus::Taken => "x ",
        DomainStatus::Unknown => "? ",
    };
    let status_text = format_status(r.status);
    let source_text = r.source.clone();
    let latency_text = format!("{}ms", r.latency_ms);

    // The prefix column is marker (2 chars) + domain padded to
    // (prefix_w - 2) chars, then a literal space, then the status column.
    // This gives:
    //   - exactly `prefix_w` chars of marker+domain visual width,
    //   - at least one space between domain and status (more for shorter
    //     domains, never zero), keeping the output breathable.
    let domain_pad = prefix_w - 2;

    if should_color() {
        let marker_s = match r.status {
            DomainStatus::Available => marker.green().bold().to_string(),
            DomainStatus::Taken => marker.red().bold().to_string(),
            DomainStatus::Unknown => marker.yellow().bold().to_string(),
        };
        let status_s = match r.status {
            DomainStatus::Available => status_text.green().bold().to_string(),
            DomainStatus::Taken => status_text.red().bold().to_string(),
            DomainStatus::Unknown => status_text.yellow().bold().to_string(),
        };
        format!(
            "{marker_s}{domain:<dp$} {status_s:<s$} {source_text:<src_w$} {latency_text:>lat_w$}",
            domain = r.domain,
            dp = domain_pad,
            s = s_w,
            src_w = src_w,
            lat_w = lat_w,
        )
    } else {
        format!(
            "{marker}{domain:<dp$} {status_text:<s$} {source_text:<src_w$} {latency_text:>lat_w$}",
            domain = r.domain,
            dp = domain_pad,
            s = s_w,
            src_w = src_w,
            lat_w = lat_w,
        )
    }
}

fn render_extra(r: &LookupResult, opts: &RenderOptions) -> String {
    let mut lines = Vec::new();
    if let Some(d) = &r.details {
        if opts.details {
            if let Some(reg) = &d.registrar {
                lines.push(format!("    registrar : {reg}"));
            }
            if let Some(c) = &d.creation_date {
                lines.push(format!("    created   : {c}"));
            }
            if let Some(e) = &d.expiry_date {
                lines.push(format!("    expires   : {e}"));
            }
            if !d.nameservers.is_empty() {
                lines.push(format!("    nservers  : {}", d.nameservers.join(", ")));
            }
        }
        if opts.show_where {
            if let Some(srv) = &d.server {
                lines.push(format!("    via       : {srv}"));
            }
        }
        if opts.show_registry {
            if let Some(reg) = &d.registry {
                lines.push(format!("    registry  : {reg}"));
            } else if let Some(srv) = &d.server {
                lines.push(format!("    registry  : {srv}"));
            }
        }
    }
    lines.join("\n")
}

fn format_status(s: DomainStatus) -> String {
    match s {
        DomainStatus::Available => "AVAILABLE".to_string(),
        DomainStatus::Taken => "TAKEN".to_string(),
        DomainStatus::Unknown => "UNKNOWN".to_string(),
    }
}

fn should_color() -> bool {
    // Honor NO_COLOR env var convention.
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    // Force colors when forced, otherwise detect TTY.
    if std::env::var_os("CLICOLOR_FORCE").is_some() {
        return true;
    }
    atty_stdout()
}

fn atty_stdout() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Print a human-readable summary line as per the spec example:
/// `summary: 4 available  0 taken  0 unknown   (4 checked in 1.1s)`.
#[allow(dead_code)]
pub fn print_summary(results: &[LookupResult], total_ms: u128) {
    let mut avail = 0u32;
    let mut taken = 0u32;
    let mut unknown = 0u32;
    for r in results {
        match r.status {
            DomainStatus::Available => avail += 1,
            DomainStatus::Taken => taken += 1,
            DomainStatus::Unknown => unknown += 1,
        }
    }
    let total = results.len();
    let secs = total_ms as f64 / 1000.0;
    if should_color() {
        println!(
            "{} {avail} available  {taken} taken  {unknown} unknown   ({total} checked in {secs:.1}s)",
            "summary:".cyan().bold()
        );
    } else {
        println!(
            "summary: {avail} available  {taken} taken  {unknown} unknown   ({total} checked in {secs:.1}s)"
        );
    }
}

/// Strip ANSI CSI escape sequences from a string (exposed for tests and
/// downstream callers that want the plain text rendering).
#[allow(dead_code)]
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // skip CSI: ESC [ ... letter
            while let Some(&next) = chars.peek() {
                chars.next();
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::LookupDetails;

    fn result(domain: &str, status: DomainStatus, source: &str) -> LookupResult {
        LookupResult {
            domain: domain.into(),
            status,
            source: source.into(),
            latency_ms: 100,
            details: None,
        }
    }

    fn plain(results: &[LookupResult], opts: &RenderOptions) -> String {
        strip_ansi(&render(results, opts))
    }

    #[test]
    fn render_produces_one_row_per_result() {
        let results = vec![
            result("a.com", DomainStatus::Available, "rdap"),
            result("b.com", DomainStatus::Taken, "rdap"),
            result("c.com", DomainStatus::Unknown, "bd"),
        ];
        let s = plain(&results, &RenderOptions::default());
        assert!(s.contains("a.com"));
        assert!(s.contains("b.com"));
        assert!(s.contains("c.com"));
        assert!(s.contains("rdap"));
        assert!(s.contains("bd"));
        // No header — exactly 3 result rows.
        let body_lines: Vec<&str> = s.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(body_lines.len(), 3);
    }

    #[test]
    fn render_columns_align_to_widest_cell() {
        let results = vec![
            result("short.com", DomainStatus::Available, "rdap"),
            result("much-longer-domain-name.io", DomainStatus::Taken, "whois"),
        ];
        let s = plain(&results, &RenderOptions::default());
        // Both domains should be in the rendered string.
        assert!(s.contains("short.com"));
        assert!(s.contains("much-longer-domain-name.io"));
        // The short domain should be padded so the status column starts at
        // the same position for every row.
        // marker(2) + max_domain_width(24) - 2 = 24 chars for the prefix.
        // `short.com` is 10 chars, so it needs 14 trailing spaces, then
        // "AVAILABLE" starts. The exact padding length depends on the
        // test fixtures — assert it lines up with the longer row by
        // counting visible chars before the status text.
        let short_line = s
            .lines()
            .find(|l| l.contains("short.com"))
            .expect("short.com line");
        let long_line = s
            .lines()
            .find(|l| l.contains("much-longer-domain-name.io"))
            .expect("long line");
        let short_status_at = short_line.find("AVAILABLE").unwrap();
        let long_status_at = long_line.find("TAKEN").unwrap();
        assert_eq!(
            short_status_at, long_status_at,
            "status columns should start at the same column"
        );
    }

    #[test]
    fn render_uneven_domains_status_columns_align() {
        // Reproduces the user's complaint: mixed-length domains should
        // still put the status column at the same offset.
        let results = vec![
            result("dolkana.bd", DomainStatus::Unknown, "bd"),
            result("dolkana.net", DomainStatus::Available, "rdap"),
            result("dolkana.app", DomainStatus::Available, "rdap"),
        ];
        let s = plain(&results, &RenderOptions::default());
        let status_cols: Vec<usize> = s
            .lines()
            .map(|l| {
                l.find("UNKNOWN")
                    .or_else(|| l.find("AVAILABLE"))
                    .unwrap_or_else(|| l.find("TAKEN").unwrap())
            })
            .collect();
        assert!(
            status_cols.iter().all(|c| *c == status_cols[0]),
            "all status columns should align at the same offset, got {:?}",
            status_cols
        );
    }

    #[test]
    fn render_with_available_only_filters() {
        let results = vec![
            result("a.com", DomainStatus::Available, "rdap"),
            result("b.com", DomainStatus::Taken, "rdap"),
        ];
        let opts = RenderOptions {
            available_only: true,
            ..Default::default()
        };
        let s = plain(&results, &opts);
        assert!(s.contains("a.com"));
        assert!(!s.contains("b.com"));
    }

    #[test]
    fn render_details_includes_registrar_and_dates() {
        let mut r = result("a.com", DomainStatus::Taken, "rdap");
        r.details = Some(LookupDetails {
            registrar: Some("Mock Registrar".into()),
            creation_date: Some("2020-01-01".into()),
            expiry_date: Some("2030-01-01".into()),
            nameservers: vec!["ns1.example.com".into()],
            server: None,
            registry: None,
        });
        let opts = RenderOptions {
            details: true,
            ..Default::default()
        };
        let s = plain(&[r], &opts);
        assert!(s.contains("Mock Registrar"));
        assert!(s.contains("2020-01-01"));
        assert!(s.contains("2030-01-01"));
        assert!(s.contains("ns1.example.com"));
    }

    #[test]
    fn render_where_includes_server() {
        let mut r = result("a.com", DomainStatus::Taken, "rdap");
        r.details = Some(LookupDetails {
            server: Some("rdap.verisign-grs.com".into()),
            ..Default::default()
        });
        let opts = RenderOptions {
            show_where: true,
            ..Default::default()
        };
        let s = plain(&[r], &opts);
        assert!(s.contains("rdap.verisign-grs.com"));
    }

    #[test]
    fn render_markers_match_status() {
        let results = vec![
            result("a.com", DomainStatus::Available, "rdap"),
            result("b.com", DomainStatus::Taken, "rdap"),
            result("c.com", DomainStatus::Unknown, "bd"),
        ];
        let s = plain(&results, &RenderOptions::default());
        assert!(s.contains("+ a.com"));
        assert!(s.contains("x b.com"));
        assert!(s.contains("? c.com"));
    }

    #[test]
    fn render_emits_no_header_row() {
        let results = vec![result("a.com", DomainStatus::Available, "rdap")];
        let s = plain(&results, &RenderOptions::default());
        // No "Domain"/"Status"/"Source"/"Latency" labels.
        assert!(!s.contains("Domain"));
        assert!(!s.contains("Status"));
        assert!(!s.contains("Source"));
        assert!(!s.contains("Latency"));
    }

    #[test]
    fn render_empty_returns_empty_string() {
        let s = plain(&[], &RenderOptions::default());
        assert_eq!(s, "");
    }

    #[test]
    fn render_available_only_empty_returns_empty_string() {
        let results = vec![result("a.com", DomainStatus::Taken, "rdap")];
        let opts = RenderOptions {
            available_only: true,
            ..Default::default()
        };
        let s = plain(&results, &opts);
        assert_eq!(s, "");
    }

    #[test]
    fn strip_ansi_removes_csi_sequences() {
        let s = "\u{1b}[31mhello\u{1b}[0m world".to_string();
        assert_eq!(strip_ansi(&s), "hello world");
    }

    #[test]
    fn render_with_color_includes_ansi_escapes() {
        // Force color regardless of TTY.
        std::env::set_var("CLICOLOR_FORCE", "1");
        let results = vec![result("a.com", DomainStatus::Available, "rdap")];
        let s = render(&results, &RenderOptions::default());
        std::env::remove_var("CLICOLOR_FORCE");
        // Green for available.
        assert!(s.contains("\u{1b}["));
        let plain_s = strip_ansi(&s);
        assert!(plain_s.contains("+ a.com"));
        assert!(plain_s.contains("AVAILABLE"));
    }
}

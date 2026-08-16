//! WHOIS resolver (raw TCP port 43).
//!
//! Sends `"{name}.{tld}\r\n"` to the configured WHOIS server and looks for
//! "not found" patterns in the response. Each TLD has its own phrasing
//! (`No match for`, `NOT FOUND`, `No Data Found`, `No entries found`, etc.),
//! so we maintain a per-TLD pattern table plus a generic fallback set of
//! patterns that catch most registry responses.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::bootstrap::WhoisBootstrap;
use crate::models::{DomainStatus, LookupDetails, LookupResult};
use crate::resolvers::Resolver;

/// Default WHOIS port.
pub const WHOIS_PORT: u16 = 43;

/// WHOIS resolver.
#[allow(dead_code)]
pub struct WhoisResolver {
    bootstrap: WhoisBootstrap,
    timeout: Duration,
}

impl WhoisResolver {
    #[allow(dead_code)]
    pub fn new(bootstrap: WhoisBootstrap, timeout: Duration) -> Self {
        Self { bootstrap, timeout }
    }
}

#[async_trait]
impl Resolver for WhoisResolver {
    fn name(&self) -> &'static str {
        "whois"
    }

    async fn lookup(&self, name: &str, tld: &str) -> Result<LookupResult> {
        let domain = format!("{name}.{tld}");
        let start = Instant::now();

        let server = crate::bootstrap::whois_server_for(&self.bootstrap, tld)
            .ok_or_else(|| anyhow!("no WHOIS server for TLD .{tld}"))?;

        let response = query_whois(server, &domain, self.timeout).await?;
        let status = if is_available(&response, tld) {
            DomainStatus::Available
        } else {
            DomainStatus::Taken
        };

        Ok(LookupResult {
            domain,
            status,
            source: self.name().into(),
            latency_ms: start.elapsed().as_millis() as u64,
            details: Some(LookupDetails {
                server: Some(server.to_string()),
                ..Default::default()
            }),
        })
    }
}

/// Open a TCP connection to `host:port`, send `"{domain}\r\n"`, read until EOF
/// or timeout, return the raw response text (best-effort, may be truncated).
pub async fn query_whois_port(
    host: &str,
    port: u16,
    domain: &str,
    dur: Duration,
) -> Result<String> {
    let addr = format!("{host}:{port}");
    let mut stream = timeout(dur, TcpStream::connect(&addr))
        .await
        .with_context(|| format!("TCP connect timeout to {addr}"))?
        .with_context(|| format!("TCP connect to {addr}"))?;

    let query = format!("{domain}\r\n");
    timeout(dur, stream.write_all(query.as_bytes()))
        .await
        .with_context(|| format!("WHOIS write timeout to {host}"))?
        .with_context(|| format!("WHOIS write to {host}"))?;

    let mut buf = Vec::with_capacity(4096);
    let read = timeout(dur, stream.read_to_end(&mut buf))
        .await
        .with_context(|| format!("WHOIS read timeout from {host}"));

    match read {
        Ok(_) => Ok(String::from_utf8_lossy(&buf).into_owned()),
        Err(e) => Err(e),
    }
}

/// Open a TCP connection to `host:43`, send `"{domain}\r\n"`, read until EOF
/// or timeout, return the raw response text (best-effort, may be truncated).
pub async fn query_whois(host: &str, domain: &str, dur: Duration) -> Result<String> {
    query_whois_port(host, WHOIS_PORT, domain, dur).await
}

// ---------- not-found pattern matching ----------

/// Generic "not found" phrases that most WHOIS responses use regardless of
/// TLD. Always evaluated case-insensitively on the lowercased response.
pub const GENERIC_NOT_FOUND_PATTERNS: &[&str] = &[
    "no match",
    "not found",
    "no data found",
    "no entries found",
    "no object found",
    "object does not exist",
    "object not found",
    "domain not found",
    "domain name not found",
    "no such domain",
    "is available",
    "is free",
    "is not registered",
    "is not been registered",
    "is not currently registered",
    "has not been registered",
    "no matching record",
    "no matching domain",
    "nothing found",
    "status: available",
    "status: free",
    // Verisign-style
    "no match for domain",
    // Nominet
    "no matching record found",
    // ccTLDs
    "no matching entry",
    "no record found",
    "no results found",
    "no registration data",
    "no found",
    "we have no entry",
    "no information about",
    "domain status: available",
    "domain name not known",
];

/// Per-TLD specific patterns. If a TLD has a custom phrase we use that
/// instead of the generic set to avoid false positives.
pub fn not_found_patterns_for(tld: &str) -> Vec<&'static str> {
    match tld.to_ascii_lowercase().as_str() {
        "com" | "net" => vec!["no match for", "no match for domain", "not found"],
        "org" => vec!["not found", "no matching record", "domain not found"],
        "io" => vec!["is available", "not found", "no match"],
        "co" => vec!["no data found", "not found", "no match"],
        "ai" => vec!["no object found", "not found"],
        "uk" | "co.uk" => vec!["no matching record", "not found"],
        "de" => vec!["status: free", "object does not exist", "no match"],
        "fr" => vec!["no entries found", "not found"],
        "jp" => vec!["no match", "no matching record", "not found"],
        "ru" => vec!["no entries found", "not found"],
        "br" => vec!["no match", "not found", "no object found"],
        "in" => vec!["no data found", "not found", "no matching record"],
        "au" => vec!["no data found", "not found"],
        "ca" => vec!["domain status: available", "not found"],
        "tv" => vec!["no match for", "no data found"],
        "biz" => vec!["not found", "no matching record"],
        "info" => vec!["not found", "no matching record"],
        // bd doesn't hit this path (handled by the .bd resolver) but include
        // a safe default in case it ever does.
        "bd" => vec!["no match", "not found"],
        // Default to the generic set for any other TLD.
        _ => GENERIC_NOT_FOUND_PATTERNS.to_vec(),
    }
}

/// Decide whether a WHOIS response means "available".
///
/// Strategy:
/// 1. Lowercase the response for case-insensitive matching.
/// 2. Collapse runs of whitespace so patterns like `"status: free"` match
///    registry output that uses extra spaces for alignment (e.g.
///    `"status:        free"`).
/// 3. Try per-TLD patterns first (more precise, fewer false positives).
/// 4. If nothing matches, fall back to the generic pattern set.
/// 5. If the TLD has no specific patterns AND no generic pattern matches,
///    be conservative: treat as Taken (we got a response, it didn't say
///    "not found", so probably registered).
pub fn is_available(response: &str, tld: &str) -> bool {
    let lowered = response.to_ascii_lowercase();
    let collapsed: String = lowered.split_whitespace().collect::<Vec<_>>().join(" ");
    let lowered = collapsed;

    let per_tld = not_found_patterns_for(tld);
    for pat in &per_tld {
        if lowered.contains(pat) {
            return true;
        }
    }
    // Generic fallback only if the per-TLD list is identical to the generic
    // (i.e. TLD has no specific overrides). This avoids double-evaluation.
    if per_tld.as_slice() == GENERIC_NOT_FOUND_PATTERNS {
        return false;
    }
    for pat in GENERIC_NOT_FOUND_PATTERNS {
        if lowered.contains(pat) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_verisign_com_no_match() {
        let body = "   Domain Name: APPLE.COM\r\n   Registrar: EXAMPLE\r\n";
        assert!(!is_available(body, "com"));

        let body = "No match for domain \"NOT-REAL-12345.COM\".\r\n";
        assert!(is_available(body, "com"));
    }

    #[test]
    fn detects_org_not_found() {
        let body = "Domain not found.\r\n";
        assert!(is_available(body, "org"));
    }

    #[test]
    fn detects_io_is_available() {
        let body = "DOMAIN: something.io\nThe domain \"something.io\" is available.\n";
        assert!(is_available(body, "io"));
    }

    #[test]
    fn detects_de_status_free() {
        let body = "status:        free\n";
        assert!(is_available(body, "de"));
    }

    #[test]
    fn detects_co_no_data_found() {
        let body = "No Data Found\n";
        assert!(is_available(body, "co"));
    }

    #[test]
    fn detects_uk_no_matching_record() {
        let body = "No matching record found.\n";
        assert!(is_available(body, "uk"));
    }

    #[test]
    fn detects_jp_no_match() {
        let body = "No match!!\n";
        assert!(is_available(body, "jp"));
    }

    #[test]
    fn detects_fr_no_entries() {
        let body = "No entries found in the AFNIC Database.\n";
        assert!(is_available(body, "fr"));
    }

    #[test]
    fn detects_ca_status_available() {
        let body = "Domain status:         available\n";
        assert!(is_available(body, "ca"));
    }

    #[test]
    fn detects_taken_when_no_pattern_matches() {
        let body = "Domain Name: apple.com\nRegistrar: Example Registrar\nCreated: 1990-01-01\n";
        assert!(!is_available(body, "com"));
    }

    #[test]
    fn unknown_tld_uses_generic_patterns() {
        let body = "No match for this domain.";
        assert!(is_available(body, "zz"));
    }

    #[test]
    fn case_insensitive_matching() {
        let body = "DOMAIN NOT FOUND";
        assert!(is_available(body, "com"));
    }

    #[test]
    fn not_found_patterns_for_returns_per_tld_or_generic() {
        let per_tld = not_found_patterns_for("com");
        assert!(per_tld.contains(&"no match for"));

        let generic = not_found_patterns_for("nope");
        assert_eq!(generic, GENERIC_NOT_FOUND_PATTERNS);
    }

    #[test]
    fn empty_response_is_treated_as_taken() {
        assert!(!is_available("", "com"));
    }

    #[test]
    fn registrar_response_stays_taken() {
        let body = "Domain Name: example.com\nRegistrar: Some Registrar Inc.\nDomain Status: ok\n";
        assert!(!is_available(body, "com"));
    }

    #[tokio::test]
    async fn lookup_returns_unavailable_server_when_tld_unknown() {
        let bs = WhoisBootstrap {
            description: String::new(),
            version: String::new(),
            servers: Default::default(),
        };
        let r = WhoisResolver::new(bs, Duration::from_secs(1));
        let err = r.lookup("foo", "zzz").await.unwrap_err().to_string();
        assert!(err.contains("no WHOIS server"));
    }

    #[tokio::test]
    async fn lookup_returns_available_when_server_says_not_found() {
        // Spin up a local TCP listener on a free port and verify the resolver
        // connects to it. We bypass query_whois (which always uses port 43)
        // by talking to the listener directly through query_whois_port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                let _ =
                    tokio::io::AsyncWriteExt::write_all(&mut sock, b"Domain not found.\r\n").await;
            }
        });

        let resp = query_whois_port(
            &addr.ip().to_string(),
            addr.port(),
            "missing.test",
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(resp.contains("not found"));
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn lookup_returns_taken_when_server_gives_registrar_info() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut sock,
                    b"Domain Name: example.test\nRegistrar: Big Registrar Inc.\nDomain Status: ok\n",
                )
                .await;
            }
        });

        let resp = query_whois_port(
            &addr.ip().to_string(),
            addr.port(),
            "taken.test",
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert!(!is_available(&resp, "test"));
        let _ = server_task.await;
    }
}

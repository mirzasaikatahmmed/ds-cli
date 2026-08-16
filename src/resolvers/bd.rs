//! `.bd` special-case handler.
//!
//! `.bd` has no public RDAP service and no public WHOIS port 43, so the
//! generic RDAP/WHOIS resolvers can't reach it. This module defines a
//! trait-based interface for `.bd` availability lookups and ships a default
//! HTTP provider pointed at a third-party BD domain-check API
//! (limda.net).
//!
//! The provider URL is configurable via:
//!   - the `--bd-endpoint <URL>` CLI flag (preferred), or
//!   - the `DS_BD_ENDPOINT` environment variable as a fallback.
//!
//! Default endpoint: `https://www.limda.net/inc/api/check-domain-availability.php?search={domain}`
//! (third-party service; see [`DEFAULT_BD_ENDPOINT`]). Override it if the
//! upstream changes or if you'd prefer a different provider.
//!
//! To add a new provider, implement the [`BdProvider`] trait and pass it
//! to [`BdResolver::with_provider`]. The engine's resolver-selection logic
//! (Phase 6) handles picking this resolver for `.bd` automatically.
//!
//! Response shape we handle (limda.net):
//!
//! ```json
//! {
//!   "success": true,
//!   "domain": "saikat.bd",
//!   "available": true,
//!   "registered": false,
//!   "reserved": false,
//!   "status": "available",
//!   "message": "Domain is available",
//!   "raw_response": "Domain is available",
//!   "source": "btcl",
//!   "tld": null,
//!   "http_code": 200
//! }
//! ```
//!
//! We prefer the `available` boolean, then fall back to the `status`
//! string. Extra fields like `registered`, `reserved`, `message`,
//! `raw_response`, `source` are kept in the `LookupDetails` so
//! `--details` can show them.

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use crate::models::{DomainStatus, LookupDetails, LookupResult};
use crate::resolvers::Resolver;

/// Default `.bd` lookup endpoint. Points at a third-party BD domain-check
/// API (limda.net) which returns JSON with `available`, `registered`,
/// `status`, `message`, `raw_response`, `source`, etc.
///
/// **Override** with `--bd-endpoint <URL>` or `DS_BD_ENDPOINT=<URL>` if
/// the upstream URL changes or you'd prefer a different provider. The
/// template must contain `{domain}` — it is replaced with the queried
/// domain name before the request.
pub const DEFAULT_BD_ENDPOINT: &str =
    "https://www.limda.net/inc/api/check-domain-availability.php?search={domain}";

/// Resolver trait for `.bd`-specific lookups. Any third-party provider can
/// be plugged in by implementing this trait.
#[async_trait]
#[allow(dead_code)]
pub trait BdProvider: Send + Sync {
    /// Human-readable name for `--where` / log output.
    fn name(&self) -> &'static str;
    /// Look up a single domain. Return the status plus any extra fields
    /// the caller should surface in `--details`.
    async fn lookup(&self, domain: &str) -> Result<BdLookup>;
}

/// Parsed `.bd` lookup result.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BdLookup {
    pub status: DomainStatus,
    pub message: Option<String>,
    pub raw_response: Option<String>,
    pub source: Option<String>,
    pub registered: Option<bool>,
    pub reserved: Option<bool>,
}

impl Default for BdLookup {
    fn default() -> Self {
        Self {
            status: DomainStatus::Unknown,
            message: None,
            raw_response: None,
            source: None,
            registered: None,
            reserved: None,
        }
    }
}

/// JSON-based HTTP provider. Expects a URL like
/// `https://provider.example/?domain={domain}` (or `?search={domain}` —
/// the placeholder name doesn't matter, only the `{domain}` token does)
/// returning JSON of the shape limda.net uses (see the module-level docs).
///
/// The `{domain}` placeholder is substituted before the request is sent.
#[allow(dead_code)]
pub struct JsonBdProvider {
    endpoint_template: String,
    client: Client,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BdResponse {
    #[serde(default)]
    available: Option<bool>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    raw_response: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    registered: Option<bool>,
    #[serde(default)]
    reserved: Option<bool>,
    #[serde(default)]
    success: Option<bool>,
}

impl JsonBdProvider {
    #[allow(dead_code)]
    pub fn new(endpoint_template: String, timeout: Duration) -> Result<Self> {
        if !endpoint_template.contains("{domain}") {
            bail!("endpoint URL must contain {{domain}} placeholder");
        }
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(concat!("ds/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building reqwest client for .bd provider")?;
        Ok(Self {
            endpoint_template,
            client,
            timeout,
        })
    }
}

#[async_trait]
impl BdProvider for JsonBdProvider {
    fn name(&self) -> &'static str {
        "limda.net"
    }

    async fn lookup(&self, domain: &str) -> Result<BdLookup> {
        let url = self.endpoint_template.replace("{domain}", domain);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        let status = resp.status();
        if !status.is_success() {
            // 404 from a JSON provider often means "available" — propagate
            // as such so providers returning 404 for free domains work.
            if status.as_u16() == 404 {
                return Ok(BdLookup {
                    status: DomainStatus::Available,
                    ..Default::default()
                });
            }
            return Err(anyhow!(".bd provider HTTP {status}"));
        }

        let body: BdResponse = resp
            .json()
            .await
            .with_context(|| "decoding .bd provider JSON")?;

        // The provider returns `success: false` on errors (rate-limit,
        // bad query, etc.) but may still include a structured body. We
        // honor the success flag when present, falling back to the
        // available/status fields otherwise.
        let status = if body.success == Some(false) {
            DomainStatus::Unknown
        } else if let Some(avail) = body.available {
            if avail {
                DomainStatus::Available
            } else {
                DomainStatus::Taken
            }
        } else if let Some(s) = body.status.as_deref() {
            let s = s.to_ascii_lowercase();
            if s.contains("available") || s.contains("free") || s.contains("not found") {
                DomainStatus::Available
            } else if s.contains("registered") || s.contains("taken") || s.contains("active") {
                DomainStatus::Taken
            } else {
                DomainStatus::Unknown
            }
        } else {
            DomainStatus::Unknown
        };

        Ok(BdLookup {
            status,
            message: body.message,
            raw_response: body.raw_response,
            source: body.source,
            registered: body.registered,
            reserved: body.reserved,
        })
    }
}

/// `BdResolver` — the implementation of the generic [`Resolver`] trait that
/// the engine routes `.bd` queries to. Delegates to a [`BdProvider`].
#[allow(dead_code)]
pub struct BdResolver {
    provider: Box<dyn BdProvider>,
    timeout: Duration,
}

impl BdResolver {
    /// Build a resolver using a user-supplied endpoint template, or the
    /// shipped default if `endpoint_template` is `None`.
    #[allow(dead_code)]
    pub fn new(endpoint_template: Option<String>, timeout: Duration) -> Result<Self> {
        let template = endpoint_template
            .or_else(|| std::env::var("DS_BD_ENDPOINT").ok())
            .unwrap_or_else(|| DEFAULT_BD_ENDPOINT.to_string());
        let provider = JsonBdProvider::new(template, timeout)?;
        Ok(Self {
            provider: Box::new(provider),
            timeout,
        })
    }

    #[allow(dead_code)]
    pub fn with_provider(provider: Box<dyn BdProvider>, timeout: Duration) -> Self {
        Self { provider, timeout }
    }
}

#[async_trait]
impl Resolver for BdResolver {
    fn name(&self) -> &'static str {
        "bd"
    }

    async fn lookup(&self, name: &str, tld: &str) -> Result<LookupResult> {
        let domain = format!("{name}.{tld}");
        let start = Instant::now();

        let bd = self.provider.lookup(&domain).await?;
        let last_modified = start.elapsed();

        let mut details = LookupDetails {
            server: Some(self.provider.name().to_string()),
            ..Default::default()
        };
        if let Some(src) = bd.source {
            details.registry = Some(format!("btcl via limda.net ({src})"));
        }
        // Stash the message / raw_response as a nameserver-shaped field —
        // there's no exact slot for these, but nameservers is the closest
        // to a free-form "extra provider notes" list we expose via
        // --details. We don't want to lose the info if the user passed
        // --details.
        let mut notes = Vec::new();
        if let Some(m) = bd.message {
            notes.push(format!("message: {m}"));
        }
        if let Some(rr) = bd.raw_response {
            notes.push(format!("upstream: {rr}"));
        }
        if let Some(reg) = bd.registered {
            notes.push(format!("registered: {reg}"));
        }
        if let Some(res) = bd.reserved {
            notes.push(format!("reserved: {res}"));
        }
        if !notes.is_empty() {
            details.nameservers = notes;
        }

        Ok(LookupResult {
            domain,
            status: bd.status,
            source: self.name().into(),
            latency_ms: last_modified.as_millis() as u64,
            details: Some(details),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_domain() -> &'static str {
        "missing.bd"
    }

    #[test]
    fn json_provider_rejects_endpoint_without_placeholder() {
        let r = JsonBdProvider::new("https://example.com/lookup".into(), Duration::from_secs(1));
        let err = r.err().expect("expected error");
        assert!(err.to_string().contains("placeholder"));
    }

    #[tokio::test]
    async fn json_provider_parses_available_true() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .and(query_param("domain", sample_domain()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "available": true,
                "premium": false
            })))
            .mount(&mock)
            .await;

        let endpoint = format!("{}/lookup?domain={{domain}}", mock.uri());
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let s = p.lookup(sample_domain()).await.unwrap();
        assert_eq!(s.status, DomainStatus::Available);
    }

    #[tokio::test]
    async fn json_provider_parses_available_false() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .and(query_param("domain", "taken.bd"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "available": false
            })))
            .mount(&mock)
            .await;

        let endpoint = format!("{}/lookup?domain={{domain}}", mock.uri());
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let s = p.lookup("taken.bd").await.unwrap();
        assert_eq!(s.status, DomainStatus::Taken);
    }

    #[tokio::test]
    async fn json_provider_parses_status_string() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "available"
            })))
            .mount(&mock)
            .await;

        let endpoint = format!("{}/lookup?domain={{domain}}", mock.uri());
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let s = p.lookup("free.bd").await.unwrap();
        assert_eq!(s.status, DomainStatus::Available);
    }

    #[tokio::test]
    async fn json_provider_404_means_available() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let endpoint = format!("{}/lookup?domain={{domain}}", mock.uri());
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let s = p.lookup("missing.bd").await.unwrap();
        assert_eq!(s.status, DomainStatus::Available);
    }

    #[tokio::test]
    async fn json_provider_500_returns_err() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let endpoint = format!("{}/lookup?domain={{domain}}", mock.uri());
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let r = p.lookup("x.bd").await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn json_provider_unknown_when_no_recognized_fields() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": "we have no opinion"
            })))
            .mount(&mock)
            .await;

        let endpoint = format!("{}/lookup?domain={{domain}}", mock.uri());
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let s = p.lookup("x.bd").await.unwrap();
        assert_eq!(s.status, DomainStatus::Unknown);
    }

    #[tokio::test]
    async fn json_provider_parses_full_limda_response() {
        // Full response shape as returned by limda.net for a registered name.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/inc/api/check-domain-availability.php"))
            .and(query_param("search", "google.com.bd"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "domain": "google.com.bd",
                "available": false,
                "registered": true,
                "reserved": false,
                "status": "registered",
                "message": "Domain already registered",
                "raw_response": "Domain already registered",
                "source": "btcl",
                "tld": null,
                "domain_ascii": "google.com.bd",
                "http_code": 200
            })))
            .mount(&mock)
            .await;

        let endpoint = format!(
            "{}/inc/api/check-domain-availability.php?search={{domain}}",
            mock.uri()
        );
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let r = p.lookup("google.com.bd").await.unwrap();
        assert_eq!(r.status, DomainStatus::Taken);
        assert_eq!(r.source.as_deref(), Some("btcl"));
        assert_eq!(r.message.as_deref(), Some("Domain already registered"));
        assert_eq!(r.raw_response.as_deref(), Some("Domain already registered"));
        assert_eq!(r.registered, Some(true));
        assert_eq!(r.reserved, Some(false));
    }

    #[tokio::test]
    async fn json_provider_success_false_returns_unknown() {
        // Rate-limited or otherwise errored response from the upstream.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lookup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "message": "rate limited"
            })))
            .mount(&mock)
            .await;

        let endpoint = format!("{}/lookup?domain={{domain}}", mock.uri());
        let p = JsonBdProvider::new(endpoint, Duration::from_secs(2)).unwrap();
        let r = p.lookup("x.bd").await.unwrap();
        assert_eq!(r.status, DomainStatus::Unknown);
    }

    #[tokio::test]
    async fn bd_resolver_uses_provider() {
        // Custom test provider that always says available.
        struct AlwaysAvailable;
        #[async_trait]
        impl BdProvider for AlwaysAvailable {
            fn name(&self) -> &'static str {
                "test"
            }
            async fn lookup(&self, _domain: &str) -> Result<BdLookup> {
                Ok(BdLookup {
                    status: DomainStatus::Available,
                    ..Default::default()
                })
            }
        }

        let r = BdResolver::with_provider(Box::new(AlwaysAvailable), Duration::from_secs(1));
        let result = r.lookup("any", "bd").await.unwrap();
        assert_eq!(result.status, DomainStatus::Available);
        assert_eq!(result.source, "bd");
        assert_eq!(result.domain, "any.bd");
        assert_eq!(result.details.unwrap().server.as_deref(), Some("test"));
    }

    #[tokio::test]
    async fn bd_resolver_surfaces_provider_details() {
        // A provider that returns extra fields should have them appear in
        // the LookupDetails so `--details` can show them.
        struct RichProvider;
        #[async_trait]
        impl BdProvider for RichProvider {
            fn name(&self) -> &'static str {
                "rich"
            }
            async fn lookup(&self, _domain: &str) -> Result<BdLookup> {
                Ok(BdLookup {
                    status: DomainStatus::Taken,
                    source: Some("btcl".into()),
                    message: Some("Domain already registered".into()),
                    raw_response: Some("Domain already registered".into()),
                    registered: Some(true),
                    reserved: Some(false),
                })
            }
        }

        let r = BdResolver::with_provider(Box::new(RichProvider), Duration::from_secs(1));
        let result = r.lookup("x", "bd").await.unwrap();
        let details = result.details.unwrap();
        assert_eq!(details.server.as_deref(), Some("rich"));
        assert!(details.registry.as_deref().unwrap().contains("btcl"));
        let notes = details.nameservers.join(" | ");
        assert!(notes.contains("Domain already registered"));
        assert!(notes.contains("registered: true"));
    }

    #[tokio::test]
    async fn bd_resolver_propagates_provider_error() {
        struct ErrProvider;
        #[async_trait]
        impl BdProvider for ErrProvider {
            fn name(&self) -> &'static str {
                "err"
            }
            async fn lookup(&self, _domain: &str) -> Result<BdLookup> {
                Err(anyhow!("upstream down"))
            }
        }

        let r = BdResolver::with_provider(Box::new(ErrProvider), Duration::from_secs(1));
        let err = r.lookup("x", "bd").await.unwrap_err().to_string();
        assert!(err.contains("upstream down"));
    }

    #[test]
    fn default_endpoint_contains_placeholder() {
        assert!(DEFAULT_BD_ENDPOINT.contains("{domain}"));
    }

    #[test]
    fn default_endpoint_points_at_limda() {
        // Sanity check so we notice if the default URL ever gets changed
        // by accident — this test documents the intended default.
        assert!(DEFAULT_BD_ENDPOINT.starts_with("https://www.limda.net/"));
        assert!(DEFAULT_BD_ENDPOINT.contains("check-domain-availability.php"));
        assert!(DEFAULT_BD_ENDPOINT.contains("?search={domain}"));
    }

    #[test]
    fn unknown_status_string_is_unknown() {
        // Provider that returns a status string we don't recognize.
        let body = serde_json::json!({"status": "pending-verification"});
        let parsed: BdResponse = serde_json::from_value(body).unwrap();
        assert!(parsed.available.is_none());
        let s = parsed.status.as_deref().unwrap();
        assert!(!s.contains("available"));
        assert!(!s.contains("registered"));
        assert!(!s.contains("free"));
    }
}

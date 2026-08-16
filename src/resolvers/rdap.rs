//! RDAP resolver.
//!
//! Sends `GET {rdap_base}/domain/{name}.{tld}` and translates the response into
//! a [`LookupResult`]:
//! * HTTP 404 (or 200 with `errorCode: 404`) → `Available`
//! * HTTP 200 with a valid domain object → `Taken`, with registrar/dates/NS
//!   parsed into `LookupDetails` for `--details` output
//! * HTTP 5xx, network error, timeout, or no RDAP entry for the TLD → returns
//!   `Err` so the engine can fall back to WHOIS.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use crate::bootstrap::{rdap_servers_for, RdapBootstrap};
use crate::models::{DomainStatus, LookupDetails, LookupResult};
use crate::resolvers::Resolver;

/// RDAP resolver. Constructs URLs from the IANA bootstrap map and queries
/// each server in priority order until one answers (or all fail).
#[allow(dead_code)]
pub struct RdapResolver {
    client: Client,
    bootstrap: RdapBootstrap,
    timeout: Duration,
}

impl RdapResolver {
    #[allow(dead_code)]
    pub fn new(bootstrap: RdapBootstrap, timeout: Duration) -> Result<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent(concat!("ds/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building reqwest client")?;
        Ok(Self {
            client,
            bootstrap,
            timeout,
        })
    }
}

#[async_trait]
impl Resolver for RdapResolver {
    fn name(&self) -> &'static str {
        "rdap"
    }

    async fn lookup(&self, name: &str, tld: &str) -> Result<LookupResult> {
        let domain = format!("{name}.{tld}");
        let start = Instant::now();

        let servers = rdap_servers_for(&self.bootstrap, tld);
        if servers.is_empty() {
            return Err(anyhow!("no RDAP server for TLD .{tld}"));
        }

        let mut last_err: Option<anyhow::Error> = None;
        for base in servers {
            let url = match build_url(base, name, tld) {
                Ok(u) => u,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            match self.query(&url).await {
                Ok(QueryOutcome::Available) => {
                    return Ok(LookupResult {
                        domain,
                        status: DomainStatus::Available,
                        source: self.name().into(),
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: None,
                    });
                }
                Ok(QueryOutcome::Taken(details)) => {
                    let mut details = details;
                    // record which server answered
                    if details.server.is_none() {
                        details.server = Some(base.to_string());
                    }
                    if details.registry.is_none() {
                        details.registry = Some(base.to_string());
                    }
                    return Ok(LookupResult {
                        domain,
                        status: DomainStatus::Taken,
                        source: self.name().into(),
                        latency_ms: start.elapsed().as_millis() as u64,
                        details: Some(details),
                    });
                }
                Err(e) => {
                    last_err = Some(e);
                    // try next server
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("all RDAP servers failed for {name}.{tld}")))
    }
}

impl RdapResolver {
    async fn query(&self, url: &str) -> Result<QueryOutcome> {
        let resp = self
            .client
            .get(url)
            .header("Accept", "application/rdap+json")
            .send()
            .await
            .with_context(|| format!("RDAP GET {url}"))?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Ok(QueryOutcome::Available);
        }
        if status == 200 {
            let body: serde_json::Value = resp
                .json()
                .await
                .with_context(|| format!("decoding RDAP body {url}"))?;

            // Some servers return 200 with an errorCode body — treat as available.
            if let Some(code) = body.get("errorCode").and_then(|v| v.as_u64()) {
                if code == 404 {
                    return Ok(QueryOutcome::Available);
                }
            }

            let parsed = parse_domain_object(&body);
            return Ok(QueryOutcome::Taken(parsed));
        }

        // 5xx and other non-200/non-404 are transport errors.
        Err(anyhow!("RDAP HTTP {status} for {url}"))
    }
}

enum QueryOutcome {
    Available,
    Taken(LookupDetails),
}

fn build_url(base: &str, name: &str, tld: &str) -> Result<String> {
    let trimmed = base.trim_end_matches('/');
    Ok(format!("{trimmed}/domain/{name}.{tld}"))
}

/// Subset of RDAP domain object we care about. Most fields are optional
/// because not every registry populates them.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RdapDomain {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    ldh_name: Option<String>,
    #[serde(default)]
    entities: Vec<RdapEntity>,
    #[serde(default)]
    nameservers: Vec<RdapNs>,
    #[serde(default)]
    events: Vec<RdapEvent>,
    #[serde(default)]
    status: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RdapEntity {
    #[serde(default)]
    handle: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default, rename = "vcardArray")]
    vcard_array: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct RdapNs {
    #[serde(default, rename = "ldhName")]
    ldh_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RdapEvent {
    #[serde(default, rename = "eventAction")]
    event_action: Option<String>,
    #[serde(default, rename = "eventDate")]
    event_date: Option<String>,
}

fn parse_domain_object(body: &serde_json::Value) -> LookupDetails {
    let parsed: RdapDomain = match serde_json::from_value(body.clone()) {
        Ok(d) => d,
        Err(_) => return LookupDetails::default(),
    };

    let nameservers = parsed
        .nameservers
        .into_iter()
        .filter_map(|ns| ns.ldh_name)
        .collect();

    let mut registrar: Option<String> = None;
    for ent in parsed.entities {
        if ent.roles.iter().any(|r| r == "registrar") {
            if let Some(vcard) = ent.vcard_array {
                if let Some(name) = vcard_name_field(&vcard) {
                    registrar = Some(name);
                } else if let Some(handle) = ent.handle {
                    registrar = Some(handle);
                }
            } else if let Some(handle) = ent.handle {
                registrar = Some(handle);
            }
        }
    }

    let mut creation_date: Option<String> = None;
    let mut expiry_date: Option<String> = None;
    for event in parsed.events {
        match event.event_action.as_deref() {
            Some("registration") | Some("creation") | Some("registered") => {
                creation_date = event.event_date;
            }
            Some("expiration") | Some("expiry") | Some("expire") => {
                expiry_date = event.event_date;
            }
            _ => {}
        }
    }

    LookupDetails {
        registrar,
        creation_date,
        expiry_date,
        nameservers,
        registry: None,
        server: None,
    }
}

/// vCard arrays are `[ "vcard", [ [field, {}, value, type], ... ] ]`. Pull
/// the "fn" (formatted name) field, which is what WHOIS calls the registrar.
fn vcard_name_field(vcard: &serde_json::Value) -> Option<String> {
    let arr = vcard.as_array()?;
    let fields = arr.get(1)?.as_array()?;
    for field in fields {
        let field = field.as_array()?;
        if field.first()?.as_str()? == "fn" {
            // value is field[3], a string or array of strings
            if let Some(value) = field.get(3) {
                if let Some(s) = value.as_str() {
                    return Some(s.to_string());
                }
                if let Some(arr) = value.as_array() {
                    if let Some(first) = arr.first().and_then(|v| v.as_str()) {
                        return Some(first.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bootstrap() -> RdapBootstrap {
        RdapBootstrap {
            description: String::new(),
            publication: String::new(),
            version: String::new(),
            services: vec![vec![
                vec!["example".into()],
                vec!["https://rdap.example/".into()],
            ]],
        }
    }

    #[test]
    fn build_url_strips_trailing_slash() {
        let u = build_url("https://rdap.example.com/", "foo", "com").unwrap();
        assert_eq!(u, "https://rdap.example.com/domain/foo.com");
    }

    #[test]
    fn parse_domain_object_picks_up_registrar_and_dates() {
        let body = json!({
            "ldhName": "example.com",
            "status": ["active"],
            "nameservers": [
                {"ldhName": "ns1.example.com"},
                {"ldhName": "ns2.example.com"}
            ],
            "entities": [
                {
                    "handle": "REG",
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]]
                }
            ],
            "events": [
                {"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}
            ]
        });
        let d = parse_domain_object(&body);
        assert_eq!(d.registrar.as_deref(), Some("Example Registrar, Inc."));
        assert_eq!(d.creation_date.as_deref(), Some("2000-01-01T00:00:00Z"));
        assert_eq!(d.expiry_date.as_deref(), Some("2030-01-01T00:00:00Z"));
        assert_eq!(d.nameservers, vec!["ns1.example.com", "ns2.example.com"]);
    }

    #[test]
    fn parse_domain_object_handles_missing_fields() {
        let body = json!({"ldhName": "example.com"});
        let d = parse_domain_object(&body);
        assert!(d.registrar.is_none());
        assert!(d.creation_date.is_none());
        assert!(d.nameservers.is_empty());
    }

    #[test]
    fn vcard_array_formatted_name_extraction() {
        let vcard = json!(["vcard", [["fn", {}, "text", "Registrar LLC"]]]);
        assert_eq!(vcard_name_field(&vcard).as_deref(), Some("Registrar LLC"));
    }

    #[test]
    fn vcard_array_returns_none_when_missing() {
        let vcard = json!(["vcard", []]);
        assert!(vcard_name_field(&vcard).is_none());
    }

    #[tokio::test]
    async fn lookup_returns_available_on_404() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/domain/missing.example"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&mock)
            .await;

        let mut bs = bootstrap();
        bs.services[0][1] = vec![mock.uri()];

        let r = RdapResolver::new(bs, Duration::from_secs(5)).unwrap();
        let result = r.lookup("missing", "example").await.unwrap();
        assert_eq!(result.status, DomainStatus::Available);
        assert_eq!(result.source, "rdap");
        assert_eq!(result.domain, "missing.example");
    }

    #[tokio::test]
    async fn lookup_returns_taken_with_details_on_200() {
        let mock = wiremock::MockServer::start().await;
        let body = json!({
            "ldhName": "taken.example",
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Mock Registrar"]]]
            }],
            "events": [
                {"eventAction": "registration", "eventDate": "2010-05-05T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2030-05-05T00:00:00Z"}
            ],
            "nameservers": [{"ldhName": "ns1.taken.example"}]
        });
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/domain/taken.example"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/rdap+json")
                    .set_body_json(body),
            )
            .mount(&mock)
            .await;

        let mut bs = bootstrap();
        bs.services[0][1] = vec![mock.uri()];

        let r = RdapResolver::new(bs, Duration::from_secs(5)).unwrap();
        let result = r.lookup("taken", "example").await.unwrap();
        assert_eq!(result.status, DomainStatus::Taken);
        let d = result.details.expect("details should be present");
        assert_eq!(d.registrar.as_deref(), Some("Mock Registrar"));
        assert_eq!(d.creation_date.as_deref(), Some("2010-05-05T00:00:00Z"));
        assert_eq!(d.expiry_date.as_deref(), Some("2030-05-05T00:00:00Z"));
        assert_eq!(d.nameservers, vec!["ns1.taken.example"]);
    }

    #[tokio::test]
    async fn lookup_returns_available_on_200_with_errorcode_404() {
        let mock = wiremock::MockServer::start().await;
        let body = json!({
            "errorCode": 404,
            "title": "Not Found"
        });
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/domain/missing.example"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "application/rdap+json")
                    .set_body_json(body),
            )
            .mount(&mock)
            .await;

        let mut bs = bootstrap();
        bs.services[0][1] = vec![mock.uri()];

        let r = RdapResolver::new(bs, Duration::from_secs(5)).unwrap();
        let result = r.lookup("missing", "example").await.unwrap();
        assert_eq!(result.status, DomainStatus::Available);
    }

    #[tokio::test]
    async fn lookup_errors_when_no_server_for_tld() {
        let bs = RdapBootstrap {
            description: String::new(),
            publication: String::new(),
            version: String::new(),
            services: vec![],
        };
        let r = RdapResolver::new(bs, Duration::from_secs(5)).unwrap();
        let err = r.lookup("foo", "zzz").await.unwrap_err().to_string();
        assert!(err.contains("no RDAP server"));
    }

    #[tokio::test]
    async fn lookup_returns_err_on_5xx() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/domain/x.example"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let mut bs = bootstrap();
        bs.services[0][1] = vec![mock.uri()];

        let r = RdapResolver::new(bs, Duration::from_secs(5)).unwrap();
        assert!(r.lookup("x", "example").await.is_err());
    }
}

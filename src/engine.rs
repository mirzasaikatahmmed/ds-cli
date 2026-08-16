//! Concurrency engine.
//!
//! Orchestrates parallel domain lookups with bounded concurrency, per-host
//! rate limiting, and graceful Ctrl+C cancellation.
//!
//! ## Resolver selection
//!
//! For each (name, tld) pair:
//! 1. If tld ends in `.bd` (e.g. `bd`, `com.bd`, `net.bd`, `org.bd`, `edu.bd`,
//!    `gov.bd`, `ac.bd`, …) → use [`BdResolver`] only. All `.bd`-zone queries
//!    go through the same third-party upstream provider.
//! 2. Otherwise, try [`RdapResolver`] first; if it returns `Err`, fall back
//!    to [`WhoisResolver`]. If both fail, the result is `DomainStatus::Unknown`
//!    with the last error captured in `LookupDetails`.
//!
//! The chain is per-TLD: each TLD gets its own pair of resolvers so e.g. a
//! timeout on `.com` doesn't waste a `.io` lookup.
//!
//! ## Concurrency control
//!
//! Total in-flight lookups are bounded by a `Semaphore` (default 20, override
//! via `--concurrent`). Per-host in-flight requests are also capped so a
//! burst of `@names.txt` against one WHOIS server doesn't get us rate-limited.
//!
//! ## Cancellation
//!
//! Listens for `SIGINT` (`Ctrl+C`) and cancels all in-flight tasks cleanly.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::sleep;

use crate::bootstrap::Bootstrap;
use crate::models::{DomainStatus, LookupDetails, LookupResult};
use crate::resolvers::bd::BdResolver;
use crate::resolvers::rdap::RdapResolver;
use crate::resolvers::whois::WhoisResolver;
use crate::resolvers::Resolver;

/// Default global concurrency when `--concurrent` is not set.
pub const DEFAULT_CONCURRENCY: usize = 20;

/// Default per-host in-flight cap (so we don't hammer one WHOIS server).
pub const DEFAULT_PER_HOST_LIMIT: usize = 4;

/// Default per-lookup timeout when `--timeout` is not set.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// True if this TLD is part of the `.bd` zone — i.e. either `bd` itself or
/// a second-level `.bd` SLD like `com.bd`, `net.bd`, `org.bd`, `edu.bd`,
/// `gov.bd`, `ac.bd`, `co.bd`, etc. All of these are registered through
/// the same registry and have no public RDAP/WHOIS, so they all route
/// through the BD provider.
pub fn is_bd_zone_tld(tld: &str) -> bool {
    let tld = tld.trim().to_ascii_lowercase();
    tld == "bd" || tld.ends_with(".bd")
}

/// Engine configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EngineConfig {
    pub concurrent: usize,
    pub per_host_limit: usize,
    pub timeout: Duration,
    pub force_whois: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            concurrent: DEFAULT_CONCURRENCY,
            per_host_limit: DEFAULT_PER_HOST_LIMIT,
            timeout: DEFAULT_TIMEOUT,
            force_whois: false,
        }
    }
}

/// Per-host in-flight tracker. A `tokio::sync::Mutex<HashMap<String, usize>>`
/// is fine here because the critical section is microseconds — we just bump a
/// counter, never block.
#[derive(Clone, Default)]
struct HostLimiter {
    inner: Arc<Mutex<std::collections::HashMap<String, usize>>>,
}

impl HostLimiter {
    async fn acquire(&self, host: &str, max: usize) -> HostPermit {
        loop {
            let mut g = self.inner.lock().await;
            let n = g.get(host).copied().unwrap_or(0);
            if n < max {
                *g.entry(host.to_string()).or_insert(0) += 1;
                return HostPermit {
                    limiter: self.clone(),
                    host: host.to_string(),
                };
            }
            drop(g);
            // brief backoff so we busy-poll less aggressively
            sleep(Duration::from_millis(25)).await;
        }
    }
}

struct HostPermit {
    limiter: HostLimiter,
    host: String,
}

impl Drop for HostPermit {
    fn drop(&mut self) {
        let limiter = self.limiter.clone();
        let host = std::mem::take(&mut self.host);
        tokio::spawn(async move {
            let mut g = limiter.inner.lock().await;
            if let Some(n) = g.get_mut(&host) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    g.remove(&host);
                }
            }
        });
    }
}

/// Run the engine. Returns one `LookupResult` per input pair, in the same
/// order as `pairs`. Resolves in parallel up to `config.concurrent`.
pub async fn run(
    pairs: &[(String, String)],
    bootstrap: &Bootstrap,
    config: EngineConfig,
) -> Vec<LookupResult> {
    let inner = bootstrap.clone();
    let factory = move |tld: &str| -> ResolverChain {
        let bs = inner.clone();
        ResolverChain::for_tld(&bs, tld, config.timeout).unwrap_or_else(|_| ResolverChain {
            rdap: Arc::new(StubErrResolver),
            whois: Arc::new(StubErrResolver),
            bd: Arc::new(StubErrResolver),
        })
    };
    run_with_resolvers(pairs, bootstrap, config, factory).await
}

/// Variant of [`run`] that lets the caller decide which resolver chain to
/// use for each TLD. Used by tests to inject mocked resolvers.
pub async fn run_with_resolvers<F>(
    pairs: &[(String, String)],
    bootstrap: &Bootstrap,
    config: EngineConfig,
    resolver_factory: F,
) -> Vec<LookupResult>
where
    F: Fn(&str) -> ResolverChain + Send + Sync + 'static,
{
    if pairs.is_empty() {
        return Vec::new();
    }

    // Listen for Ctrl+C once; signal cancellation to all in-flight tasks.
    let cancel = Arc::new(tokio::sync::Notify::new());
    let cancel_signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_signal.notify_waiters();
        }
    });

    let semaphore = Arc::new(Semaphore::new(config.concurrent));
    let host_limiter = HostLimiter::default();
    let factory = Arc::new(resolver_factory);

    let mut join: JoinSet<(usize, LookupResult)> = JoinSet::new();
    for (i, (name, tld)) in pairs.iter().enumerate() {
        let permit_src = semaphore.clone();
        let factory = factory.clone();
        let bootstrap = bootstrap.clone();
        let cancel = cancel.clone();
        let host_limiter = host_limiter.clone();
        let (name, tld) = (name.clone(), tld.clone());
        let config = config.clone();

        join.spawn(async move {
            let _permit = permit_src.acquire_owned().await.expect("semaphore closed");
            if is_bd_zone_tld(&tld) {
                // .bd and .bd SLDs (com.bd, net.bd, edu.bd, ...) all route
                // through the dedicated BD resolver. There's no public
                // RDAP/WHOIS for any of them.
                let resolver = factory(&tld);
                return (
                    i,
                    resolve_bd(&resolver.bd, &name, &tld, config.timeout, &cancel).await,
                );
            }
            if config.force_whois {
                let resolver = factory(&tld);
                return (
                    i,
                    resolve_whois_only(
                        &resolver.whois,
                        &name,
                        &tld,
                        config.timeout,
                        &host_limiter,
                        &cancel,
                    )
                    .await,
                );
            }
            let resolver = factory(&tld);
            (
                i,
                resolve_chain(
                    &resolver.rdap,
                    &resolver.whois,
                    &name,
                    &tld,
                    config.timeout,
                    &host_limiter,
                    &cancel,
                    &bootstrap,
                )
                .await,
            )
        });
    }

    let mut results: Vec<Option<LookupResult>> = (0..pairs.len()).map(|_| None).collect();
    while let Some(joined) = join.join_next().await {
        if let Ok((i, result)) = joined {
            results[i] = Some(result);
        } else {
            // task panicked — leave None; will be filled as Unknown at the end.
        }
    }
    results
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            r.unwrap_or_else(|| LookupResult {
                domain: format!("{}.{}", pairs[i].0, pairs[i].1),
                status: DomainStatus::Unknown,
                source: "engine".into(),
                latency_ms: 0,
                details: Some(LookupDetails {
                    server: Some("cancelled".into()),
                    ..Default::default()
                }),
            })
        })
        .collect()
}

/// Resolver chain for a single TLD. The engine's `resolver_factory` returns
/// one of these per TLD.
#[allow(dead_code)]
pub struct ResolverChain {
    pub rdap: Arc<dyn Resolver>,
    pub whois: Arc<dyn Resolver>,
    pub bd: Arc<dyn Resolver>,
}

/// Companion of `ResolverChain`. Used as a placeholder when the default
/// factory can't build a real chain (e.g. in error fallbacks).
pub struct StubErrResolver;
#[async_trait]
impl Resolver for StubErrResolver {
    fn name(&self) -> &'static str {
        "err"
    }
    async fn lookup(&self, _name: &str, _tld: &str) -> Result<LookupResult> {
        Err(anyhow::anyhow!("resolver unavailable"))
    }
}

impl ResolverChain {
    /// Build the default chain for a TLD: RDAP + WHOIS for general TLDs,
    /// `.bd` only for `.bd` (RDAP/WHOIS will return `Err` because there's no
    /// server configured for them anyway).
    pub fn for_tld(bootstrap: &Bootstrap, tld: &str, timeout: Duration) -> Result<Self> {
        let rdap = Arc::new(RdapResolver::new(bootstrap.rdap.clone(), timeout)?);
        let whois = Arc::new(WhoisResolver::new(bootstrap.whois.clone(), timeout));
        let bd = Arc::new(BdResolver::new(None, timeout)?);
        let _ = tld; // intentionally unused — chains are reusable across TLDs
        Ok(Self { rdap, whois, bd })
    }
}

async fn resolve_bd(
    bd: &Arc<dyn Resolver>,
    name: &str,
    tld: &str,
    timeout: Duration,
    cancel: &Arc<tokio::sync::Notify>,
) -> LookupResult {
    let domain = format!("{name}.{tld}");
    let start = Instant::now();
    let res = tokio::select! {
        r = tokio::time::timeout(timeout, bd.lookup(name, tld)) => r,
        _ = cancel.notified() => Ok(Err(anyhow::anyhow!("cancelled"))),
    };
    let latency = start.elapsed().as_millis() as u64;
    match res {
        Ok(Ok(mut r)) => {
            r.latency_ms = latency;
            r
        }
        Ok(Err(e)) => LookupResult {
            domain,
            status: DomainStatus::Unknown,
            source: "bd".into(),
            latency_ms: latency,
            details: Some(LookupDetails {
                server: Some(format!("err: {e}")),
                ..Default::default()
            }),
        },
        Err(_) => LookupResult {
            domain,
            status: DomainStatus::Unknown,
            source: "bd".into(),
            latency_ms: latency,
            details: Some(LookupDetails {
                server: Some("timeout".into()),
                ..Default::default()
            }),
        },
    }
}

async fn resolve_whois_only(
    whois: &Arc<dyn Resolver>,
    name: &str,
    tld: &str,
    timeout: Duration,
    host_limiter: &HostLimiter,
    cancel: &Arc<tokio::sync::Notify>,
) -> LookupResult {
    let domain = format!("{name}.{tld}");
    let start = Instant::now();
    let host = tld.to_string();
    let _permit = host_limiter.acquire(&host, DEFAULT_PER_HOST_LIMIT).await;
    let res = tokio::select! {
        r = tokio::time::timeout(timeout, whois.lookup(name, tld)) => r,
        _ = cancel.notified() => Ok(Err(anyhow::anyhow!("cancelled"))),
    };
    let latency = start.elapsed().as_millis() as u64;
    finalize(res, latency, "whois", &domain, "whois")
}

#[allow(clippy::too_many_arguments)]
async fn resolve_chain(
    rdap: &Arc<dyn Resolver>,
    whois: &Arc<dyn Resolver>,
    name: &str,
    tld: &str,
    timeout: Duration,
    host_limiter: &HostLimiter,
    cancel: &Arc<tokio::sync::Notify>,
    _bootstrap: &Bootstrap,
) -> LookupResult {
    let domain = format!("{name}.{tld}");
    let start = Instant::now();

    // Try RDAP first.
    let rdap_res = {
        let _permit = host_limiter
            .acquire(&format!("rdap:{tld}"), DEFAULT_PER_HOST_LIMIT)
            .await;
        tokio::select! {
            r = tokio::time::timeout(timeout, rdap.lookup(name, tld)) => r,
            _ = cancel.notified() => Ok(Err(anyhow::anyhow!("cancelled"))),
        }
    };

    match rdap_res {
        Ok(Ok(mut r)) => {
            r.latency_ms = start.elapsed().as_millis() as u64;
            return r;
        }
        Ok(Err(_)) | Err(_) => {
            // fall through to WHOIS
        }
    }

    // Fall back to WHOIS.
    let whois_res = {
        let _permit = host_limiter
            .acquire(&format!("whois:{tld}"), DEFAULT_PER_HOST_LIMIT)
            .await;
        tokio::select! {
            r = tokio::time::timeout(timeout, whois.lookup(name, tld)) => r,
            _ = cancel.notified() => Ok(Err(anyhow::anyhow!("cancelled"))),
        }
    };
    let latency = start.elapsed().as_millis() as u64;
    finalize(whois_res, latency, "whois", &domain, "whois")
}

fn finalize(
    res: Result<Result<LookupResult, anyhow::Error>, tokio::time::error::Elapsed>,
    latency: u64,
    source: &str,
    domain: &str,
    fallback_source: &str,
) -> LookupResult {
    match res {
        Ok(Ok(mut r)) => {
            r.latency_ms = latency;
            r
        }
        Ok(Err(e)) => LookupResult {
            domain: domain.to_string(),
            status: DomainStatus::Unknown,
            source: source.into(),
            latency_ms: latency,
            details: Some(LookupDetails {
                server: Some(format!("err: {e}")),
                ..Default::default()
            }),
        },
        Err(_) => LookupResult {
            domain: domain.to_string(),
            status: DomainStatus::Unknown,
            source: fallback_source.into(),
            latency_ms: latency,
            details: Some(LookupDetails {
                server: Some("timeout".into()),
                ..Default::default()
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DomainStatus, LookupDetails, LookupResult};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn empty_bootstrap() -> Bootstrap {
        Bootstrap {
            rdap: crate::bootstrap::RdapBootstrap {
                description: String::new(),
                publication: String::new(),
                version: String::new(),
                services: vec![],
            },
            whois: crate::bootstrap::WhoisBootstrap {
                description: String::new(),
                version: String::new(),
                servers: HashMap::new(),
            },
        }
    }

    struct StubResolver {
        name: &'static str,
        status: DomainStatus,
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Resolver for StubResolver {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn lookup(&self, _name: &str, _tld: &str) -> Result<LookupResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            Ok(LookupResult {
                domain: format!("{_name}.{_tld}"),
                status: self.status,
                source: self.name.into(),
                latency_ms: 0,
                details: Some(LookupDetails::default()),
            })
        }
    }

    struct ErrResolver;
    #[async_trait]
    impl Resolver for ErrResolver {
        fn name(&self) -> &'static str {
            "err"
        }
        async fn lookup(&self, _name: &str, _tld: &str) -> Result<LookupResult> {
            Err(anyhow::anyhow!("upstream down"))
        }
    }

    fn chain(
        rdap: Arc<dyn Resolver>,
        whois: Arc<dyn Resolver>,
        bd: Arc<dyn Resolver>,
    ) -> ResolverChain {
        ResolverChain { rdap, whois, bd }
    }

    #[test]
    fn is_bd_zone_tld_matches_bd_and_2ld_bd() {
        assert!(is_bd_zone_tld("bd"));
        assert!(is_bd_zone_tld("BD"));
        assert!(is_bd_zone_tld("com.bd"));
        assert!(is_bd_zone_tld("net.bd"));
        assert!(is_bd_zone_tld("edu.bd"));
        assert!(is_bd_zone_tld("gov.bd"));
        assert!(is_bd_zone_tld("ac.bd"));
        assert!(is_bd_zone_tld("co.bd"));
        assert!(is_bd_zone_tld(" info.bd  "));
        assert!(!is_bd_zone_tld("com"));
        assert!(!is_bd_zone_tld("net"));
        assert!(!is_bd_zone_tld("app"));
        assert!(!is_bd_zone_tld("bds"));
        assert!(!is_bd_zone_tld("xbd"));
        assert!(!is_bd_zone_tld(""));
    }

    #[tokio::test]
    async fn bd_2ld_routes_to_bd_resolver() {
        // `com.bd` should route to the BD resolver, not the WHOIS resolver.
        let bs = empty_bootstrap();
        let pairs = vec![("any".to_string(), "com.bd".to_string())];
        let bd_calls = Arc::new(AtomicUsize::new(0));
        let whois_calls = Arc::new(AtomicUsize::new(0));
        let bd_calls_f = bd_calls.clone();
        let whois_calls_f = whois_calls.clone();
        let out = run_with_resolvers(&pairs, &bs, EngineConfig::default(), move |_| {
            chain(
                Arc::new(StubResolver {
                    name: "rdap",
                    status: DomainStatus::Taken,
                    delay: Duration::from_millis(1),
                    calls: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(StubResolver {
                    name: "whois",
                    status: DomainStatus::Taken,
                    delay: Duration::from_millis(1),
                    calls: whois_calls_f.clone(),
                }),
                Arc::new(StubResolver {
                    name: "bd",
                    status: DomainStatus::Available,
                    delay: Duration::from_millis(1),
                    calls: bd_calls_f.clone(),
                }),
            )
        })
        .await;
        assert_eq!(out[0].domain, "any.com.bd");
        assert_eq!(out[0].source, "bd");
        assert_eq!(out[0].status, DomainStatus::Available);
        assert_eq!(bd_calls.load(Ordering::SeqCst), 1);
        assert_eq!(whois_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn empty_pairs_returns_empty() {
        let bs = empty_bootstrap();
        let out = run(&[], &bs, EngineConfig::default()).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn results_preserve_input_order() {
        let bs = empty_bootstrap();
        let pairs = vec![
            ("a".to_string(), "com".to_string()),
            ("b".to_string(), "com".to_string()),
            ("c".to_string(), "com".to_string()),
        ];
        let out = run_with_resolvers(&pairs, &bs, EngineConfig::default(), move |_| {
            chain(
                Arc::new(StubResolver {
                    name: "rdap",
                    status: DomainStatus::Taken,
                    delay: Duration::from_millis(50),
                    calls: Arc::new(AtomicUsize::new(0)),
                }),
                Arc::new(ErrResolver),
                Arc::new(ErrResolver),
            )
        })
        .await;

        assert_eq!(out.len(), 3);
        assert_eq!(out[0].domain, "a.com");
        assert_eq!(out[1].domain, "b.com");
        assert_eq!(out[2].domain, "c.com");
    }

    #[tokio::test]
    async fn rdap_failure_falls_back_to_whois() {
        let bs = empty_bootstrap();
        let pairs = vec![("foo".to_string(), "com".to_string())];
        let whois_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_factory = whois_calls.clone();
        let out = run_with_resolvers(&pairs, &bs, EngineConfig::default(), move |_| {
            chain(
                Arc::new(ErrResolver),
                Arc::new(StubResolver {
                    name: "whois",
                    status: DomainStatus::Available,
                    delay: Duration::from_millis(1),
                    calls: calls_for_factory.clone(),
                }),
                Arc::new(ErrResolver),
            )
        })
        .await;
        assert_eq!(out[0].status, DomainStatus::Available);
        assert_eq!(out[0].source, "whois");
        assert_eq!(whois_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bd_tld_uses_bd_resolver_first() {
        let bs = empty_bootstrap();
        let pairs = vec![("any".to_string(), "bd".to_string())];
        let bd_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_factory = bd_calls.clone();
        let out = run_with_resolvers(&pairs, &bs, EngineConfig::default(), move |_| {
            chain(
                Arc::new(ErrResolver),
                Arc::new(ErrResolver),
                Arc::new(StubResolver {
                    name: "bd",
                    status: DomainStatus::Taken,
                    delay: Duration::from_millis(1),
                    calls: calls_for_factory.clone(),
                }),
            )
        })
        .await;
        assert_eq!(out[0].source, "bd");
        assert_eq!(out[0].status, DomainStatus::Taken);
        assert_eq!(bd_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn force_whois_skips_rdap() {
        let bs = empty_bootstrap();
        let pairs = vec![("foo".to_string(), "com".to_string())];
        let rdap_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_factory = rdap_calls.clone();
        let out = run_with_resolvers(
            &pairs,
            &bs,
            EngineConfig {
                force_whois: true,
                ..EngineConfig::default()
            },
            move |_| {
                chain(
                    Arc::new(StubResolver {
                        name: "rdap",
                        status: DomainStatus::Taken,
                        delay: Duration::from_millis(1),
                        calls: calls_for_factory.clone(),
                    }),
                    Arc::new(StubResolver {
                        name: "whois",
                        status: DomainStatus::Available,
                        delay: Duration::from_millis(1),
                        calls: Arc::new(AtomicUsize::new(0)),
                    }),
                    Arc::new(ErrResolver),
                )
            },
        )
        .await;
        assert_eq!(out[0].source, "whois");
        assert_eq!(rdap_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn both_resolvers_fail_returns_unknown() {
        let bs = empty_bootstrap();
        let pairs = vec![("foo".to_string(), "com".to_string())];
        let out = run_with_resolvers(&pairs, &bs, EngineConfig::default(), move |_| {
            chain(
                Arc::new(ErrResolver),
                Arc::new(ErrResolver),
                Arc::new(ErrResolver),
            )
        })
        .await;
        assert_eq!(out[0].status, DomainStatus::Unknown);
    }

    #[tokio::test]
    async fn concurrency_is_bounded() {
        let bs = empty_bootstrap();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        struct CountingResolver {
            in_flight: Arc<AtomicUsize>,
            max_seen: Arc<AtomicUsize>,
            delay: Duration,
        }
        #[async_trait]
        impl Resolver for CountingResolver {
            fn name(&self) -> &'static str {
                "count"
            }
            async fn lookup(&self, _name: &str, _tld: &str) -> Result<LookupResult> {
                let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                let mut m = self.max_seen.load(Ordering::SeqCst);
                while cur > m {
                    match self
                        .max_seen
                        .compare_exchange(m, cur, Ordering::SeqCst, Ordering::SeqCst)
                    {
                        Ok(_) => break,
                        Err(v) => m = v,
                    }
                }
                tokio::time::sleep(self.delay).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(LookupResult {
                    domain: format!("{_name}.{_tld}"),
                    status: DomainStatus::Taken,
                    source: "count".into(),
                    latency_ms: 0,
                    details: None,
                })
            }
        }

        let pairs: Vec<_> = (0..50)
            .map(|i| (format!("n{i}"), "com".to_string()))
            .collect();
        let limit = 5;
        let in_flight_f = in_flight.clone();
        let max_seen_f = max_seen.clone();
        let _ = run_with_resolvers(
            &pairs,
            &bs,
            EngineConfig {
                concurrent: limit,
                ..EngineConfig::default()
            },
            move |_| {
                chain(
                    Arc::new(CountingResolver {
                        in_flight: in_flight_f.clone(),
                        max_seen: max_seen_f.clone(),
                        delay: Duration::from_millis(20),
                    }),
                    Arc::new(ErrResolver),
                    Arc::new(ErrResolver),
                )
            },
        )
        .await;
        let max = max_seen.load(Ordering::SeqCst);
        assert!(
            max <= limit,
            "max in-flight ({max}) exceeded limit ({limit})"
        );
        assert!(max >= 1, "should have run at least one task concurrently");
    }

    #[tokio::test]
    async fn timeout_marks_unknown() {
        struct SlowResolver;
        #[async_trait]
        impl Resolver for SlowResolver {
            fn name(&self) -> &'static str {
                "slow"
            }
            async fn lookup(&self, _name: &str, _tld: &str) -> Result<LookupResult> {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(LookupResult {
                    domain: format!("{_name}.{_tld}"),
                    status: DomainStatus::Taken,
                    source: "slow".into(),
                    latency_ms: 0,
                    details: None,
                })
            }
        }
        let bs = empty_bootstrap();
        let pairs = vec![("foo".to_string(), "com".to_string())];
        let out = run_with_resolvers(
            &pairs,
            &bs,
            EngineConfig {
                timeout: Duration::from_millis(50),
                ..EngineConfig::default()
            },
            move |_| {
                chain(
                    Arc::new(SlowResolver),
                    Arc::new(SlowResolver),
                    Arc::new(SlowResolver),
                )
            },
        )
        .await;
        assert_eq!(out[0].status, DomainStatus::Unknown);
    }
}

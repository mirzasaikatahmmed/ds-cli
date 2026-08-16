//! Bootstrap data: IANA RDAP bootstrap + WHOIS server list.
//!
//! The bundle ships a static snapshot of `data.iana.org/rdap/dns.json` and a
//! curated `whois.json` (IANA's WHOIS server list, picked for the TLDs we
//! actually check). At runtime we look for a cached copy in the user's config
//! dir (TTL: 7 days); if the cache is stale or missing we fetch a fresh one
//! in the background and fall back to the bundled snapshot if the network
//! is unavailable.
//!
//! Users can also override/merge with `--rdap-json` / `--whois-json`.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

/// IANA RDAP bootstrap JSON shape (only the bits we use).
///
/// Shape: `services` is a list of `[ [tld_labels], [service_urls] ]` entries.
/// IANA wraps the TLD in an array to support multi-label TLD entries (e.g.
/// `.co.uk`); we collapse that to a single key string per TLD for lookups.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RdapBootstrap {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub publication: String,
    #[serde(default)]
    pub version: String,
    /// Each entry is `[ [tld_labels], [service_urls] ]`.
    pub services: Vec<Vec<Vec<String>>>,
}

/// WHOIS server list JSON shape.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WhoisBootstrap {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub version: String,
    /// TLD (lowercase, no leading dot) -> WHOIS server host.
    pub servers: HashMap<String, String>,
}

/// Cache TTL for bootstrap files in the user's config dir.
pub const BOOTSTRAP_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

const PROJECT_APP_NAME: &str = "ds";

/// Bundled snapshots, embedded at compile time.
pub const BUNDLED_RDAP_JSON: &str = include_str!("data/rdap-dns.json");
pub const BUNDLED_WHOIS_JSON: &str = include_str!("data/whois.json");

/// Combined bootstrap data needed by the engine.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Bootstrap {
    pub rdap: RdapBootstrap,
    pub whois: WhoisBootstrap,
}

/// Load bootstrap data, merging any user-supplied JSON files on top.
///
/// Behaviour:
/// 1. Start with the bundled snapshot (fast, always available).
/// 2. If a cached copy exists in the config dir and is fresh, prefer it.
/// 3. If `--rdap-json` / `--whois-json` are set, load them and merge
///    (user entries win) unless `--no-merge` is set, in which case the
///    user file fully replaces the bundled data.
pub fn load(
    user_rdap: Option<&Path>,
    user_whois: Option<&Path>,
    no_merge: bool,
) -> Result<Bootstrap> {
    let rdap = load_rdap(user_rdap, no_merge)?;
    let whois = load_whois(user_whois, no_merge)?;
    Ok(Bootstrap { rdap, whois })
}

fn load_rdap(user_path: Option<&Path>, no_merge: bool) -> Result<RdapBootstrap> {
    // Base: bundled snapshot.
    let mut current: RdapBootstrap =
        serde_json::from_str(BUNDLED_RDAP_JSON).context("parsing bundled RDAP bootstrap")?;

    // Optionally overlay cached + user data.
    if let Some(cache_path) = cache_path("rdap-dns.json") {
        if let Some(cached) = read_cache_if_fresh::<RdapBootstrap>(&cache_path) {
            current = merge_rdap(current, cached);
        }
    }

    if let Some(p) = user_path {
        let user = read_user_rdap(p)?;
        if no_merge {
            current = user;
        } else {
            current = merge_rdap(current, user);
        }
    }

    Ok(current)
}

fn load_whois(user_path: Option<&Path>, no_merge: bool) -> Result<WhoisBootstrap> {
    let mut current: WhoisBootstrap =
        serde_json::from_str(BUNDLED_WHOIS_JSON).context("parsing bundled WHOIS bootstrap")?;

    if let Some(cache_path) = cache_path("whois.json") {
        if let Some(cached) = read_cache_if_fresh::<WhoisBootstrap>(&cache_path) {
            current = merge_whois(current, cached);
        }
    }

    if let Some(p) = user_path {
        let user = read_user_whois(p)?;
        if no_merge {
            current = user;
        } else {
            current = merge_whois(current, user);
        }
    }

    Ok(current)
}

/// Merge two RDAP bootstrap objects. User entries (in `b`) win for any
/// overlap. Service URLs for the same TLD are merged and de-duplicated.
pub fn merge_rdap(mut base: RdapBootstrap, overlay: RdapBootstrap) -> RdapBootstrap {
    // Index base by TLD.
    let mut by_tld: HashMap<String, Vec<String>> = base
        .services
        .drain(..)
        .filter_map(|entry| {
            let tld = entry.first()?.first()?.clone();
            let urls = entry.get(1).cloned().unwrap_or_default();
            Some((tld, urls))
        })
        .collect();

    for entry in overlay.services {
        let Some(tld) = entry.first().and_then(|t| t.first()).cloned() else {
            continue;
        };
        let urls = entry.get(1).cloned().unwrap_or_default();
        let bucket = by_tld.entry(tld).or_default();
        for url in urls {
            if !bucket.iter().any(|u| u == &url) {
                bucket.push(url);
            }
        }
    }

    // Re-emit in stable TLD order.
    let mut tlds: Vec<String> = by_tld.keys().cloned().collect();
    tlds.sort();
    let services = tlds
        .into_iter()
        .map(|tld| {
            let urls = by_tld.remove(&tld).unwrap_or_default();
            vec![vec![tld], urls]
        })
        .collect();

    RdapBootstrap {
        description: base.description,
        publication: base.publication,
        version: base.version,
        services,
    }
}

/// Merge two WHOIS bootstrap objects. User entries win.
pub fn merge_whois(mut base: WhoisBootstrap, overlay: WhoisBootstrap) -> WhoisBootstrap {
    for (tld, server) in overlay.servers {
        base.servers.insert(tld.to_ascii_lowercase(), server);
    }
    base
}

/// Return the RDAP base URLs for a TLD, in priority order.
#[allow(dead_code)]
pub fn rdap_servers_for<'a>(bootstrap: &'a RdapBootstrap, tld: &str) -> Vec<&'a str> {
    let tld = tld.to_ascii_lowercase();
    bootstrap
        .services
        .iter()
        .filter(|entry| {
            entry
                .first()
                .and_then(|t| t.first())
                .map(|s| s == &tld)
                .unwrap_or(false)
        })
        .flat_map(|entry| entry.get(1).into_iter().flatten().map(|s| s.as_str()))
        .collect()
}

/// Return the WHOIS server for a TLD, if known.
#[allow(dead_code)]
pub fn whois_server_for<'a>(bootstrap: &'a WhoisBootstrap, tld: &str) -> Option<&'a str> {
    let tld = tld.to_ascii_lowercase();
    bootstrap.servers.get(&tld).map(|s| s.as_str())
}

// ---------- cache helpers ----------

fn cache_path(filename: &str) -> Option<PathBuf> {
    let dirs = ProjectDirs::from("dev", "ds", PROJECT_APP_NAME)?;
    Some(dirs.cache_dir().join(filename))
}

fn read_cache_if_fresh<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    refresh_age(path).ok().filter(|age| *age < BOOTSTRAP_TTL)?;
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn refresh_age(path: &Path) -> io::Result<Duration> {
    let meta = fs::metadata(path)?;
    let mtime = meta.modified()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let then = mtime.duration_since(UNIX_EPOCH).unwrap_or_default();
    Ok(now.saturating_sub(then))
}

// ---------- user file helpers ----------

fn read_user_rdap(path: &Path) -> Result<RdapBootstrap> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading rdap json: {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing rdap json: {}", path.display()))
}

fn read_user_whois(path: &Path) -> Result<WhoisBootstrap> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading whois json: {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing whois json: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rdap() -> RdapBootstrap {
        RdapBootstrap {
            description: "base".into(),
            publication: "p1".into(),
            version: "v1".into(),
            services: vec![
                vec![
                    vec!["com".into()],
                    vec!["https://rdap.verisign.com/".into()],
                ],
                vec![vec!["io".into()], vec!["https://rdap.nic.io/".into()]],
            ],
        }
    }

    fn sample_whois() -> WhoisBootstrap {
        let mut s = WhoisBootstrap {
            description: "".into(),
            version: "".into(),
            servers: HashMap::new(),
        };
        s.servers
            .insert("com".into(), "whois.verisign-grs.com".into());
        s.servers.insert("io".into(), "whois.nic.io".into());
        s
    }

    #[test]
    fn merge_whois_user_wins() {
        let base = sample_whois();
        let mut overlay = WhoisBootstrap {
            description: "".into(),
            version: "".into(),
            servers: HashMap::new(),
        };
        overlay
            .servers
            .insert("com".into(), "whois.custom.com".into());
        overlay
            .servers
            .insert("net".into(), "whois.verisign-grs.com".into());

        let merged = merge_whois(base, overlay);
        assert_eq!(merged.servers.get("com").unwrap(), "whois.custom.com");
        assert_eq!(merged.servers.get("io").unwrap(), "whois.nic.io");
        assert_eq!(merged.servers.get("net").unwrap(), "whois.verisign-grs.com");
    }

    #[test]
    fn merge_whois_lowercases_keys() {
        let base = sample_whois();
        let mut overlay = WhoisBootstrap {
            description: "".into(),
            version: "".into(),
            servers: HashMap::new(),
        };
        overlay
            .servers
            .insert("COM".into(), "whois.upper.com".into());
        let merged = merge_whois(base, overlay);
        assert_eq!(merged.servers.get("com").unwrap(), "whois.upper.com");
    }

    #[test]
    fn merge_rdap_dedupes_service_urls() {
        let base = sample_rdap();
        let overlay = RdapBootstrap {
            description: "".into(),
            publication: "".into(),
            version: "".into(),
            services: vec![
                vec![
                    vec!["com".into()],
                    vec!["https://rdap.verisign.com/".into()],
                ],
                vec![vec!["com".into()], vec!["https://rdap.alt.com/".into()]],
                vec![
                    vec!["net".into()],
                    vec!["https://rdap.verisign.com/".into()],
                ],
            ],
        };
        let merged = merge_rdap(base, overlay);
        let com = rdap_servers_for(&merged, "com");
        assert_eq!(
            com,
            vec!["https://rdap.verisign.com/", "https://rdap.alt.com/"]
        );
        let net = rdap_servers_for(&merged, "net");
        assert_eq!(net, vec!["https://rdap.verisign.com/"]);
    }

    #[test]
    fn rdap_servers_for_unknown_tld_is_empty() {
        let b = sample_rdap();
        assert!(rdap_servers_for(&b, "ZZ").is_empty());
    }

    #[test]
    fn whois_server_for_lookup() {
        let b = sample_whois();
        assert_eq!(whois_server_for(&b, "com"), Some("whois.verisign-grs.com"));
        assert_eq!(whois_server_for(&b, "io"), Some("whois.nic.io"));
        assert_eq!(whois_server_for(&b, "nope"), None);
    }

    #[test]
    fn bundled_rdap_parses() {
        let _: RdapBootstrap = serde_json::from_str(BUNDLED_RDAP_JSON).unwrap();
    }

    #[test]
    fn bundled_whois_parses() {
        let parsed: WhoisBootstrap = serde_json::from_str(BUNDLED_WHOIS_JSON).unwrap();
        assert!(parsed.servers.contains_key("com"));
        assert!(parsed.servers.contains_key("bd"));
    }

    #[test]
    fn load_works_with_no_user_data() {
        let b = load(None, None, false).unwrap();
        assert!(!b.rdap.services.is_empty());
        assert!(b.whois.servers.contains_key("com"));
    }

    #[test]
    fn load_with_user_whois_no_merge_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut user = WhoisBootstrap {
            description: "user".into(),
            version: "1".into(),
            servers: HashMap::new(),
        };
        user.servers
            .insert("example".into(), "whois.example".into());
        fs::write(&path, serde_json::to_string(&user).unwrap()).unwrap();

        let b = load(None, Some(&path), true).unwrap();
        assert_eq!(b.whois.servers.get("example").unwrap(), "whois.example");
        assert!(!b.whois.servers.contains_key("com"));
    }

    #[test]
    fn load_with_user_whois_merge_extends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.json");
        let mut user = WhoisBootstrap {
            description: "user".into(),
            version: "1".into(),
            servers: HashMap::new(),
        };
        user.servers
            .insert("example".into(), "whois.example".into());
        user.servers
            .insert("com".into(), "whois.override.com".into());
        fs::write(&path, serde_json::to_string(&user).unwrap()).unwrap();

        let b = load(None, Some(&path), false).unwrap();
        assert_eq!(b.whois.servers.get("example").unwrap(), "whois.example");
        assert_eq!(b.whois.servers.get("com").unwrap(), "whois.override.com");
        // bundled data still present
        assert!(b.whois.servers.contains_key("net"));
    }

    #[test]
    fn load_with_user_rdap_no_merge_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.json");
        let user = RdapBootstrap {
            description: "".into(),
            publication: "".into(),
            version: "".into(),
            services: vec![vec![vec!["test".into()], vec!["https://rdap.test/".into()]]],
        };
        fs::write(&path, serde_json::to_string(&user).unwrap()).unwrap();

        let b = load(Some(&path), None, true).unwrap();
        assert_eq!(b.rdap.services.len(), 1);
        assert_eq!(b.rdap.services[0][0][0], "test");
    }

    #[test]
    fn load_with_user_rdap_merge_extends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.json");
        let user = RdapBootstrap {
            description: "".into(),
            publication: "".into(),
            version: "".into(),
            services: vec![vec![vec!["test".into()], vec!["https://rdap.test/".into()]]],
        };
        fs::write(&path, serde_json::to_string(&user).unwrap()).unwrap();

        let b = load(Some(&path), None, false).unwrap();
        assert!(b
            .rdap
            .services
            .iter()
            .any(|e| e.first().and_then(|t| t.first()) == Some(&"test".to_string())));
        assert!(b
            .rdap
            .services
            .iter()
            .any(|e| e.first().and_then(|t| t.first()) == Some(&"com".to_string())));
    }
}

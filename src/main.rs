//! ds - Domain Search CLI
//!
//! Entry point. Wires together CLI parsing, bootstrap data loading,
//! concurrent lookups, and output rendering.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Result;

mod bootstrap;
mod cli;
mod config;
mod dns;
mod engine;
mod models;
mod output;
mod resolvers;

use bootstrap::load as load_bootstrap;
use cli::{expand_inputs, known_tlds, Cli};
use engine::{run, EngineConfig, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT};
use output::export::{timestamped_path, write_csv, write_json};
use output::table::{print_summary, render, RenderOptions};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Load bootstrap first so we can extend the known-TLD set with
    // whatever the IANA RDAP snapshot / bundled WHOIS list teaches us.
    // This lets `ds apple.com` or `ds example.io` be detected as a full
    // domain even when the TLD isn't in POPULAR_TLDS.
    let bs_for_tld_scan = load_bootstrap(
        cli.rdap_json.as_deref().map(Path::new),
        cli.whois_json.as_deref().map(Path::new),
        cli.no_merge,
    )?;
    let mut tlds = known_tlds();
    for entry in &bs_for_tld_scan.rdap.services {
        if let Some(first) = entry.first() {
            if let Some(tld) = first.first() {
                tlds.insert(tld.to_ascii_lowercase());
            }
        }
    }
    for tld in bs_for_tld_scan.whois.servers.keys() {
        tlds.insert(tld.to_ascii_lowercase());
    }

    let inputs = expand_inputs(&cli, &tlds)?;
    if inputs.pairs.is_empty() {
        eprintln!("No (name, tld) pairs to check.");
        return Ok(());
    }

    let bs = bs_for_tld_scan;

    let config = EngineConfig {
        concurrent: cli.concurrent.unwrap_or(DEFAULT_CONCURRENCY),
        per_host_limit: engine::DEFAULT_PER_HOST_LIMIT,
        timeout: Duration::from_millis(cli.timeout.unwrap_or(DEFAULT_TIMEOUT.as_millis() as u64)),
        force_whois: cli.whois,
    };

    eprintln!(
        "Checking {} domains ({} concurrent)",
        inputs.pairs.len(),
        config.concurrent
    );

    let started = Instant::now();
    let mut results = run(&inputs.pairs, &bs, config).await;
    let total_ms = started.elapsed().as_millis();

    // Optional DNS-record enrichment for taken domains.
    if cli.dns_records {
        for r in results.iter_mut() {
            if r.status == models::DomainStatus::Taken {
                if let Ok(recs) = dns::resolve(&r.domain, None).await {
                    let details = r.details.get_or_insert_with(Default::default);
                    details.registrar = details.registrar.clone();
                    // We piggy-back on `LookupDetails.nameservers` is already
                    // populated by RDAP. We add the others via new fields
                    // when needed — for now, just stash them in a way the
                    // --details output will show by writing to a synthetic
                    // details shape.
                    if !recs.a.is_empty() {
                        // Use a sentinel: append to nameservers with `A=ip`.
                        details
                            .nameservers
                            .extend(recs.a.into_iter().map(|ip| format!("A:{ip}")));
                    }
                    if !recs.aaaa.is_empty() {
                        details
                            .nameservers
                            .extend(recs.aaaa.into_iter().map(|ip| format!("AAAA:{ip}")));
                    }
                    if !recs.mx.is_empty() {
                        details
                            .nameservers
                            .extend(recs.mx.into_iter().map(|m| format!("MX:{m}")));
                    }
                    if !recs.ns.is_empty() {
                        details
                            .nameservers
                            .extend(recs.ns.into_iter().map(|n| format!("NS:{n}")));
                    }
                }
            }
        }
    }

    let render_opts = RenderOptions {
        details: cli.details,
        show_where: cli.r#where,
        show_registry: cli.registry,
        available_only: cli.available_only,
    };
    print!("{}", render(&results, &render_opts));
    print_summary(&results, total_ms);

    if cli.save {
        let csv_path = timestamped_path("csv");
        let json_path = timestamped_path("json");
        write_csv(&csv_path, &results)?;
        write_json(&json_path, &results)?;
        eprintln!("saved: {} and {}", csv_path.display(), json_path.display());
    }

    Ok(())
}

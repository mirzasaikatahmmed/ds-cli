//! Resolvers: RDAP, WHOIS, .bd special-case.
//!
//! All resolvers implement the [`Resolver`] trait so the engine can pick the
//! right chain per TLD without caring about the underlying protocol.

use anyhow::Result;
use async_trait::async_trait;

use crate::models::LookupResult;

#[async_trait]
#[allow(dead_code)]
pub trait Resolver: Send + Sync {
    /// Protocol name (used for the `source` column, e.g. "rdap", "whois", "bd").
    fn name(&self) -> &'static str;

    /// Look up a single (name, tld) pair. Implementations should return
    /// `LookupResult` for both successful and "available" outcomes; errors
    /// should be reserved for transport-level failures that the engine may
    /// decide to retry via a fallback resolver.
    async fn lookup(&self, name: &str, tld: &str) -> Result<LookupResult>;
}

pub mod bd;
pub mod rdap;
pub mod whois;

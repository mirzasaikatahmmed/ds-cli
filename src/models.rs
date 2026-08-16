//! Core data models: LookupResult, DomainStatus, LookupLevel, etc.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum DomainStatus {
    Available,
    Taken,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LookupLevel {
    /// Check `name.tld` (e.g. `apple.com`).
    #[default]
    First,
    /// For multi-part TLDs like `co.uk`, check `name.co.uk` instead of
    /// `name.tld`. (No second-level labels like `foo.apple.com`.)
    Second,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct LookupResult {
    pub domain: String,
    pub status: DomainStatus,
    pub source: String,
    pub latency_ms: u64,
    pub details: Option<LookupDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(dead_code)]
pub struct LookupDetails {
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiry_date: Option<String>,
    pub nameservers: Vec<String>,
    pub registry: Option<String>,
    pub server: Option<String>,
}

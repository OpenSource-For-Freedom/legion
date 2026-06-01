//! Feed clients for the DEFCON Database APIs.
//!
//! # Sources
//! - `events_cyber_attack.json`  – cyber events with NVD/NIST enrichment
//! - `data/abuseipdb.json`       – AbuseIPDB IP blacklist snapshot

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const CYBER_EVENTS_URL: &str =
    "https://www.defcondatabase.com/data/events_cyber_attack.json";
const ABUSEIPDB_URL: &str =
    "https://www.defcondatabase.com/data/abuseipdb.json";

// ─────────────────────────── Cyber Attack Events ────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CyberEvent {
    pub id: String,
    pub source: String,
    pub source_url: Option<String>,
    pub title: String,
    pub summary: Option<String>,
    pub event_type: String,
    /// 0-100 severity score
    pub severity: Option<f64>,
    pub risk_band: Option<u8>,
    pub date_start: Option<String>,
    pub date_end: Option<String>,
    pub country: Option<String>,
    pub admin1: Option<String>,
    pub city: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub casualties: Option<serde_json::Value>,
    pub tags: Option<Vec<String>>,
    pub enrichment: Option<Enrichment>,
}

/// NVD/NIST-style enrichment block attached to each CyberEvent.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Enrichment {
    pub cve_ids: Option<Vec<String>>,
    pub affected_packages: Option<Vec<AffectedPackage>>,
    pub threat_actors: Option<Vec<String>>,
    pub campaigns: Option<Vec<String>>,
    pub attack_techniques: Option<Vec<String>>,
    /// "ci" | "local_machines"
    pub asset_buckets: Option<Vec<String>>,
    pub references: Option<Vec<EventReference>>,
    pub so_what: Option<String>,
    pub model: Option<String>,
    pub generated_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AffectedPackage {
    /// npm | pypi | crates | nuget | maven | go | packagist | rubygems | vscode | openvsx
    pub ecosystem: String,
    pub name: String,
    pub version_constraint: Option<String>,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EventReference {
    /// "related_event" | "advisory" | "external"
    pub kind: String,
    pub event_id: Option<String>,
    pub source: Option<String>,
    pub url: Option<String>,
    pub title: Option<String>,
}

// ──────────────────────────── AbuseIPDB Blacklist ───────────────────────────

/// Full payload from the AbuseIPDB /blacklist snapshot.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AbuseIpPayload {
    pub ok: bool,
    pub configured: bool,
    pub generated_at: String,
    pub source: String,
    pub license: Option<String>,
    pub min_confidence: Option<u8>,
    pub limit: Option<u32>,
    pub meta: Option<serde_json::Value>,
    pub note: Option<String>,
    pub ips: Vec<AbuseIpEntry>,
}

impl Default for AbuseIpPayload {
    fn default() -> Self {
        Self {
            ok: false,
            configured: false,
            generated_at: chrono::Utc::now().to_rfc3339(),
            source: String::new(),
            license: None,
            min_confidence: None,
            limit: None,
            meta: None,
            note: None,
            ips: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AbuseIpEntry {
    pub ip: String,
    pub country: Option<String>,
    pub abuse_score: Option<u8>,
    pub last_reported: Option<String>,
}

// ─────────────────────────────── Feed Manager ───────────────────────────────

/// Wraps a shared HTTP client; call `fetch_*` methods to pull feed data.
#[derive(Clone)]
pub struct FeedManager {
    client: Client,
}

impl FeedManager {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("legion-siem/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client })
    }

    /// Fetch the full cyber-attack event list with embedded enrichment.
    pub async fn fetch_cyber_events(&self) -> Result<Vec<CyberEvent>> {
        tracing::info!("Fetching cyber events from {CYBER_EVENTS_URL}");
        let resp = self.client.get(CYBER_EVENTS_URL).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("cyber events feed returned HTTP {status}");
        }
        let events: Vec<CyberEvent> = resp.json().await?;
        tracing::info!("Fetched {} cyber events", events.len());
        Ok(events)
    }

    /// Fetch the AbuseIPDB blacklist snapshot.
    pub async fn fetch_abuseips(&self) -> Result<AbuseIpPayload> {
        tracing::info!("Fetching AbuseIPDB blacklist from {ABUSEIPDB_URL}");
        let resp = self.client.get(ABUSEIPDB_URL).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("AbuseIPDB feed returned HTTP {status}");
        }
        let payload: AbuseIpPayload = resp.json().await?;
        tracing::info!("Fetched {} blacklisted IPs", payload.ips.len());
        Ok(payload)
    }
}

impl Default for FeedManager {
    fn default() -> Self {
        Self::new().expect("Failed to build HTTP client")
    }
}

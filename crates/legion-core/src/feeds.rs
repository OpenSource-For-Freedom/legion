//! Feed clients for public threat-intel feeds.
//!
//! # Sources
//! - `events_cyber_attack.json`  – cyber events with NVD/NIST enrichment
//! - Feodo Tracker CSV           – public IP blacklist snapshot

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const CYBER_EVENTS_URL: &str = "https://www.defcondatabase.com/data/events_cyber_attack.json";
const FEODO_TRACKER_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv";

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

// ──────────────────────────── IP Blacklist (Feodo Tracker) ──────────────────

/// Normalised payload returned by `fetch_abuseips` — source-agnostic.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AbuseIpPayload {
    pub ok: bool,
    pub configured: bool,
    pub generated_at: String,
    pub source: String,
    pub ips: Vec<AbuseIpEntry>,
}

impl Default for AbuseIpPayload {
    fn default() -> Self {
        Self {
            ok: false,
            configured: false,
            generated_at: chrono::Utc::now().to_rfc3339(),
            source: String::new(),
            ips: vec![],
        }
    }
}

/// Normalised IP blacklist entry (compatible with the abuse_ips DB table).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AbuseIpEntry {
    pub ip: String,
    /// Not published by Feodo Tracker. Left `None` rather than filled with a
    /// placeholder that reads like a real lookup.
    pub country: Option<String>,
    /// Reputation score, 0-100. Feodo Tracker publishes **no** such metric, so
    /// this stays `None` for that feed. It used to be synthesized from the C2
    /// status (online → 100, offline → 90) and rendered to the operator as
    /// "abuse score: 100/100", which is a precise-looking number that no source
    /// ever produced.
    pub abuse_score: Option<u8>,
    pub last_reported: Option<String>,
    /// Botnet family operating this C2 (Emotet, QakBot, Dridex, ...). Real
    /// Feodo data, and the most useful field it publishes — previously parsed
    /// past and discarded in favour of the invented score.
    #[serde(default)]
    pub malware: Option<String>,
    /// C2 status as published: `online` / `offline`.
    #[serde(default)]
    pub c2_status: Option<String>,
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
        let bytes = crate::http::read_capped_verified(
            resp,
            crate::http::DEFAULT_MAX_BODY,
            &crate::integrity::FeedIntegrity::TlsOnly,
            "cyber-events",
        )
        .await?;
        let events: Vec<CyberEvent> = serde_json::from_slice(&bytes)?;
        tracing::info!("Fetched {} cyber events", events.len());
        Ok(events)
    }

    /// Fetch the IP blacklist snapshot from Feodo Tracker.
    pub async fn fetch_abuseips(&self) -> Result<AbuseIpPayload> {
        tracing::info!("Fetching IP blacklist from {FEODO_TRACKER_URL}");
        let resp = self.client.get(FEODO_TRACKER_URL).send().await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("IP blacklist feed returned HTTP {status}");
        }
        let bytes = crate::http::read_capped_verified(
            resp,
            crate::http::DEFAULT_MAX_BODY,
            &crate::integrity::FeedIntegrity::TlsOnly,
            "abuseips",
        )
        .await?;
        let text = String::from_utf8(bytes.to_vec())?;
        let payload = parse_feodo_tracker_csv(&text);
        tracing::info!("Fetched {} blacklisted IPs", payload.ips.len());
        Ok(payload)
    }
}

fn parse_feodo_tracker_csv(csv_text: &str) -> AbuseIpPayload {
    let mut payload = AbuseIpPayload {
        ok: true,
        configured: true,
        generated_at: chrono::Utc::now().to_rfc3339(),
        source: "Feodo Tracker".to_string(),
        ips: Vec::new(),
    };

    for line in csv_text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('"') && line.contains("dst_ip")
        {
            continue;
        }

        let columns: Vec<&str> = line.split(',').collect();
        if columns.len() < 6 {
            continue;
        }

        let ip = columns[1].trim().trim_matches('"');
        if ip.is_empty() {
            continue;
        }

        // Feodo columns: first_seen_utc, dst_ip, dst_port, c2_status,
        // last_online, malware.
        let last_reported = columns[4].trim().trim_matches('"');
        let c2_status = columns[3].trim().trim_matches('"');
        let malware = columns[5].trim().trim_matches('"');
        let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());

        payload.ips.push(AbuseIpEntry {
            ip: ip.to_string(),
            // Feodo publishes neither a country nor a reputation score. Report
            // what the feed actually says instead of manufacturing both.
            country: None,
            abuse_score: None,
            last_reported: non_empty(last_reported),
            malware: non_empty(malware),
            c2_status: non_empty(c2_status),
        });
    }

    payload
}

impl Default for FeedManager {
    fn default() -> Self {
        Self::new().expect("Failed to build HTTP client")
    }
}

#[cfg(test)]
mod tests {
    use super::parse_feodo_tracker_csv;

    #[test]
    fn parse_feodo_tracker_csv_extracts_ips() {
        let sample = r#"################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)
# Last updated: 2026-03-04 14:28:39 UTC
################################################################
"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"
"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
"#;

        let payload = parse_feodo_tracker_csv(sample);
        assert!(payload.ok);
        assert_eq!(payload.source, "Feodo Tracker");
        assert_eq!(payload.ips.len(), 2);
        assert_eq!(payload.ips[0].ip, "162.243.103.246");
        assert_eq!(payload.ips[1].ip, "50.16.16.211");
    }

    #[test]
    fn feodo_parse_keeps_the_real_fields_and_invents_none() {
        let sample = r#""first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"
"2022-06-04 21:24:53","162.243.103.246","8080","offline","2026-03-07","Emotet"
"2025-12-30 13:56:31","50.16.16.211","443","online","2026-03-12","QakBot"
"#;
        let payload = parse_feodo_tracker_csv(sample);

        // The botnet family is the most useful thing this feed publishes, and it
        // was parsed past and dropped.
        assert_eq!(payload.ips[0].malware.as_deref(), Some("Emotet"));
        assert_eq!(payload.ips[1].malware.as_deref(), Some("QakBot"));
        assert_eq!(payload.ips[0].c2_status.as_deref(), Some("offline"));
        assert_eq!(payload.ips[1].c2_status.as_deref(), Some("online"));
        assert_eq!(payload.ips[1].last_reported.as_deref(), Some("2026-03-12"));

        // Feodo publishes neither of these. They must stay absent rather than be
        // synthesized: the score used to be conjured from the C2 status
        // (online -> 100, offline -> 90) and shown as "abuse score: 100/100",
        // and the country was the literal string "unknown".
        for e in &payload.ips {
            assert_eq!(e.abuse_score, None, "no source publishes this score");
            assert_eq!(e.country, None, "no source publishes this country");
        }
    }
}

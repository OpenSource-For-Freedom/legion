//! Threat intelligence enrichment feeds — all free, no API keys required.
//!
//! Sources:
//!   1. OSV.dev      — open-source vuln DB; batch-queries scanned packages
//!   2. CISA KEV     — Known Exploited Vulnerabilities catalog
//!   3. ThreatFox    — Abuse.ch malicious IOC feed (IPs/domains/hashes)

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::scanner::ScannedPackage;

const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const THREATFOX_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";

// ─────────────────────────────── OSV.dev ─────────────────────────────────────

/// One vulnerability finding from OSV.dev for an installed package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvFinding {
    pub package: String,
    pub ecosystem: String,
    pub version: Option<String>,
    pub osv_id: String,
    pub summary: String,
    /// "Critical" | "High" | "Medium" | "Low"
    pub severity: Option<String>,
    pub cve_ids: Vec<String>,
    pub ghsa_ids: Vec<String>,
    pub fixed_version: Option<String>,
    pub published: Option<String>,
}

// ── internal request shapes ───────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvPkg {
    name: String,
    ecosystem: String,
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPkg,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Serialize)]
struct OsvBatchReq {
    queries: Vec<OsvQuery>,
}

#[derive(Deserialize)]
struct OsvBatchResp {
    results: Option<Vec<OsvResult>>,
}

#[derive(Deserialize)]
struct OsvResult {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    aliases: Option<Vec<String>>,
    severity: Option<Vec<OsvSev>>,
    affected: Option<Vec<OsvAffected>>,
    published: Option<String>,
}

#[derive(Deserialize)]
struct OsvSev {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct OsvAffected {
    ranges: Option<Vec<OsvRange>>,
}

#[derive(Deserialize)]
struct OsvRange {
    events: Option<Vec<OsvRangeEvent>>,
}

#[derive(Deserialize)]
struct OsvRangeEvent {
    fixed: Option<String>,
}

fn osv_ecosystem(eco: &str) -> &'static str {
    match eco {
        "crates" => "crates.io",
        "npm" => "npm",
        "pypi" => "PyPI",
        _ => "PyPI",
    }
}

/// Derive a severity label from a CVSS vector string.
fn severity_from_cvss(sev: &Option<Vec<OsvSev>>) -> Option<String> {
    let list = sev.as_deref()?;
    for s in list {
        if s.kind.starts_with("CVSS_V") {
            let label = if s.score.contains("/C:H/I:H")
                || s.score.contains("/C:C/I:C")
                || s.score.contains("/A:H/C:H")
            {
                "Critical"
            } else if s.score.contains("/C:H")
                || s.score.contains("/I:H")
                || s.score.contains("/A:H")
            {
                "High"
            } else if s.score.contains("/C:L") || s.score.contains("/I:L") {
                "Medium"
            } else {
                "Low"
            };
            return Some(label.to_string());
        }
    }
    None
}

/// Query OSV.dev for vulnerabilities in every scanned package (batched, max 500/req).
pub async fn query_osv(packages: &[ScannedPackage]) -> Result<Vec<OsvFinding>> {
    if packages.is_empty() {
        return Ok(vec![]);
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("legion-siem/0.1")
        .build()?;

    // Deduplicate by (name, ecosystem)
    let mut seen = std::collections::HashSet::new();
    let mut queries: Vec<(String, String, Option<String>)> = vec![];
    for p in packages {
        let eco = osv_ecosystem(&p.ecosystem_str()).to_string();
        let key = format!("{}:{}", p.name.to_lowercase(), eco);
        if seen.insert(key) {
            queries.push((p.name.clone(), eco, p.version.clone()));
        }
    }

    let mut findings = Vec::new();

    for chunk in queries.chunks(500) {
        let req_queries: Vec<OsvQuery> = chunk
            .iter()
            .map(|(name, eco, ver)| OsvQuery {
                package: OsvPkg {
                    name: name.clone(),
                    ecosystem: eco.clone(),
                },
                version: ver.clone(),
            })
            .collect();

        let resp = match client
            .post(OSV_BATCH_URL)
            .json(&OsvBatchReq {
                queries: req_queries,
            })
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("OSV batch request failed: {e}");
                continue;
            }
        };

        if !resp.status().is_success() {
            tracing::warn!("OSV returned HTTP {}", resp.status());
            continue;
        }

        let batch: OsvBatchResp = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("OSV response parse failed: {e}");
                continue;
            }
        };

        let results = batch.results.unwrap_or_default();
        for (i, result) in results.iter().enumerate() {
            let Some((pkg_name, pkg_eco, pkg_ver)) = chunk.get(i) else {
                continue;
            };
            for vuln in result.vulns.as_deref().unwrap_or_default() {
                let aliases = vuln.aliases.as_deref().unwrap_or_default();
                let cve_ids: Vec<String> = aliases
                    .iter()
                    .filter(|a| a.starts_with("CVE-"))
                    .cloned()
                    .collect();
                let ghsa_ids: Vec<String> = aliases
                    .iter()
                    .filter(|a| a.starts_with("GHSA-"))
                    .cloned()
                    .collect();

                let fixed_version = vuln
                    .affected
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .flat_map(|a| a.ranges.as_deref().unwrap_or_default())
                    .flat_map(|r| r.events.as_deref().unwrap_or_default())
                    .filter_map(|e| e.fixed.clone())
                    .next();

                findings.push(OsvFinding {
                    package: pkg_name.clone(),
                    ecosystem: pkg_eco.clone(),
                    version: pkg_ver.clone(),
                    osv_id: vuln.id.clone(),
                    summary: vuln
                        .summary
                        .clone()
                        .unwrap_or_else(|| "No description".into()),
                    severity: severity_from_cvss(&vuln.severity),
                    cve_ids,
                    ghsa_ids,
                    fixed_version,
                    published: vuln.published.clone(),
                });
            }
        }
    }

    Ok(findings)
}

// ─────────────────────────────── CISA KEV ────────────────────────────────────

/// One entry in the CISA Known Exploited Vulnerabilities catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevEntry {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub vuln_name: String,
    pub date_added: String,
    pub description: String,
    /// True if actively used in ransomware campaigns.
    pub ransomware: bool,
}

#[derive(Deserialize)]
struct KevCatalog {
    vulnerabilities: Vec<KevRaw>,
}

#[derive(Deserialize)]
struct KevRaw {
    #[serde(rename = "cveID", default)]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "vulnerabilityName", default)]
    vuln_name: String,
    #[serde(rename = "dateAdded", default)]
    date_added: String,
    #[serde(rename = "shortDescription", default)]
    description: String,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    ransomware: String,
}

/// Fetch the CISA KEV catalog (~1500 entries, refreshed daily).
pub async fn fetch_kev() -> Result<Vec<KevEntry>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(45))
        .user_agent("legion-siem/0.1")
        .build()?;

    let text = client.get(CISA_KEV_URL).send().await?.text().await?;
    let catalog: KevCatalog =
        serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("CISA KEV parse: {e}"))?;

    Ok(catalog
        .vulnerabilities
        .into_iter()
        .map(|r| KevEntry {
            cve_id: r.cve_id,
            vendor: r.vendor,
            product: r.product,
            vuln_name: r.vuln_name,
            date_added: r.date_added,
            description: r.description,
            ransomware: r.ransomware == "Known",
        })
        .collect())
}

/// Cross-reference OSV findings against KEV catalog by CVE-ID.
/// Returns one `KevCrossRef` per (finding × matching KEV entry).
pub fn kev_cross_ref(findings: &[OsvFinding], kev: &[KevEntry]) -> Vec<KevCrossRef> {
    let mut out = Vec::new();
    for f in findings {
        for cve in &f.cve_ids {
            if let Some(k) = kev.iter().find(|k| &k.cve_id == cve) {
                out.push(KevCrossRef {
                    package: f.package.clone(),
                    ecosystem: f.ecosystem.clone(),
                    version: f.version.clone(),
                    osv_id: f.osv_id.clone(),
                    cve_id: cve.clone(),
                    vendor: k.vendor.clone(),
                    product: k.product.clone(),
                    vuln_name: k.vuln_name.clone(),
                    date_added: k.date_added.clone(),
                    ransomware: k.ransomware,
                });
            }
        }
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KevCrossRef {
    pub package: String,
    pub ecosystem: String,
    pub version: Option<String>,
    pub osv_id: String,
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub vuln_name: String,
    pub date_added: String,
    pub ransomware: bool,
}

// ─────────────────────────────── ThreatFox ───────────────────────────────────

/// One IOC entry from ThreatFox (Abuse.ch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFoxIoc {
    pub id: String,
    pub ioc: String,
    pub ioc_type: String,
    pub threat_type: String,
    pub malware: String,
    pub confidence: u8,
    pub first_seen: String,
}

/// Fetch recent IOCs from ThreatFox (last `days` days, free public API).
pub async fn fetch_threatfox(days: u32) -> Result<Vec<ThreatFoxIoc>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("legion-siem/0.1")
        .build()?;

    let body = serde_json::json!({"query": "get_iocs", "days": days});
    let resp = client.post(THREATFOX_URL).json(&body).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("ThreatFox HTTP {}", resp.status());
    }

    // data field is an array when there are results, or "empty_result" (string) when none.
    #[derive(Deserialize)]
    struct TfResp {
        query_status: String,
        data: Option<serde_json::Value>,
    }

    let r: TfResp = resp.json().await?;
    if r.query_status != "ok" {
        anyhow::bail!("ThreatFox status: {}", r.query_status);
    }

    let arr = match r.data {
        Some(serde_json::Value::Array(a)) => a,
        _ => return Ok(vec![]),
    };

    let iocs = arr
        .into_iter()
        .filter_map(|v| {
            Some(ThreatFoxIoc {
                id: v["id"].as_str()?.to_string(),
                ioc: v["ioc"].as_str()?.to_string(),
                ioc_type: v["ioc_type"].as_str()?.to_string(),
                threat_type: v["threat_type"].as_str().unwrap_or("").to_string(),
                malware: v["malware"].as_str().unwrap_or("").to_string(),
                confidence: v["confidence_level"].as_u64().unwrap_or(50) as u8,
                first_seen: v["first_seen"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect();

    Ok(iocs)
}

/// Find active IP connections that match ThreatFox ip:port IOCs.
pub fn match_threatfox_ips<'a>(
    active_ips: &[String],
    iocs: &'a [ThreatFoxIoc],
) -> Vec<&'a ThreatFoxIoc> {
    let mut out = Vec::new();
    for ioc in iocs {
        if ioc.ioc_type != "ip:port" && ioc.ioc_type != "ip" {
            continue;
        }
        let ioc_ip = ioc.ioc.split(':').next().unwrap_or(&ioc.ioc);
        if active_ips.iter().any(|ip| ip == ioc_ip) {
            out.push(ioc);
        }
    }
    out
}

//! Threat intelligence enrichment feeds — all free, no API keys required.
//!
//! Sources:
//!   1. OSV.dev      — open-source vuln DB; batch-queries scanned packages
//!   2. CISA KEV     — Known Exploited Vulnerabilities catalog

use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::scanner::ScannedPackage;

const OSV_VULN_URL: &str = "https://api.osv.dev/v1/vulns/";
const OSV_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const CISA_KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

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

/// Map Legion's ecosystem string to OSV's, or `None` when OSV has no matching
/// ecosystem. Unknown/system packages must NOT default to PyPI: querying a
/// system package against PyPI risked a false CVE on a name collision (e.g. a
/// distro `cryptography`/`requests`) and hid genuine misses behind a wrong DB.
fn osv_ecosystem(eco: &str) -> Option<&'static str> {
    match eco {
        "crates" => Some("crates.io"),
        "npm" => Some("npm"),
        "pypi" => Some("PyPI"),
        _ => None,
    }
}

/// Derive a severity label from a CVSS vector string.
fn severity_from_cvss(sev: &Option<Vec<OsvSev>>) -> Option<String> {
    let list = sev.as_deref()?;
    for s in list {
        if s.kind.starts_with("CVSS_V") {
            // Count the high-impact metrics INDEPENDENTLY. The previous code
            // tested `/A:H/C:H` as a substring for the two-high-impact case, but
            // CVSS orders the metrics C, I, A, so "A:H" never precedes "C:H" and
            // that branch was unreachable: a C:H + A:H vector (no I:H) was
            // down-rated to High instead of Critical.
            let sc = s.score.as_str();
            let high_impacts = [
                sc.contains("/C:H"),
                sc.contains("/I:H"),
                sc.contains("/A:H"),
            ]
            .iter()
            .filter(|&&b| b)
            .count();
            let cvss2_complete = sc.contains("/C:C/I:C");
            let label = if high_impacts >= 2 || cvss2_complete {
                "Critical"
            } else if high_impacts == 1 {
                "High"
            } else if sc.contains("/C:L") || sc.contains("/I:L") {
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
        // Skip packages whose ecosystem OSV does not index rather than querying
        // them under the wrong ecosystem.
        let Some(eco) = osv_ecosystem(&p.ecosystem_str()) else {
            continue;
        };
        let eco = eco.to_string();
        let key = format!("{}:{}", p.name.to_lowercase(), eco);
        if seen.insert(key) {
            queries.push((p.name.clone(), eco, p.version.clone()));
        }
    }

    let mut findings = Vec::new();
    // (package, ecosystem, version, osv_id) for every hit the batch reports.
    let mut hits: Vec<(String, String, Option<String>, String)> = Vec::new();

    // Track batch failures so a total OSV outage is reported as a DEGRADED scan
    // rather than a clean one. Previously every failure path `continue`d and the
    // function returned `Ok(vec![])`, so "OSV is down" looked identical to "no
    // vulnerabilities" and the dashboard showed a green corpus. fetch_kev and the
    // feeds.rs fetchers already fail loudly; this brings query_osv in line.
    let mut total_chunks = 0usize;
    let mut failed_chunks = 0usize;

    for chunk in queries.chunks(500) {
        total_chunks += 1;
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
                failed_chunks += 1;
                continue;
            }
        };

        if !resp.status().is_success() {
            tracing::warn!("OSV returned HTTP {}", resp.status());
            failed_chunks += 1;
            continue;
        }

        let batch: OsvBatchResp =
            match crate::http::json_capped(resp, crate::http::DEFAULT_MAX_BODY).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!("OSV response parse failed: {e}");
                    failed_chunks += 1;
                    continue;
                }
            };

        let results = batch.results.unwrap_or_default();
        for (i, result) in results.iter().enumerate() {
            let Some((pkg_name, pkg_eco, pkg_ver)) = chunk.get(i) else {
                continue;
            };
            for vuln in result.vulns.as_deref().unwrap_or_default() {
                // Record the hit; details are hydrated after the batch loop.
                hits.push((
                    pkg_name.clone(),
                    pkg_eco.clone(),
                    pkg_ver.clone(),
                    vuln.id.clone(),
                ));
            }
        }
    }

    // Every batch failed: the scan is BLIND, not clean. Fail loudly so the
    // caller marks the run degraded instead of reporting zero vulnerabilities.
    if total_chunks > 0 && failed_chunks == total_chunks {
        anyhow::bail!(
            "OSV unreachable: all {total_chunks} batch request(s) failed; \
             reporting the package scan as degraded rather than clean"
        );
    }

    // OSV's batch endpoint answers with `{id, modified}` and NOTHING else — no
    // severity, no CVE aliases, no summary, no fixed version. Reading those
    // straight off the batch response yielded a finding whose every interesting
    // field was empty, which is why the console showed 153 findings that were
    // uniformly "Medium" with the summary "No description".
    //
    // It also silently disabled the KEV escalation: that joins on CVE id, and
    // the CVE id lives in `aliases`, which only the per-vulnerability document
    // carries. Hydrate each unique id.
    let unique_ids: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        hits.iter()
            .map(|(_, _, _, id)| id.clone())
            .filter(|id| seen.insert(id.clone()))
            .take(MAX_HYDRATE)
            .collect()
    };
    let details = hydrate_vulns(&client, &unique_ids).await;
    tracing::info!(
        "OSV: hydrated {}/{} advisories",
        details.len(),
        unique_ids.len()
    );

    {
        for (pkg_name, pkg_eco, pkg_ver, id) in &hits {
            // Fall back to an id-only finding when hydration failed, rather than
            // dropping a real hit.
            let empty = OsvVuln {
                id: id.clone(),
                summary: None,
                aliases: None,
                severity: None,
                affected: None,
                published: None,
            };
            let vuln = details.get(id).unwrap_or(&empty);
            {
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

/// Cap on per-advisory hydration requests for one scan, so a machine with a huge
/// dependency tree cannot hammer OSV.
const MAX_HYDRATE: usize = 600;

/// Concurrent hydration requests. Enough to keep a scan quick, few enough to be
/// a polite client of a free public API.
const HYDRATE_CONCURRENCY: usize = 8;

/// Fetch the full advisory document for each id.
///
/// Failures are skipped rather than fatal: a finding with no detail is still a
/// finding, and one flaky request must not lose the rest of the scan.
async fn hydrate_vulns(
    client: &Client,
    ids: &[String],
) -> std::collections::HashMap<String, OsvVuln> {
    use std::collections::HashMap;
    let mut out: HashMap<String, OsvVuln> = HashMap::new();
    for batch in ids.chunks(HYDRATE_CONCURRENCY) {
        let mut set = tokio::task::JoinSet::new();
        for id in batch {
            let client = client.clone();
            let id = id.clone();
            set.spawn(async move {
                let url = format!("{OSV_VULN_URL}{id}");
                let resp = client.get(&url).send().await.ok()?;
                if !resp.status().is_success() {
                    return None;
                }
                let vuln: OsvVuln = crate::http::json_capped(resp, crate::http::DEFAULT_MAX_BODY)
                    .await
                    .ok()?;
                Some((id, vuln))
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok(Some((id, vuln))) = joined {
                out.insert(id, vuln);
            }
        }
    }
    out
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

    let resp = client.get(CISA_KEV_URL).send().await?;
    // Optional operator-pinned SHA-256 of the KEV catalog (audit CORE-3). When
    // `LEGION_KEV_SHA256` is set, verification is fail-closed; otherwise the body
    // is TLS-only but its hash is still logged for auditability.
    let kev_pin = std::env::var("LEGION_KEV_SHA256")
        .ok()
        .filter(|s| !s.is_empty());
    let integrity = match kev_pin.as_deref() {
        Some(hex) => crate::integrity::FeedIntegrity::Sha256(hex),
        None => crate::integrity::FeedIntegrity::TlsOnly,
    };
    let bytes = crate::http::read_capped_verified(
        resp,
        crate::http::DEFAULT_MAX_BODY,
        &integrity,
        "cisa-kev",
    )
    .await?;
    let text = String::from_utf8(bytes).map_err(|e| anyhow::anyhow!("CISA KEV utf8: {e}"))?;
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

/// Whether an OSV advisory id denotes a **confirmed-malicious package** rather
/// than a vulnerability in a legitimate one.
///
/// OSV publishes malicious-code reports under the `MAL-` prefix (for example
/// `MAL-2025-41558`, "Malicious code in ethrs.js"). This is a curated, live feed
/// of confirmed malware, and Legion already queries OSV for every scanned
/// package — it simply never distinguished these from ordinary CVEs, so a
/// confirmed-malicious dependency was reported as just another Medium vuln.
///
/// It is also the answer to the compiled-in malicious list going stale: that
/// list is 34 hand-written entries that only change when someone ships a new
/// binary, whereas this updates continuously with no release.
pub fn is_malicious_advisory(osv_id: &str) -> bool {
    osv_id.trim().to_ascii_uppercase().starts_with("MAL-")
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

#[cfg(test)]
mod detection_tests {
    use super::*;

    fn sev(vector: &str) -> Option<String> {
        severity_from_cvss(&Some(vec![OsvSev {
            kind: "CVSS_V3".to_string(),
            score: vector.to_string(),
        }]))
    }

    #[test]
    fn cvss_two_high_impacts_is_critical_regardless_of_order() {
        // C:H + A:H (no I:H): the metrics are ordered C, I, A, so the old
        // "/A:H/C:H" substring never matched and this was down-rated to High.
        assert_eq!(
            sev("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H").as_deref(),
            Some("Critical")
        );
        // The common C:H + I:H critical case still holds.
        assert_eq!(
            sev("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N").as_deref(),
            Some("Critical")
        );
    }

    #[test]
    fn cvss_single_high_impact_is_high() {
        assert_eq!(
            sev("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N").as_deref(),
            Some("High")
        );
    }

    #[test]
    fn cvss_low_impact_is_medium() {
        assert_eq!(
            sev("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N").as_deref(),
            Some("Medium")
        );
    }

    #[test]
    fn osv_ecosystem_maps_supported_and_skips_unknown() {
        assert_eq!(osv_ecosystem("crates"), Some("crates.io"));
        assert_eq!(osv_ecosystem("npm"), Some("npm"));
        assert_eq!(osv_ecosystem("pypi"), Some("PyPI"));
        // Unknown / system must NOT default to PyPI (would query the wrong DB).
        assert_eq!(osv_ecosystem("system"), None);
        assert_eq!(osv_ecosystem("nuget"), None);
    }
}

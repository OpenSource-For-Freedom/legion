use legion_core::{AiThreat, Alert, Drift, OsvFinding, WinEvent, YaraMatch};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleSet {
    pub framework: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub hunt_config: Option<HuntConfig>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HuntConfig {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub os_detection_first: bool,
    #[serde(default)]
    pub architecture_lanes: Vec<ArchitectureLane>,
    #[serde(default)]
    pub escalation_policy: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArchitectureLane {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub data_sources: Vec<String>,
    #[serde(default)]
    pub hunt_focus: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub description: String,
    /// "Critical" | "High" | "Medium" | "Low"
    pub severity: String,
    /// "alert_kind" | "cve_present" | "ai_threat" | "drift" | "yara" | "event_id" | "event_level" | "event_message"
    pub check_kind: String,
    /// Value to match (alert kind string, event ID, drift type, or "*" for any)
    pub check_value: String,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub architectures: Vec<String>,
    #[serde(default)]
    pub data_sources: Vec<String>,
    #[serde(default)]
    pub mitre: Vec<String>,
    #[serde(default)]
    pub nist_controls: Vec<String>,
    #[serde(default)]
    pub hunt_steps: Vec<String>,
    pub remediation: String,
    pub reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleHit {
    pub framework: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub evidence: String,
    pub remediation: String,
    pub reference: String,
}

/// Load rule sets from `<agents_dir>/poncho/rules/*.json`.
/// Falls back to embedded defaults when files are absent.
pub fn load_rule_sets(agents_dir: &std::path::Path) -> Vec<RuleSet> {
    let rule_dir = agents_dir.join("poncho").join("rules");
    let files = [
        "owasp.json",
        "nist.json",
        "cis.json",
        "dev.json",
        "system.json",
    ];
    let mut sets: Vec<RuleSet> = Vec::new();
    for file in &files {
        let path = rule_dir.join(file);
        if let Ok(s) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<RuleSet>(&s) {
                Ok(rs) => sets.push(rs),
                Err(e) => tracing::warn!("poncho: failed to parse rule file {file}: {e}"),
            }
        }
    }
    if sets.is_empty() {
        tracing::debug!(
            "poncho: rule files not found at {:?}, using embedded defaults",
            rule_dir
        );
        sets = embedded_rule_sets();
    }
    sets
}

/// Evaluate all rules against current system state and return sorted hits.
pub fn evaluate_rules(
    rule_sets: &[RuleSet],
    alerts: &[Alert],
    osv: &[OsvFinding],
    ai_threats: &[AiThreat],
    yara_matches: &[YaraMatch],
    drifts: &[Drift],
    win_events: &[WinEvent],
) -> Vec<RuleHit> {
    let mut hits = Vec::new();
    for rs in rule_sets {
        for rule in &rs.rules {
            if let Some(evidence) = check_rule(
                rule,
                alerts,
                osv,
                ai_threats,
                yara_matches,
                drifts,
                win_events,
            ) {
                hits.push(RuleHit {
                    framework: rs.framework.clone(),
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    severity: rule.severity.clone(),
                    evidence,
                    remediation: rule.remediation.clone(),
                    reference: rule.reference.clone(),
                });
            }
        }
    }
    hits.sort_by_key(|h| severity_order(&h.severity));
    hits
}

fn severity_order(s: &str) -> u8 {
    match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

fn check_rule(
    rule: &Rule,
    alerts: &[Alert],
    osv: &[OsvFinding],
    ai_threats: &[AiThreat],
    yara_matches: &[YaraMatch],
    drifts: &[Drift],
    win_events: &[WinEvent],
) -> Option<String> {
    match rule.check_kind.as_str() {
        "alert_kind" => {
            let val = rule.check_value.to_ascii_lowercase();
            let matching: Vec<&Alert> = alerts
                .iter()
                .filter(|a| format!("{:?}", a.kind).to_ascii_lowercase().contains(&val))
                .collect();
            if matching.is_empty() {
                return None;
            }
            Some(format!(
                "{} alert(s): {}",
                matching.len(),
                matching
                    .iter()
                    .take(3)
                    .map(|a| a.title.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        }

        "cve_present" => {
            if osv.is_empty() {
                return None;
            }
            Some(format!(
                "{} OSV finding(s): e.g. {}",
                osv.len(),
                osv.first().map(|o| o.osv_id.as_str()).unwrap_or("unknown")
            ))
        }

        "ai_threat" => {
            let patterns: Vec<String> = rule
                .check_value
                .split('|')
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty() && v != "*")
                .collect();
            let severe: Vec<&AiThreat> = ai_threats
                .iter()
                .filter(|t| {
                    let is_severe = matches!(t.severity.as_str(), "Critical" | "High");
                    if !is_severe {
                        return false;
                    }
                    if patterns.is_empty() {
                        return true;
                    }
                    let text = format!(
                        "{:?} {} {} {} {}",
                        t.kind,
                        t.package.as_deref().unwrap_or(""),
                        t.ecosystem.as_deref().unwrap_or(""),
                        t.atlas_id.as_deref().unwrap_or(""),
                        t.detail
                    )
                    .to_ascii_lowercase();
                    patterns.iter().any(|pattern| text.contains(pattern))
                })
                .collect();
            if severe.is_empty() {
                return None;
            }
            Some(format!(
                "{} high/critical AI threat(s): {}",
                severe.len(),
                severe
                    .iter()
                    .take(2)
                    .map(|t| t.detail.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        }

        "drift" => {
            let val = rule.check_value.to_ascii_lowercase();
            let matching: Vec<&Drift> = drifts
                .iter()
                .filter(|d| val == "*" || d.kind.to_ascii_lowercase().contains(&val))
                .collect();
            if matching.is_empty() {
                return None;
            }
            Some(format!(
                "{} baseline drift(s): {}",
                matching.len(),
                matching
                    .iter()
                    .take(2)
                    .map(|d| d.detail.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        }

        "yara" => {
            let val = rule.check_value.to_ascii_lowercase();
            let matching: Vec<&YaraMatch> = yara_matches
                .iter()
                .filter(|y| val == "*" || y.rule.to_ascii_lowercase().contains(&val))
                .collect();
            if matching.is_empty() {
                return None;
            }
            Some(format!(
                "{} YARA match(es): {}",
                matching.len(),
                matching
                    .iter()
                    .take(2)
                    .map(|y| y.rule.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }

        "event_id" => {
            let eid: u32 = rule.check_value.parse().unwrap_or(0);
            let matching: Vec<&WinEvent> =
                win_events.iter().filter(|e| e.event_id == eid).collect();
            if matching.is_empty() {
                return None;
            }
            Some(format!(
                "{} event(s) with ID {}: {}",
                matching.len(),
                eid,
                matching.first().map(|e| e.log_name.as_str()).unwrap_or("")
            ))
        }

        "event_level" => {
            let level = rule.check_value.to_ascii_lowercase();
            let matching: Vec<&WinEvent> = win_events
                .iter()
                .filter(|e| e.level.to_ascii_lowercase() == level)
                .collect();
            if matching.is_empty() {
                return None;
            }
            Some(format!(
                "{} '{}'-level event(s): {}",
                matching.len(),
                rule.check_value,
                matching.first().map(|e| e.log_name.as_str()).unwrap_or("")
            ))
        }

        "event_message" => {
            let patterns: Vec<String> = rule
                .check_value
                .split('|')
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .collect();
            if patterns.is_empty() {
                return None;
            }
            let matching: Vec<&WinEvent> = win_events
                .iter()
                .filter(|e| {
                    let text = format!("{} {}", e.log_name, e.message).to_ascii_lowercase();
                    patterns.iter().any(|pattern| text.contains(pattern))
                })
                .collect();
            if matching.is_empty() {
                return None;
            }
            Some(format!(
                "{} local event(s) matched '{}': {}",
                matching.len(),
                rule.check_value,
                matching.first().map(|e| e.log_name.as_str()).unwrap_or("")
            ))
        }

        _ => None,
    }
}

fn embedded_rule_sets() -> Vec<RuleSet> {
    let jsons: &[&str] = &[
        include_str!("../../../agents/poncho/rules/owasp.json"),
        include_str!("../../../agents/poncho/rules/nist.json"),
        include_str!("../../../agents/poncho/rules/cis.json"),
        include_str!("../../../agents/poncho/rules/dev.json"),
        include_str!("../../../agents/poncho/rules/system.json"),
    ];
    jsons
        .iter()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect()
}

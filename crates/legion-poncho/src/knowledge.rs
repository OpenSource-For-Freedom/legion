use crate::config::PonchoConfig;
use crate::rules::{evaluate_rules, RuleHit, RuleSet};
use legion_core::{
    telemetry, AiThreat, Alert, AlertKind, Database, DockerInfo, Drift, OsvFinding, Severity,
    SystemStats, WinEvent, YaraMatch,
};
use serde::Serialize;

/// All security context collected from Legion for a single Poncho request.
pub struct KnowledgeContext {
    pub alerts: Vec<Alert>,
    pub osv: Vec<OsvFinding>,
    pub ai_threats: Vec<AiThreat>,
    pub yara_matches: Vec<YaraMatch>,
    pub drifts: Vec<Drift>,
    pub stats: SystemStats,
    pub win_events: Vec<WinEvent>,
    pub docker: Vec<DockerInfo>,
    pub connections: Vec<String>,
    pub rule_hits: Vec<RuleHit>,
}

#[derive(Debug, Serialize)]
pub struct ContextSummary {
    pub alert_count: usize,
    pub critical_count: usize,
    pub osv_count: usize,
    pub yara_count: usize,
    pub ai_threat_count: usize,
    pub rule_hit_count: usize,
    pub critical_rules: usize,
    pub high_rules: usize,
}

impl KnowledgeContext {
    /// Collect all available context from the Legion DB and live system telemetry.
    /// This is a **blocking** function — call inside `spawn_blocking`.
    pub fn collect(db: &Database, cfg: &PonchoConfig, rule_sets: &[RuleSet]) -> Self {
        let mut alerts = db.get_alerts(Some(false)).unwrap_or_default();
        alerts.truncate(cfg.max_context_alerts);

        let osv = db.get_osv_vulns().unwrap_or_default();
        let ai_threats = db.get_ai_detections().unwrap_or_default();
        let yara_matches = db.get_yara_matches().unwrap_or_default();
        let stats = telemetry::collect();
        let win_events = telemetry::collect_win_events(cfg.max_context_events);
        let docker = telemetry::collect_docker();
        let connections = telemetry::active_remote_ips();

        // Derive Drift values from BaselineDrift alerts (drifts are not persisted separately)
        let drifts: Vec<Drift> = alerts
            .iter()
            .filter(|a| matches!(a.kind, AlertKind::BaselineDrift))
            .map(|a| Drift {
                kind: "BaselineDrift".to_string(),
                severity: format!("{:?}", a.severity),
                detail: a.detail.clone(),
            })
            .collect();

        let rule_hits = evaluate_rules(
            rule_sets,
            &alerts,
            &osv,
            &ai_threats,
            &yara_matches,
            &drifts,
            &win_events,
        );

        Self {
            alerts,
            osv,
            ai_threats,
            yara_matches,
            drifts,
            stats,
            win_events,
            docker,
            connections,
            rule_hits,
        }
    }

    pub fn summary(&self) -> ContextSummary {
        let critical_count = self
            .alerts
            .iter()
            .filter(|a| matches!(a.severity, Severity::Critical))
            .count();
        let critical_rules = self
            .rule_hits
            .iter()
            .filter(|h| h.severity == "Critical")
            .count();
        let high_rules = self
            .rule_hits
            .iter()
            .filter(|h| h.severity == "High")
            .count();
        ContextSummary {
            alert_count: self.alerts.len(),
            critical_count,
            osv_count: self.osv.len(),
            yara_count: self.yara_matches.len(),
            ai_threat_count: self.ai_threats.len(),
            rule_hit_count: self.rule_hits.len(),
            critical_rules,
            high_rules,
        }
    }

    /// Build the structured system prompt injected into the LLM context.
    pub fn to_system_prompt(&self, cfg: &PonchoConfig) -> String {
        let mut p = String::with_capacity(8192);

        p.push_str(
            "You are PONCHO, a Blue Team threat hunter AI integrated into the Legion SIEM/SOAR system.\n\
             You have READ-ONLY access to all Legion security data shown below.\n\
             You CANNOT modify systems, files, configurations, or networks.\n\
             Hunt for LOCAL, OWASP Top 10, NIST SP 800-53, CIS Controls v8, development, and system vulnerabilities.\n\
             Be direct, technical, and actionable. Prioritize by actual risk to this system.\n\n",
        );

        p.push_str("=== CURRENT SYSTEM STATE ===\n");
        p.push_str(&format!(
            "CPU: {:.1}%  MEM: {}MB/{}MB  Processes: {}  Load: {:.2}\n\n",
            self.stats.cpu_pct,
            self.stats.mem_used_mb,
            self.stats.mem_total_mb,
            self.stats.proc_count,
            self.stats.load_avg_1,
        ));

        if !self.alerts.is_empty() {
            p.push_str(&format!("=== ACTIVE ALERTS ({}) ===\n", self.alerts.len()));
            for a in self.alerts.iter().take(cfg.max_context_alerts) {
                p.push_str(&format!("[{:?}] {:?} — {}", a.severity, a.kind, a.title));
                if !a.detail.is_empty() {
                    p.push_str(&format!(" | {}", a.detail));
                }
                if !a.cve_ids.is_empty() {
                    p.push_str(&format!(" | CVEs: {}", a.cve_ids.join(", ")));
                }
                p.push('\n');
            }
            p.push('\n');
        }

        if !self.osv.is_empty() {
            p.push_str(&format!(
                "=== OSV VULNERABILITY FINDINGS ({}) ===\n",
                self.osv.len()
            ));
            for o in self.osv.iter().take(20) {
                p.push_str(&format!(
                    "{} [{}/{}{} fixed:{}] — {}\n",
                    o.osv_id,
                    o.package,
                    o.ecosystem,
                    o.severity
                        .as_deref()
                        .map(|s| format!(" {s}"))
                        .unwrap_or_default(),
                    o.fixed_version.as_deref().unwrap_or("n/a"),
                    o.summary,
                ));
            }
            p.push('\n');
        }

        if !self.ai_threats.is_empty() {
            p.push_str(&format!(
                "=== AI SDK THREATS ({}) ===\n",
                self.ai_threats.len()
            ));
            for t in self.ai_threats.iter().take(10) {
                p.push_str(&format!(
                    "[{}] {:?}{} — {}\n",
                    t.severity,
                    t.kind,
                    t.atlas_id
                        .as_deref()
                        .map(|id| format!(" {id}"))
                        .unwrap_or_default(),
                    t.detail,
                ));
            }
            p.push('\n');
        }

        if !self.yara_matches.is_empty() {
            p.push_str(&format!(
                "=== YARA MATCHES ({}) ===\n",
                self.yara_matches.len()
            ));
            for y in self.yara_matches.iter().take(10) {
                p.push_str(&format!(
                    "[{}] {} — {} @ {}\n",
                    y.severity, y.rule, y.description, y.target,
                ));
            }
            p.push('\n');
        }

        if !self.rule_hits.is_empty() {
            p.push_str(&format!(
                "=== FRAMEWORK RULE HITS ({}) ===\n",
                self.rule_hits.len()
            ));
            for h in &self.rule_hits {
                p.push_str(&format!(
                    "[{}] {} {} — {}\n",
                    h.severity, h.framework, h.rule_id, h.evidence,
                ));
            }
            p.push('\n');
        }

        if !self.connections.is_empty() {
            p.push_str(&format!(
                "=== ACTIVE TCP CONNECTIONS ({}) ===\n",
                self.connections.len()
            ));
            for ip in self.connections.iter().take(20) {
                p.push_str(&format!("{ip}\n"));
            }
            p.push('\n');
        }

        if !self.win_events.is_empty() {
            p.push_str(&format!(
                "=== RECENT WINDOWS EVENTS ({}) ===\n",
                self.win_events.len()
            ));
            for e in self.win_events.iter().take(20) {
                let msg = if e.message.len() > 120 {
                    &e.message[..120]
                } else {
                    &e.message
                };
                p.push_str(&format!(
                    "[{}] EID:{} {} — {}\n",
                    e.level, e.event_id, e.log_name, msg,
                ));
            }
            p.push('\n');
        }

        if !self.docker.is_empty() {
            p.push_str(&format!(
                "=== DOCKER CONTAINERS ({}) ===\n",
                self.docker.len()
            ));
            for d in &self.docker {
                p.push_str(&format!(
                    "{} [{}] {} CPU:{} MEM:{} NET:{}/{}\n",
                    d.name, d.state, d.image, d.cpu_pct, d.mem_usage, d.net_in, d.net_out,
                ));
            }
            p.push('\n');
        }

        p.push_str(
            "=== PONCHO CAPABILITIES (READ-ONLY) ===\n\
             - Analyze all Legion security data above\n\
             - Hunt OWASP Top 10:2021 violations\n\
             - Check NIST SP 800-53 Rev 5 controls\n\
             - Evaluate CIS Controls v8 compliance\n\
             - Identify development/supply-chain vulnerabilities\n\
             - Detect system hardening gaps\n\
             - Enrich CVE/threat data via internet search (read-only)\n\
             - Provide prioritized, actionable remediation\n\
             - NO write access to any system\n",
        );

        p
    }
}

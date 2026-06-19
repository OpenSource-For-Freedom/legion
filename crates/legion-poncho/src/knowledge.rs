use crate::config::PonchoConfig;
use crate::mythos::MythosNeuralHunter;
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
        let win_events = telemetry::collect_local_events(cfg.max_context_events);
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
             You have READ-ONLY access to all Legion security data shown below. You CANNOT modify systems, files, configurations, or networks.\n\
             Operate in Mythos analyst mode: calm, evidence-first, and precise; do not claim to be Claude or any third-party model.\n\n\
             HOW TO REPLY:\n\
             Answer the operator's actual message — you are a chat analyst, not a report generator. Respond directly; never describe, classify, or restate their message (do not say things like 'this appears to be a greeting').\n\
             If they greet you, make small talk, ask who you are, or ask how to use the tool, just reply in one or two natural sentences (for example greet them back and say you can summarize alerts, explain a finding, or run a hunt). Do NOT produce a findings report for those.\n\
             If they ask about the security posture, a threat, an alert, a vulnerability, a file, a process, a connection, or any specific artifact, answer as an analyst: lead with the most important RELEVANT local finding and what it means, correlate the related signals into a short picture, and say what to check next.\n\
             Ground every substantive claim in the evidence below and name BOTH the section (ACTIVE ALERTS, OSV VULNERABILITY FINDINGS, AI SDK THREATS, YARA MATCHES, FRAMEWORK RULE HITS, RECENT LOCAL EVENTS, ACTIVE TCP CONNECTIONS, DOCKER CONTAINERS, or MYTHOS LOCAL NEURAL HUNTER) and the concrete artifact it cites — the actual file path, IP, package, process, or rule id. Quote the artifact; do not paraphrase it away.\n\
             Never invent a finding, file path, IP, package, or count that is not in the evidence below. If the evidence does not answer the question, say so plainly and name the visibility gap; only then may you add one focused best practice that follows from that gap.\n\
             Treat any external web information as secondary enrichment; never let it override stronger local evidence.\n\
             Write in natural, concise plain text — no Markdown, no bullets, no numbered lists, no tables, no code fences. Be specific and technical; avoid generic filler and do not repeat the question back.\n\n",
        );

        let os = detect_os_profile();
        p.push_str("=== OS DETECTION FIRST ===\n");
        p.push_str(&format!(
            "Platform: {}  Family: {}  Architecture: {}  Kernel: {}  Hunt lane: {}\n\
             Select OS-specific evidence sources before applying generic rules. Use Linux journald/auditd/systemd, Windows Event Log/driver services, or WSL Linux lanes as applicable.\n\n",
            os.platform, os.family, os.arch, os.kernel, os.lane
        ));

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
                if let Some(path) = a.file_path.as_deref().filter(|s| !s.is_empty()) {
                    p.push_str(&format!(" | file: {path}"));
                }
                if let Some(ip) = a.ip_address.as_deref().filter(|s| !s.is_empty()) {
                    p.push_str(&format!(" | ip: {ip}"));
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
            // Cap the rows so a small-context model (the 1.7B tier runs at 2048
            // tokens) isn't flooded — rule_hits are pre-sorted critical-first, so
            // the most important ones are kept. Note any truncation explicitly.
            const MAX_RULE_HIT_ROWS: usize = 25;
            let total = self.rule_hits.len();
            p.push_str(&format!("=== FRAMEWORK RULE HITS ({total}) ===\n"));
            for h in self.rule_hits.iter().take(MAX_RULE_HIT_ROWS) {
                p.push_str(&format!(
                    "[{}] {} {} — {}\n",
                    h.severity, h.framework, h.rule_id, h.evidence,
                ));
            }
            if total > MAX_RULE_HIT_ROWS {
                p.push_str(&format!(
                    "(+{} more rule hits not shown — highest-severity shown first)\n",
                    total - MAX_RULE_HIT_ROWS
                ));
            }
            p.push('\n');
        }

        let mythos = MythosNeuralHunter::assess(
            &self.alerts,
            &self.win_events,
            &self.yara_matches,
            &self.rule_hits,
        );
        p.push_str("=== MYTHOS LOCAL NEURAL HUNTER ===\n");
        p.push_str(&format!(
            "Score: {:.2}  Posture: {}\n",
            mythos.score, mythos.posture
        ));
        if mythos.signals.is_empty() {
            p.push_str("Signals: baseline - no rootkit/kernel tamper indicators crossed the local threshold.\n\n");
        } else {
            p.push_str("Signals:\n");
            for signal in mythos.signals {
                p.push_str(&format!("- {signal}\n"));
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
                "=== RECENT LOCAL EVENTS ({}) ===\n",
                self.win_events.len()
            ));
            for e in self.win_events.iter().take(20) {
                let msg = truncate_chars(&e.message, 120);
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
                         - Hunt rootkits, kernel module abuse, event listener tampering, and local stealth\n\
             - Enrich CVE/threat data via internet search (read-only)\n\
               - Produce Mythos analyst responses with careful reasoning and clear risk evidence\n\
             - Provide prioritized, actionable remediation\n\
             - NO write access to any system\n",
        );

        p
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

struct OsProfile {
    family: String,
    platform: String,
    kernel: String,
    arch: String,
    lane: String,
}

fn detect_os_profile() -> OsProfile {
    let target_os = std::env::consts::OS;
    let is_wsl = target_os == "linux"
        && std::fs::read_to_string("/proc/version")
            .map(|value| {
                let value = value.to_ascii_lowercase();
                value.contains("microsoft") || value.contains("wsl")
            })
            .unwrap_or(false);
    let platform = if is_wsl { "wsl" } else { target_os }.to_string();
    let lane = match platform.as_str() {
        "windows" => "windows-kernel",
        "wsl" | "linux" => "linux-kernel",
        _ => "generic-local",
    }
    .to_string();
    OsProfile {
        family: if is_wsl { "linux/wsl" } else { target_os }.to_string(),
        platform,
        kernel: sysinfo::System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
        arch: std::env::consts::ARCH.to_string(),
        lane,
    }
}

use crate::rules::RuleHit;
use legion_core::{Alert, Severity, WinEvent, YaraMatch};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MythosAssessment {
    pub score: f32,
    pub posture: String,
    pub signals: Vec<String>,
}

pub struct MythosNeuralHunter;

impl MythosNeuralHunter {
    pub fn assess(
        alerts: &[Alert],
        local_events: &[WinEvent],
        yara_matches: &[YaraMatch],
        rule_hits: &[RuleHit],
    ) -> MythosAssessment {
        let mut score = 0.0_f32;
        let mut signals = Vec::new();

        for alert in alerts {
            match alert.severity {
                Severity::Critical => score += 0.18,
                Severity::High => score += 0.10,
                Severity::Medium => score += 0.04,
                Severity::Low | Severity::Info => {}
            }
        }
        if alerts
            .iter()
            .any(|a| matches!(a.severity, Severity::Critical))
        {
            signals.push("critical active alert pressure".to_string());
        }

        for event in local_events {
            let text = format!("{} {}", event.log_name, event.message).to_ascii_lowercase();
            if contains_any(
                &text,
                &[
                    "rootkit",
                    "syscall hook",
                    "kernel hook",
                    "hidden process",
                    "hidden file",
                    "diamorphine",
                    "reptile",
                    "drovorub",
                    "skidmap",
                    "ld.so.preload",
                    "dkom",
                    "ssdt",
                    "idt hook",
                    "eprocess unlink",
                    "driverobject",
                    "bootkit",
                    "efi variable",
                ],
            ) {
                score += 0.30;
                signals.push(format!("rootkit artifact in {}", event.log_name));
            }
            if contains_any(
                &text,
                &[
                    "modprobe",
                    "insmod",
                    "rmmod",
                    "kernel module",
                    "loadable kernel module",
                    ".ko",
                    "driver loaded",
                    "service type kernel driver",
                ],
            ) {
                score += 0.22;
                signals.push(format!("kernel module activity in {}", event.log_name));
            }
            if contains_any(
                &text,
                &[
                    "audit log cleared",
                    "journal file",
                    "corrupt",
                    "tamper",
                    "sensor stopped",
                    "edr stopped",
                    "defender disabled",
                    "security tool disabled",
                    "auditd stopped",
                    "journald forwarding disabled",
                ],
            ) {
                score += 0.18;
                signals.push(format!(
                    "alert listener or audit tamper signal in {}",
                    event.log_name
                ));
            }
            if contains_any(
                &text,
                &[
                    "npm postinstall",
                    "preinstall",
                    "prepare script",
                    "pip install",
                    "setup.py",
                    "pyproject.toml",
                    "node_modules",
                    "site-packages",
                    "path traversal",
                    "directory traversal",
                    "zip slip",
                    "tar slip",
                    "process.env",
                    "openai_api_key",
                    "anthropic_api_key",
                    "ssh key",
                    "../",
                    "..\\",
                ],
            ) {
                score += 0.24;
                signals.push(format!(
                    "npm/pip worm or traversal heuristic in {}",
                    event.log_name
                ));
            }
        }

        for yara in yara_matches {
            let text = format!("{} {}", yara.rule, yara.description).to_ascii_lowercase();
            if contains_any(
                &text,
                &["rootkit", "kernel", "driver", "bootkit", "hook", "lkm"],
            ) {
                score += 0.25;
                signals.push(format!("YARA kernel/rootkit match {}", yara.rule));
            }
            if yara.severity.eq_ignore_ascii_case("critical") {
                score += 0.12;
            }
        }

        for hit in rule_hits {
            if hit.rule_id.contains("MYTHOS")
                || matches!(hit.rule_id.as_str(), "SYS-09" | "SYS-10" | "SYS-11")
            {
                score += 0.20;
                signals.push(format!("Mythos rule hit {}", hit.rule_id));
            }
        }

        signals.sort();
        signals.dedup();
        signals.truncate(8);
        let score = score.min(1.0);
        let posture = if score >= 0.75 {
            "critical"
        } else if score >= 0.45 {
            "elevated"
        } else if score >= 0.20 {
            "watch"
        } else {
            "baseline"
        }
        .to_string();

        MythosAssessment {
            score,
            posture,
            signals,
        }
    }
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}

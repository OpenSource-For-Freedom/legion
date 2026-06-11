use crate::config::PonchoConfig;
use crate::knowledge::KnowledgeContext;
use crate::rules::RuleHit;
use crate::search::web_search;
use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// "user" | "assistant"
    pub role: String,
    pub content: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    pub content: String,
    pub model_used: String,
    pub search_used: bool,
    pub search_queries: Vec<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    pub analysis: String,
    pub rule_hits: Vec<RuleHit>,
    pub alert_count: usize,
    pub critical_count: usize,
    pub osv_count: usize,
    pub model_used: String,
    pub timestamp: String,
}

#[derive(Serialize, Clone)]
struct OllamaMsg {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OllamaReq<'a> {
    model: &'a str,
    messages: Vec<OllamaMsg>,
    stream: bool,
    options: OllamaOpts,
}

#[derive(Serialize)]
struct OllamaOpts {
    num_ctx: u32,
    temperature: f32,
}

#[derive(Deserialize)]
struct OllamaResp {
    #[serde(default)]
    message: Option<OllamaMsgResp>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct OllamaMsgResp {
    content: String,
}

pub struct PonchoChat {
    cfg: PonchoConfig,
    client: Client,
}

impl PonchoChat {
    pub fn new(cfg: PonchoConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("failed to build Ollama client");
        Self { cfg, client }
    }

    /// Generate a response to a user message, injecting full Legion KB context.
    pub async fn respond(
        &self,
        history: &[ChatMessage],
        user_msg: &str,
        ctx: &KnowledgeContext,
    ) -> Result<ChatResponse> {
        let system_prompt = ctx.to_system_prompt(&self.cfg);

        // Optionally enrich with a DuckDuckGo search
        let (search_ctx, search_queries) = if self.cfg.search_enabled && needs_search(user_msg) {
            let query = build_search_query(user_msg, ctx);
            match web_search(&query, 3).await {
                Ok(results) if !results.is_empty() => {
                    let mut s = String::from("\n=== WEB SEARCH ENRICHMENT (READ-ONLY) ===\n");
                    for r in &results {
                        s.push_str(&format!(
                            "- {} — {}\n  URL: {}\n",
                            r.title, r.snippet, r.url
                        ));
                    }
                    (s, vec![query])
                }
                _ => (String::new(), vec![]),
            }
        } else {
            (String::new(), vec![])
        };

        let full_system = format!("{system_prompt}{search_ctx}");

        // Build message list: system + trimmed history + user
        let mut messages: Vec<OllamaMsg> = vec![OllamaMsg {
            role: "system".to_string(),
            content: full_system,
        }];

        let limit = self.cfg.chat_history_limit;
        let hist = if history.len() > limit {
            &history[history.len() - limit..]
        } else {
            history
        };
        for m in hist {
            messages.push(OllamaMsg {
                role: m.role.clone(),
                content: m.content.clone(),
            });
        }
        messages.push(OllamaMsg {
            role: "user".to_string(),
            content: user_msg.to_string(),
        });

        let (content, model_used) = match self.call_ollama(messages.clone(), &self.cfg.model).await
        {
            Ok(c) => (c, self.cfg.model.clone()),
            Err(e) => {
                tracing::warn!(
                    "poncho: primary model '{}' failed: {e}, trying fallback '{}'",
                    self.cfg.model,
                    self.cfg.fallback_model
                );
                match self.call_ollama(messages, &self.cfg.fallback_model).await {
                    Ok(c) => (c, self.cfg.fallback_model.clone()),
                    Err(e2) => {
                        // Both models failed — degrade gracefully instead of
                        // throwing a bare HTTP 500 at the operator.
                        tracing::warn!("poncho: fallback model also failed: {e2}");
                        (
                            ollama_failure_message(&self.cfg, &e, &e2),
                            "unavailable".to_string(),
                        )
                    }
                }
            }
        };

        Ok(ChatResponse {
            content,
            model_used,
            search_used: !search_queries.is_empty(),
            search_queries,
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Run a structured full blue-team threat hunt.
    pub async fn hunt(&self, ctx: &KnowledgeContext) -> Result<HuntReport> {
        let system_prompt = ctx.to_system_prompt(&self.cfg);
        let hunt_prompt = build_hunt_prompt(ctx);

        let messages = vec![
            OllamaMsg {
                role: "system".to_string(),
                content: system_prompt,
            },
            OllamaMsg {
                role: "user".to_string(),
                content: hunt_prompt,
            },
        ];

        let (content, model_used) = match self.call_ollama(messages.clone(), &self.cfg.model).await
        {
            Ok(c) => (c, self.cfg.model.clone()),
            Err(e) => {
                tracing::warn!("poncho hunt: primary model failed: {e}");
                match self.call_ollama(messages, &self.cfg.fallback_model).await {
                    Ok(c) => (c, self.cfg.fallback_model.clone()),
                    Err(e2) => {
                        tracing::warn!("poncho hunt: fallback model also failed: {e2}");
                        (
                            ollama_failure_message(&self.cfg, &e, &e2),
                            "unavailable".to_string(),
                        )
                    }
                }
            }
        };

        let summary = ctx.summary();
        Ok(HuntReport {
            analysis: content,
            rule_hits: ctx.rule_hits.clone(),
            alert_count: summary.alert_count,
            critical_count: summary.critical_count,
            osv_count: summary.osv_count,
            model_used,
            timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    async fn call_ollama(&self, messages: Vec<OllamaMsg>, model: &str) -> Result<String> {
        // Re-validate policy on the execution path, not just at config-save time:
        // a config edited out-of-band must not be able to reach a blocked model
        // or a non-loopback host (audit PON-2).
        PonchoConfig::validate_host(&self.cfg.ollama_host)?;
        if crate::model_registry::ModelRegistry::is_blocked(model) {
            anyhow::bail!("model '{model}' is blocked by Poncho policy");
        }
        let url = format!("{}/api/chat", self.cfg.ollama_host);
        let req = OllamaReq {
            model,
            messages,
            stream: false,
            options: OllamaOpts {
                num_ctx: 8192,
                temperature: 0.3,
            },
        };
        let resp = self.client.post(&url).json(&req).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Ollama /api/chat returned {}", resp.status());
        }
        let body: OllamaResp = resp.json().await?;
        if let Some(err) = body.error {
            anyhow::bail!("Ollama error: {err}");
        }
        Ok(body.message.map(|m| m.content).unwrap_or_default())
    }
}

/// Build an operator-facing explanation when neither the primary nor fallback
/// model could be reached, with the most likely remediation.
fn ollama_failure_message(
    cfg: &PonchoConfig,
    primary_err: &anyhow::Error,
    fallback_err: &anyhow::Error,
) -> String {
    let conn_failed = primary_err.to_string().contains("error sending request")
        || fallback_err.to_string().contains("error sending request");
    let hint = if conn_failed {
        format!(
            "Ollama is not reachable at {host}. Start it with `ollama serve`, \
             then pull the models: `ollama pull {model}` and `ollama pull {fallback}`.",
            host = cfg.ollama_host,
            model = cfg.model,
            fallback = cfg.fallback_model,
        )
    } else {
        format!(
            "Both models failed to respond. Confirm `{model}` and `{fallback}` are \
             installed (`ollama list`).",
            model = cfg.model,
            fallback = cfg.fallback_model,
        )
    };
    format!(
        "PONCHO could not reach a language model.\n\n{hint}\n\nDetails:\n- primary ({model}): {primary_err}\n- fallback ({fallback}): {fallback_err}",
        model = cfg.model,
        fallback = cfg.fallback_model,
    )
}

fn needs_search(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("cve-")
        || lower.contains("vuln")
        || lower.contains("exploit")
        || lower.contains("patch")
        || lower.contains("advisory")
        || lower.contains("nvd")
        || lower.contains("ghsa-")
        || lower.contains("lookup")
        || lower.contains("search")
}

fn build_search_query(msg: &str, ctx: &KnowledgeContext) -> String {
    // If the message mentions a CVE ID, use that as the primary search term
    if let Some(start) = msg.to_ascii_uppercase().find("CVE-") {
        let candidate = &msg[start..];
        let end = candidate
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .unwrap_or(candidate.len());
        let cve_id = &candidate[..end.min(20)];
        return format!("{cve_id} security vulnerability");
    }
    // Otherwise use the first OSV finding if available
    if let Some(osv) = ctx.osv.first() {
        if !osv.cve_ids.is_empty() {
            return format!("{} vulnerability {}", osv.cve_ids[0], osv.package);
        }
        return format!("{} {} vulnerability", osv.osv_id, osv.package);
    }
    // Fallback: truncate the raw message
    let q = msg.trim();
    q.chars().take(100).collect()
}

pub fn build_hunt_prompt(ctx: &KnowledgeContext) -> String {
    let summary = ctx.summary();
    format!(
        "Perform a comprehensive Mythos blue-team threat hunt on this system using all context above.\n\n\
         Return plain text only. Do not use Markdown, asterisks, numbered headings, tables, or decorative prose.\n\
         Use these exact section headers on their own lines:\n\
         CRITICAL FINDINGS\n\
         ROOTKIT AND KERNEL VIEW\n\
         ALERT LISTENER HEALTH\n\
         OWASP NIST CIS GAPS\n\
         ATTACK VECTORS\n\
         PRIORITY REMEDIATION\n\n\
         Under each header, write short SOC analyst rows in this format: Label: Evidence.\n\
         Separate observed evidence from hypothesis. If evidence is missing, say No direct evidence and name the gap.\n\
         Do not repeat section titles inside row text. Do not claim active compromise from rule candidates alone.\n\n\
         Context summary: {} active alerts ({} critical), {} OSV findings, \
         {} rule hits ({} critical, {} high).\n\
         Use the Mythos local neural hunter posture from context as supporting evidence, not as proof by itself. \
         Be concise, technical, and prioritize by real risk. No preamble.",
        summary.alert_count,
        summary.critical_count,
        summary.osv_count,
        summary.rule_hit_count,
        summary.critical_rules,
        summary.high_rules,
    )
}

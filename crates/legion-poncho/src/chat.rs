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
    think: bool,
    options: OllamaOpts,
    /// Keep the model resident after the call so the next hunt/chat doesn't pay
    /// the multi-second cold-load again (the cause of the earlier cold-start
    /// "error sending request"). Ollama accepts a duration string.
    keep_alive: &'a str,
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
        // Split timeouts: a short connect timeout fails fast and cleanly when
        // Ollama is down (so the caller can fall back), while a generous overall
        // timeout tolerates slow CPU-only inference of large models (an 8B model
        // on CPU can take minutes per hunt).
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(600))
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
        // Direct (deterministic) responses for trivial conversational turns —
        // greetings, thanks, identity, help. A small local model cannot be
        // trusted to follow a "don't produce a findings report for a greeting"
        // instruction (it acknowledges the greeting and then dumps a report
        // anyway), so we answer these in code and never call the model. This is
        // the reliable, no-parrot path for chitchat and also saves a slow call.
        if let Some(reply) = direct_reply(user_msg, ctx) {
            return Ok(ChatResponse {
                content: reply,
                model_used: "poncho-direct".to_string(),
                search_used: false,
                search_queries: vec![],
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

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
            content: build_chat_prompt(user_msg),
        });

        // Chat runs warmer than a structured hunt: we want synthesis and
        // natural phrasing, not a deterministic restatement of the evidence.
        let temp = 0.5;
        let (content, model_used) = match self
            .call_ollama(messages.clone(), &self.cfg.model, temp)
            .await
        {
            Ok(c) => (c, self.cfg.model.clone()),
            Err(e) => {
                tracing::warn!(
                    "poncho: primary model '{}' failed: {e}, trying fallback '{}'",
                    self.cfg.model,
                    self.cfg.fallback_model
                );
                match self
                    .call_ollama(messages, &self.cfg.fallback_model, temp)
                    .await
                {
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

        // A hunt is a structured report — keep it low-temperature for stable,
        // section-aligned output.
        let temp = 0.2;
        let (content, model_used) = match self
            .call_ollama(messages.clone(), &self.cfg.model, temp)
            .await
        {
            Ok(c) => (c, self.cfg.model.clone()),
            Err(e) => {
                tracing::warn!("poncho hunt: primary model failed: {e}");
                match self
                    .call_ollama(messages, &self.cfg.fallback_model, temp)
                    .await
                {
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

    async fn call_ollama(
        &self,
        messages: Vec<OllamaMsg>,
        model: &str,
        temperature: f32,
    ) -> Result<String> {
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
            think: false,
            options: OllamaOpts {
                // Match the context to the model tier so a GPU-resident small
                // model stays fully on the GPU (a too-large window spills the KV
                // cache to CPU — the original cause of multi-minute responses).
                num_ctx: num_ctx_for(model),
                temperature,
            },
            keep_alive: "30m",
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

/// Context window for a model tier. Larger models are only selected on hosts
/// with the VRAM to back a bigger window; small/CPU tiers get a capped window
/// so the KV cache stays resident and prompt prefill stays fast.
fn num_ctx_for(model: &str) -> u32 {
    let m = model.to_ascii_lowercase();
    if m.contains("qwen3-8b") || m.contains("qwen3:8b") {
        8192
    } else if m.contains("qwen3-1.7b") || m.contains("qwen3:1.7b") {
        2048
    } else {
        // 4B tiers (Mythos default and bare base) and anything unrecognised.
        4096
    }
}

fn needs_search(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("cve-")
        || lower.contains("ghsa-")
        || lower.contains("nvd")
        || lower.contains("advisory")
        || lower.contains("web search")
        || lower.contains("internet")
        || lower.contains("external lookup")
        || lower.contains("search for")
        || lower.contains("look up")
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

/// A trivial conversational turn that we answer in code rather than via the LLM.
#[derive(Debug, PartialEq, Eq)]
enum TrivialIntent {
    Greeting,
    Thanks,
    Identity,
    Help,
}

/// Classify trivial chitchat. Pure and deterministic so it is unit-testable and
/// independent of any model. Returns `None` for anything substantive, which is
/// then routed to the grounded model path.
fn trivial_intent(user_msg: &str) -> Option<TrivialIntent> {
    let m = user_msg
        .trim()
        .trim_end_matches(|c: char| matches!(c, '!' | '.' | '?' | ',' | ' '))
        .to_ascii_lowercase();
    if m.is_empty() {
        return None;
    }
    let words: Vec<&str> = m.split_whitespace().collect();

    const GREETINGS: &[&str] = &[
        "hi", "hii", "hello", "helo", "hey", "heya", "yo", "hiya", "sup", "howdy", "gm", "morning",
    ];
    if GREETINGS.contains(&m.as_str())
        || m == "hey there"
        || m == "hello there"
        || m == "good morning"
        || m == "good afternoon"
        || m == "good evening"
        || (words.len() <= 2 && !words.is_empty() && words.iter().all(|w| GREETINGS.contains(w)))
    {
        return Some(TrivialIntent::Greeting);
    }

    const THANKS: &[&str] = &[
        "thanks",
        "thank you",
        "thx",
        "ty",
        "cheers",
        "nice",
        "cool",
        "great",
        "ok",
        "okay",
        "k",
        "got it",
    ];
    if THANKS.contains(&m.as_str()) {
        return Some(TrivialIntent::Thanks);
    }

    if m.contains("who are you") || m.contains("what are you") || m.contains("your name") {
        return Some(TrivialIntent::Identity);
    }

    if m == "help"
        || m.contains("what can you do")
        || m.contains("how do i use")
        || m.contains("how do you work")
        || m.contains("what do you do")
    {
        return Some(TrivialIntent::Help);
    }

    None
}

/// Answer trivial conversational turns deterministically (no LLM call) so the
/// small model never gets a chance to dump a findings report on "hi". Returns
/// `None` for substantive questions, which go to the grounded model path.
fn direct_reply(user_msg: &str, ctx: &KnowledgeContext) -> Option<String> {
    Some(match trivial_intent(user_msg)? {
        TrivialIntent::Greeting => {
            let s = ctx.summary();
            format!(
                "Hey — PONCHO here, your local blue-team analyst. Right now I can see {} active \
                 alert(s) ({} critical) and {} rule hit(s) in your Legion data. Ask me what's most \
                 critical, about a specific alert or file, or say \"run a hunt\" for a full sweep.",
                s.alert_count, s.critical_count, s.rule_hit_count
            )
        }
        TrivialIntent::Thanks => {
            "Anytime. Point me at any alert, finding, or file path and I'll dig into the local evidence."
                .to_string()
        }
        TrivialIntent::Identity => {
            "I'm PONCHO, the local Mythos blue-team threat hunter built into Legion. I run fully \
             on-device and only read your security data — alerts, YARA hits, OSV findings, events, \
             rule hits — to help you triage. I never modify anything."
                .to_string()
        }
        TrivialIntent::Help => {
            "Ask me things like: \"what's the most critical finding?\", \"what file did YARA flag?\", \
             \"explain this alert\", or \"run a hunt\". I ground every answer in your local Legion \
             evidence and cite the file path, IP, package, or rule it came from."
                .to_string()
        }
    })
}

fn build_chat_prompt(user_msg: &str) -> String {
    format!(
        "Operator message: {user_msg}\n\n\
         Reply per your response rules. If this is a greeting or a general/meta question, answer briefly and naturally in a sentence or two — no findings report.\n\
         If it asks about the posture, a threat, or a specific artifact, give a grounded analyst answer: lead with the most relevant local finding, correlate the related signals, and say what to check next, citing the concrete evidence — name the actual file path, IP, package, process, or rule id from the context.\n\
         Never invent anything that is not in the context; if the evidence does not cover it, say so and name the visibility gap.\n\
         Do not use external, CVE, NVD, GHSA, advisory, or web information unless the user explicitly asks for it.\n\
         Plain text only — no Markdown, bullets, numbered lists, tables, or code fences. Be concise and specific; do not repeat the question back."
    )
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

#[cfg(test)]
mod tests {
    use super::{trivial_intent, TrivialIntent};

    #[test]
    fn greetings_are_answered_directly() {
        for g in [
            "hi",
            "helo",
            "hey",
            "Hello!",
            "yo",
            "hey there",
            "good morning",
        ] {
            assert_eq!(
                trivial_intent(g),
                Some(TrivialIntent::Greeting),
                "greeting not detected: {g:?}"
            );
        }
    }

    #[test]
    fn identity_thanks_help_are_answered_directly() {
        assert_eq!(
            trivial_intent("who are you?"),
            Some(TrivialIntent::Identity)
        );
        assert_eq!(
            trivial_intent("what are you exactly"),
            Some(TrivialIntent::Identity)
        );
        assert_eq!(trivial_intent("thanks"), Some(TrivialIntent::Thanks));
        assert_eq!(trivial_intent("help"), Some(TrivialIntent::Help));
        assert_eq!(trivial_intent("what can you do"), Some(TrivialIntent::Help));
    }

    #[test]
    fn substantive_questions_go_to_the_model() {
        // These must NOT be short-circuited — they need the grounded model path.
        for q in [
            "what's the most critical finding?",
            "what file did yara flag",
            "explain alert SYS-04",
            "is 192.168.1.5 malicious",
            "summarize my posture",
            "show me the privilege escalation evidence",
        ] {
            assert_eq!(trivial_intent(q), None, "wrongly treated as trivial: {q:?}");
        }
    }
}

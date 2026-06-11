use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Model families blocked from Poncho use. DeepSeek is excluded due to data
/// handling policy. Matched against a normalised form of the tag (see
/// [`ModelRegistry::is_blocked`]) so common evasions — separators, registry /
/// namespace prefixes, and `:tag` suffixes — do not bypass the block.
const BLOCKED_TAGS: &[&str] = &["deepseek"];

struct Approved {
    tag: &'static str,
    name: &'static str,
    size_gb: f32,
    description: &'static str,
}

const APPROVED: &[Approved] = &[
    Approved {
        tag: "legion-mythos:qwen3-8b",
        name: "Legion Mythos Qwen3 8B",
        size_gb: 5.2,
        description: "Assigned Mythos rootkit/kernel hunter profile built from qwen3:8b.",
    },
    Approved {
        tag: "qwen3:8b",
        name: "Qwen3 8B",
        size_gb: 5.2,
        description: "Best reasoning, large context. Recommended primary for deep threat analysis.",
    },
    Approved {
        tag: "qwen3:4b",
        name: "Qwen3 4B",
        size_gb: 2.8,
        description:
            "Fast fallback with excellent quality/speed. Auto-selected under VRAM pressure.",
    },
    Approved {
        tag: "qwen3:1.7b",
        name: "Qwen3 1.7B",
        size_gb: 1.1,
        description: "Minimal footprint. CPU-only safe for constrained environments.",
    },
    Approved {
        tag: "qwen2.5-coder:7b",
        name: "Qwen2.5 Coder 7B",
        size_gb: 4.7,
        description:
            "Code vulnerability specialist. Best for dependency chain and injection analysis.",
    },
    Approved {
        tag: "llama3.1:8b",
        name: "Llama 3.1 8B",
        size_gb: 5.0,
        description: "Meta Llama 3.1. Strong instruction following and structured output.",
    },
    Approved {
        tag: "mistral:7b",
        name: "Mistral 7B",
        size_gb: 4.1,
        description: "Fast, excellent for structured JSON threat reports.",
    },
    Approved {
        tag: "gemma3:4b",
        name: "Gemma 3 4B",
        size_gb: 2.7,
        description: "Google Gemma 3. Efficient and accurate for security analysis.",
    },
    Approved {
        tag: "phi4-mini:3.8b",
        name: "Phi-4 Mini",
        size_gb: 2.5,
        description: "Microsoft Phi-4 Mini. Low VRAM, high accuracy for its size.",
    },
    Approved {
        tag: "af-intel-analyst:v1",
        name: "Intel Analyst v1",
        size_gb: 0.0,
        description: "Custom local threat intelligence model. Domain-specific security analysis.",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub tag: String,
    pub name: String,
    pub size_gb: f32,
    pub description: String,
    pub installed: bool,
    pub digest: Option<String>,
    pub modified_at: Option<String>,
    pub blocked: bool,
    pub approved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelScanResult {
    pub tag: String,
    pub blocked: bool,
    pub clean: bool,
    pub warnings: Vec<String>,
}

#[derive(Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModelEntry>,
}

#[derive(Deserialize)]
struct OllamaModelEntry {
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    modified_at: Option<String>,
}

pub struct ModelRegistry {
    pub ollama_host: String,
    client: Client,
}

impl ModelRegistry {
    pub fn new(ollama_host: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("legion-poncho/0.1")
            .build()
            .expect("failed to build HTTP client");
        Self {
            ollama_host: ollama_host.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Returns `true` if the tag is blocked by Poncho policy.
    ///
    /// The check is identity-oriented rather than a raw substring match: the tag
    /// is lowercased and stripped of every non-alphanumeric character before
    /// comparison, so a registry/namespace prefix or separator variant
    /// (`hf.co/u/DeepSeek-R1:q4`, `deep-seek`, `deep_seek`) still matches the
    /// blocked family (audit PON-3).
    ///
    /// Limits, by design: name-based blocking cannot catch a locally *renamed*
    /// model (`ollama cp deepseek-r1:7b ds:7b`) or a homoglyph built from
    /// non-ASCII look-alikes — those require digest-level pinning. This is a
    /// policy filter, not a cryptographic control.
    pub fn is_blocked(tag: &str) -> bool {
        let squashed: String = tag
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        BLOCKED_TAGS.iter().any(|b| squashed.contains(b))
    }

    /// List approved models cross-referenced with locally installed Ollama models.
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let installed = self.fetch_installed().await.unwrap_or_default();
        let mut out: Vec<ModelInfo> = Vec::new();

        // Approved models first
        for a in APPROVED {
            let inst = installed
                .iter()
                .find(|m| normalise(m.name.as_str()) == normalise(a.tag));
            out.push(ModelInfo {
                tag: a.tag.to_string(),
                name: a.name.to_string(),
                size_gb: inst
                    .map(|m| m.size as f32 / 1_073_741_824.0)
                    .filter(|&g| g > 0.01)
                    .unwrap_or(a.size_gb),
                description: a.description.to_string(),
                installed: inst.is_some(),
                digest: inst.and_then(|m| m.digest.clone()),
                modified_at: inst.and_then(|m| m.modified_at.clone()),
                blocked: false,
                approved: true,
            });
        }

        // Any locally installed model not in the approved list
        for inst in &installed {
            let already = out
                .iter()
                .any(|m| normalise(&m.tag) == normalise(&inst.name));
            if !already {
                let blocked = Self::is_blocked(&inst.name);
                out.push(ModelInfo {
                    tag: inst.name.clone(),
                    name: inst
                        .name
                        .split(':')
                        .next()
                        .unwrap_or(&inst.name)
                        .to_string(),
                    size_gb: inst.size as f32 / 1_073_741_824.0,
                    description: if blocked {
                        "BLOCKED — not permitted for Poncho use (policy violation)".into()
                    } else {
                        "Locally installed (not in approved list)".into()
                    },
                    installed: true,
                    digest: inst.digest.clone(),
                    modified_at: inst.modified_at.clone(),
                    blocked,
                    approved: false,
                });
            }
        }

        Ok(out)
    }

    async fn fetch_installed(&self) -> Result<Vec<OllamaModelEntry>> {
        let url = format!("{}/api/tags", self.ollama_host);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Ollama /api/tags returned {}", resp.status());
        }
        let list: OllamaTagsResponse = resp.json().await?;
        Ok(list.models)
    }

    /// Pull (install) a model. Blocked models are rejected immediately.
    pub async fn install_model(&self, tag: &str) -> Result<()> {
        if Self::is_blocked(tag) {
            anyhow::bail!(
                "model '{}' is blocked by Poncho policy and cannot be installed",
                tag
            );
        }
        let url = format!("{}/api/pull", self.ollama_host);
        let body = serde_json::json!({ "name": tag, "stream": false });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .timeout(Duration::from_secs(600))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("Ollama pull failed: {}", resp.status());
        }
        Ok(())
    }

    /// Re-pull a model to apply any available updates from the registry.
    pub async fn update_model(&self, tag: &str) -> Result<()> {
        if Self::is_blocked(tag) {
            anyhow::bail!("model '{}' is blocked — update refused", tag);
        }
        self.install_model(tag).await
    }

    /// Inspect a model's Ollama manifest for prompt-injection or suspicious metadata patterns.
    pub async fn scan_model(&self, tag: &str) -> Result<ModelScanResult> {
        if Self::is_blocked(tag) {
            return Ok(ModelScanResult {
                tag: tag.to_string(),
                blocked: true,
                clean: false,
                warnings: vec!["BLOCKED: model tag matches Poncho deny-list policy.".into()],
            });
        }

        let url = format!("{}/api/show", self.ollama_host);
        let body = serde_json::json!({ "name": tag });
        let resp = match self.client.post(&url).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                return Ok(ModelScanResult {
                    tag: tag.to_string(),
                    blocked: false,
                    clean: false,
                    warnings: vec![format!("Cannot reach Ollama to inspect model: {e}")],
                });
            }
        };

        let manifest: serde_json::Value = resp.json().await.unwrap_or_default();
        let mut warnings: Vec<String> = Vec::new();

        let modelfile = manifest
            .get("modelfile")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mf_lower = modelfile.to_ascii_lowercase();

        let suspicious: &[(&str, &str)] = &[
            (
                "ignore previous",
                "Prompt-injection pattern: 'ignore previous' in SYSTEM block",
            ),
            (
                "disregard your instructions",
                "Prompt-injection: 'disregard your instructions'",
            ),
            ("you are now", "Role-hijack pattern: 'you are now' detected"),
            ("curl ", "Shell command (curl) embedded in model definition"),
            ("wget ", "Shell command (wget) embedded in model definition"),
            ("powershell", "PowerShell invocation in model definition"),
            ("cmd.exe", "cmd.exe reference in model definition"),
            ("eval(", "eval() pattern in model definition"),
            ("<script", "Script tag injection in model definition"),
        ];

        for (pattern, desc) in suspicious {
            if mf_lower.contains(pattern) {
                warnings.push(format!("WARNING: {desc}"));
            }
        }

        if let Some(tpl) = manifest.get("template").and_then(|v| v.as_str()) {
            let tpl_lower = tpl.to_ascii_lowercase();
            if tpl_lower.contains("<script")
                || tpl_lower.contains("javascript:")
                || tpl_lower.contains("onerror=")
            {
                warnings.push("Suspicious script content in model template".into());
            }
        }

        Ok(ModelScanResult {
            tag: tag.to_string(),
            blocked: false,
            clean: warnings.is_empty(),
            warnings,
        })
    }

    /// Check whether Ollama is reachable.
    pub async fn is_online(&self) -> bool {
        let url = format!("{}/api/tags", self.ollama_host);
        self.client
            .get(&url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }
}

fn normalise(tag: &str) -> String {
    if tag.contains(':') {
        tag.to_ascii_lowercase()
    } else {
        format!("{}:latest", tag.to_ascii_lowercase())
    }
}

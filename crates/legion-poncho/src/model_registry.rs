use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The Poncho Mythos Modelfile embedded at compile time so the model can be
/// created (or rebuilt) from inside Legion without needing the source tree
/// present at runtime. The Modelfile is baked into the binary — it is never
/// downloaded and never changes at runtime; updates come only via a Legion
/// release (dashboard UPDATE button rebuilds from this embedded content).
pub const MYTHOS_MODELFILE: &str = include_str!("../../../agents/poncho/models/Modelfile.mythos");

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
        name: "PONCHO Qwen3 8B",
        size_gb: 5.2,
        description: "PONCHO's primary model — rootkit/kernel hunter profile built from qwen3:8b. Install with: ollama create legion-mythos:qwen3-8b -f agents/poncho/models/Modelfile.mythos",
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

#[derive(Default)]
struct ParsedModelfile {
    from: Option<String>,
    system: Option<String>,
    template: Option<String>,
    parameters: serde_json::Map<String, serde_json::Value>,
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

    /// Returns `true` when `tag` is present in Ollama's local model list.
    pub async fn is_model_installed(&self, tag: &str) -> bool {
        let want = normalise(tag);
        self.fetch_installed()
            .await
            .unwrap_or_default()
            .iter()
            .any(|m| normalise(&m.name) == want)
    }

    /// Provision the full Poncho Mythos model stack automatically.
    ///
    /// Call this once after Ollama is confirmed online.  The sequence is:
    ///
    /// 1. Check whether `legion-mythos:qwen3-8b` is already installed — if yes,
    ///    nothing to do.
    /// 2. If the base model (`qwen3:8b`) is missing, pull it first.
    /// 3. Build `legion-mythos:qwen3-8b` from the embedded Modelfile.
    ///
    /// Returns a human-readable status string suitable for dashboard display
    /// and a bool indicating whether provisioning changed anything.
    ///
    /// The function is intentionally idempotent — running it when everything is
    /// already installed is a fast no-op (one `/api/tags` call).
    pub async fn auto_provision_poncho(&self, primary: &str, _base: &str) -> (bool, String) {
        // Step 0 — quick exit if primary already installed.
        if self.is_model_installed(primary).await {
            return (
                false,
                format!("{primary} already installed — no provisioning needed"),
            );
        }

        tracing::info!("poncho auto-provision: {primary} not found, starting provisioning");

        // Step 1 — pick the best available base model from what Ollama already
        // has, preferring larger variants. If none present, pull the smallest.
        let candidates = [
            "qwen3:8b",
            "qwen3:4b",
            "qwen3:1.7b",
            "llama3.1:8b",
            "mistral:7b",
        ];
        let mut base_to_use: Option<String> = None;
        for candidate in &candidates {
            if self.is_model_installed(candidate).await {
                base_to_use = Some(candidate.to_string());
                tracing::info!("poncho auto-provision: using installed base {candidate}");
                break;
            }
        }
        let base_to_use = match base_to_use {
            Some(b) => b,
            None => {
                let smallest = "qwen3:4b";
                tracing::info!("poncho auto-provision: no base installed, pulling {smallest}");
                match self.pull_model(smallest).await {
                    Ok(()) => smallest.to_string(),
                    Err(e) => {
                        let msg = format!("Failed to pull base model {smallest}: {e}");
                        tracing::warn!("{msg}");
                        return (false, msg);
                    }
                }
            }
        };

        // Step 2 — build the Mythos model, substituting FROM with actual base.
        tracing::info!(
            "poncho auto-provision: building {primary} from {base_to_use} via embedded Modelfile"
        );
        match self
            .create_mythos_model_with_base(primary, &base_to_use)
            .await
        {
            Ok(()) => {
                let msg = format!("{primary} built from {base_to_use} and ready");
                tracing::info!("poncho auto-provision: {msg}");
                (true, msg)
            }
            Err(e) => {
                let msg = format!("Failed to build {primary} from {base_to_use}: {e}");
                tracing::warn!("{msg}");
                (false, msg)
            }
        }
    }

    /// Pull a model from the Ollama registry (no policy enforcement — use only
    /// for base models where `install_model` would recurse).
    async fn pull_model(&self, tag: &str) -> Result<()> {
        let url = format!("{}/api/pull", self.ollama_host);
        let body = serde_json::json!({ "name": tag, "stream": false });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .timeout(Duration::from_secs(900)) // base models can be large
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("Ollama pull failed for {tag}: {}", resp.status());
        }
        Ok(())
    }

    /// Returns `true` for models that are built locally via `ollama create`
    /// and must NOT be updated from an external Ollama registry.  Updates to
    /// these models are supplied exclusively through Legion dashboard releases
    /// (which carry the updated embedded Modelfile).
    pub fn is_dashboard_only(tag: &str) -> bool {
        tag.starts_with("legion-mythos:")
    }

    /// Build (or rebuild) a `legion-mythos:*` model from the Modelfile that is
    /// embedded in this binary.
    /// Uses the FROM line from the embedded Modelfile (default base).
    pub async fn create_mythos_model(&self, tag: &str) -> Result<()> {
        let base = MYTHOS_MODELFILE
            .lines()
            .find(|l| l.trim().to_ascii_uppercase().starts_with("FROM "))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("qwen3:8b")
            .to_string();
        self.create_mythos_model_with_base(tag, &base).await
    }

    /// Build a `legion-mythos:*` model, substituting `base_model` into the
    /// `FROM` line so we can use whichever model is actually installed.
    ///
    /// API strategy (version-resilient):
    ///   1. POST /api/create `files: {"Modelfile": ...}` — Ollama 0.23.x+
    ///   2. Retry with legacy `modelfile` key — Ollama < 0.23
    ///   3. Shell out: `ollama create` via PATH (WSL/container/Windows fallback)
    pub async fn create_mythos_model_with_base(&self, tag: &str, base_model: &str) -> Result<()> {
        let modelfile = substitute_from(MYTHOS_MODELFILE, base_model);
        let api_url = format!("{}/api/create", self.ollama_host);

        // Preferred path: compile the Modelfile into Ollama's JSON shape
        // (`model`, `from`, `system`, `template`, `parameters`).
        let parsed = parse_modelfile(&modelfile);
        let from = parsed.from.unwrap_or_else(|| base_model.to_string());
        let mut body_obj = serde_json::Map::new();
        body_obj.insert("model".into(), serde_json::Value::String(tag.to_string()));
        body_obj.insert("from".into(), serde_json::Value::String(from));
        body_obj.insert("stream".into(), serde_json::Value::Bool(false));
        if let Some(system) = parsed.system {
            body_obj.insert("system".into(), serde_json::Value::String(system));
        }
        if let Some(template) = parsed.template {
            body_obj.insert("template".into(), serde_json::Value::String(template));
        }
        if !parsed.parameters.is_empty() {
            body_obj.insert(
                "parameters".into(),
                serde_json::Value::Object(parsed.parameters),
            );
        }
        let body = serde_json::Value::Object(body_obj);
        match self
            .client
            .post(&api_url)
            .json(&body)
            .timeout(Duration::from_secs(900))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => return Ok(()),
            Ok(r) => {
                let st = r.status();
                let tx = r.text().await.unwrap_or_default();
                tracing::warn!("ollama /api/create (compiled-modelfile) {tag}: {st} {tx}");
            }
            Err(e) => tracing::warn!("ollama /api/create (compiled-modelfile) request: {e}"),
        }

        // Last resort fallback: shell out to `ollama create`.
        // Use "ollama" directly for PATH resolution (WSL, containers, Windows).
        let tmp_dir = std::env::temp_dir();
        let mf_path = tmp_dir.join("legion_poncho_Modelfile.mythos");
        std::fs::write(&mf_path, &modelfile)?;
        let tag_owned = tag.to_string();
        let mf_str = mf_path.to_string_lossy().to_string();
        // Resolve: prefer PATH `ollama`, fall back to absolute find_binary().
        let bin = if std::process::Command::new("ollama")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            "ollama".to_string()
        } else {
            crate::bootstrap::find_binary()
                .ok_or_else(|| anyhow::anyhow!("ollama not found on PATH or known locations"))?
                .to_string_lossy()
                .to_string()
        };
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(&bin)
                .args(["create", &tag_owned, "-f", &mf_str])
                .output()
        })
        .await??;
        let _ = std::fs::remove_file(&mf_path);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("ollama create failed: {}", stderr);
        }
        Ok(())
    }

    /// Install a model.  Dashboard-only (`legion-mythos:*`) models are built
    /// via `ollama create` from the embedded Modelfile; all other approved
    /// models are pulled from the Ollama registry.  Blocked models are always
    /// rejected.
    pub async fn install_model(&self, tag: &str) -> Result<()> {
        if Self::is_blocked(tag) {
            anyhow::bail!(
                "model '{}' is blocked by Poncho policy and cannot be installed",
                tag
            );
        }
        if Self::is_dashboard_only(tag) {
            return self.create_mythos_model(tag).await;
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

    /// Update a model.  Dashboard-only (`legion-mythos:*`) models are rebuilt
    /// from the embedded Modelfile rather than re-pulled; this guarantees that
    /// the model definition can only change through a Legion release.  All
    /// other models are re-pulled from the Ollama registry.
    pub async fn update_model(&self, tag: &str) -> Result<()> {
        if Self::is_blocked(tag) {
            anyhow::bail!("model '{}' is blocked — update refused", tag);
        }
        if Self::is_dashboard_only(tag) {
            return self.create_mythos_model(tag).await;
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

    /// Look up the installed manifest digest for `tag` from Ollama, if present
    /// (audit PON-1). Tags are compared after normalisation so `qwen3:8b` and
    /// `qwen3:8b:latest`-style variants resolve consistently.
    pub async fn fetch_digest(&self, tag: &str) -> Result<Option<String>> {
        let installed = self.fetch_installed().await?;
        let want = normalise(tag);
        Ok(installed
            .into_iter()
            .find(|m| normalise(&m.name) == want)
            .and_then(|m| m.digest))
    }

    /// Trust-on-first-use pin: record the model's current digest. Called after a
    /// successful install (first pin) or update (re-pin), since a digest change
    /// is expected then. No-op if Ollama reports no digest for the tag.
    pub async fn pin_current(
        &self,
        data_dir: &std::path::Path,
        tag: &str,
    ) -> Result<Option<String>> {
        let Some(digest) = self.fetch_digest(tag).await? else {
            return Ok(None);
        };
        let mut pins = crate::pins::DigestPins::load(data_dir);
        pins.pin(tag, &digest);
        pins.save(data_dir)?;
        Ok(Some(digest))
    }

    /// Verify a model's live digest against the stored pin (audit PON-1).
    /// `FirstUse` means no pin exists yet; `Mismatch` means the model content
    /// changed under the tag without an explicit update — a possible swap.
    pub async fn verify_pinned(
        &self,
        data_dir: &std::path::Path,
        tag: &str,
    ) -> Result<crate::pins::PinCheck> {
        let Some(digest) = self.fetch_digest(tag).await? else {
            anyhow::bail!("model '{tag}' is not installed; cannot verify digest");
        };
        let pins = crate::pins::DigestPins::load(data_dir);
        Ok(pins.check(tag, &digest))
    }
}

fn normalise(tag: &str) -> String {
    if tag.contains(':') {
        tag.to_ascii_lowercase()
    } else {
        format!("{}:latest", tag.to_ascii_lowercase())
    }
}

/// Rewrite the `FROM <base>` line in a Modelfile to use `new_base`.
fn substitute_from(modelfile: &str, new_base: &str) -> String {
    modelfile
        .lines()
        .map(|line| {
            if line.trim().to_ascii_uppercase().starts_with("FROM ") {
                format!("FROM {}", new_base)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_modelfile(modelfile: &str) -> ParsedModelfile {
    let mut parsed = ParsedModelfile::default();
    let lines: Vec<&str> = modelfile.lines().collect();
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = lines[idx].trim();
        idx += 1;

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("FROM ") {
            parsed.from = Some(rest.trim().to_string());
            continue;
        }

        if let Some(rest) = line.strip_prefix("PARAMETER ") {
            let mut parts = rest.splitn(2, char::is_whitespace);
            let key = parts.next().unwrap_or("").trim();
            let raw = parts.next().unwrap_or("").trim();
            if !key.is_empty() {
                let value = if let Ok(n) = raw.parse::<i64>() {
                    serde_json::Value::Number(n.into())
                } else if let Ok(f) = raw.parse::<f64>() {
                    serde_json::json!(f)
                } else if raw.eq_ignore_ascii_case("true") || raw.eq_ignore_ascii_case("false") {
                    serde_json::Value::Bool(raw.eq_ignore_ascii_case("true"))
                } else {
                    serde_json::Value::String(raw.trim_matches('"').to_string())
                };
                parsed.parameters.insert(key.to_string(), value);
            }
            continue;
        }

        if line == "SYSTEM \"\"\"" {
            let mut block = String::new();
            while idx < lines.len() {
                let cur = lines[idx];
                idx += 1;
                if cur.trim() == "\"\"\"" {
                    break;
                }
                if !block.is_empty() {
                    block.push('\n');
                }
                block.push_str(cur);
            }
            parsed.system = Some(block);
            continue;
        }

        if line == "TEMPLATE \"\"\"" {
            let mut block = String::new();
            while idx < lines.len() {
                let cur = lines[idx];
                idx += 1;
                if cur.trim() == "\"\"\"" {
                    break;
                }
                if !block.is_empty() {
                    block.push('\n');
                }
                block.push_str(cur);
            }
            parsed.template = Some(block);
            continue;
        }
    }

    parsed
}

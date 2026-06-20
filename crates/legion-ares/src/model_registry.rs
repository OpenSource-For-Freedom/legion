use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

/// The Ares Modelfile embedded at compile time so the model can be created (or
/// rebuilt) from inside Legion without needing the source tree present at
/// runtime. The Modelfile is baked into the binary — it is never downloaded and
/// never changes at runtime; updates come only via a Legion release.
pub const ARES_MODELFILE: &str = include_str!("../../../agents/ares/models/Modelfile.ares");

/// Model families blocked from Ares use. DeepSeek is excluded due to data
/// handling policy. Matched against a normalised form of the tag (see
/// [`ModelRegistry::is_blocked`]) so common evasions — separators, registry /
/// namespace prefixes, and `:tag` suffixes — do not bypass the block.
const BLOCKED_TAGS: &[&str] = &["deepseek"];

#[derive(Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModelEntry>,
}

#[derive(Deserialize)]
struct OllamaModelEntry {
    name: String,
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Default)]
struct ParsedModelfile {
    from: Option<String>,
    system: Option<String>,
    template: Option<String>,
    parameters: serde_json::Map<String, serde_json::Value>,
}

/// Manages the single local Ares model: provisioning it from the embedded
/// Modelfile, checking Ollama health, and trust-on-first-use digest pinning.
/// Legion ships exactly one model (Ares) — there is no downloadable catalog.
pub struct ModelRegistry {
    pub ollama_host: String,
    client: Client,
}

impl ModelRegistry {
    pub fn new(ollama_host: &str) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("legion-ares/0.1")
            .build()
            .expect("failed to build HTTP client");
        Self {
            ollama_host: ollama_host.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Returns `true` if the tag is blocked by Ares policy.
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

    /// Provision the single Ares model automatically.
    ///
    /// Call this once after Ollama is confirmed online, with the
    /// hardware-selected `primary` tag. The sequence is:
    ///
    /// 1. If `primary` is already installed, nothing to do.
    /// 2. Pick the base to build from — the one matching the tier
    ///    (`qwen3:4b` for `legion-ares:qwen3-4b`), else any installed base,
    ///    else pull it.
    /// 3. Build `primary` from that base via the embedded Modelfile.
    ///
    /// Returns a human-readable status string suitable for dashboard display
    /// and a bool indicating whether provisioning changed anything.
    ///
    /// The function is intentionally idempotent — running it when everything is
    /// already installed is a fast no-op (one `/api/tags` call).
    pub async fn auto_provision_ares(&self, primary: &str, data_dir: &Path) -> (bool, String) {
        // Step 0 — quick exit if primary already installed.
        if self.is_model_installed(primary).await {
            return (
                false,
                format!("{primary} already installed — no provisioning needed"),
            );
        }

        // Step 1 — prefer the TRAINED model from the distribution manifest
        // (downloaded + SHA-256-verified from HuggingFace). Falls through to a
        // local build only when no model is published for this tier yet, or the
        // pull fails (offline / mismatch).
        let manifest = crate::manifest::ModelManifest::embedded();
        match manifest.tier(primary) {
            Some(tier) if tier.is_pullable() => {
                match self.provision_from_manifest(primary, tier, data_dir).await {
                    Ok(msg) => return (true, msg),
                    Err(e) => tracing::warn!(
                        "ares auto-provision: manifest pull for {primary} failed ({e}); building from a stock base"
                    ),
                }
            }
            _ => tracing::info!(
                "ares auto-provision: no published model for {primary} yet; building from a stock base"
            ),
        }

        tracing::info!("ares auto-provision: building {primary} locally from a base model");

        // Step 2 — pick the base to build from. Prefer the base that *matches*
        // the requested Ares tier (qwen3:4b for legion-ares:qwen3-4b) so a
        // 4B profile is never accidentally built on top of an installed 8B.
        // Fall back to any other installed base, then to pulling the matching
        // base (or qwen3:4b if the tier can't be derived).
        let preferred = preferred_base_for(primary);
        let mut base_to_use: Option<String> = None;
        if let Some(p) = &preferred {
            if self.is_model_installed(p).await {
                base_to_use = Some(p.clone());
                tracing::info!("ares auto-provision: using matching base {p}");
            }
        }
        if base_to_use.is_none() {
            let candidates = [
                "qwen3:4b",
                "qwen3:8b",
                "qwen3:1.7b",
                "llama3.1:8b",
                "mistral:7b",
            ];
            for candidate in &candidates {
                if self.is_model_installed(candidate).await {
                    base_to_use = Some(candidate.to_string());
                    tracing::info!("ares auto-provision: using installed base {candidate}");
                    break;
                }
            }
        }
        let base_to_use = match base_to_use {
            Some(b) => b,
            None => {
                let to_pull = preferred.as_deref().unwrap_or("qwen3:4b");
                tracing::info!("ares auto-provision: no base installed, pulling {to_pull}");
                match self.pull_model(to_pull).await {
                    Ok(()) => to_pull.to_string(),
                    Err(e) => {
                        let msg = format!("Failed to pull base model {to_pull}: {e}");
                        tracing::warn!("{msg}");
                        return (false, msg);
                    }
                }
            }
        };

        // Step 3 — build the Ares model, substituting FROM with actual base.
        tracing::info!(
            "ares auto-provision: building {primary} from {base_to_use} via embedded Modelfile"
        );
        match self
            .create_ares_model_with_base(primary, &base_to_use)
            .await
        {
            Ok(()) => {
                let msg = format!("{primary} built from {base_to_use} and ready");
                tracing::info!("ares auto-provision: {msg}");
                (true, msg)
            }
            Err(e) => {
                let msg = format!("Failed to build {primary} from {base_to_use}: {e}");
                tracing::warn!("{msg}");
                (false, msg)
            }
        }
    }

    /// Pull a model from the Ollama registry. Used only for the base model the
    /// Ares profile is built on (no policy enforcement — the base is fixed).
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

    /// Build (or rebuild) the `legion-ares:*` model, substituting `base_model`
    /// into the `FROM` line so we can use whichever base is actually installed.
    ///
    /// API strategy (version-resilient):
    ///   1. POST /api/create with the compiled Modelfile shape — Ollama 0.23.x+
    ///   2. Shell out: `ollama create` via PATH (WSL/container/Windows fallback)
    pub async fn create_ares_model_with_base(&self, tag: &str, base_model: &str) -> Result<()> {
        let modelfile = substitute_from(ARES_MODELFILE, base_model);
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
        let mf_path = tmp_dir.join("legion_ares_Modelfile.ares");
        std::fs::write(&mf_path, &modelfile)?;
        let tag_owned = tag.to_string();
        let mf_str = mf_path.to_string_lossy().to_string();
        let bin = resolve_ollama_bin()?;
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

    /// Pull the trained model for `tier` from HuggingFace, verify it, build it,
    /// and pin its digest. The GGUF is streamed to `<data_dir>/models/` and
    /// SHA-256-verified against the manifest before it is handed to Ollama; the
    /// temp file is removed once Ollama has imported it.
    async fn provision_from_manifest(
        &self,
        primary: &str,
        tier: &crate::manifest::TierSpec,
        data_dir: &Path,
    ) -> Result<String> {
        let models_dir = data_dir.join("models");
        std::fs::create_dir_all(&models_dir)?;
        legion_core::harden_dir(&models_dir);

        let safe: String = primary
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let gguf = models_dir.join(format!("{safe}.gguf"));

        // Cap at the pinned size plus slack; if size is unknown, fall back to a
        // generous 12 GiB ceiling (largest tier is well under this).
        let cap = if tier.size_bytes > 0 {
            (tier.size_bytes + 16 * 1024 * 1024) as usize
        } else {
            12 * 1024 * 1024 * 1024
        };

        tracing::info!(
            "ares: downloading trained model {primary} from {}",
            tier.url
        );
        let resp = self
            .client
            .get(&tier.url)
            .timeout(Duration::from_secs(3600)) // multi-GB weights
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("download of {} returned {}", tier.url, resp.status());
        }
        let integrity = legion_core::integrity::FeedIntegrity::Sha256(&tier.sha256);
        let bytes =
            legion_core::http::download_verified_to_file(resp, &gguf, cap, &integrity).await?;
        tracing::info!("ares: downloaded + verified {bytes} bytes for {primary}");

        let built = self.create_from_gguf(primary, &gguf).await;
        let _ = std::fs::remove_file(&gguf); // Ollama copies it into its own store
        built?;

        // Trust-on-first-use digest pin (PON-1); best-effort.
        if let Err(e) = self.pin_current(data_dir, primary).await {
            tracing::warn!("ares: digest pin for {primary} failed: {e}");
        }
        Ok(format!("{primary} pulled from {} and ready", tier.url))
    }

    /// Build a model from a local GGUF file via `ollama create`. The HTTP
    /// `/api/create` does not accept a local file as `from`, so this uses the CLI
    /// path with a `FROM <gguf>` Modelfile.
    async fn create_from_gguf(&self, tag: &str, gguf_path: &Path) -> Result<()> {
        let modelfile = substitute_from(ARES_MODELFILE, &gguf_path.to_string_lossy());
        let mf_path = std::env::temp_dir().join("legion_ares_gguf.Modelfile");
        std::fs::write(&mf_path, &modelfile)?;
        let bin = resolve_ollama_bin()?;
        let tag_owned = tag.to_string();
        let mf_str = mf_path.to_string_lossy().to_string();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(&bin)
                .args(["create", &tag_owned, "-f", &mf_str])
                .output()
        })
        .await??;
        let _ = std::fs::remove_file(&mf_path);
        if !output.status.success() {
            anyhow::bail!(
                "ollama create from gguf failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
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
    /// successful provision (first pin) or rebuild (re-pin), since a digest
    /// change is expected then. No-op if Ollama reports no digest for the tag.
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

/// Resolve the Ollama executable: prefer `ollama` on PATH, else the absolute
/// path discovered by [`crate::bootstrap::find_binary`].
fn resolve_ollama_bin() -> Result<String> {
    if std::process::Command::new("ollama")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok("ollama".to_string());
    }
    Ok(crate::bootstrap::find_binary()
        .ok_or_else(|| anyhow::anyhow!("ollama not found on PATH or known locations"))?
        .to_string_lossy()
        .to_string())
}

fn normalise(tag: &str) -> String {
    if tag.contains(':') {
        tag.to_ascii_lowercase()
    } else {
        format!("{}:latest", tag.to_ascii_lowercase())
    }
}

/// Map a `legion-ares:qwen3-Nb` primary tag to the Ollama base it should be
/// built from (`qwen3:Nb`). Returns `None` for non-Ares tags. The tag format
/// is `legion-ares:<family>-<size>`; the base is `<family>:<size>`.
fn preferred_base_for(primary: &str) -> Option<String> {
    let suffix = primary.strip_prefix("legion-ares:")?; // e.g. "qwen3-4b"
    let idx = suffix.rfind('-')?;
    Some(format!("{}:{}", &suffix[..idx], &suffix[idx + 1..]))
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

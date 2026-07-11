use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default Ares tier. This is the value used before hardware-aware selection
/// runs (and on hosts where automatic selection is turned off). It targets the
/// common 4–6 GB laptop GPU so the model stays fully GPU-resident; larger and
/// smaller tiers are chosen automatically by [`crate::hardware::select_model`].
pub const ARES_MODEL: &str = "legion-ares:qwen3-4b";
const DEFAULT_MODEL: &str = ARES_MODEL;
const DEFAULT_FALLBACK: &str = "qwen3:4b";

fn default_true() -> bool {
    true
}

fn default_runtime() -> String {
    "openai_compat".to_string()
}

fn default_llm_host() -> String {
    "http://127.0.0.1:8080".to_string()
}

const DEFAULT_OLLAMA_HOST: &str = "http://localhost:11434";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AresConfig {
    /// LLM runtime backend: `openai_compat` (default, e.g. llama.cpp server)
    /// or `ollama` (legacy path).
    #[serde(default = "default_runtime")]
    pub llm_runtime: String,
    /// Generic LLM API base URL for `openai_compat` runtimes.
    #[serde(default = "default_llm_host")]
    pub llm_host: String,
    /// Primary model tag — must not be blocked.
    pub model: String,
    /// Fallback model used when primary is unavailable or the system is under load.
    pub fallback_model: String,
    /// Ollama API base URL.
    pub ollama_host: String,
    /// Root directory for code scanning (read-only).
    pub scan_root: String,
    /// Which rule frameworks are active.
    pub rules_enabled: RulesEnabled,
    /// Maximum alerts injected into LLM context per request.
    pub max_context_alerts: usize,
    /// Maximum Windows events injected per request.
    pub max_context_events: usize,
    /// Allow Ares to enrich CVE queries via DuckDuckGo (read-only).
    pub search_enabled: bool,
    /// In-session chat history limit (message pairs kept in memory).
    pub chat_history_limit: usize,
    /// When true, the model is (re)selected automatically from detected
    /// hardware on each boot. Set false once the operator pins a model in the
    /// dashboard, so their explicit choice is respected.
    #[serde(default = "default_true")]
    pub model_auto: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesEnabled {
    pub owasp: bool,
    pub nist: bool,
    pub cis: bool,
    pub dev: bool,
    pub system: bool,
}

impl Default for RulesEnabled {
    fn default() -> Self {
        Self {
            owasp: true,
            nist: true,
            cis: true,
            dev: true,
            system: true,
        }
    }
}

impl Default for AresConfig {
    fn default() -> Self {
        Self {
            llm_runtime: default_runtime(),
            llm_host: default_llm_host(),
            model: DEFAULT_MODEL.into(),
            fallback_model: DEFAULT_FALLBACK.into(),
            ollama_host: DEFAULT_OLLAMA_HOST.into(),
            scan_root: ".".into(),
            rules_enabled: RulesEnabled::default(),
            max_context_alerts: 50,
            max_context_events: 50,
            search_enabled: true,
            chat_history_limit: 20,
            model_auto: true,
        }
    }
}

impl AresConfig {
    pub fn config_path(data_dir: &Path) -> PathBuf {
        data_dir.join("ares.json")
    }

    /// Load config from `data_dir/ares.json`, falling back to defaults if absent or corrupt.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::config_path(data_dir);
        let cfg: Self = match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        };
        // L1: revalidate the on-disk config at load — a host/model edited
        // out-of-band that violates policy must not be contacted at startup.
        // Degrade to safe defaults rather than honoring it.
        if let Err(e) = cfg.validate() {
            tracing::warn!(
                target: "legion.web",
                "ares config failed validation ({e}); falling back to safe defaults"
            );
            return Self::default();
        }
        cfg
    }

    /// Persist config to `data_dir/ares.json` with owner-only permissions.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = Self::config_path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json.as_bytes())?;
        legion_core::harden_file(&path);
        Ok(())
    }

    /// Validate an LLM API base URL: it must be `http(s)://` and resolve to a
    /// loopback host, unless the operator has explicitly opted into a remote
    /// model host via `LEGION_ALLOW_REMOTE_LLM` (or legacy
    /// `LEGION_ALLOW_REMOTE_OLLAMA`). This blocks the SSRF /
    /// system-prompt-exfiltration vector of pointing the agent at an arbitrary
    /// attacker host (audit PON-2).
    pub fn validate_host(host: &str) -> Result<()> {
        let is_https = host.starts_with("https://");
        let rest = host
            .strip_prefix("http://")
            .or_else(|| host.strip_prefix("https://"))
            .ok_or_else(|| anyhow::anyhow!("llm host must start with http:// or https://"))?;
        // authority = everything up to the first '/' or '?'
        let authority = rest.split(['/', '?']).next().unwrap_or(rest);
        // drop any userinfo ("user:pass@")
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        // extract the bare hostname, handling [ipv6]:port and host:port
        let hostname = if let Some(stripped) = authority.strip_prefix('[') {
            stripped.split(']').next().unwrap_or(stripped)
        } else {
            authority.split(':').next().unwrap_or(authority)
        };
        let parsed_ip = hostname.parse::<std::net::IpAddr>().ok();
        let is_local = matches!(hostname, "localhost" | "127.0.0.1" | "::1")
            || hostname.starts_with("127.")
            || parsed_ip.map(|ip| ip.is_loopback()).unwrap_or(false);
        if is_local {
            return Ok(());
        }

        // Non-loopback target from here on.
        let allow_remote = std::env::var_os("LEGION_ALLOW_REMOTE_LLM").is_some()
            || std::env::var_os("LEGION_ALLOW_REMOTE_OLLAMA").is_some();
        if !allow_remote {
            anyhow::bail!(
                "LLM host '{host}' is not a loopback address; set \
                 LEGION_ALLOW_REMOTE_LLM=1 to deliberately allow a remote model host"
            );
        }

        // Even with the opt-in, refuse SSRF-adjacent targets — cloud metadata
        // (169.254.169.254), link-local, unspecified, multicast — and, unless a
        // second explicit flag is set, RFC-1918 / unique-local private ranges.
        // Require TLS for any remote host so findings/telemetry are never sent in
        // cleartext (audit 2026-07 L1).
        if let Some(ip) = parsed_ip {
            let allow_private = std::env::var_os("LEGION_ALLOW_PRIVATE_LLM").is_some();
            let blocked = ip.is_unspecified()
                || ip.is_multicast()
                || match ip {
                    std::net::IpAddr::V4(v4) => {
                        v4.is_link_local()
                            || v4.is_broadcast()
                            || (v4.is_private() && !allow_private)
                    }
                    std::net::IpAddr::V6(v6) => {
                        let seg0 = v6.segments()[0];
                        let link_local = (seg0 & 0xffc0) == 0xfe80;
                        let unique_local = (seg0 & 0xfe00) == 0xfc00;
                        link_local || (unique_local && !allow_private)
                    }
                };
            if blocked {
                anyhow::bail!(
                    "remote LLM host '{host}' resolves to a blocked internal / link-local \
                     address; refusing (set LEGION_ALLOW_PRIVATE_LLM=1 only for a trusted \
                     private-range model server)"
                );
            }
        }
        if !is_https {
            anyhow::bail!(
                "remote LLM host '{host}' must use https:// — refusing to send findings \
                 to a non-loopback host over plaintext"
            );
        }
        Ok(())
    }

    pub fn runtime_is_ollama(&self) -> bool {
        self.llm_runtime.eq_ignore_ascii_case("ollama")
    }

    pub fn active_host(&self) -> &str {
        if self.runtime_is_ollama() {
            &self.ollama_host
        } else {
            &self.llm_host
        }
    }

    /// Validate that neither configured model is blocked by policy and that the
    /// selected runtime host is acceptable.
    pub fn validate(&self) -> Result<()> {
        let runtime = self.llm_runtime.to_ascii_lowercase();
        if runtime != "ollama" && runtime != "openai_compat" {
            anyhow::bail!(
                "unsupported llm_runtime '{}' (expected 'openai_compat' or 'ollama')",
                self.llm_runtime
            );
        }
        Self::validate_host(self.active_host())?;
        if crate::model_registry::ModelRegistry::is_blocked(&self.model) {
            anyhow::bail!(
                "configured model '{}' is blocked by Ares policy",
                self.model
            );
        }
        if crate::model_registry::ModelRegistry::is_blocked(&self.fallback_model) {
            anyhow::bail!(
                "configured fallback model '{}' is blocked by Ares policy",
                self.fallback_model
            );
        }
        Ok(())
    }
}

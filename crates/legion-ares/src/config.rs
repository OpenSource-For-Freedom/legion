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
const DEFAULT_OLLAMA_HOST: &str = "http://localhost:11434";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AresConfig {
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
        match std::fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
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

    /// Validate the Ollama base URL: it must be `http(s)://` and resolve to a
    /// loopback host, unless the operator has explicitly opted into a remote
    /// model host via `LEGION_ALLOW_REMOTE_OLLAMA`. This blocks the SSRF /
    /// system-prompt-exfiltration vector of pointing the agent at an arbitrary
    /// attacker host (audit PON-2).
    pub fn validate_host(host: &str) -> Result<()> {
        let rest = host
            .strip_prefix("http://")
            .or_else(|| host.strip_prefix("https://"))
            .ok_or_else(|| anyhow::anyhow!("ollama_host must start with http:// or https://"))?;
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
        let is_local = matches!(hostname, "localhost" | "127.0.0.1" | "::1")
            || hostname.starts_with("127.")
            || hostname
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        if !is_local && std::env::var_os("LEGION_ALLOW_REMOTE_OLLAMA").is_none() {
            anyhow::bail!(
                "ollama_host '{host}' is not a loopback address; set \
                 LEGION_ALLOW_REMOTE_OLLAMA=1 to deliberately allow a remote model host"
            );
        }
        Ok(())
    }

    /// Validate that neither configured model is blocked by policy and that the
    /// Ollama host is acceptable.
    pub fn validate(&self) -> Result<()> {
        Self::validate_host(&self.ollama_host)?;
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

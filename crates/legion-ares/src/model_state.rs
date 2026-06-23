//! Installed-model state for auto-update (see `docs/AUTO-UPDATE-PRD.md`).
//!
//! Records which trained model is currently provisioned for the Ares tier, so on
//! the next launch the app can tell whether the distribution manifest names a
//! newer one and a re-pull is needed. Without this, provisioning was
//! first-install-only: once a tag existed it was never refreshed.
//!
//! The trust anchor stays the manifest SHA-256 (verified at download). This file
//! only answers "is what I already have still the version the manifest names?".

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Identity of the model currently provisioned for an Ares tier.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelState {
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub model_version: String,
    #[serde(default)]
    pub sha256: String,
}

impl ModelState {
    /// Location of the state file inside the data directory.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("ares-model-state.json")
    }

    /// Load state, or `None` if absent or corrupt (treated as "nothing recorded",
    /// which forces a refresh against the current manifest).
    pub fn load(data_dir: &Path) -> Option<Self> {
        let s = std::fs::read_to_string(Self::path(data_dir)).ok()?;
        serde_json::from_str(&s).ok()
    }

    /// Persist state with owner-only permissions.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        legion_core::harden_file(&path);
        Ok(())
    }

    /// True when the recorded state already satisfies `tier` + `sha256` — i.e. the
    /// installed model is the one the manifest currently names, so no re-pull.
    /// An empty `sha256` (unpublished tier) is never "current".
    pub fn is_current(&self, tier: &str, sha256: &str) -> bool {
        !sha256.is_empty() && self.tier == tier && self.sha256 == sha256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ModelState::load(dir.path()).is_none());
    }

    #[test]
    fn roundtrip_and_is_current() {
        let dir = tempfile::tempdir().unwrap();
        let st = ModelState {
            tier: "legion-ares:qwen3-4b".into(),
            model_version: "2026.06.20-v4-sft".into(),
            sha256: "0f7e323".into(),
        };
        st.save(dir.path()).unwrap();
        let loaded = ModelState::load(dir.path()).unwrap();
        assert_eq!(loaded, st);

        // Same tier + sha -> current.
        assert!(loaded.is_current("legion-ares:qwen3-4b", "0f7e323"));
        // Bumped sha (new model published) -> stale.
        assert!(!loaded.is_current("legion-ares:qwen3-4b", "deadbeef"));
        // Different tier -> stale.
        assert!(!loaded.is_current("legion-ares:qwen3-8b", "0f7e323"));
        // Empty sha (unpublished) is never current.
        assert!(!loaded.is_current("legion-ares:qwen3-4b", ""));
    }

    #[test]
    fn base_build_marker_is_never_current() {
        // A local base build records an empty sha, so any published model
        // (non-empty sha) is detected as an update.
        let st = ModelState {
            tier: "legion-ares:qwen3-4b".into(),
            model_version: "base:qwen3:4b".into(),
            sha256: String::new(),
        };
        assert!(!st.is_current("legion-ares:qwen3-4b", "abc123"));
    }
}

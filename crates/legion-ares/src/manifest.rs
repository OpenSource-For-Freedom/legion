//! Ares model distribution manifest — see `docs/MODEL-DISTRIBUTION.md`.
//!
//! The manifest is the source of truth for which trained model the app pulls,
//! keyed by hardware tier tag (`legion-ares:qwen3-4b`, …). Each tier pins an
//! immutable HuggingFace file URL and its SHA-256; the SHA-256 is the trust
//! anchor — the download is rejected unless it matches. The manifest is embedded
//! in the binary as the offline default; a tier is only *pullable* once it has
//! both a URL and a SHA-256, so before a model is published the app falls back to
//! building Ares from a stock base.

use serde::Deserialize;
use std::collections::BTreeMap;

/// Manifest compiled into the binary (the offline default).
pub const EMBEDDED_MANIFEST: &str = include_str!("../../../agents/ares/models/manifest.json");

#[derive(Debug, Clone, Deserialize)]
pub struct ModelManifest {
    #[serde(default)]
    pub model_version: String,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub tiers: BTreeMap<String, TierSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TierSpec {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size_bytes: u64,
}

impl TierSpec {
    /// A tier can be pulled only once it carries both a URL and a pinned
    /// SHA-256. An empty SHA-256 marks an as-yet-unpublished tier.
    pub fn is_pullable(&self) -> bool {
        !self.url.trim().is_empty() && !self.sha256.trim().is_empty()
    }
}

impl ModelManifest {
    /// Parse the embedded manifest. Panics only if the bundled JSON is invalid,
    /// which a unit test guards against.
    pub fn embedded() -> Self {
        serde_json::from_str(EMBEDDED_MANIFEST).expect("embedded ares manifest is valid JSON")
    }

    pub fn tier(&self, tag: &str) -> Option<&TierSpec> {
        self.tiers.get(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_manifest_parses_and_lists_tiers() {
        let m = ModelManifest::embedded();
        assert!(!m.repo.is_empty(), "manifest must name an HF repo");
        // The three hardware tiers must all be present.
        for tag in [
            "legion-ares:qwen3-1.7b",
            "legion-ares:qwen3-4b",
            "legion-ares:qwen3-8b",
        ] {
            assert!(m.tier(tag).is_some(), "missing tier {tag}");
        }
    }

    #[test]
    fn pullable_requires_url_and_sha256() {
        let ready = TierSpec {
            url: "https://example/model.gguf".into(),
            sha256: "abc".into(),
            size_bytes: 10,
        };
        assert!(ready.is_pullable());
        let no_sha = TierSpec {
            url: "https://example/model.gguf".into(),
            sha256: "".into(),
            size_bytes: 0,
        };
        assert!(!no_sha.is_pullable());
    }
}

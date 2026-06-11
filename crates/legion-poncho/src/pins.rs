//! Model digest pinning (audit PON-1).
//!
//! Name-based blocking (`ModelRegistry::is_blocked`) stops an operator from
//! *naming* a disallowed model, but it cannot detect a model whose **content**
//! was swapped underneath an approved tag (a re-pulled or `ollama cp`-renamed
//! model with a different manifest). Digest pinning closes that gap.
//!
//! Strategy: **trust-on-first-use.** The first time an approved model is
//! installed or verified, its Ollama manifest digest (sha256) is recorded to an
//! owner-only `model_pins.json`. On later use, a digest that changed *without*
//! an explicit update is treated as a possible swap/tamper and rejected. An
//! explicit `update` re-pins, because a digest change is then expected.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Persisted `tag -> digest` pins.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DigestPins {
    #[serde(default)]
    pins: BTreeMap<String, String>,
}

/// Outcome of checking a live digest against the pinned one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// No prior pin exists; the caller should pin this digest now (TOFU).
    FirstUse,
    /// Live digest matches the pinned digest.
    Match,
    /// Live digest differs from the pin — possible swap/tamper; reject.
    Mismatch { pinned: String, got: String },
}

impl DigestPins {
    /// Location of the pin store inside the data directory.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("model_pins.json")
    }

    /// Load pins, falling back to empty if absent or corrupt.
    pub fn load(data_dir: &Path) -> Self {
        match std::fs::read_to_string(Self::path(data_dir)) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist pins with owner-only permissions.
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        let path = Self::path(data_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        legion_core::harden_file(&path);
        Ok(())
    }

    /// The pinned digest for `tag`, if any.
    pub fn get(&self, tag: &str) -> Option<&str> {
        self.pins.get(tag).map(String::as_str)
    }

    /// Compare a freshly-observed digest against the stored pin.
    pub fn check(&self, tag: &str, live_digest: &str) -> PinCheck {
        match self.pins.get(tag) {
            None => PinCheck::FirstUse,
            Some(pinned) if pinned == live_digest => PinCheck::Match,
            Some(pinned) => PinCheck::Mismatch {
                pinned: pinned.clone(),
                got: live_digest.to_string(),
            },
        }
    }

    /// Record or replace the pin for `tag` (install TOFU, or explicit update).
    pub fn pin(&mut self, tag: &str, digest: &str) {
        self.pins.insert(tag.to_string(), digest.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_then_match_then_mismatch() {
        let mut p = DigestPins::default();
        assert_eq!(p.check("qwen3:8b", "sha256:aaa"), PinCheck::FirstUse);

        p.pin("qwen3:8b", "sha256:aaa");
        assert_eq!(p.check("qwen3:8b", "sha256:aaa"), PinCheck::Match);

        match p.check("qwen3:8b", "sha256:bbb") {
            PinCheck::Mismatch { pinned, got } => {
                assert_eq!(pinned, "sha256:aaa");
                assert_eq!(got, "sha256:bbb");
            }
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn explicit_repin_overwrites() {
        let mut p = DigestPins::default();
        p.pin("m", "sha256:1");
        p.pin("m", "sha256:2"); // explicit update re-pins
        assert_eq!(p.check("m", "sha256:2"), PinCheck::Match);
    }

    #[test]
    fn load_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut p = DigestPins::default();
        p.pin("legion-mythos:qwen3-8b", "sha256:deadbeef");
        p.save(dir.path()).unwrap();

        let loaded = DigestPins::load(dir.path());
        assert_eq!(
            loaded.get("legion-mythos:qwen3-8b"),
            Some("sha256:deadbeef")
        );
        assert_eq!(
            loaded.check("legion-mythos:qwen3-8b", "sha256:deadbeef"),
            PinCheck::Match
        );
    }

    #[test]
    fn missing_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = DigestPins::load(dir.path());
        assert_eq!(p.check("anything", "x"), PinCheck::FirstUse);
    }
}

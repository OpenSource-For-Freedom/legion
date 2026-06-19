//! Host hardware detection and hardware-aware model selection.
//!
//! At setup (and on every boot in automatic mode) Legion probes the local
//! accelerator and memory, then picks the largest Mythos model that stays
//! *fully resident on the GPU*. A model that spills to CPU is the root cause of
//! multi-minute chat latency (and, on this class of laptop, sustained all-core
//! thermal load), so the default policy is "fit in VRAM" rather than "biggest
//! model that technically runs".
//!
//! Detection is best-effort and never fails: if no GPU can be identified the
//! host is treated as CPU-only and a small, capped model is selected.

use serde::{Deserialize, Serialize};
use std::process::Command;

/// Which compute path inference will actually use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Accel {
    /// A usable GPU was detected with enough VRAM to hold a model.
    Gpu,
    /// No usable GPU — inference runs on the CPU.
    Cpu,
}

/// A best-effort snapshot of the host's inference-relevant hardware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    /// Detected GPU name, if any (e.g. "Quadro T2000 with Max-Q Design").
    pub gpu_name: Option<String>,
    /// Total GPU VRAM in GiB (0.0 when no GPU is detected).
    pub vram_gb: f32,
    /// Total system RAM in GiB.
    pub ram_gb: f32,
    /// Logical CPU threads.
    pub cpu_threads: usize,
    /// The compute path inference will use.
    pub accel: Accel,
}

impl HardwareProfile {
    /// Probe the host. Synchronous and cheap — call once at startup.
    pub fn detect() -> Self {
        let (gpu_name, vram_gb) = detect_gpu().unwrap_or((None, 0.0));
        let ram_gb = detect_ram_gb();
        let cpu_threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        // A GPU is only "usable" for our purposes if it can hold the smallest
        // viable model with some headroom; below ~1 GiB we treat it as CPU-only.
        let accel = if vram_gb >= 1.0 {
            Accel::Gpu
        } else {
            Accel::Cpu
        };
        Self {
            gpu_name,
            vram_gb,
            ram_gb,
            cpu_threads,
            accel,
        }
    }

    /// Compact one-line summary for logs and the dashboard.
    pub fn summary(&self) -> String {
        match self.accel {
            Accel::Gpu => format!(
                "{} · {:.0} GB VRAM · {:.0} GB RAM · {} threads",
                self.gpu_name.as_deref().unwrap_or("GPU"),
                self.vram_gb,
                self.ram_gb,
                self.cpu_threads
            ),
            Accel::Cpu => format!(
                "CPU-only · {:.0} GB RAM · {} threads",
                self.ram_gb, self.cpu_threads
            ),
        }
    }
}

/// The model chosen for a given hardware profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSelection {
    /// Primary model tag to run (e.g. `legion-mythos:qwen3-4b`).
    pub primary: String,
    /// Ollama base the Mythos profile is built from (e.g. `qwen3:4b`).
    pub base: String,
    /// Fallback used if the primary is unavailable or fails.
    pub fallback: String,
    /// Short tier label for the UI (e.g. `Mythos 4B`).
    pub tier: String,
    /// Context window appropriate for the tier and accelerator.
    pub num_ctx: u32,
    /// Operator-facing explanation of *why* this model was chosen.
    pub reason: String,
}

/// Pick the largest Mythos model that stays fully GPU-resident on this host
/// (GPU-resident priority policy). Below the smallest GPU tier we fall back to
/// capped CPU base models so the agent still works on constrained hardware.
pub fn select_model(hw: &HardwareProfile) -> ModelSelection {
    // GPU tiers. The thresholds are sized for the model's *loaded* footprint
    // (weights + KV cache + compute buffers), not its on-disk size, and they
    // leave ~1 GB of headroom for the desktop/display that the OS holds on a
    // laptop GPU. Observed loaded sizes: 8B@8192 ≈ 6.6 GB, 4B@4096 ≈ 5.3 GB,
    // 1.7B@2048 ≈ 2 GB. A model that does not fully fit gets split to CPU by
    // Ollama and becomes minutes-slow — the whole problem we are avoiding — so
    // the cutoffs are deliberately conservative: only pick a tier that stays
    // fully resident.
    if hw.accel == Accel::Gpu {
        if hw.vram_gb >= 8.0 {
            return ModelSelection {
                primary: "legion-mythos:qwen3-8b".into(),
                base: "qwen3:8b".into(),
                fallback: "qwen3:8b".into(),
                tier: "Mythos 8B".into(),
                num_ctx: 8192,
                reason: format!(
                    "{}: {:.0} GB VRAM fits the 8B model (~6.6 GB loaded) fully on GPU.",
                    hw.gpu_name.as_deref().unwrap_or("GPU"),
                    hw.vram_gb
                ),
            };
        }
        if hw.vram_gb >= 6.0 {
            return ModelSelection {
                primary: "legion-mythos:qwen3-4b".into(),
                base: "qwen3:4b".into(),
                fallback: "qwen3:4b".into(),
                tier: "Mythos 4B".into(),
                num_ctx: 4096,
                reason: format!(
                    "{}: {:.0} GB VRAM runs the 4B model (~5.3 GB loaded) fully on GPU. \
                     The 8B needs ~8 GB and would spill to CPU here.",
                    hw.gpu_name.as_deref().unwrap_or("GPU"),
                    hw.vram_gb
                ),
            };
        }
        // ≤6 GB (incl. the common 4 GB laptop GPU): only the 1.7B stays fully on
        // the GPU once the desktop's ~1 GB and the KV cache are accounted for.
        // The 4B wants ~5.3 GB loaded and would run ~half on CPU here (minutes
        // per reply), so we do NOT pick it just because the weights are small.
        return ModelSelection {
            primary: "legion-mythos:qwen3-1.7b".into(),
            base: "qwen3:1.7b".into(),
            fallback: "qwen3:1.7b".into(),
            tier: "Mythos 1.7B".into(),
            num_ctx: 2048,
            reason: format!(
                "{}: {:.0} GB VRAM (~3 GB usable after the desktop) only holds the 1.7B \
                 fully on GPU — picked for real-time replies. The 4B needs ~6 GB or it \
                 splits to CPU and takes minutes. Pin the 4B in config if you prefer depth over speed.",
                hw.gpu_name.as_deref().unwrap_or("GPU"),
                hw.vram_gb
            ),
        };
    }

    // CPU-only: use capped base models (no Mythos build needed — the Mythos
    // posture is injected via the system prompt at runtime). Pick by RAM.
    if hw.ram_gb >= 16.0 {
        ModelSelection {
            primary: "qwen3:4b".into(),
            base: "qwen3:4b".into(),
            fallback: "qwen3:4b".into(),
            tier: "Qwen3 4B (CPU)".into(),
            num_ctx: 2048,
            reason: format!(
                "No GPU detected; {:.0} GB RAM runs the 4B on CPU with a capped context.",
                hw.ram_gb
            ),
        }
    } else {
        ModelSelection {
            primary: "qwen3:1.7b".into(),
            base: "qwen3:1.7b".into(),
            fallback: "qwen3:1.7b".into(),
            tier: "Qwen3 1.7B (CPU)".into(),
            num_ctx: 2048,
            reason: format!(
                "No GPU detected and {:.0} GB RAM — the 1.7B is the safe CPU choice.",
                hw.ram_gb
            ),
        }
    }
}

/// Total system RAM in GiB via sysinfo (`total_memory` is bytes in 0.30+).
fn detect_ram_gb() -> f32 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.total_memory() as f32 / 1_073_741_824.0
}

/// Best-effort GPU probe. Returns `(name, vram_gb)`.
///
/// Strategy: query NVIDIA's `nvidia-smi` (covers the common laptop/workstation
/// case). Other vendors fall through to CPU-only selection today; the policy
/// degrades safely rather than guessing.
fn detect_gpu() -> Option<(Option<String>, f32)> {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Take the first GPU line: "Quadro T2000 with Max-Q Design, 4096"
    let line = text.lines().next()?.trim();
    let mut parts = line.rsplitn(2, ',');
    let mib: f32 = parts.next()?.trim().parse().ok()?;
    let name = parts.next().map(|s| s.trim().to_string());
    Some((name, mib / 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hw(vram: f32, ram: f32, accel: Accel) -> HardwareProfile {
        HardwareProfile {
            gpu_name: Some("Test GPU".into()),
            vram_gb: vram,
            ram_gb: ram,
            cpu_threads: 16,
            accel,
        }
    }

    #[test]
    fn high_vram_gets_8b() {
        let s = select_model(&hw(8.0, 32.0, Accel::Gpu));
        assert_eq!(s.primary, "legion-mythos:qwen3-8b");
        assert_eq!(s.num_ctx, 8192);
    }

    #[test]
    fn six_gb_gpu_gets_4b() {
        let s = select_model(&hw(6.0, 32.0, Accel::Gpu));
        assert_eq!(s.primary, "legion-mythos:qwen3-4b");
        assert_eq!(s.base, "qwen3:4b");
        assert_eq!(s.num_ctx, 4096);
    }

    #[test]
    fn four_gb_gpu_gets_1_7b() {
        // The Quadro T2000 / 4 GB case that motivated this work: a 4B wants
        // ~5.3 GB loaded and would split to CPU, so the 1.7B is the fast choice.
        let s = select_model(&hw(4.0, 32.0, Accel::Gpu));
        assert_eq!(s.primary, "legion-mythos:qwen3-1.7b");
        assert_eq!(s.base, "qwen3:1.7b");
        assert_eq!(s.num_ctx, 2048);
    }

    #[test]
    fn small_gpu_gets_1_7b() {
        let s = select_model(&hw(2.0, 16.0, Accel::Gpu));
        assert_eq!(s.primary, "legion-mythos:qwen3-1.7b");
    }

    #[test]
    fn cpu_only_uses_capped_base() {
        let big = select_model(&hw(0.0, 32.0, Accel::Cpu));
        assert_eq!(big.primary, "qwen3:4b");
        assert_eq!(big.num_ctx, 2048);

        let small = select_model(&hw(0.0, 8.0, Accel::Cpu));
        assert_eq!(small.primary, "qwen3:1.7b");
    }
}

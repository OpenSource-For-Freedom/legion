# Ares Model Distribution

How the **trained** Ares model reaches users who download Legion.

Status: **design / planning.** This describes the target pipeline; the client
side (manifest-driven, verified pull-on-install) is not implemented yet — today
`auto_provision_ares()` builds Ares from a stock `qwen3` base. See
[Implementation checklist](#implementation-checklist).

---

## 1. The problem

"Ares" today is **stock `qwen3` + an embedded system prompt**. On first launch
`legion_ares::model_registry::ModelRegistry::auto_provision_ares()` runs the
equivalent of `ollama create legion-ares:qwen3-4b FROM qwen3:4b` using the
`Modelfile` baked into the binary (`agents/ares/models/Modelfile.ares`). The
**only** thing distributed is that ~4 KB Modelfile.

If we LoRA-train Ares, the output is **weights** — a merged/quantized model of
~1.5–5 GB per tier. Those are far too big for the binary or the git repo, and
there is currently **no path to deliver them to users**. Training would produce
an artifact that never ships. This document closes that gap.

Goal: a user downloads the Legion app → on first launch the app pulls the
*trained* Ares model for their hardware tier, verifies it, builds it locally in
Ollama, and pins it — no manual steps, fully offline thereafter.

---

## 2. Architecture

Three stages: **build → host → pull-on-install.**

```
 train (LoRA)        publish (CI)                 host (HuggingFace)        pull-on-install (app)
 ┌──────────┐   ┌────────────────────┐   ┌──────────────────────────┐   ┌───────────────────────┐
 │ adapter  │──▶│ merge → quantize   │──▶│ legion-ares-qwen3-4b.gguf │──▶│ read_capped_verified  │
 │ weights  │   │ → GGUF (per tier)  │   │ + sha256, versioned repo  │   │ → ollama create FROM  │
 └──────────┘   │ → bump manifest.json│  └──────────────────────────┘   │ → pin digest          │
                └────────────────────┘            ▲                       └───────────────────────┘
                         │ manifest.json (URL + sha256 + version)         lives in GitHub ───────────┘
                         └──────────────── source of truth in GitHub ─────────────────────────────────┘
```

**Source of truth stays in GitHub.** HuggingFace only *hosts the bytes*; what the
app trusts is the `manifest.json` committed to this repo (URL + SHA-256 +
version). Changing the trusted model is a reviewed git commit, not an opaque push.

### 2.1 Build

The `agents/ares/training/` LoRA pipeline produces an adapter. The release job:

1. Merges the adapter into the base (`qwen3:Nb`).
2. Quantizes to **GGUF** (`Q4_K_M` default — the format Ollama consumes via
   `FROM ./file.gguf`), one file per hardware tier (1.7b / 4b / 8b).
3. Emits each file's **SHA-256**.

Artifacts: `legion-ares-qwen3-{1.7b,4b,8b}.Q4_K_M.gguf` (+ `.sha256`).

### 2.2 Host — HuggingFace

A single HF model repo, e.g. `OpenSource-For-Freedom/legion-ares`, holds the GGUF
files (HF Git LFS — free, uncapped, CDN-backed). Tiers are either separate files
or HF "quant tags." HF is purpose-built for this and Ollama supports it natively,
so it is the lowest-friction host; GitHub Releases are avoided because of the
2 GB-per-asset cap (every 4B/8B tier would need split-and-reassemble).

> The app does **not** trust HF blindly — it downloads the exact file URL pinned
> in `manifest.json` and verifies the committed SHA-256 (§4). HF is a dumb CDN.

### 2.3 Pull-on-install

`auto_provision_ares()` becomes manifest-driven (see §3, §5). It reuses the
security primitives already in the tree:

- `legion_core::http::read_capped_verified` — size-capped, SHA-256-verified fetch
  (CORE-1 / CORE-3).
- `legion_core::integrity` — SHA-256 / Ed25519 verification.
- `legion_ares::pins::DigestPins` — trust-on-first-use Ollama digest pin (PON-1).

---

## 3. The model manifest

Committed at `agents/ares/models/manifest.json`, embedded in the binary
(`include_str!`) so a fresh install has a trusted default, and optionally
refreshed from `main` like the YARA rules feed.

```json
{
  "schema": 1,
  "model_version": "2026.06.1",
  "base_family": "qwen3",
  "quant": "Q4_K_M",
  "tiers": {
    "legion-ares:qwen3-1.7b": {
      "url": "https://huggingface.co/OpenSource-For-Freedom/legion-ares/resolve/v2026.06.1/legion-ares-qwen3-1.7b.Q4_K_M.gguf",
      "sha256": "…",
      "size_bytes": 1503238553
    },
    "legion-ares:qwen3-4b": {
      "url": "https://huggingface.co/OpenSource-For-Freedom/legion-ares/resolve/v2026.06.1/legion-ares-qwen3-4b.Q4_K_M.gguf",
      "sha256": "…",
      "size_bytes": 2684354560
    },
    "legion-ares:qwen3-8b": {
      "url": "https://huggingface.co/OpenSource-For-Freedom/legion-ares/resolve/v2026.06.1/legion-ares-qwen3-8b.Q4_K_M.gguf",
      "sha256": "…",
      "size_bytes": 4831838208
    }
  }
}
```

- **`url`** pins an immutable HF revision (`/resolve/<tag>/…`), never a moving
  branch, so the bytes can't change under a version.
- **`sha256`** is the trust anchor — verified after download (§4).
- **`model_version`** advances each release; the app re-provisions when it changes.

---

## 4. Security model

Every model byte that reaches a user is gated by controls already implemented:

1. **Pinned source.** App downloads only the exact `url` from the in-repo
   manifest — an immutable HF revision. The manifest changes via reviewed commit.
2. **Size cap.** Download streams through `read_capped_verified` with a per-tier
   cap (`size_bytes` + slack), so a swapped/oversized file can't exhaust disk/RAM.
3. **SHA-256 verify.** The download must match the manifest `sha256` or it is
   rejected and discarded — a tampered or wrong file never reaches Ollama.
4. **Digest pin (TOFU).** After `ollama create`, the model's Ollama manifest
   digest is pinned (`DigestPins`); a later silent content swap under the same tag
   is flagged (PON-1).
5. **No execution.** The artifact is GGUF *data* fed to `ollama create`; nothing
   is executed during provisioning. The existing `scan_model`-style Modelfile
   checks remain available for the embedded Modelfile.
6. **DeepSeek/policy block** (`is_blocked`) still applies to any tag.

Optional hardening: sign the manifest (or a per-tier sha256 list) with Ed25519
using `legion_core::integrity` and ship the public key in the binary — then even
a compromised GitHub repo can't point users at a malicious model.

---

## 5. Client flow (target `auto_provision_ares`)

```
1. selection = hardware::select_model()          // existing: tier → primary tag
2. if ollama has `selection.primary` AND its pinned digest still matches → done
3. entry = manifest.tiers[selection.primary]
4. gguf  = http::read_capped_verified(entry.url, cap=entry.size_bytes+slack,
                                      FeedIntegrity::Sha256(entry.sha256))   // §4.2–4.3
5. write gguf to <data_dir>/models/<primary>.gguf  (owner-only)
6. modelfile = substitute_from(ARES_MODELFILE, "<that gguf path>")          // existing helper
7. ollama create `selection.primary` -f modelfile                          // existing path
8. pin_current(<data_dir>, selection.primary)                              // existing PON-1
9. delete the temp gguf (Ollama has imported it into its store)
```

Failure / offline behavior (explicit, not silent):

- **No network / download fails** → log it and surface a clear dashboard state
  ("Ares model download unavailable — retry"). Optionally a config flag
  `allow_stock_fallback` lets it fall back to building from stock `qwen3` (the
  current behavior) so chat still works at reduced quality. Default: do **not**
  silently serve stock; tell the operator.
- **SHA-256 mismatch** → reject, never build, raise a tamper alert.

This is a change to **one function** plus a manifest reader; the download,
verification, pinning, tier selection, and `ollama create` plumbing all exist.

---

## 6. HuggingFace repo layout

```
OpenSource-For-Freedom/legion-ares          (HF model repo, Git LFS)
├── README.md                               model card: base, training data, license, quant
├── legion-ares-qwen3-1.7b.Q4_K_M.gguf
├── legion-ares-qwen3-4b.Q4_K_M.gguf
├── legion-ares-qwen3-8b.Q4_K_M.gguf
└── (tagged releases: v2026.06.1, …)        immutable revisions referenced by manifest URLs
```

License/attribution: the model card must carry the **Qwen3 base license**
(Apache-2.0) and state the Ares fine-tune + system persona; mirror this in
`NOTICE`. Base weights are not redistributed beyond the quantized fine-tune.

---

## 7. CI: train → publish (one tag)

A `release-model` GitHub Actions workflow (separate from app CI — model builds are
heavy and infrequent), triggered on a `model-vX.Y.Z` tag:

1. Run the LoRA pipeline (or download the trained adapter artifact).
2. Merge + quantize to GGUF per tier; compute SHA-256.
3. `huggingface-cli upload` each GGUF to the HF repo at an immutable tag.
4. Open a PR bumping `agents/ares/models/manifest.json` (URLs + sha256 +
   `model_version`). Merging that PR is what actually ships the new model to users.

Secrets: `HF_TOKEN` (write to the HF repo) in GitHub Actions secrets only.

---

## 8. Versioning & updates

- The model version (`manifest.json`) is **decoupled** from the app version — you
  can ship a better Ares without an app release, or vice-versa.
- On launch, if `manifest.model_version` differs from the pinned/installed model,
  the app re-provisions (download → verify → create → re-pin).
- App releases embed the manifest current at build time as the offline default.

---

## Implementation checklist

- [ ] `agents/ares/models/manifest.json` + `include_str!` embed + a typed reader
      in `legion-ares` (with `model_version`, per-tier url/sha256/size).
- [ ] Rework `auto_provision_ares()` to the §5 flow (verified download →
      `create FROM gguf` → pin), reusing `http::read_capped_verified` + `pins`.
- [ ] `<data_dir>/models/` staging dir (owner-only), cleaned after import.
- [ ] Dashboard state for download/verify/build progress + failure surface.
- [ ] `manifest.model_version` change detection → re-provision.
- [ ] (optional) Ed25519-sign the manifest; ship the public key in-binary.
- [ ] `release-model` workflow (merge → quantize → HF upload → manifest PR).
- [ ] HF repo `OpenSource-For-Freedom/legion-ares` + model card + license.
- [ ] Update `README.md` / `NOTICE` to describe the pulled, trained Ares model.
```

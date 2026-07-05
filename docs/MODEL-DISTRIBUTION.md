# Ares Model Distribution

How the **trained** Ares model reaches users who download Legion.

Status: **live.** The manifest-driven, SHA-256-verified pull-on-install path is
built and wired in, and the manifest (`agents/ares/models/manifest.json`) now
carries real published tiers (`legion-ares:qwen3-1.7b` and `-4b`; the `-8b` tier
is not published yet and falls back to a stock `qwen3` base build). Any tier whose
`url`/`sha256` is empty is "not pullable" and falls back to the stock base.

**Runtime.** The default LLM runtime is `openai_compat`: Legion talks to a local
**OpenAI-compatible model server** (e.g. `llama.cpp`'s `llama-server`) at
`http://127.0.0.1:8080/v1`, which loads and serves the staged GGUF directly — no
`ollama create` import step. **Ollama is a supported legacy backend**
(`llm_runtime = "ollama"` in `ares.json`), on the `/api/*` path at
`http://localhost:11434`; that path still imports the GGUF via `ollama create`
and pins the resulting digest. Both runtimes consume the same verified GGUF from
the same manifest — only the destination differs (a staged file the server loads
vs. an `ollama create` import). See the
[Implementation checklist](#implementation-checklist).

---

## 1. The problem

Before this system, "Ares" was **stock `qwen3` + an embedded system prompt**: on
first launch the app built the model locally from the `Modelfile` baked into the
binary (`agents/ares/models/Modelfile.ares`), and the **only** thing distributed
was that ~4 KB Modelfile. That stock-base build is now the offline *fallback*
(§5) when no trained tier is published or reachable.

If we LoRA-train Ares, the output is **weights** — a merged/quantized model of
~1.5–5 GB per tier. Those are far too big for the binary or the git repo, and
there is currently **no path to deliver them to users**. Training would produce
an artifact that never ships. This document closes that gap.

Goal: a user downloads the Legion app → on first launch the app pulls the
*trained* Ares model for their hardware tier, verifies it, and stages it for the
local model server to serve (or, on the legacy Ollama backend, imports and pins
it) — no manual steps, fully offline thereafter.

---

## 2. Architecture

Three stages: **build → host → pull-on-install.**

```
 train (LoRA)        publish (CI)                 host (HuggingFace)        pull-on-install (app)
 ┌──────────┐   ┌────────────────────┐   ┌──────────────────────────┐   ┌───────────────────────┐
 │ adapter  │──▶│ merge → quantize   │──▶│ legion-ares-qwen3-4b.gguf │──▶│ read_capped_verified  │
 │ weights  │   │ → GGUF (per tier)  │   │ + sha256, versioned repo  │   │ → stage GGUF for the  │
 └──────────┘   │ → bump manifest.json│  └──────────────────────────┘   │   local model server  │
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
2. Quantizes to **GGUF** (`Q4_K_M` default — the format `llama.cpp` loads directly
   and Ollama consumes via `FROM ./file.gguf`), one file per hardware tier
   (1.7b / 4b / 8b).
3. Emits each file's **SHA-256**.

Artifacts: `legion-ares-qwen3-{1.7b,4b,8b}.Q4_K_M.gguf` (+ `.sha256`).

### 2.2 Host — HuggingFace

A single HF model repo, e.g. `tburns-actual/legion-ares`, holds the GGUF
files (HF Git LFS — free, uncapped, CDN-backed). Tiers are either separate files
or HF "quant tags." HF is purpose-built for this and Ollama supports it natively,
so it is the lowest-friction host; GitHub Releases are avoided because of the
2 GB-per-asset cap (every 4B/8B tier would need split-and-reassemble).

> The app does **not** trust HF blindly — it downloads the exact file URL pinned
> in `manifest.json` and verifies the committed SHA-256 (§4). HF is a dumb CDN.

### 2.3 Pull-on-install

Provisioning is manifest-driven (see §3, §5) and reuses the security primitives
already in the tree:

- `legion_core::http::download_verified_to_file` — **streaming** size-capped,
  SHA-256-verified download to disk (does not buffer multi-GB weights in RAM).
- `legion_core::integrity` — SHA-256 / Ed25519 verification.

On the default `openai_compat` path (`stage_model_from_manifest`) the verified
GGUF is written to `<data_dir>/models/<tier>.gguf` and the local model server
loads it from there — nothing is imported into a separate runtime store. On the
legacy Ollama path (`auto_provision_ares`) the same verified GGUF is imported via
`ollama create` and the resulting Ollama manifest digest is pinned trust-on-
first-use (`legion_ares::pins::DigestPins`, PON-1).

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
      "url": "https://huggingface.co/tburns-actual/legion-ares/resolve/v2026.06.1/legion-ares-qwen3-1.7b.Q4_K_M.gguf",
      "sha256": "…",
      "size_bytes": 1503238553
    },
    "legion-ares:qwen3-4b": {
      "url": "https://huggingface.co/tburns-actual/legion-ares/resolve/v2026.06.1/legion-ares-qwen3-4b.Q4_K_M.gguf",
      "sha256": "…",
      "size_bytes": 2684354560
    },
    "legion-ares:qwen3-8b": {
      "url": "https://huggingface.co/tburns-actual/legion-ares/resolve/v2026.06.1/legion-ares-qwen3-8b.Q4_K_M.gguf",
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
   rejected and discarded — a tampered or wrong file never reaches the model
   server (or `ollama create`).
4. **Digest pin (TOFU).** On the legacy Ollama backend, after `ollama create` the
   model's Ollama manifest digest is pinned (`DigestPins`); a later silent content
   swap under the same tag is flagged (PON-1). On the default path the staged GGUF
   is itself the SHA-256-verified trust anchor.
5. **No execution.** The artifact is GGUF *data* — loaded by the local model
   server, or fed to `ollama create` on the legacy path; nothing is executed
   during provisioning. The existing `scan_model`-style Modelfile
   checks remain available for the embedded Modelfile.
6. **DeepSeek/policy block** (`is_blocked`) still applies to any tag.

Optional hardening: sign the manifest (or a per-tier sha256 list) with Ed25519
using `legion_core::integrity` and ship the public key in the binary — then even
a compromised GitHub repo can't point users at a malicious model.

---

## 5. Client flow

**Default `openai_compat` path** (`stage_model_from_manifest`), the local model
server loads the staged GGUF:

```
1. selection = hardware::select_model()          // tier → primary tag
2. if <data_dir>/models/<primary>.gguf is present AND its ModelState is current → done
3. entry = manifest.tiers[selection.primary]
4. gguf  = http::download_verified_to_file(entry.url, cap=entry.size_bytes+slack,
                                           FeedIntegrity::Sha256(entry.sha256))   // §4.2–4.3
5. write gguf to <data_dir>/models/<primary>.gguf  (owner-only) + record ModelState
6. the local model server (llama.cpp on 127.0.0.1:8080) loads that GGUF and serves /v1
```

**Legacy Ollama path** (`auto_provision_ares`, when `llm_runtime = "ollama"`):

```
6'. modelfile = substitute_from(ARES_MODELFILE, "<that gguf path>")
7'. ollama create `selection.primary` -f modelfile
8'. pin_current(<data_dir>, selection.primary)                              // PON-1
9'. delete the temp gguf (Ollama has imported it into its store)
```

Failure / offline behavior (explicit, not silent):

- **No network / download fails** → log it and surface a clear dashboard state
  ("Ares model download unavailable — retry"). Optionally a config flag
  `allow_stock_fallback` lets it fall back to building from stock `qwen3` (the
  prior behavior) so chat still works at reduced quality. Default: do **not**
  silently serve stock; tell the operator.
- **SHA-256 mismatch** → reject, never build, raise a tamper alert.
- **Default path, server not reachable** → the app logs a warning
  ("OpenAI-compatible runtime not reachable — start your local model server");
  it stages the weights but does not itself launch the server.

The download, verification, pinning, tier selection, staging, and `ollama create`
plumbing all exist in the tree.

---

## 6. HuggingFace repo layout

```
tburns-actual/legion-ares          (HF model repo, Git LFS)
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
3. `hf upload` each GGUF to the HF repo at an immutable tag.
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

- [x] `agents/ares/models/manifest.json` + `include_str!` embed + typed reader
      `legion_ares::manifest` (`model_version`, per-tier url/sha256/size,
      `is_pullable()`), with unit tests.
- [x] Rework `auto_provision_ares()` to the §5 flow (verified download →
      `create FROM gguf` → pin), via `http::download_verified_to_file` + `pins`;
      falls back to a stock-base build when no model is published.
- [x] `<data_dir>/models/` staging dir (owner-only), cleaned after import.
- [ ] Dashboard state for download/verify/build progress + failure surface.
- [ ] `manifest.model_version` change detection → re-provision on upgrade.
- [ ] (optional) Ed25519-sign the manifest; ship the public key in-binary.
- [ ] **Publish side:** train → merge → quantize → `hf upload tburns-actual/legion-ares`.
- [ ] `release-model` GitHub Actions workflow (uses `HF_TOKEN` secret) → manifest PR.
- [ ] HF repo `tburns-actual/legion-ares` + model card + license, then fill the
      manifest URLs/SHA-256 and bump `model_version` to activate the pull.
- [ ] Update `README.md` / `NOTICE` to describe the pulled, trained Ares model.
```

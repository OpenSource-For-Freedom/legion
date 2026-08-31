# Model lifecycle

**Status: Real.** `legion-web/src/main.rs`, `legion-ares/src/llama.rs`, `manifest.rs`

Gets a model onto the machine and **serves it**, entirely locally.

## The pipeline

1. **Select a tier** from detected hardware (`hardware.rs`).
2. **Stage the GGUF** from Hugging Face, SHA-256 pinned by
   `agents/ares/models/manifest.json`, streamed to disk with the hash enforced
   and the partial removed on failure.
3. **Stage a `llama-server`** — an operator-supplied one on `PATH` always wins;
   otherwise a pinned llama.cpp build (`b10054`), also SHA-256 verified before
   extraction. The staged binary is then run once (`--list-devices`) to confirm
   it starts on this host, and the CPU build is staged instead if it does not.
   See [gpu-offload](gpu-offload.md).
4. **Serve it** on loopback with `--alias` set to the tier name, so `/v1/models`
   reports exactly what Legion staged.
5. Adopt a free port if the configured one is taken, and stop the server on exit
   — but only if Legion started it.

Published tiers: `qwen3-1.7b` (1.11 GB) and `qwen3-4b` (2.50 GB). `qwen3-8b` is
in the manifest but unpublished, and `pick_pullable_primary` silently downgrades.

Artifacts live in the **machine-wide** store (`/var/lib/legion`) when writable,
falling back per-user. The runtime directory is keyed by build **and variant**
(`llama-b10054-vulkan`).

## Manual control

`POST /api/agent/model/pull` and `GET /api/agent/model/progress` drive an
on-demand pull with a progress bar. Progress is read from the staged file's size
on disk rather than plumbed through the downloader.

## Verify

```bash
curl -s localhost:3000/api/agent/status   # online, model_installed, llm_host
ps -o cmd= -C llama-server                # --alias, --device, --threads, --ctx-size
```

## Limits

- The 8B tier cannot be pulled; the manifest entry has an empty hash.
- `fallback_model` maps to a tag with no manifest entry, so it is never
  stageable.
- The server holds its VRAM between hunts rather than releasing it when idle.

## Fixed here, worth knowing

**Nothing ever loaded the model.** Staging worked, the hash verified, the file
landed — and `staged_model_path` was read only to set two status booleans. The
weights were a write-only artifact, so every chat and hunt fell back to
`engine-only` forever on a stock install. The Ollama path had a complete
pull-import-serve pipeline; the default path stopped after "pull".

# Legion training workflows

Every Legion model trains from ONE shared **core** plus a small per-model **split**.
The config is in `legion_training/` (`registry.py`), imported by every harness. A new
model plugs in with a single registry entry and inherits the core.

## Core (shared by all models)
- **Settings** — `DEFAULTS`: QLoRA hyperparameters, GPU cap (0.75 of VRAM), seed,
  teacher, the promotion gate, budgets. One place; no harness hardcodes these.
- **Synthetic** — `SYNTHETIC`: execution-verified self-distillation. A sample/trajectory
  is kept ONLY if it passes its pytest spec (or grounded reference). Shapes: `gold`,
  `fix`, `explore_fix`. Anti-overfit: training steps are capped to `epochs` real passes
  (`resolve_steps`), never a raw step count — the fix for low eval is more DISTINCT
  tasks, not more epochs.
- **Security-first** — `SECURITY`: a Legion invariant, not an option. The **CLLMSP
  handbook** (`core/CLLMSP_Handbook.pdf`) is the shared reference. Every model's context
  is prefixed with `security_prefix()` and its data includes execution-checked security
  tasks.

## Split (per model, in `MODELS`)
Each model declares only what is unique and inherits the core:
- **process** — how it trains: `agentic` / `sft` / `vision` / `scenario` (-> a harness + entry).
- **context** — who it is: `objective` + the `system_prompt` it trains/serves under.
- **skills** — what it needs: `tools` + `behavior`.
- **data** — its synthetic `source` (made via the shared core).
- plus any hyperparameter overrides (e.g. vision uses `rank 16`, `max_length 2048`).

## The standard workflow (every model)
1. `cfg = lt.get(model)` — resolve core + split + env overrides.
2. Synthesize execution-verified data from `cfg["data"]["source"]` (shared method).
3. Train QLoRA with `max_steps = lt.resolve_steps(cfg, n_examples)` (epoch-capped).
4. Evaluate by execution (pass@1) on the held-out set.
5. Gate: promote only if `pass_rate >= gate_pass_rate_min` with no regression.
6. Publish (GGUF, `hf_quant`) and serve under `serve_tag`.

## Adding a NEW model
Add one entry to `MODELS` in `registry.py`:
```python
"legion-<name>": {
    "process": "agentic|sft|vision|scenario",
    "base": "<HF base id>",
    "serve_tag": "<ollama tag>",
    "context": {"objective": "...", "system_prompt": "<module path>"},
    "skills":  {"tools": "...", "behavior": "..."},
    "data":    {"source": "...", "synth": "..."},
    # override a DEFAULT only if needed (rank, lr, max_length, epochs, ...)
}
```
It inherits every shared setting, the synthetic discipline, the anti-overfit cap, and
security-first automatically. Launch it from its process's harness.

## Runtime overrides
Any field: `LEGION_TRAIN_<FIELD>=<value>` (e.g. `LEGION_TRAIN_EPOCHS=2`,
`LEGION_TRAIN_GPU_FRACTION=0.6`) for ad-hoc runs without editing the registry.

## Layout
```
legion/training/
  legion_training/   <- this central config (registry.py, __init__.py)
  core/              <- shared assets (CLLMSP_Handbook.pdf, security-first)
  legion-dev/        <- coding-agent harness (agentic / sft / vision)
  legion-ares/       <- security-scenario harness
  _backup/           <- consolidation snapshot
  README.md · WORKFLOWS.md
```

## Status / next
Config + registry + security core are in place. Next: wire each harness's entry point
to read `legion_training` (use `get()` for hyperparams, `resolve_steps()` for the cap,
`security_prefix()` on personas) instead of local argparse defaults, and grow
`legion-dev/legion_dev/tasks.py` into a large, diverse, realistic task pool (the real
lever for eval quality).

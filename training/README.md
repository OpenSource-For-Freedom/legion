# Legion training

The single, centralized home for training every Legion model. All training runs
from here (not from `legion_dev` or scattered `legion-agent` dirs, which were removed
and folded in).

## `legion-dev/` — the coding-agent training
Trains **Legion Dev**, the local software-engineer agent served by `legiondev-studio`.
One agent profile, two roles, execution-verified (a solution is kept only if pytest
passes):
- **Coder (hands)** — agentic tool-use + code correction. It drives the real tool loop
  (understand -> edit -> run tests -> fix) over the same tool surface the Studio serves.
- **Vision (eyes)** — reads a screenshot of a dev artifact and hands a precise
  **observation** to the coder (transcribe + describe + restate the task), it does not
  write the fix itself. This matches serve-time `vision_describe`.

Package: `legion_dev/`. Launch: `run_agent_iterate.cmd` (agentic), `run_iterate.cmd`
(single-file SFT), `iterate_vl` (vision). Base tiers target the served models
(`qwen2.5-coder:7b`, `qwen2.5-vl-3b`).

## `legion-ares/` — the Legion Ares training
Security / threat-scenario training (`scenarios`, `scenarios_ai`, `evidence`).
Package: `ares_train/`. Launch: `run_iterate.cmd` / `run_iterate_4h.ps1`.

## Conventions
- **Environments and adapters are NOT committed here.** The multi-GB `.work` / `.venv`
  and trained adapters regenerate on the first run (Python 3.14 + the training deps).
- `_backup/legion-training-src.tgz` is a source snapshot from the consolidation.
- The `LegionAgentIterate` and `AresIterate` scheduled tasks launch the `run_*` scripts
  in this tree.
- Training does not overfit tiny datasets: `max_steps` is capped to a few real epochs
  (see `train.py` / `train_vl.py`). The real lever for quality is a larger, diverse
  task pool, not more epochs.

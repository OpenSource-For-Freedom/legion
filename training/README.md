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

## Trigger a run yourself
All runs are **time-boxed and self-pacing**: they keep running fresh
synth -> train -> eval rounds until the budget is spent (or `--patience` rounds pass
with no improvement), and keep the best adapter. Ollama is auto-started if needed.

- **Agentic coder** (tool-driving: understand -> edit -> run tests -> fix) - the default track:
  ```powershell
  F:\dev\legion\training\run_agent.ps1              # 2 hours, 1.5B (default)
  F:\dev\legion\training\run_agent.ps1 -Hours 4     # 4 hours
  F:\dev\legion\training\run_agent.ps1 -Hours 2 -Tier 3b
  F:\dev\legion\training\run_agent.ps1 -Hours 8 -Tier 3b -EvalMode both   # + multi-file PROJECTS
  ```
- **Sequenced multi-model** (run several tiers back-to-back, auto-chained):
  ```powershell
  F:\dev\legion\training\train_sequence.ps1                       # 1.5B 6h -> 3B 4h
  F:\dev\legion\training\train_sequence.ps1 -Plan '1.5b:120,3b:120'
  ```
- **Monitor / stop** any run:
  ```powershell
  F:\dev\legion\training\monitor.ps1 dev     # agentic  (also: seq | seq15 | seq3 | pipeline | vision)
  # stop: Stop-Process -Id <pid> -Force   (the launcher prints the pid)
  ```
Under the hood these call `python -m legion_dev.iterate_agent` (agentic) or
`legion_dev.iterate` (single-file SFT); pass `--no-fill-budget` for a single round,
`--patience N` to change the early-stop, `--eval-mode single|project|both` to pick what the
gate scores, and `--publish` to push the best adapter + metrics card to HuggingFace on
completion (so Legion Studio can pull the served model).

## Two capability tiers + self-improvement (all execution-verified)
- **Single-file** (`tasks.py`) — fix/implement one function against a pytest spec.
- **Project** (`project_tasks.py`) — build a small MULTI-FILE package end to end (scaffold ->
  wire -> run the suite -> iterate). Graded by running the pristine tests over the final
  workspace (`executor.run_project`), so it can't be gamed and isn't a string match. This is
  the tier that teaches "complete a project", which single-file tasks can't.
- **`--eval-mode both`** merges the tiers into one gate: a fine-tune must gain projects
  WITHOUT regressing single-file.
- **Self-improvement** (`experience.py`) — every real run the agent drives to green is captured
  (verified only). It's retrieved as an in-context worked example on similar future requests
  (improves immediately, no retrain) and replayed into the next fine-tune (recursive). The
  promote gate stops the recursion from drifting. Weights never change during inference; the
  system improves by capturing and folding back what it actually solved.
- Guards (CPU-only, CI): `pytest legion_dev/test_project_tier.py legion_dev/test_experience.py
  legion_dev/test_agent_contract.py`.

## Contract parity (train -> eval -> serve -> deploy)
The agent speaks ONE tool protocol across every surface, and it is enforced, not
assumed. `agent_contracts.AGENT_TOOLS` is the source of truth; `iterate_agent` runs a
**preflight each run** that fails fast unless:
- every declared tool is actually EXECUTABLE by the eval loop
  (`evaluate_agent._exec_tool`), and every tool the trajectories teach exists + runs, and
- every trained tool is SERVED by Legion Studio with a matching schema
  (`legiondev-studio/backend/tools.py` `TOOL_DEFS`; override its path with
  `LEGION_STUDIO_DIR`).

Run the same checks yourself: `python -m pytest legion_dev/test_agent_contract.py -q`.
This is why a run can't silently score 0 (or ship a model the Studio can't drive) on a
protocol drift. Deploy uses `publish.py`, which handles both the SFT and agentic summaries.

## Conventions
- **Environments and adapters are NOT committed here.** The multi-GB `.work` / `.venv`
  and trained adapters regenerate on the first run (Python 3.14 + the training deps).
- `_backup/legion-training-src.tgz` is a source snapshot from the consolidation.
- The `LegionAgentIterate` and `AresIterate` scheduled tasks launch the `run_*` scripts
  in this tree.
- Training does not overfit tiny datasets: `max_steps` is capped to a few real epochs
  (see `train.py` / `train_vl.py`). The real lever for quality is a larger, diverse
  task pool, not more epochs.

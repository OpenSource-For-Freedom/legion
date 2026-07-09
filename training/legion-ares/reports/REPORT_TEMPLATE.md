# Ares LoRA run <run_id>

**Status:** ok | partial | skipped | crash

## Configuration
- run_id, tier, base_model, teacher_model, time_budget_min, n_per, cycles, wall_clock_min

## Dataset
- candidates / accepted / rejected / deduped, train/val/test, by backend

## Training
- status, base model, steps done, wall-clock vs budget, adapter path

## Build
- status, tag, method (ollama-import | gguf), gguf sha256

## Evaluation — candidate / baseline
- pass rate, invented total, grounding, plain-text format, citation coverage,
  anti-parrot, mean latency, gates cleared

## Promote decision
- promote: true/false + reason

<!-- Written by ares_train.report.write_report on every run.
     iterate runs also write reports/iterate-summary-<run_id>.json.
     One-line-per-stage history is in ../logs/runs.log -->

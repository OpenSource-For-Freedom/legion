# Ares LoRA run iterate-20260706T124233Z

**Status:** ok

## Configuration
- run_id: 20260706T124233Z
- tier: legion-ares:qwen3-1.7b
- base_model: Qwen/Qwen3-1.7B
- teacher_model: qwen3:14b
- time_budget_min: 240.0
- instructions_per: 3
- n_per: 8
- smoke: False
- wall_clock_min: 256.7
- cycles: 5

## Dataset
- candidates: 329
- accepted:   329
- rejected:   0
- deduped:    58
- train/val/test: 217/54/48
- by backend: {'model': 228, 'template': 43}

## Training
- status:     ok
- base model: Qwen/Qwen3-1.7B
- steps done: 300
- wall-clock: 955s (budget 70 min)
- adapter:    F:\dev\legion\training\legion-ares\.work\iter-20260706T124233Z\cycle4\adapter
- detail:     completed

## Build
  (none)

## Evaluation â€” candidate
  pass rate:          39/48 (0.81)
  invented total:     1
  grounding:          0.98
  plain-text format:  1.00
  citation coverage:  0.95
  anti-parrot:        0.93
  mean latency:       11.0s
  gates cleared:      False

## Evaluation â€” baseline
  pass rate:          8/48 (0.17)
  invented total:     4
  grounding:          0.96
  plain-text format:  0.52
  citation coverage:  0.84
  anti-parrot:        0.92
  mean latency:       4.0s
  gates cleared:      False

## Promote decision
- promote: False
- reason:  candidate did not clear all eval gates

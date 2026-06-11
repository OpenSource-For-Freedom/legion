# Legion mythos LoRA — weekly run report (template)

- run_id: <YYYYMMDD-HHMMSSZ>
- timestamp_utc: <ISO-8601 UTC>
- status: success | partial | skipped | skeleton
- base_model: <approved model tag>
- ollama_host: http://127.0.0.1:11434
- budget: max_examples=<n> rank=<n> steps=<n> time_min=<n>

## Dataset
- candidates: <n>
- accepted: <n>
- rejected: <n>

## Training
- wall_clock_min: <n>
- adapter: <path to .gguf or (none)>

## Evaluation
- previous_score: <0..1 or n/a>
- new_score: <0..1 or n/a>
- promote_decision: promoted:<new tag> | keep_previous

## Notes
<free text: failures, budget exhaustion, visibility gaps>

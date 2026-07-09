---
license: apache-2.0
base_model: Qwen/Qwen2.5-Coder-1.5B-Instruct
tags:
  - code
  - coding-assistant
  - qlora
  - legion
  - qwen2.5-coder
  - execution-verified
library_name: peft
pipeline_tag: text-generation
---

# legion_dev

A local, self-hosted **coding model** — QLoRA-distilled on Qwen2.5-Coder with an
**execution-verified** training loop, served by the Legion Dev dashboard. Runs
entirely on your machine.

## What it does

Given a task, the current contents of a file, and a `pytest` spec, it returns the
**complete corrected file** so the tests pass. It also works as a general local
coding assistant (write/fix/refactor with a short explanation + the code).

## How it was built (this is the point)

Not naive distillation. The training data is **execution-verified**:

1. A local coder teacher samples solutions to real coding tasks (offline, $0).
2. A sandboxed runner executes each solution against the task's real `pytest`
   tests and **keeps only the ones that pass** (execution-verified rejection
   sampling). The fallback is a hand-verified reference solution — a *working*
   program, never a stub — so the data never degenerates.
3. QLoRA SFT on the verified pairs.
4. The trained model is judged by **pass@1 on a held-out task set, by execution** —
   a real capability metric, not a surface score. Promotion requires no regression
   vs. the base model.

Curriculum: bug-fix, implement-from-spec, refactor, edge-case handling, plus
security tasks (SQL injection, hardcoded secret) that are *also* graded by running
tests.

**Honest scope:** a 1.5B–7B local coder is a fast, private, offline helper — not a
frontier model. The value is local + private + free + fast.

## Use

```bash
ollama pull qwen2.5-coder:1.5b        # or 3b / 7b — the served tier's base
# build the tagged model from the adapter with the training harness (build.py),
# or run the merged GGUF, then:
ollama run legion-dev:qwen2.5-coder-1.5b
```

Point any Ollama/OpenAI-compatible IDE plugin (Continue.dev, etc.) at the tag, or
use the Legion Dev dashboard.

<!-- legiondev:latest-run:start -->
<!-- legiondev:latest-run:end -->

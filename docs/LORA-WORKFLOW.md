# Mythos LoRA Self-Improvement Workflow — Design

**Status:** Planning (skeleton wired, training not yet executing)
**Owner:** Legion Contributors
**Run model:** local cron / systemd timer on the Legion host — **CPU-only, lightweight, any machine**
**Cadence:** weekly
**Goal:** continuously strengthen the local `legion-mythos` Ollama model from the
host's own accumulated hunt evidence, with **no external data and no RAG store**.

---

## 1. Why

Today the mythos model is a hardware-selected Qwen3 tier (`FROM qwen3:4b` by
default, or `qwen3:8b` / `qwen3:1.7b`) plus a fixed SYSTEM prompt
(`agents/poncho/models/Modelfile.mythos`). Its "knowledge" is injected at
inference time by `legion-poncho/src/knowledge.rs`, which builds a prompt from
Legion's live structured data (alerts, YARA matches, baseline drift, OSV
findings, local events, Docker state, connections) — a **RAG-less** context, not
a vector database.

That makes the model *informed* but never *improved*: every week of real hunt
evidence on the host is discarded. This workflow captures that evidence, distils
it into a small instruction-tuning dataset, trains a lightweight LoRA adapter on
CPU, and folds it back into the mythos model — so the model gets measurably
better at *this host's* threat surface over time, entirely offline.

Non-goals: cloud training, GPU requirement, RAG/vector store, telemetry leaving
the host, changing PONCHO's read-only posture.

---

## 2. The two training agents (Teacher + Critic distillation)

The workflow calls **two agent definition files** (this PR ships them as stubs):

| File | Role |
|------|------|
| `agents/poncho/training/teacher.json` | **Synthesizer.** Given a real evidence bundle from the Legion DB (the same RAG-less context `knowledge.rs` already assembles), prompts the *current* mythos model to produce high-quality `instruction → response` training pairs in the strict mythos SOC-row format. Output is grounded only in supplied evidence. |
| `agents/poncho/training/critic.json` | **Grader / filter.** Independently scores each candidate pair for (a) faithfulness to the evidence, (b) mythos format compliance, (c) no fabricated active-compromise claims, (d) actionable remediation. Pairs below threshold are dropped — **rejection sampling**, the quality gate that prevents the model learning its own hallucinations. |

This is teacher–student self-distillation with a critic in the loop: cheap,
local, and self-correcting. Neither agent has write access; both run through the
existing Ollama chat path.

---

## 3. Data flow

```
              ┌──────────────────────────────────────────────┐
              │ Legion SQLite (alerts, hunt reports, rule     │
              │ hits, YARA, baseline drift, OSV, events)      │
              └───────────────────────┬──────────────────────┘
                                      │ evidence bundles (RAG-less, knowledge.rs)
                                      ▼
                       ┌─────────────────────────-─┐
   teacher.json ─────► │  SYNTHESIZE (current      │  candidate pairs (JSONL)
                       │  mythos model via Ollama) │
                       └────────────┬──────────────┘
                                    ▼
   critic.json  ─────► ┌─────────────────────────-─┐  accept / reject + score
                       │  GRADE / FILTER           │  (rejection sampling)
                       └────────────┬──────────────┘
                                    ▼
                       dataset.jsonl  (capped, deduped)
                                    ▼
                       ┌──────────────────────────-┐
                       │  LoRA TRAIN (CPU, time-   │  adapter (GGUF)
                       │  boxed, small rank)       │
                       └────────────┬──────────────┘
                                    ▼
              ollama create legion-mythos:<date>  (Modelfile + ADAPTER)
                                    ▼
   evaluator  ─────►   ┌──────────────────────────┐  eval score vs held-out set
   (critic in          │  EVAL + PROMOTE GATE      │  promote ⇄ keep previous
   eval mode)          └────────────┬──────────────┘
                                    ▼
              timestamped success report written in-place
```

The evaluator reuses the critic agent in "eval mode" against a held-out slice of
graded pairs, so a regression cannot be silently promoted.

---

## 4. Lightweight, CPU-only training

Hard constraint: **runs on CPU on any machine.** Full LoRA on an 8B model on CPU
is *not* lightweight, so the weekly job is deliberately scaled and time-boxed:

- **Backend:** `llama.cpp` LoRA finetune (no Python ML stack; same GGUF/Ollama
  toolchain Legion already uses). Pure-CPU, portable across Linux/macOS/Windows.
- **Default trainable base:** the smallest approved model (`qwen3:1.7b`) →
  produces `legion-mythos-lite`. The 8B remains the inference default; promotion
  to an 8B adapter is an **opt-in** when more compute is available
  (`LEGION_LORA_BASE=qwen3:8b`).
- **Budget caps (all configurable):**
  - `LEGION_LORA_MAX_EXAMPLES` (default 256 accepted pairs)
  - `LEGION_LORA_RANK` (default 8), `LEGION_LORA_STEPS` (default 200)
  - `LEGION_LORA_TIME_BUDGET_MIN` (default 30) — hard wall-clock stop; the job
    checkpoints and reports `partial` rather than overrunning.
- **Resource cap (thermal/power safety):** uncapped, a CPU finetune pins every
  core at 100% and can overheat or crash the host. `run_weekly.sh` caps the
  worker-thread count to `LEGION_LORA_CPU_PERCENT` (default **60%**) of `nproc` —
  `threads = floor(nproc * percent / 100)` — exported to every CPU backend
  (`OMP_NUM_THREADS`, `OPENBLAS_NUM_THREADS`, `MKL_NUM_THREADS`, `GGML_NTHREADS`,
  …) and passed as `--threads` to the finetune. `LEGION_LORA_THREADS` overrides
  the percentage outright. Heavy stages also run under `nice`/`ionice` so the
  desktop stays responsive. The trade-off is intentional: fewer cores → cooler
  machine → longer run. The systemd unit adds cgroup-level insurance
  (`CPUWeight`, `IOWeight`, optional `CPUQuota`/`MemoryMax`).
- **Fail-safe:** if training can't finish a single epoch within budget, the run
  reports `skipped (insufficient_budget)` and the previous model is kept. The
  cron never degrades the live model.

Adapter → GGUF → applied via a generated Modelfile:

```Modelfile
FROM qwen3:1.7b
ADAPTER ./legion-mythos.lora.gguf
# SYSTEM block inherited from Modelfile.mythos
```

---

## 5. File layout (this PR)

```
agents/poncho/training/
├── teacher.json                 # synthesizer agent (stub)
├── critic.json                  # grader/evaluator agent (stub)
├── run_weekly.sh                # orchestrator skeleton (no real train yet)
├── config.env                   # tunable budget caps (sourced by the script)
├── Modelfile.mythos.adapter.tmpl# Modelfile template with ADAPTER directive
├── systemd/
│   ├── legion-lora.service      # oneshot unit template
│   └── legion-lora.timer        # weekly timer template
└── reports/
    └── REPORT_TEMPLATE.md       # success-report format
```

The orchestrator stages everything under a working dir but the **report is
written next to the training files**, in `reports/`, with a UTC timestamp:

```
agents/poncho/training/reports/lora-report-YYYYMMDD-HHMMSSZ.md
```

---

## 6. Weekly schedule (local, no GitHub Actions)

Per the chosen run host, scheduling is local — a systemd timer (Linux) or cron:

```ini
# legion-lora.timer
[Timer]
OnCalendar=Sun 04:00
Persistent=true
```

```cron
# crontab equivalent
0 4 * * 0  /path/to/legion/agents/poncho/training/run_weekly.sh >> ~/.local/share/legion/lora.log 2>&1
```

The job is idempotent and single-flight (lockfile), so a missed week simply runs
on next boot (`Persistent=true`).

---

## 7. Success report format

Written in-place on every run (success, partial, or skipped). See
`reports/REPORT_TEMPLATE.md`. Key fields: run id + UTC timestamp, evidence
window, candidate/accepted/rejected counts, dataset size, base model, rank/steps,
wall-clock used vs budget, eval score vs baseline, **promote decision**, and the
resulting model tag + digest.

---

## 8. Security & safety

- **Offline & read-only.** No data leaves the host; both agents use the local
  Ollama endpoint, which PON-2 already pins to loopback.
- **Poisoning resistance.** The critic's rejection sampling is the primary guard
  against training on hallucinated or attacker-influenced evidence; the evidence
  itself is Legion's own validated DB rows, not raw network feeds.
- **Promotion gate.** A retrained model is only promoted if it beats the previous
  on the held-out eval — no silent regressions.
- **Provenance.** Each promoted model's digest is recorded in the report and
  (once PON-1 lands) pinned, so a swapped adapter is detectable.
- **Resource safety.** Hard time/example/step caps keep the weekly job light on
  any machine; the job yields rather than starving the host.
- **Policy.** Blocked families (DeepSeek) remain refused; the trainable base must
  be an approved model.

---

## 9. Phased delivery

1. **This PR (plan + skeleton):** doc, teacher/critic stubs, orchestrator
   skeleton, systemd/cron templates, report template. No training executes.
2. **Next:** implement evidence-bundle export from the DB + teacher synthesis +
   critic grading → produce a real `dataset.jsonl`; ship the eval harness.
3. **Then:** wire the llama.cpp CPU LoRA train + GGUF + `ollama create`, behind
   the budget caps, with the promote gate and report emission.
4. **Hardening:** dataset retention/rotation, digest pinning of promoted models
   (depends on PON-1), optional opt-in 8B base.

---

## 10. Open questions (track before phase 2)

- Minimum evidence volume before a weekly run is worthwhile (skip threshold).
- Retention policy for datasets/adapters/old model tags (disk budget).
- Whether to expose run status/last-report on the dashboard AGENT tab.

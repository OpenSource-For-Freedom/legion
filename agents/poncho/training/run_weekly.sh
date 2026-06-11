#!/usr/bin/env bash
# Legion mythos LoRA — weekly orchestrator (SKELETON).
#
# Runs locally on the Legion host (systemd timer / cron). CPU-only, time-boxed.
# This skeleton wires the stages and writes a timestamped report, but the
# synthesis / grading / training steps are stubs (see docs/LORA-WORKFLOW.md,
# phases 2-3). It is safe to run: it never modifies the live mythos model.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
[ -f "${HERE}/config.env" ] && . "${HERE}/config.env"

: "${LEGION_LORA_BASE:=qwen3:1.7b}"
: "${LEGION_LORA_MAX_EXAMPLES:=256}"
: "${LEGION_LORA_RANK:=8}"
: "${LEGION_LORA_STEPS:=200}"
: "${LEGION_LORA_TIME_BUDGET_MIN:=30}"
: "${OLLAMA_HOST:=http://127.0.0.1:11434}"

REPORTS_DIR="${HERE}/reports"
mkdir -p "${REPORTS_DIR}"
TS="$(date -u +%Y%m%d-%H%M%SZ)"
REPORT="${REPORTS_DIR}/lora-report-${TS}.md"
LOCK="${HERE}/.run.lock"

# Single-flight: never let two weekly runs overlap.
exec 9>"${LOCK}"
if ! flock -n 9; then
  echo "another LoRA run is in progress; exiting" >&2
  exit 0
fi

status="skeleton"
note="orchestrator skeleton — synthesis/grading/training not yet implemented"

# ── Stage 1: export evidence bundle (RAG-less, from Legion DB) ────────────────
# TODO(phase2): dump alerts/hunt_reports/rule_hits/yara/baseline/osv/events.
# ── Stage 2: teacher synthesis (teacher.json) ────────────────────────────────
# TODO(phase2): prompt current mythos model -> candidate pairs (jsonl).
# ── Stage 3: critic grading / rejection sampling (critic.json) ───────────────
# TODO(phase2): grade pairs, keep score >= accept_threshold -> dataset.jsonl.
# ── Stage 4: CPU LoRA train (llama.cpp), time-boxed ──────────────────────────
# TODO(phase3): train adapter under rank/steps/time budget -> .gguf.
# ── Stage 5: ollama create + held-out eval + promote gate ────────────────────
# TODO(phase3): build legion-mythos:<date>, eval, promote only if not worse.

write_report() {
  cat >"${REPORT}" <<EOF
# Legion mythos LoRA — weekly run report

- run_id: ${TS}
- timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- status: ${status}
- base_model: ${LEGION_LORA_BASE}
- ollama_host: ${OLLAMA_HOST}
- budget: max_examples=${LEGION_LORA_MAX_EXAMPLES} rank=${LEGION_LORA_RANK} steps=${LEGION_LORA_STEPS} time_min=${LEGION_LORA_TIME_BUDGET_MIN}

## Dataset
- candidates: 0
- accepted: 0
- rejected: 0

## Training
- wall_clock_min: 0
- adapter: (none)

## Evaluation
- previous_score: n/a
- new_score: n/a
- promote_decision: keep_previous

## Notes
${note}
EOF
  echo "report written: ${REPORT}"
}

write_report
exit 0

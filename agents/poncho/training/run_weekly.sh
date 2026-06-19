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
: "${LEGION_LORA_CPU_PERCENT:=60}"
: "${LEGION_LORA_NICE:=10}"
: "${OLLAMA_HOST:=http://127.0.0.1:11434}"

# ── Resource cap ─────────────────────────────────────────────────────────────
# CPU LoRA finetune saturates every core and overheats the host if uncapped.
# Derive a thread count from LEGION_LORA_CPU_PERCENT (default 60% of cores) so
# the job uses fewer cores and just runs longer. An explicit LEGION_LORA_THREADS
# overrides the percentage. Clamp to [1, nproc].
NPROC="$(nproc 2>/dev/null || echo 1)"
if [ -n "${LEGION_LORA_THREADS:-}" ]; then
  THREADS="${LEGION_LORA_THREADS}"
else
  THREADS=$(( NPROC * LEGION_LORA_CPU_PERCENT / 100 ))
fi
[ "${THREADS}" -lt 1 ] && THREADS=1
[ "${THREADS}" -gt "${NPROC}" ] && THREADS="${NPROC}"

# Every common CPU backend honors one of these — set them all so the cap holds
# whether the trainer uses OpenMP, OpenBLAS, MKL, Accelerate, or raw ggml.
export LEGION_LORA_THREADS="${THREADS}"
export OMP_NUM_THREADS="${THREADS}"
export OPENBLAS_NUM_THREADS="${THREADS}"
export MKL_NUM_THREADS="${THREADS}"
export NUMEXPR_NUM_THREADS="${THREADS}"
export VECLIB_MAXIMUM_THREADS="${THREADS}"
export GGML_NTHREADS="${THREADS}"

# Run heavy commands de-prioritized (CPU + I/O) so the host stays responsive and
# cool. Threads above are the real cap; nice/ionice keep the desktop usable.
throttle() {
  local pre=()
  command -v nice   >/dev/null 2>&1 && pre+=(nice -n "${LEGION_LORA_NICE}")
  command -v ionice >/dev/null 2>&1 && pre+=(ionice -c3)
  "${pre[@]}" "$@"
}

echo "resource cap: ${THREADS}/${NPROC} cores (${LEGION_LORA_CPU_PERCENT}%), nice=${LEGION_LORA_NICE}, ionice=idle"

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
package_status="skipped (no_adapter)"
MODEL_TAG=""

# Heavy artifacts live outside the repo (build caches, adapters). Reports stay
# next to the training files (REPORTS_DIR) per the workflow design.
WORK_DIR="${LEGION_LORA_WORK_DIR:-${CACHE_DIRECTORY:-${XDG_CACHE_HOME:-$HOME/.cache}/legion/lora}}"
mkdir -p "${WORK_DIR}"
ADAPTER_GGUF="${ADAPTER_GGUF:-${WORK_DIR}/legion-mythos.lora.gguf}"

# ── Stage 1: export evidence bundle (RAG-less, from Legion DB) ────────────────
# TODO(phase2): dump alerts/hunt_reports/rule_hits/yara/baseline/osv/events.
# ── Stage 2: teacher synthesis (teacher.json) ────────────────────────────────
# TODO(phase2): prompt current mythos model -> candidate pairs (jsonl).
# ── Stage 3: critic grading / rejection sampling (critic.json) ───────────────
# TODO(phase2): grade pairs, keep score >= accept_threshold -> dataset.jsonl.
# ── Stage 4: CPU LoRA train (llama.cpp), time-boxed + thread-capped ───────────
# TODO(phase3): run the finetune under the resource cap, e.g.
#   throttle llama-finetune --threads "${LEGION_LORA_THREADS}" \
#       --model-base <base.gguf> --lora-out "${ADAPTER_GGUF}" \
#       --lora-r "${LEGION_LORA_RANK}" --adam-iter "${LEGION_LORA_STEPS}" ...
# The throttle/--threads cap is what keeps this from cooking the machine.

# ── Stage 5: package the adapter into an Ollama model ─────────────────────────
# Renders the adapter Modelfile and runs `ollama create`. Idempotent and gated:
# only runs once Stage 4 has produced an adapter, so the live model is untouched
# until there is a real trained adapter to package.
package_model() {
  if [ ! -f "${ADAPTER_GGUF}" ]; then
    package_status="skipped (no_adapter)"
    echo "no adapter at ${ADAPTER_GGUF}; skipping packaging" >&2
    return 0
  fi
  if ! command -v ollama >/dev/null 2>&1; then
    package_status="skipped (ollama_missing)"
    echo "ollama not installed; skipping packaging" >&2
    return 0
  fi

  # lite base -> legion-mythos-lite; an 8B base -> legion-mythos.
  local name="legion-mythos-lite"
  case "${LEGION_LORA_BASE}" in *8b*|*8B*) name="legion-mythos" ;; esac
  MODEL_TAG="${name}:${TS}"

  local mf="${WORK_DIR}/Modelfile.${TS}"
  sed -e "s|{{BASE_MODEL}}|${LEGION_LORA_BASE}|g" \
      -e "s|{{ADAPTER_GGUF}}|${ADAPTER_GGUF}|g" \
      "${HERE}/Modelfile.mythos.adapter.tmpl" > "${mf}"

  echo "packaging ${MODEL_TAG} (${LEGION_LORA_BASE} + $(basename "${ADAPTER_GGUF}"))"
  if OLLAMA_HOST="${OLLAMA_HOST}" throttle ollama create "${MODEL_TAG}" -f "${mf}"; then
    package_status="created ${MODEL_TAG}"
  else
    package_status="failed (ollama_create)"
  fi
}

package_model

write_report() {
  cat >"${REPORT}" <<EOF
# Legion mythos LoRA — weekly run report

- run_id: ${TS}
- timestamp_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- status: ${status}
- base_model: ${LEGION_LORA_BASE}
- ollama_host: ${OLLAMA_HOST}
- budget: max_examples=${LEGION_LORA_MAX_EXAMPLES} rank=${LEGION_LORA_RANK} steps=${LEGION_LORA_STEPS} time_min=${LEGION_LORA_TIME_BUDGET_MIN}
- resource_cap: ${THREADS}/${NPROC} cores (${LEGION_LORA_CPU_PERCENT}%), nice=${LEGION_LORA_NICE}, ionice=idle

## Dataset
- candidates: 0
- accepted: 0
- rejected: 0

## Training
- wall_clock_min: 0
- threads: ${THREADS}/${NPROC} (${LEGION_LORA_CPU_PERCENT}%)
- adapter: ${ADAPTER_GGUF}

## Packaging
- ollama_create: ${package_status}
- model_tag: ${MODEL_TAG:-(none)}

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

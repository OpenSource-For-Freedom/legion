"""Per-run markdown report writer (ok / partial / skipped)."""

from __future__ import annotations

from pathlib import Path


def _fmt_eval(e) -> str:
    if e is None:
        return "  (none)\n"
    return (f"  pass rate:          {e.passed}/{e.n} ({e.pass_rate:.2f})\n"
            f"  invented total:     {e.invented_total}\n"
            f"  grounding:          {e.grounding:.2f}\n"
            f"  plain-text format:  {e.format:.2f}\n"
            f"  citation coverage:  {e.citation_coverage:.2f}\n"
            f"  anti-parrot:        {e.anti_parrot:.2f}\n"
            f"  mean latency:       {e.mean_latency_s:.1f}s\n"
            f"  gates cleared:      {e.gates_cleared}\n")


def write_report(reports_dir, run_id, *, status, config, ds_stats=None, train_result=None,
                 build_result=None, candidate_eval=None, baseline_eval=None,
                 promote_decision=None) -> str:
    reports = Path(reports_dir)
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / f"lora-report-{run_id}.md"

    lines, a = [], None
    out = []
    def a(s): out.append(s)

    a(f"# Ares LoRA run {run_id}\n")
    a(f"**Status:** {status}\n")
    a("## Configuration")
    for k, v in config.items():
        a(f"- {k}: {v}")
    a("\n## Dataset")
    if ds_stats:
        a(f"- candidates: {ds_stats.candidates}")
        a(f"- accepted:   {ds_stats.accepted}")
        a(f"- rejected:   {ds_stats.rejected}")
        a(f"- deduped:    {ds_stats.deduped}")
        a(f"- train/val/test: {ds_stats.train}/{ds_stats.val}/{ds_stats.test}")
        a(f"- by backend: {ds_stats.by_backend}")
        if ds_stats.reject_reasons:
            a(f"- sample reject reasons: {ds_stats.reject_reasons[:5]}")
    else:
        a("  (none)")
    a("\n## Training")
    if train_result:
        a(f"- status:     {train_result.status}")
        a(f"- base model: {train_result.base_model}")
        a(f"- steps done: {train_result.steps_done}")
        a(f"- wall-clock: {train_result.seconds_used:.0f}s (budget {train_result.time_budget_min:.0f} min)")
        a(f"- adapter:    {train_result.adapter_dir}")
        a(f"- detail:     {train_result.detail}")
    else:
        a("  (none)")
    a("\n## Build")
    if build_result:
        a(f"- status: {build_result.status}")
        a(f"- tag:    {build_result.tag}")
        a(f"- method: {build_result.method}")
        if build_result.gguf_sha256:
            a(f"- gguf sha256: {build_result.gguf_sha256}")
        a(f"- detail: {build_result.detail[:500]}")
    else:
        a("  (none)")
    a("\n## Evaluation — candidate")
    a(_fmt_eval(candidate_eval))
    a("## Evaluation — baseline")
    a(_fmt_eval(baseline_eval))
    a("## Promote decision")
    if promote_decision:
        a(f"- promote: {promote_decision.promote}")
        a(f"- reason:  {promote_decision.reason}")
    else:
        a("  (none)")

    path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return str(path)

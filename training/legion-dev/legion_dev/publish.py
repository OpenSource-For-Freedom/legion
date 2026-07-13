"""
Auto-publish a finished iterate run to HuggingFace (tburns-actual/legion_dev).

Runs at the end of an iterate run (via --publish) so the result reaches HF even
if no operator/Claude session is around. Pushes:
  - the run summary JSON      -> training-runs/iterate-summary-<run_id>.json
  - the best LoRA adapter     -> adapters/<tier-size>-<run_id>/   (if one cleared)
  - a "Latest training run" metrics block in the model card (README.md)

It does NOT replace the live GGUF — Ollama-ready weights still need a llama.cpp
GGUF conversion. The HF write token is read from the legion-agent .env
(HUGGINGFACE_API_KEY); if absent it falls back to your local `huggingface-cli
login` token. It is never logged.
"""

from __future__ import annotations

import glob
import json
import os
from pathlib import Path

from . import runlog

REPO = "tburns-actual/legion_dev"
ROOT = Path(__file__).resolve().parents[1]
ENV = Path(r"F:\dev\legion-agent\.env")
START = "<!-- legiondev:latest-run:start -->"
END = "<!-- legiondev:latest-run:end -->"


def _token() -> str | None:
    try:
        for line in ENV.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("HUGGINGFACE_API_KEY"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    if os.environ.get("HF_TOKEN"):
        return os.environ["HF_TOKEN"]
    try:  # fall back to a local `huggingface-cli login`
        from huggingface_hub import get_token
        return get_token()
    except Exception:
        return None


def _latest_summary() -> Path | None:
    # Both tracks publish here: sft writes iterate-summary-*, agentic writes
    # agent-summary-*. Pick the newest of either by mtime so the agentic track
    # is publishable too (else it would grab a stale sft summary).
    fs = glob.glob(str(ROOT / "reports" / "iterate-summary-*.json")) + \
         glob.glob(str(ROOT / "reports" / "agent-summary-*.json"))
    if not fs:
        return None
    return Path(max(fs, key=os.path.getmtime))


def _adapter_subdir(summary: dict, rid: str) -> str:
    tier = (summary.get("config") or {}).get("tier", "legion-dev:model")
    size = tier.split(":")[-1]
    return f"adapters/{size}-{rid}"


def _metrics_block(summary: dict) -> str:
    cfg = summary.get("config") or {}
    be = summary.get("best_eval") or {}
    ba = summary.get("baseline_eval") or {}
    pr = summary.get("promote") or {}

    def g(d, k):
        v = d.get(k)
        return f"{v:.2f}" if isinstance(v, float) else ("-" if v is None else v)

    return "\n".join([
        START, "",
        "## Latest training run", "",
        f"- run `{summary.get('run_id')}` · status **{summary.get('status')}** · "
        f"tier {cfg.get('tier')} · teacher {cfg.get('teacher_model') or cfg.get('teacher_backend')} · "
        f"{cfg.get('cycles')} sweep cycles in {cfg.get('wall_clock_min')} min",
        "- method: execution-verified self-distillation — the local coder teacher's "
        "solutions are kept only when they pass real pytest tests; graded by pass@1 "
        "on a held-out task set (bug-fix, implement-from-spec, refactor, edge-case, "
        "SQL-injection, hardcoded-secret)",
        "",
        "| metric | base | trained |",
        "|---|---|---|",
        f"| pass@1 (execution) | {ba.get('passed')}/{ba.get('n')} | {be.get('passed')}/{be.get('n')} |",
        f"| produced code | {ba.get('had_code', ba.get('wrote_file'))}/{ba.get('n')} | {be.get('had_code', be.get('wrote_file'))}/{be.get('n')} |",
        f"| gates cleared | {ba.get('gates_cleared')} | {be.get('gates_cleared')} |",
        "",
        f"Promote decision: **{pr.get('promote')}** — {pr.get('reason')}",
        "", END,
    ])


def _update_readme(api, summary: dict) -> None:
    from huggingface_hub import hf_hub_download
    try:
        cur = Path(hf_hub_download(REPO, "README.md", token=api.token)).read_text(encoding="utf-8")
    except Exception:
        cur = (
            "# Legion Dev\n\n"
            "**A local, self-hosted software-engineering agent.** Legion Dev drives a real tool "
            "loop on your own machine: understand (`list_dir` / `read_file` / `search` / "
            "`find_definition`) -> edit (`edit_file` / `write_file`) -> verify (`run_shell`, "
            "actually runs the tests) -> fix, and keeps going until the tests are green. It is "
            "served locally through Ollama on loopback by "
            "[Legion Studio](https://github.com/OpenSource-For-Freedom/legion_studio). Nothing "
            "leaves your machine.\n\n"
            "## What gets published here\n\n"
            "- **The model card + metrics for every training run** (below), including runs that "
            "were **rejected**.\n"
            "- **LoRA adapters only when they beat the base model.** A fine-tune that scores "
            "below baseline is a regression: publishing it would hand you a model *worse* than "
            "the base you already have. So its weights are never published, only its result. "
            "Adapters that earn it live under `adapters/`.\n\n"
            "## Doctrine (what the agent is held to)\n\n"
            "- **Security first.** Never introduce SQL/command injection, path traversal, unsafe "
            "deserialization, SSRF, weak crypto, or eval/exec on untrusted input. Contain paths by "
            "NORMALIZING before checking (a raw string check does not stop `../`). Never hardcode "
            "or print a secret; read it from the environment.\n"
            "- **Verify before finish.** Writing the file is not finishing. The agent is done only "
            "after it has actually RUN the tests and seen them pass.\n"
            "- **Understand before you change.** Read the real code before editing it. Never invent "
            "files, APIs, or command output; ground every claim in something actually read or run.\n\n"
            "## Evaluation\n\n"
            "Graded by **execution**, not text similarity: pass@1 on a held-out task set where the "
            "agent must drive the tool loop itself and a real pytest suite decides pass/fail. Task "
            "families: bug-fix, implement-from-spec, refactor, edge-case, and security (SQL "
            "injection, hardcoded secrets, path traversal, command injection).\n"
        )
    block = _metrics_block(summary)
    if START in cur and END in cur:
        new = cur.split(START)[0] + block + cur.split(END, 1)[1]
    else:
        new = cur.rstrip() + "\n\n" + block + "\n"
    out = ROOT / "reports" / "README_published.md"
    out.write_text(new, encoding="utf-8")
    api.upload_file(path_or_fileobj=str(out), path_in_repo="README.md", repo_id=REPO,
                    commit_message=f"model card: training run {summary.get('run_id')} metrics")


def main() -> int:
    from huggingface_hub import HfApi
    tok = _token()
    api = HfApi(token=tok)
    try:
        who = api.whoami()
        api.token = tok  # ensure downstream downloads use the resolved token
    except Exception as e:
        runlog.log("publish", "FAIL", f"not authenticated to HuggingFace: {e}")
        return 1

    s = _latest_summary()
    if not s:
        runlog.log("publish", "WARN", "no iterate summary found")
        return 0
    summary = json.loads(s.read_text(encoding="utf-8"))
    rid = summary.get("run_id")
    try:
        api.create_repo(REPO, repo_type="model", exist_ok=True)
        api.upload_file(path_or_fileobj=str(s),
                        path_in_repo=f"training-runs/iterate-summary-{rid}.json",
                        repo_id=REPO, commit_message=f"training run {rid} summary")
        best = summary.get("best_adapter")
        decision = summary.get("promote") or {}
        pushed = False
        # ONLY publish an adapter that EARNED it. The gate compares the candidate against
        # the BASE model; a fine-tune scoring below baseline is a REGRESSION, and shipping
        # that publicly hands people a model worse than the base they already have. The
        # run summary + card are still published (honestly, including a "did not clear"),
        # so the result is recorded either way — but the weights are not.
        if best and Path(best).exists() and decision.get("promote"):
            api.upload_folder(folder_path=best, path_in_repo=_adapter_subdir(summary, rid),
                              repo_id=REPO, commit_message=f"LoRA adapter from run {rid}")
            pushed = True
        elif best:
            runlog.log("publish", "INFO",
                       "adapter NOT published (did not clear the gate): "
                       f"{decision.get('reason', 'no promote decision')}", run_id=rid)
        _update_readme(api, summary)
        runlog.log("publish", "OK", f"pushed run {rid} as {who.get('name','?')} "
                   f"(status={summary.get('status')}, adapter={pushed})", run_id=rid)
        return 0
    except Exception as e:
        runlog.log("publish", "FAIL", f"{type(e).__name__}: {e}", run_id=rid)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

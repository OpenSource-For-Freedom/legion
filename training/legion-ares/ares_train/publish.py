"""
Auto-publish a finished iterate run to HuggingFace (tburns-actual/legion-ares).

Runs at the end of an iterate run (via --publish) so the result reaches HF even
if no operator/Claude session is around. Pushes:
  - the run summary JSON      -> training-runs/iterate-summary-<run_id>.json
  - the best LoRA adapter     -> adapters/qwen3-1.7b-<run_id>/   (if one cleared)
  - a "Latest training run" metrics block in the model card (README.md)

It does NOT replace the live GGUF. Ollama-ready weights still need a llama.cpp
GGUF conversion. The HF write token is read from the legion-agent .env
(HUGGINGFACE_API_KEY) and never logged.
"""

from __future__ import annotations

import glob
import json
import os
import re
from pathlib import Path

from . import runlog

REPO = "tburns-actual/legion-ares"
ROOT = Path(__file__).resolve().parents[1]
ENV = Path(r"F:\dev\legion-agent\.env")
START = "<!-- ares:latest-run:start -->"
END = "<!-- ares:latest-run:end -->"


def _token() -> str | None:
    try:
        for line in ENV.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("HUGGINGFACE_API_KEY"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return os.environ.get("HF_TOKEN")


def _latest_summary() -> Path | None:
    fs = sorted(glob.glob(str(ROOT / "reports" / "iterate-summary-*.json")))
    return Path(fs[-1]) if fs else None


def _load_summaries() -> list[dict]:
    """Every iterate run this machine has produced, oldest first."""
    out = []
    for f in sorted(glob.glob(str(ROOT / "reports" / "iterate-summary-*.json"))):
        try:
            out.append(json.loads(Path(f).read_text(encoding="utf-8")))
        except Exception:
            pass
    return out


def _fmt(v, nd: int = 2) -> str:
    return f"{v:.{nd}f}" if isinstance(v, float) else ("-" if v is None else str(v))


def _run_date(run_id: str) -> str:
    return f"{run_id[0:4]}-{run_id[4:6]}-{run_id[6:8]}" if run_id and len(run_id) >= 8 else "-"


def _champion(summaries: list[dict]) -> dict | None:
    """Best build across all runs by (gates cleared, pass rate, fewest invented)."""
    def key(s):
        be = s.get("best_eval") or {}
        return (1 if be.get("gates_cleared") else 0,
                be.get("pass_rate") or 0.0, -(be.get("invented_total") or 0))
    cand = [s for s in summaries if s.get("best_eval")]
    return max(cand, key=key) if cand else None


def _champion_block(champ: dict) -> list[str]:
    cfg = champ.get("config") or {}
    be = champ.get("best_eval") or {}
    ba = champ.get("baseline_eval") or {}
    rows = [
        "## Best build", "",
        f"- run `{champ.get('run_id')}`, tier {cfg.get('tier')}, "
        f"base {cfg.get('base_model')}, teacher {cfg.get('teacher_model')}",
        f"- graded on a frozen {be.get('n')}-case test set held out from training",
        "- curriculum: dual-OS (Linux and Windows), package and supply-chain, "
        "C2, exfil, obfuscation, and credential-harvesting specialties, five "
        "guardrail classes, and the CLLMSP AI and LLM security backbone",
        "",
        "| metric | base | trained |",
        "|---|---|---|",
        f"| pass rate | {ba.get('passed')}/{ba.get('n')} | {be.get('passed')}/{be.get('n')} |",
        f"| grounding | {_fmt(ba.get('grounding'))} | {_fmt(be.get('grounding'))} |",
        f"| citation coverage | {_fmt(ba.get('citation_coverage'))} | {_fmt(be.get('citation_coverage'))} |",
        f"| anti-parrot | {_fmt(ba.get('anti_parrot'))} | {_fmt(be.get('anti_parrot'))} |",
    ]
    if "format" in be or "format" in ba:
        rows.append(f"| plain-text format | {_fmt(ba.get('format'))} | {_fmt(be.get('format'))} |")
    rows += [
        f"| invented indicators | {ba.get('invented_total')} | {be.get('invented_total')} |",
        f"| gates cleared | {ba.get('gates_cleared')} | {be.get('gates_cleared')} |",
        "",
    ]
    return rows


def _cfg_rank_steps(cf) -> tuple:
    """Cycle cfg is a dict {rank, steps} in newer runs, a string 'rank16/steps150'
    in older ones. Return (rank, steps) either way."""
    if isinstance(cf, dict):
        return cf.get("rank", "-"), cf.get("steps", "-")
    if isinstance(cf, str):
        r = re.search(r"rank(\d+)", cf)
        s = re.search(r"steps(\d+)", cf)
        return (r.group(1) if r else "-"), (s.group(1) if s else "-")
    return "-", "-"


def _sweep_block(champ: dict) -> list[str]:
    ba = champ.get("baseline_eval") or {}
    be = champ.get("best_eval") or {}
    n = be.get("n") or ba.get("n")  # every cycle is graded on the same frozen test set
    rows = [
        "## How the best build was reached", "",
        "Each run sweeps several QLoRA configs against the base and keeps the best. "
        "This one climbed from the stock base:", "",
        "| stage | rank | steps | pass | gates |",
        "|---|---|---|---|---|",
        f"| baseline | - | - | {ba.get('passed')}/{n} | {ba.get('gates_cleared')} |",
    ]
    for i, c in enumerate(champ.get("cycles") or [], 1):
        if not isinstance(c, dict):
            continue
        ev = c.get("eval") or {}
        if "passed" not in ev:
            continue
        rank, steps = _cfg_rank_steps(c.get("cfg"))
        rows.append(f"| cycle {i} | {rank} | {steps} | {ev.get('passed')}/{ev.get('n') or n} "
                    f"| {ev.get('gates_cleared')} |")
    rows.append("")
    return rows


def _history_block(summaries: list[dict], champ_id: str | None) -> list[str]:
    rows = [
        "## Training history", "",
        "One row per iterate run, newest first. The test set grows as new guardrail "
        "scenarios are added, so later runs are graded on a wider bar.", "",
        "| run | date | tier | test set | pass rate | grounding | invented | gates |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in sorted(summaries, key=lambda s: s.get("run_id", ""), reverse=True):
        be = s.get("best_eval") or {}
        cfg = s.get("config") or {}
        rid = s.get("run_id", "")
        star = " (best)" if rid == champ_id else ""
        rows.append(f"| `{rid}`{star} | {_run_date(rid)} | {cfg.get('tier')} | "
                    f"{be.get('n')} | {be.get('passed')}/{be.get('n')} | "
                    f"{_fmt(be.get('grounding'))} | {be.get('invented_total')} | {be.get('gates_cleared')} |")
    rows.append("")
    return rows


def _metrics_block(summaries: list[dict]) -> str:
    champ = _champion(summaries)
    parts = [START, ""]
    if champ:
        parts += _champion_block(champ)
        parts += _sweep_block(champ)
    parts += _history_block(summaries, champ.get("run_id") if champ else None)
    parts += [
        "Every answer is graded by code, not a judge model: indicators are extracted by "
        "regex and checked against the evidence, markdown is detected structurally, and "
        "token overlap measures restatement. A build ships only if it clears every gate: "
        "zero invented indicators, grounding at or above 0.95, plain-text format at or "
        "above 0.98, citation coverage at or above 0.80, and anti-parrot at or above 0.90.",
        "", END,
    ]
    return "\n".join(parts)


def _update_readme(api, summaries: list[dict]) -> None:
    from huggingface_hub import hf_hub_download
    cur = Path(hf_hub_download(REPO, "README.md", token=api.token)).read_text(encoding="utf-8")
    block = _metrics_block(summaries)
    if START in cur and END in cur:
        new = cur.split(START)[0] + block + cur.split(END, 1)[1]
    else:
        new = cur.rstrip() + "\n\n" + block + "\n"
    out = ROOT / "reports" / "README_published.md"
    out.write_text(new, encoding="utf-8")
    rid = summaries[-1].get("run_id") if summaries else "?"
    api.upload_file(path_or_fileobj=str(out), path_in_repo="README.md", repo_id=REPO,
                    commit_message=f"model card: best build + training history (through run {rid})")


def main() -> int:
    tok = _token()
    if not tok:
        runlog.log("publish", "FAIL", "no HF token in .env")
        return 1
    s = _latest_summary()
    if not s:
        runlog.log("publish", "WARN", "no iterate summary found")
        return 0
    summary = json.loads(s.read_text(encoding="utf-8"))
    rid = summary.get("run_id")

    # Ship gate: never push a run whose shipped GGUF failed the coherence check.
    # verified is False -> refuse; None (older run / verify skipped) -> allow the
    # adapter (it is the fp16 artifact, not the broken GGUF) but warn.
    gv = summary.get("gguf_verify") or {}
    if gv.get("verified") is False:
        runlog.log("publish", "FAIL", f"refusing to publish run {rid}: GGUF failed coherence "
                   f"gate (pass {gv.get('pass')}, {gv.get('detail','')[:120]})", run_id=rid)
        return 1

    try:
        from huggingface_hub import HfApi
        api = HfApi(token=tok)
        api.upload_file(path_or_fileobj=str(s),
                        path_in_repo=f"training-runs/iterate-summary-{rid}.json",
                        repo_id=REPO, commit_message=f"training run {rid} summary")
        best = summary.get("best_adapter")
        pushed = False
        if best and Path(best).exists():
            api.upload_folder(folder_path=best, path_in_repo=f"adapters/qwen3-1.7b-{rid}",
                              repo_id=REPO, commit_message=f"1.7b LoRA adapter from run {rid}")
            pushed = True
        _update_readme(api, _load_summaries())
        runlog.log("publish", "OK", f"pushed run {rid} (status={summary.get('status')}, "
                   f"adapter={pushed})", run_id=rid)
        return 0
    except Exception as e:
        runlog.log("publish", "FAIL", f"{type(e).__name__}: {e}", run_id=rid)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

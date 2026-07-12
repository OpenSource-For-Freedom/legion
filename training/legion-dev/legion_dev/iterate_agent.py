"""Time-boxed AGENTIC iterate loop — "train tool-use for N hours, keep the best".

Phase A: synthesize execution-verified tool trajectories (gold + fix).
Phase B: sweep QLoRA configs; each is scored by evaluate_agent — the model must
DRIVE the tool loop to green, not just emit one file. Keep the best by agentic
pass@1.

Self-healing: every cycle (train + eval) is wrapped; a failure logs and the sweep
continues with the best-so-far preserved. Eval OOM (the 8 GB card can't always
reload the model after training) frees VRAM and retries, then skips the cycle.
Designed to run under a durable Windows Scheduled Task so it survives session
teardown.

GPU scale-back: set LEGION_DEV_GPU_FRACTION (e.g. 0.8) to cap this process's VRAM
so other apps keep headroom; expandable_segments reduces fragmentation OOM.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import dataset_agent, promote as promote_mod, runlog
from .contracts import DEFAULT_TIER, TIERS

TRAINING_ROOT = Path(__file__).resolve().parents[1]

# Lighter than the single-file sweep — fewer, smaller configs (scale-back friendly,
# and the agentic dataset is small so more steps just overfit).
SWEEP = [
    {"rank": 16, "steps": 200, "lr": 2e-4, "cap_min": 60},
    {"rank": 32, "steps": 350, "lr": 2e-4, "cap_min": 80},
    {"rank": 32, "steps": 500, "lr": 1e-4, "cap_min": 90},
]
SWEEP_SMOKE = [{"rank": 8, "steps": 2, "lr": 2e-4, "cap_min": 5}]


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%SZ')}] {msg}", flush=True)


def _scale_back_gpu() -> None:
    """Leave the user some GPU: cap this process's VRAM fraction and reduce
    fragmentation. Call before any CUDA allocation."""
    os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")
    frac = os.environ.get("LEGION_DEV_GPU_FRACTION")
    if not frac:
        return
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.set_per_process_memory_fraction(float(frac), 0)
            log(f"GPU scale-back: capped to {float(frac):.0%} of VRAM")
    except Exception as e:
        log(f"GPU scale-back skipped: {e}")


def _free_vram() -> None:
    gc.collect()
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
    except Exception:
        pass


def _stop_ollama(model: str) -> None:
    """Evict the teacher from VRAM after dataset synthesis so training has the card."""
    import subprocess
    try:
        subprocess.run(["ollama", "stop", model], capture_output=True, timeout=60)
    except Exception:
        pass


def _better(a, b) -> bool:
    if b is None:
        return True
    return (a.gates_cleared, a.pass_rate, a.ran_tests) > (b.gates_cleared, b.pass_rate, b.ran_tests)


def _safe_agent_eval(base_model, adapter_dir, tier, run_id, cycle):
    """evaluate_agent with OOM self-heal: free VRAM and retry once, then give up
    on this cycle (best-so-far is preserved)."""
    from .evaluate_agent import evaluate_agent
    for attempt in range(2):
        try:
            return _free_vram() or evaluate_agent(base_model, adapter_dir, tier=tier)
        except Exception as e:
            msg = str(e).lower()
            if attempt == 0 and ("out of memory" in msg or "gpu ram" in msg or "cuda" in msg):
                log(f"  eval OOM; freeing VRAM and retrying once")
                _free_vram()
                continue
            runlog.log(cycle, "FAIL", f"agent eval error: {e}", run_id=run_id)
            return None
    return None


def parse_args(argv=None):
    p = argparse.ArgumentParser("legion_dev.iterate_agent")
    p.add_argument("--tier", default="legion-dev:qwen2.5-coder-1.5b")  # lighter default (scale-back)
    p.add_argument("--time-budget-min", type=float, default=120.0)
    p.add_argument("--teacher-model", default="qwen2.5-coder:7b")
    p.add_argument("--teacher-backend", default="reference",
                   choices=["reference", "model"],
                   help="reference = offline gold+starter-fix; model = also mine failing teacher samples")
    p.add_argument("--dataset-frac", type=float, default=0.25)
    p.add_argument("--max-examples", type=int, default=400)
    p.add_argument("--base-override", default=None)
    p.add_argument("--reports-dir", default=str(TRAINING_ROOT / "reports"))
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--fill-budget", action=argparse.BooleanOptionalAction, default=True,
                   help="after the config sweep, keep running fresh synth+sweep rounds until the "
                        "time budget is spent (default on). --no-fill-budget = single round.")
    p.add_argument("--patience", type=int, default=3,
                   help="with --fill-budget, stop early after this many rounds with no new best.")
    p.add_argument("--round-synth-min", type=float, default=12.0,
                   help="max minutes spent re-synthesising trajectories at the start of each extra round")
    p.add_argument("--publish", action="store_true",
                   help="on completion, push the best adapter + metrics card to HuggingFace "
                        "(so Legion Studio can pull the served model)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.tier not in TIERS:
        print(f"unknown tier {args.tier}")
        return 2
    _scale_back_gpu()

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Preflight: the agent's protocol must be coherent end to end (train -> eval -> serve),
    # else the run silently scores 0 or the served model can't be driven. Fail fast.
    from .agent_contracts import verify_serve_parity
    from .evaluate_agent import verify_contract
    problems = verify_contract() + verify_serve_parity()
    if problems:
        log("PREFLIGHT FAILED - agentic pieces are out of sync (train <-> eval <-> serve):")
        for pb in problems:
            log(f"  - {pb}")
        runlog.log("preflight", "FAIL", f"{len(problems)} contract issue(s)", run_id=run_id)
        return 3
    log("preflight OK: tools are trained, eval-executable, and served by the Studio in sync")

    t_start = time.monotonic()
    deadline = t_start + args.time_budget_min * 60.0
    data_dir = TRAINING_ROOT / ".work" / f"agent-{run_id}"
    data_dir.mkdir(parents=True, exist_ok=True)
    base_model = args.base_override or TIERS[args.tier]["hf_base"]
    sweep = SWEEP_SMOKE if args.smoke else SWEEP

    log(f"iterate_agent {run_id} tier={args.tier} base={base_model} "
        f"budget={args.time_budget_min}min teacher={args.teacher_backend} smoke={args.smoke}")
    runlog.log("start", "INFO", f"AGENT tier={args.tier} base={base_model} "
               f"budget={args.time_budget_min}min teacher={args.teacher_backend} smoke={args.smoke}", run_id=run_id)

    ds_stats = base_eval = best_eval = best_train = decision = None
    cycles = []
    status = "skipped"
    try:
        # --- Phase A+B in budget-filling rounds ---
        # Round 1 = standard trajectory synth + sweep. With --fill-budget (default),
        # keep starting fresh rounds (re-synthesise diverse trajectories, re-sweep, keep
        # the GLOBAL best) until the deadline, or until --patience rounds with no new best.
        from . import train as train_mod
        round_no = 0
        no_improve = 0
        while True:
            round_no += 1
            round_dir = data_dir / f"round{round_no}"
            round_dir.mkdir(parents=True, exist_ok=True)

            # Phase A: (re)synthesise this round's trajectories
            if round_no == 1:
                ds_deadline = t_start + args.time_budget_min * 60.0 * args.dataset_frac
            else:
                rem = max(60.0, deadline - time.monotonic())
                ds_deadline = time.monotonic() + min(rem * args.dataset_frac, args.round_synth_min * 60.0)
            log(f"round {round_no} phase A: trajectory synthesis")
            ds_stats = dataset_agent.build_agent_dataset(
                round_dir, teacher_backend=("reference" if args.smoke else args.teacher_backend),
                model=args.teacher_model, wrong_attempts=(1 if args.smoke else 2),
                max_examples=args.max_examples, deadline=ds_deadline)
            log(f"  trajectories: {ds_stats.train} train / {ds_stats.val} val / {ds_stats.test} test "
                f"(kinds {ds_stats.by_kind}, teacher_wrong {ds_stats.teacher_wrong})")
            runlog.log("dataset", "OK" if ds_stats.train else "WARN",
                       f"round{round_no}: {ds_stats.train} train/{ds_stats.val} val ({ds_stats.by_kind})",
                       run_id=run_id, kinds=ds_stats.by_kind, teacher_wrong=ds_stats.teacher_wrong)
            if args.teacher_backend == "model" and not args.smoke:
                _stop_ollama(args.teacher_model)
                _free_vram()

            # baseline eval once (round 1 only)
            if round_no == 1:
                log("baseline agentic eval (base, no adapter)")
                base_eval = _safe_agent_eval(base_model, None, args.tier, run_id, "baseline")
                if base_eval:
                    log(f"  baseline: pass@1 {base_eval.passed}/{base_eval.n} ran_tests={base_eval.ran_tests} "
                        f"mean_steps={base_eval.mean_steps:.1f}")
                    runlog.log("baseline", "INFO", f"pass@1 {base_eval.passed}/{base_eval.n} "
                               f"ran_tests={base_eval.ran_tests}", run_id=run_id,
                               pass_rate=round(base_eval.pass_rate, 3), ran_tests=base_eval.ran_tests)

            # Phase B: sweep configs for this round
            improved = False
            for i, cfg in enumerate(sweep, 1):
                if time.monotonic() >= deadline:
                    log("budget exhausted; stopping sweep")
                    break
                remaining = max(1.0, (deadline - time.monotonic()) / 60.0)
                cap = min(cfg["cap_min"], remaining)
                log(f"round {round_no} cycle {i}/{len(sweep)}: rank={cfg['rank']} steps={cfg['steps']} cap={cap:.0f}min")
                cyc_out = round_dir / f"cycle{i}"
                _free_vram()
                try:
                    tr = train_mod.train(round_dir, cyc_out, tier=args.tier, base_override=args.base_override,
                                         rank=cfg["rank"], alpha=cfg["rank"], steps=cfg["steps"],
                                         lr=cfg["lr"], time_budget_min=cap, smoke=args.smoke,
                                         assistant_only_loss=False)
                except Exception as e:
                    log(f"  train failed: {e}")
                    runlog.log(f"r{round_no}c{i}", "FAIL", f"train error: {e}", run_id=run_id)
                    cycles.append({"round": round_no, "cfg": cfg, "error": str(e)})
                    _free_vram()
                    continue
                log(f"  train: {tr.status} ({tr.steps_done} steps, {tr.seconds_used:.0f}s)")
                if tr.status == "skipped":
                    continue

                ce = _safe_agent_eval(base_model, tr.adapter_dir, args.tier, run_id, f"r{round_no}c{i}")
                if ce is None:
                    cycles.append({"round": round_no, "cfg": cfg, "train": tr.status, "eval": "failed"})
                    continue
                log(f"  eval: pass@1 {ce.passed}/{ce.n} ran_tests={ce.ran_tests}/{ce.n} "
                    f"wrote_file={ce.wrote_file}/{ce.n} mean_steps={ce.mean_steps:.1f}")
                runlog.log(f"r{round_no}c{i}", "OK", f"rank={cfg['rank']} steps={cfg['steps']} "
                           f"pass@1 {ce.passed}/{ce.n} ran_tests={ce.ran_tests}", run_id=run_id,
                           pass_rate=round(ce.pass_rate, 3), ran_tests=ce.ran_tests, mean_steps=ce.mean_steps)
                cycles.append({"round": round_no, "cfg": cfg, "train": tr.status, "eval": ce.summary()})
                if _better(ce, best_eval):
                    best_eval, best_train = ce, tr
                    improved = True
                    log(f"  ** new best (pass {ce.passed}/{ce.n}, ran_tests {ce.ran_tests}) **")
                    runlog.log(f"r{round_no}c{i}", "INFO", f"NEW BEST pass {ce.passed}/{ce.n}", run_id=run_id)

            # --- round stop conditions ---
            if time.monotonic() >= deadline:
                log(f"budget reached after {round_no} round(s)")
                break
            if not args.fill_budget:
                break
            if improved:
                no_improve = 0
            else:
                no_improve += 1
                log(f"round {round_no}: no new best ({no_improve}/{args.patience} before early stop)")
                if no_improve >= args.patience:
                    log(f"no improvement in {args.patience} rounds; stopping early")
                    runlog.log("run", "INFO", f"early stop: {args.patience} rounds no improvement", run_id=run_id)
                    break

        decision = promote_mod.decide(best_eval, base_eval) if (best_eval and base_eval) else None
        status = "ok" if best_eval else ("partial" if (ds_stats and ds_stats.train) else "skipped")
    except Exception as e:
        import traceback
        traceback.print_exc()
        status = "crash"
        runlog.log("run", "FAIL", f"CRASH: {type(e).__name__}: {e}", run_id=run_id)

    cfg_meta = {"run_id": run_id, "track": "agent", "tier": args.tier, "base_model": base_model,
                "teacher_backend": args.teacher_backend, "time_budget_min": args.time_budget_min,
                "smoke": args.smoke, "wall_clock_min": round((time.monotonic() - t_start) / 60, 1),
                "cycles": len(cycles)}
    summary = {"run_id": run_id, "status": status, "config": cfg_meta,
               "dataset": asdict(ds_stats) if ds_stats else None,
               "baseline_eval": base_eval.summary() if base_eval else None,
               "best_eval": best_eval.summary() if best_eval else None,
               "best_adapter": best_train.adapter_dir if best_train else None,
               "promote": asdict(decision) if decision else None, "cycles": cycles}
    Path(args.reports_dir).mkdir(parents=True, exist_ok=True)
    (Path(args.reports_dir) / f"agent-summary-{run_id}.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    log(f"DONE status={status}")
    runlog.log("run", "DONE", f"AGENT {status.upper()} "
               f"best={(str(best_eval.passed)+'/'+str(best_eval.n)) if best_eval else 'none'}",
               run_id=run_id, result=status, cycles=len(cycles))

    if args.publish:
        log("publish: pushing best adapter + card to HuggingFace (for Legion Studio to pull)")
        try:
            from . import publish as publish_mod
            publish_mod.main()
        except Exception as e:
            runlog.log("publish", "FAIL", f"{type(e).__name__}: {e}", run_id=run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

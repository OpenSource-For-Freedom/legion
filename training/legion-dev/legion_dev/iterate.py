"""
Time-boxed iterate loop — "train for N hours and keep the best".

Phase A: synthesise a quality dataset with a strong local coder teacher
(qwen2.5-coder:7b) + template fallback, multi-phrasing, bounded to a fraction of
the budget.
Phase B: sweep QLoRA configs; train each, score the adapter against its base via
the transformers eval path, keep the best. Every milestone is logged to
logs/runs.log (success + failure), and a crash is logged too.

  python -m legion_dev.iterate --tier legion-dev:qwen2.5-coder-1.5b \
      --time-budget-min 360 --teacher-model qwen2.5-coder:7b
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import dataset as dataset_mod
from . import evaluate_hf as ehf
from . import promote as promote_mod
from . import report as report_mod
from . import runlog
from .contracts import DEFAULT_TIER, TIERS

TRAINING_ROOT = Path(__file__).resolve().parents[1]


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%SZ')}] {msg}", flush=True)


def stop_ollama(model: str) -> None:
    try:
        subprocess.run(["ollama", "stop", model], capture_output=True,
                       encoding="utf-8", errors="replace", timeout=60)
    except Exception:
        pass


SWEEP = [
    {"rank": 16, "steps": 150, "lr": 2e-4, "cap_min": 45},
    {"rank": 32, "steps": 250, "lr": 2e-4, "cap_min": 60},
    {"rank": 32, "steps": 400, "lr": 1e-4, "cap_min": 70},
    {"rank": 64, "steps": 300, "lr": 2e-4, "cap_min": 70},
    {"rank": 64, "steps": 500, "lr": 1e-4, "cap_min": 80},
    {"rank": 32, "steps": 600, "lr": 2e-4, "cap_min": 80},
]
SWEEP_SMOKE = [{"rank": 8, "steps": 2, "lr": 2e-4, "cap_min": 5}]


def _better(a, b) -> bool:
    if b is None:
        return True
    return (a.gates_cleared, a.pass_rate, a.had_code) > (b.gates_cleared, b.pass_rate, b.had_code)


def parse_args(argv=None):
    p = argparse.ArgumentParser("legion_dev.iterate")
    p.add_argument("--tier", default=DEFAULT_TIER)
    p.add_argument("--time-budget-min", type=float, default=120.0)
    p.add_argument("--teacher-model", default="qwen2.5-coder:7b")
    p.add_argument("--dataset-frac", type=float, default=0.4)
    p.add_argument("--instructions-per", type=int, default=3,
                   help="verified solutions to sample per training task")
    p.add_argument("--max-examples", type=int, default=600)
    p.add_argument("--base-override", default=None)
    p.add_argument("--reports-dir", default=str(TRAINING_ROOT / "reports"))
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--publish", action="store_true",
                   help="push the result (adapter + summary + model-card metrics) to HuggingFace on completion")
    p.add_argument("--fill-budget", action=argparse.BooleanOptionalAction, default=True,
                   help="after the config sweep, keep running fresh synth+sweep rounds until the "
                        "time budget is spent (default on). --no-fill-budget = single round (old behavior).")
    p.add_argument("--patience", type=int, default=3,
                   help="with --fill-budget, stop early after this many rounds with no new best "
                        "(data exhausted). Set high to force full-budget use.")
    p.add_argument("--round-synth-min", type=float, default=12.0,
                   help="max minutes spent re-synthesising data at the start of each extra round")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.tier not in TIERS:
        print(f"unknown tier {args.tier}")
        return 2

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    t_start = time.monotonic()
    deadline = t_start + args.time_budget_min * 60.0
    data_dir = TRAINING_ROOT / ".work" / f"iter-{run_id}"
    data_dir.mkdir(parents=True, exist_ok=True)
    base_model = args.base_override or TIERS[args.tier]["hf_base"]
    sweep = SWEEP_SMOKE if args.smoke else SWEEP

    log(f"iterate {run_id} tier={args.tier} base={base_model} budget={args.time_budget_min}min "
        f"teacher={args.teacher_model} smoke={args.smoke}")
    runlog.log("start", "INFO", f"tier={args.tier} base={base_model} "
               f"budget={args.time_budget_min}min teacher={args.teacher_model} smoke={args.smoke}",
               run_id=run_id)

    ds_stats = base_eval = best_eval = best_train = decision = None
    cycles = []
    status = "skipped"
    try:
        # --- Phase A+B in budget-filling rounds ---
        # Round 1 = standard synth + sweep. With --fill-budget (default), keep
        # starting fresh rounds (re-synthesise diverse teacher data, re-sweep, keep
        # the GLOBAL best) until the deadline, or until --patience rounds pass with
        # no new best (data exhausted -> no point burning the clock).
        from . import train as train_mod
        round_no = 0
        no_improve = 0
        while True:
            round_no += 1
            round_dir = data_dir / f"round{round_no}"
            round_dir.mkdir(parents=True, exist_ok=True)

            # Phase A: (re)synthesise this round's dataset
            if round_no == 1:
                ds_deadline = t_start + args.time_budget_min * 60.0 * args.dataset_frac
            else:
                rem = max(60.0, deadline - time.monotonic())
                ds_deadline = time.monotonic() + min(rem * args.dataset_frac, args.round_synth_min * 60.0)
            log(f"round {round_no} phase A: dataset synthesis")
            ds_stats = dataset_mod.build_dataset(
                round_dir, instructions_per=(1 if args.smoke else args.instructions_per),
                max_examples=args.max_examples,
                teacher_backend=("reference" if args.smoke else "hybrid"),
                model=args.teacher_model, attempts=(2 if args.smoke else 5), deadline=ds_deadline)
            log(f"  dataset: {ds_stats.train} train / {ds_stats.val} val / {ds_stats.test} test "
                f"(accepted {ds_stats.accepted}/{ds_stats.candidates}, rejected {ds_stats.rejected})")
            runlog.log("dataset", "OK" if ds_stats.accepted else "WARN",
                       f"round{round_no}: {ds_stats.train} train/{ds_stats.val} val/{ds_stats.test} test",
                       run_id=run_id, accepted=ds_stats.accepted, rejected=ds_stats.rejected,
                       by_backend=ds_stats.by_backend)
            stop_ollama(args.teacher_model)

            # baseline eval once (round 1 only)
            if round_no == 1:
                log("baseline eval (base, no adapter)")
                try:
                    base_eval = ehf.evaluate_hf(base_model, None, tier=args.tier)
                    log(f"  baseline: pass@1 {base_eval.passed}/{base_eval.n} gates={base_eval.gates_cleared}")
                    runlog.log("baseline", "INFO", f"pass@1 {base_eval.passed}/{base_eval.n}",
                               run_id=run_id, gates=base_eval.gates_cleared,
                               pass_rate=round(base_eval.pass_rate, 3))
                except Exception as e:
                    log(f"  baseline eval failed: {e}")
                    runlog.log("baseline", "WARN", f"eval failed: {e}", run_id=run_id)

            # Phase B: sweep configs for this round
            improved = False
            for i, cfg in enumerate(sweep, 1):
                if time.monotonic() >= deadline:
                    log("budget exhausted; stopping sweep")
                    runlog.log(f"r{round_no}c{i}", "INFO", "budget exhausted; stopping", run_id=run_id)
                    break
                remaining = max(1.0, (deadline - time.monotonic()) / 60.0)
                cap = min(cfg["cap_min"], remaining)
                log(f"round {round_no} cycle {i}/{len(sweep)}: rank={cfg['rank']} steps={cfg['steps']} "
                    f"lr={cfg['lr']} cap={cap:.0f}min (remaining {remaining:.0f}min)")
                cyc_out = round_dir / f"cycle{i}"
                try:
                    tr = train_mod.train(round_dir, cyc_out, tier=args.tier, base_override=args.base_override,
                                         rank=cfg["rank"], alpha=cfg["rank"], steps=cfg["steps"],
                                         lr=cfg["lr"], time_budget_min=cap, smoke=args.smoke)
                except Exception as e:
                    log(f"  train failed: {e}")
                    runlog.log(f"r{round_no}c{i}", "FAIL", f"train error: {e}", run_id=run_id)
                    cycles.append({"round": round_no, "cfg": cfg, "error": str(e)})
                    continue
                log(f"  train: {tr.status} ({tr.steps_done} steps, {tr.seconds_used:.0f}s)")
                if tr.status == "skipped":
                    continue
                try:
                    ce = ehf.evaluate_hf(base_model, tr.adapter_dir, tier=args.tier)
                except Exception as e:
                    log(f"  eval failed: {e}")
                    runlog.log(f"r{round_no}c{i}", "FAIL", f"eval error: {e}", run_id=run_id)
                    cycles.append({"round": round_no, "cfg": cfg, "train": tr.status, "error": str(e)})
                    continue
                log(f"  eval: pass@1 {ce.passed}/{ce.n} gates={ce.gates_cleared} "
                    f"code={ce.had_code}/{ce.n}")
                runlog.log(f"r{round_no}c{i}", "OK", f"rank={cfg['rank']} steps={cfg['steps']} "
                           f"pass@1 {ce.passed}/{ce.n}", run_id=run_id, gates=ce.gates_cleared,
                           pass_rate=round(ce.pass_rate, 3), had_code=ce.had_code)
                cycles.append({"round": round_no, "cfg": cfg, "train": tr.status, "eval": ce.summary()})
                if _better(ce, best_eval):
                    best_eval, best_train = ce, tr
                    improved = True
                    log(f"  ** new best (pass {ce.passed}/{ce.n}, gates={ce.gates_cleared}) **")
                    runlog.log(f"r{round_no}c{i}", "INFO", f"NEW BEST pass {ce.passed}/{ce.n} gates={ce.gates_cleared}",
                               run_id=run_id)

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
                    log(f"no improvement in {args.patience} rounds; data likely exhausted, stopping early")
                    runlog.log("run", "INFO", f"early stop: {args.patience} rounds no improvement", run_id=run_id)
                    break

        decision = promote_mod.decide(best_eval, base_eval) if best_eval else None
        status = "ok" if best_eval else ("partial" if (ds_stats and ds_stats.accepted) else "skipped")
    except Exception as e:
        import traceback
        traceback.print_exc()
        status = "crash"
        runlog.log("run", "FAIL", f"CRASH: {type(e).__name__}: {e}", run_id=run_id)

    cfg_meta = {"run_id": run_id, "tier": args.tier, "base_model": base_model,
                "teacher_model": args.teacher_model, "time_budget_min": args.time_budget_min,
                "instructions_per": args.instructions_per, "smoke": args.smoke,
                "wall_clock_min": round((time.monotonic() - t_start) / 60, 1), "cycles": len(cycles)}
    report_path = report_mod.write_report(args.reports_dir, f"iterate-{run_id}", status=status,
                                          config=cfg_meta, ds_stats=ds_stats, train_result=best_train,
                                          candidate_eval=best_eval, baseline_eval=base_eval,
                                          promote_decision=decision)
    summary = {"run_id": run_id, "status": status, "config": cfg_meta,
               "dataset": asdict(ds_stats) if ds_stats else None,
               "baseline_eval": base_eval.summary() if base_eval else None,
               "best_eval": best_eval.summary() if best_eval else None,
               "best_adapter": best_train.adapter_dir if best_train else None,
               "promote": asdict(decision) if decision else None, "cycles": cycles}
    (Path(args.reports_dir) / f"iterate-summary-{run_id}.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    log(f"DONE status={status} report={report_path}")
    runlog.log("run", "DONE", f"{status.upper()} "
               f"best={(str(best_eval.passed)+'/'+str(best_eval.n)) if best_eval else 'none'} "
               f"report={report_path}", run_id=run_id, result=status, cycles=len(cycles))

    if args.publish:
        log("publish: pushing result to HuggingFace")
        try:
            from . import publish as publish_mod
            publish_mod.main()
        except Exception as e:
            runlog.log("publish", "FAIL", f"{type(e).__name__}: {e}", run_id=run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

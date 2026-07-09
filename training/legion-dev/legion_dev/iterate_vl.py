"""
Time-boxed vision iterate loop — the multimodal twin of iterate.py. Renders
screenshots, synthesizes execution-verified image+code data, sweeps QLoRA configs
on Qwen2.5-VL, and keeps the best adapter by pass@1 (execution).

  python -m legion_dev.iterate_vl --tier legion-dev-vl:qwen2.5-vl-3b \
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

from . import dataset_vl as ds_vl
from . import evaluate_vl as evl
from . import promote as promote_mod
from . import report as report_mod
from . import runlog
from .contracts import DEFAULT_VL_TIER, VL_TIERS

TRAINING_ROOT = Path(__file__).resolve().parents[1]

SWEEP = [
    {"rank": 8, "steps": 150, "lr": 1e-4, "cap_min": 60},
    {"rank": 16, "steps": 250, "lr": 1e-4, "cap_min": 80},
    {"rank": 16, "steps": 400, "lr": 5e-5, "cap_min": 90},
]
SWEEP_SMOKE = [{"rank": 8, "steps": 2, "lr": 1e-4, "cap_min": 5}]


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%SZ')}] {msg}", flush=True)


def stop_ollama(model: str) -> None:
    try:
        subprocess.run(["ollama", "stop", model], capture_output=True,
                       encoding="utf-8", errors="replace", timeout=60)
    except Exception:
        pass


def _better(a, b) -> bool:
    if b is None:
        return True
    return (a.gates_cleared, a.pass_rate, a.had_code) > (b.gates_cleared, b.pass_rate, b.had_code)


def parse_args(argv=None):
    p = argparse.ArgumentParser("legion_dev.iterate_vl")
    p.add_argument("--tier", default=DEFAULT_VL_TIER)
    p.add_argument("--time-budget-min", type=float, default=180.0)
    p.add_argument("--teacher-model", default="qwen2.5-coder:7b")
    p.add_argument("--dataset-frac", type=float, default=0.4)
    p.add_argument("--instructions-per", type=int, default=3)
    p.add_argument("--kind", choices=["code", "terminal"], default="code",
                   help="screenshot content: the buggy file, or the failing test output")
    p.add_argument("--max-examples", type=int, default=600)
    p.add_argument("--base-override", default=None)
    p.add_argument("--reports-dir", default=str(TRAINING_ROOT / "reports"))
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--publish", action="store_true")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.tier not in VL_TIERS:
        print(f"unknown VL tier {args.tier}")
        return 2

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    t_start = time.monotonic()
    deadline = t_start + args.time_budget_min * 60.0
    data_dir = TRAINING_ROOT / ".work" / f"itervl-{run_id}"
    data_dir.mkdir(parents=True, exist_ok=True)
    base_model = args.base_override or VL_TIERS[args.tier]["hf_base"]
    sweep = SWEEP_SMOKE if args.smoke else SWEEP

    log(f"iterate_vl {run_id} tier={args.tier} base={base_model} budget={args.time_budget_min}min "
        f"teacher={args.teacher_model} kind={args.kind} smoke={args.smoke}")
    runlog.log("start", "INFO", f"VL tier={args.tier} base={base_model} kind={args.kind}", run_id=run_id)

    ds_stats = base_eval = best_eval = best_train = decision = None
    cycles = []
    status = "skipped"
    try:
        ds_deadline = t_start + args.time_budget_min * 60.0 * args.dataset_frac
        log("phase A: screenshot + verified dataset synthesis")
        ds_stats = ds_vl.build_vl_dataset(
            data_dir, kind=args.kind,
            instructions_per=(1 if args.smoke else args.instructions_per),
            max_examples=args.max_examples,
            teacher_backend=("reference" if args.smoke else "hybrid"),
            model=args.teacher_model, attempts=(2 if args.smoke else 5), deadline=ds_deadline)
        log(f"  dataset: {ds_stats.train} train / {ds_stats.val} val / {ds_stats.test} test "
            f"(accepted {ds_stats.accepted}/{ds_stats.candidates})")
        runlog.log("dataset", "OK" if ds_stats.accepted else "WARN",
                   f"{ds_stats.train} train/{ds_stats.val} val/{ds_stats.test} test",
                   run_id=run_id, accepted=ds_stats.accepted, rejected=ds_stats.rejected)
        stop_ollama(args.teacher_model)

        from . import train_vl as train_mod

        log("baseline VL eval (base, no adapter)")
        try:
            base_eval = evl.evaluate_vl(base_model, None, tier=args.tier, work_dir=data_dir, kind=args.kind)
            log(f"  baseline: pass@1 {base_eval.passed}/{base_eval.n} gates={base_eval.gates_cleared}")
            runlog.log("baseline", "INFO", f"pass@1 {base_eval.passed}/{base_eval.n}",
                       run_id=run_id, gates=base_eval.gates_cleared, pass_rate=round(base_eval.pass_rate, 3))
        except Exception as e:
            log(f"  baseline eval failed: {e}")
            runlog.log("baseline", "WARN", f"eval failed: {e}", run_id=run_id)

        for i, cfg in enumerate(sweep, 1):
            if time.monotonic() >= deadline:
                log("budget exhausted; stopping sweep")
                break
            remaining = max(1.0, (deadline - time.monotonic()) / 60.0)
            cap = min(cfg["cap_min"], remaining)
            log(f"cycle {i}/{len(sweep)}: rank={cfg['rank']} steps={cfg['steps']} lr={cfg['lr']} cap={cap:.0f}min")
            cyc_out = data_dir / f"cycle{i}"
            try:
                tr = train_mod.train_vl(data_dir, cyc_out, tier=args.tier, base_override=args.base_override,
                                        rank=cfg["rank"], alpha=cfg["rank"], steps=cfg["steps"],
                                        lr=cfg["lr"], time_budget_min=cap, smoke=args.smoke)
            except Exception as e:
                log(f"  train failed: {e}")
                runlog.log(f"cycle{i}", "FAIL", f"train error: {e}", run_id=run_id)
                cycles.append({"cfg": cfg, "error": str(e)})
                continue
            log(f"  train: {tr.status} ({tr.steps_done} steps, {tr.seconds_used:.0f}s)")
            if tr.status == "skipped":
                continue
            try:
                ce = evl.evaluate_vl(base_model, tr.adapter_dir, tier=args.tier, work_dir=data_dir, kind=args.kind)
            except Exception as e:
                log(f"  eval failed: {e}")
                runlog.log(f"cycle{i}", "FAIL", f"eval error: {e}", run_id=run_id)
                cycles.append({"cfg": cfg, "train": tr.status, "error": str(e)})
                continue
            log(f"  eval: pass@1 {ce.passed}/{ce.n} gates={ce.gates_cleared} code={ce.had_code}/{ce.n}")
            runlog.log(f"cycle{i}", "OK", f"rank={cfg['rank']} pass@1 {ce.passed}/{ce.n}",
                       run_id=run_id, gates=ce.gates_cleared, pass_rate=round(ce.pass_rate, 3))
            cycles.append({"cfg": cfg, "train": tr.status, "eval": ce.summary()})
            if _better(ce, best_eval):
                best_eval, best_train = ce, tr
                log(f"  ** new best (pass@1 {ce.passed}/{ce.n}) **")

        decision = promote_mod.decide(best_eval, base_eval) if best_eval else None
        status = "ok" if best_eval else ("partial" if (ds_stats and ds_stats.accepted) else "skipped")
    except Exception as e:
        import traceback
        traceback.print_exc()
        status = "crash"
        runlog.log("run", "FAIL", f"CRASH: {type(e).__name__}: {e}", run_id=run_id)

    cfg_meta = {"run_id": run_id, "tier": args.tier, "base_model": base_model, "modality": "vision",
                "teacher_model": args.teacher_model, "kind": args.kind, "time_budget_min": args.time_budget_min,
                "instructions_per": args.instructions_per, "smoke": args.smoke,
                "wall_clock_min": round((time.monotonic() - t_start) / 60, 1), "cycles": len(cycles)}
    report_path = report_mod.write_report(args.reports_dir, f"iterate-vl-{run_id}", status=status,
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
    runlog.log("run", "DONE", f"{status.upper()} report={report_path}", run_id=run_id, result=status)

    if args.publish:
        try:
            from . import publish as publish_mod
            publish_mod.main()
        except Exception as e:
            runlog.log("publish", "FAIL", f"{type(e).__name__}: {e}", run_id=run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

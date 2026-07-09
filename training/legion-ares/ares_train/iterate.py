"""
Time-boxed iterate loop — "train for N hours and keep the best".

Phase A: synthesise a quality dataset with a strong local teacher (qwen3:14b) +
template fallback, multi-phrasing, bounded to a fraction of the budget.
Phase B: sweep QLoRA configs; train each, score the adapter against its base via
the transformers eval path, keep the best. Every milestone is logged to
logs/runs.log (success + failure), and a crash is logged too.

  python -m ares_train.iterate --tier legion-ares:qwen3-1.7b --time-budget-min 360 \
      --teacher-model qwen3:14b
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
    return (a.gates_cleared, a.pass_rate, -a.invented_total) > (b.gates_cleared, b.pass_rate, -b.invented_total)


def parse_args(argv=None):
    p = argparse.ArgumentParser("ares_train.iterate")
    p.add_argument("--tier", default=DEFAULT_TIER)
    p.add_argument("--time-budget-min", type=float, default=120.0)
    p.add_argument("--teacher-model", default="qwen3:14b")
    p.add_argument("--dataset-frac", type=float, default=0.4)
    p.add_argument("--instructions-per", type=int, default=3)
    p.add_argument("--n-per", type=int, default=8)
    p.add_argument("--max-examples", type=int, default=600)
    p.add_argument("--base-override", default=None)
    p.add_argument("--reports-dir", default=str(TRAINING_ROOT / "reports"))
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--publish", action="store_true",
                   help="push the result (adapter + summary + model-card metrics) to HuggingFace on completion")
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
    gguf_verify = None
    cycles = []
    status = "skipped"
    try:
        # --- Phase A: dataset ---
        ds_deadline = t_start + args.time_budget_min * 60.0 * args.dataset_frac
        log("phase A: dataset synthesis")
        ds_stats = dataset_mod.build_dataset(
            data_dir, n_per=args.n_per,
            instructions_per=(1 if args.smoke else args.instructions_per),
            max_examples=args.max_examples,
            teacher_backend=("template" if args.smoke else "hybrid"),
            model=args.teacher_model, attempts=2, deadline=ds_deadline)
        log(f"  dataset: {ds_stats.train} train / {ds_stats.val} val / {ds_stats.test} test "
            f"(accepted {ds_stats.accepted}/{ds_stats.candidates}, rejected {ds_stats.rejected})")
        runlog.log("dataset", "OK" if ds_stats.accepted else "WARN",
                   f"{ds_stats.train} train/{ds_stats.val} val/{ds_stats.test} test",
                   run_id=run_id, accepted=ds_stats.accepted, rejected=ds_stats.rejected,
                   by_backend=ds_stats.by_backend)
        stop_ollama(args.teacher_model)

        from . import train as train_mod

        log("baseline eval (base, no adapter)")
        try:
            base_eval = ehf.evaluate_hf(base_model, None, n_per=args.n_per, tier=args.tier)
            log(f"  baseline: pass {base_eval.passed}/{base_eval.n} gates={base_eval.gates_cleared}")
            runlog.log("baseline", "INFO", f"pass {base_eval.passed}/{base_eval.n}",
                       run_id=run_id, gates=base_eval.gates_cleared, invented=base_eval.invented_total,
                       grounding=round(base_eval.grounding, 3))
        except Exception as e:
            log(f"  baseline eval failed: {e}")
            runlog.log("baseline", "WARN", f"eval failed: {e}", run_id=run_id)

        # --- Phase B: sweep ---
        for i, cfg in enumerate(sweep, 1):
            if time.monotonic() >= deadline:
                log("budget exhausted; stopping sweep")
                runlog.log(f"cycle{i}", "INFO", "budget exhausted; stopping", run_id=run_id)
                break
            remaining = max(1.0, (deadline - time.monotonic()) / 60.0)
            cap = min(cfg["cap_min"], remaining)
            log(f"cycle {i}/{len(sweep)}: rank={cfg['rank']} steps={cfg['steps']} "
                f"lr={cfg['lr']} cap={cap:.0f}min (remaining {remaining:.0f}min)")
            cyc_out = data_dir / f"cycle{i}"
            try:
                tr = train_mod.train(data_dir, cyc_out, tier=args.tier, base_override=args.base_override,
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
                ce = ehf.evaluate_hf(base_model, tr.adapter_dir, n_per=args.n_per, tier=args.tier)
            except Exception as e:
                log(f"  eval failed: {e}")
                runlog.log(f"cycle{i}", "FAIL", f"eval error: {e}", run_id=run_id)
                cycles.append({"cfg": cfg, "train": tr.status, "error": str(e)})
                continue
            log(f"  eval: pass {ce.passed}/{ce.n} gates={ce.gates_cleared} inv={ce.invented_total} "
                f"grnd={ce.grounding:.2f} cit={ce.citation_coverage:.2f} ap={ce.anti_parrot:.2f}")
            runlog.log(f"cycle{i}", "OK", f"rank={cfg['rank']} steps={cfg['steps']} "
                       f"pass {ce.passed}/{ce.n}", run_id=run_id, gates=ce.gates_cleared,
                       invented=ce.invented_total, grounding=round(ce.grounding, 3),
                       citation=round(ce.citation_coverage, 3), anti_parrot=round(ce.anti_parrot, 3))
            cycles.append({"cfg": cfg, "train": tr.status, "eval": ce.summary()})
            if _better(ce, best_eval):
                best_eval, best_train = ce, tr
                log(f"  ** new best (pass {ce.passed}/{ce.n}, gates={ce.gates_cleared}) **")
                runlog.log(f"cycle{i}", "INFO", f"NEW BEST pass {ce.passed}/{ce.n} gates={ce.gates_cleared}",
                           run_id=run_id)

        # --- Phase C: build the best adapter's GGUF and verify it in Ollama ---
        # Scores the *shipped* artifact (quant + chat template) with the coherence
        # gate, so a template/quant break can never pass selection again. Fully
        # guarded: a build/verify failure downgrades status but never crashes.
        if best_train is not None:
            try:
                from . import build as build_mod
                log("phase C: build + verify best adapter GGUF in Ollama")
                vtag = f"legion-ares-verify:{args.tier.split('-')[-1]}-{run_id}"
                br = build_mod.build_model(best_train.adapter_dir, data_dir / "ggufbuild",
                                           tier=args.tier, tag=vtag, base_model=base_model, verify=True)
                gguf_verify = {"status": br.status, "verified": br.verified,
                               "pass": br.verify_pass, "method": br.method, "quant": TIERS[args.tier].get("quant"),
                               "detail": (br.detail or "")[:300]}
                log(f"  gguf build={br.status} verified={br.verified} pass={br.verify_pass}")
                runlog.log("verify", "OK" if br.verified else "FAIL",
                           f"gguf {br.status} verified={br.verified} pass={br.verify_pass}", run_id=run_id)
                # prune the throwaway verify tag (rebuildable from the saved adapter)
                try:
                    subprocess.run(["ollama", "rm", vtag], capture_output=True, timeout=30)
                except Exception:
                    pass
            except Exception as e:
                log(f"  gguf build/verify skipped: {e}")
                runlog.log("verify", "WARN", f"skipped: {e}", run_id=run_id)

        decision = promote_mod.decide(best_eval, base_eval) if best_eval else None
        status = "ok" if best_eval else ("partial" if (ds_stats and ds_stats.accepted) else "skipped")
        if gguf_verify and gguf_verify.get("verified") is False:
            status = "gguf-degenerate"  # fp16 adapter is good but the shipped GGUF is not
    except Exception as e:
        import traceback
        traceback.print_exc()
        status = "crash"
        runlog.log("run", "FAIL", f"CRASH: {type(e).__name__}: {e}", run_id=run_id)

    cfg_meta = {"run_id": run_id, "tier": args.tier, "base_model": base_model,
                "teacher_model": args.teacher_model, "time_budget_min": args.time_budget_min,
                "instructions_per": args.instructions_per, "n_per": args.n_per, "smoke": args.smoke,
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
               "gguf_verify": gguf_verify,
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

"""
Orchestrator — single end-to-end Ares LoRA run, single-flight + time-boxed.
Stages: dataset -> train -> build -> eval -> promote -> report. Logs every
milestone (success/failure) to logs/runs.log via runlog.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import build as build_mod
from . import dataset as dataset_mod
from . import evaluate as eval_mod
from . import ollama_client as oc
from . import promote as promote_mod
from . import report as report_mod
from . import runlog
from .contracts import DEFAULT_TIER, TIERS, is_blocked

TRAINING_ROOT = Path(__file__).resolve().parents[1]


def _envf(name, default):
    v = os.environ.get(name)
    return type(default)(v) if v not in (None, "") else default


def parse_args(argv=None):
    p = argparse.ArgumentParser("ares_train.run")
    p.add_argument("--tier", default=os.environ.get("LEGION_LORA_TIER", DEFAULT_TIER))
    p.add_argument("--time-budget-min", type=float, default=_envf("LEGION_LORA_TIME_BUDGET_MIN", 30.0))
    p.add_argument("--steps", type=int, default=_envf("LEGION_LORA_STEPS", 200))
    p.add_argument("--rank", type=int, default=_envf("LEGION_LORA_RANK", 32))
    p.add_argument("--max-examples", type=int, default=_envf("LEGION_LORA_MAX_EXAMPLES", 256))
    p.add_argument("--n-per", type=int, default=_envf("LEGION_LORA_N_PER", 8))
    p.add_argument("--teacher", choices=["hybrid", "model", "template"],
                   default=os.environ.get("LEGION_LORA_TEACHER", "hybrid"))
    p.add_argument("--model", default=os.environ.get("LEGION_LORA_TEACHER_MODEL", DEFAULT_TIER))
    p.add_argument("--candidate-tag", default=None)
    p.add_argument("--base-override", default=None)
    p.add_argument("--stages", default="dataset,train,build,eval,promote")
    p.add_argument("--data-dir", default=None)
    p.add_argument("--reports-dir", default=str(TRAINING_ROOT / "reports"))
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--force", action="store_true")
    return p.parse_args(argv)


class Lock:
    def __init__(self, path, force):
        self.path, self.force = path, force

    def __enter__(self):
        if self.path.exists() and not self.force:
            raise SystemExit(f"another run holds the lock {self.path}; use --force")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(str(os.getpid()), encoding="utf-8")
        return self

    def __exit__(self, *exc):
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def main(argv=None) -> int:
    args = parse_args(argv)
    if is_blocked(args.tier):
        print(f"tier {args.tier} is policy-blocked", file=sys.stderr)
        return 2
    if args.tier not in TIERS:
        print(f"unknown tier {args.tier}", file=sys.stderr)
        return 2

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stages = {s.strip() for s in args.stages.split(",") if s.strip()}
    data_dir = Path(args.data_dir or (TRAINING_ROOT / ".work" / run_id))
    size = args.tier.split("-")[-1]
    candidate_tag = args.candidate_tag or f"legion-ares:{size}-{run_id}"
    cfg = {"run_id": run_id, "tier": args.tier, "candidate_tag": candidate_tag,
           "time_budget_min": args.time_budget_min, "steps": args.steps, "rank": args.rank,
           "n_per": args.n_per, "teacher": args.teacher, "stages": sorted(stages),
           "smoke": args.smoke, "ollama_up": oc.is_up()}
    print(f"[run {run_id}] config: {cfg}")
    runlog.log("start", "INFO", f"tier={args.tier} budget={args.time_budget_min}min "
               f"teacher={args.teacher}/{args.model}", run_id=run_id)

    ds_stats = train_result = build_result = cand_eval = base_eval = decision = None
    status = "ok"
    try:
        with Lock(TRAINING_ROOT / ".work" / "lora.lock", args.force):
            if "dataset" in stages:
                ds_stats = dataset_mod.build_dataset(data_dir, n_per=args.n_per,
                                                     max_examples=args.max_examples,
                                                     teacher_backend=args.teacher, model=args.model)
                runlog.log("dataset", "OK" if ds_stats.accepted else "WARN",
                           f"{ds_stats.train} train/{ds_stats.val} val/{ds_stats.test} test",
                           run_id=run_id, accepted=ds_stats.accepted, rejected=ds_stats.rejected)

            if "train" in stages:
                from . import train as train_mod
                train_result = train_mod.train(data_dir, data_dir, tier=args.tier,
                                               base_override=args.base_override, rank=args.rank,
                                               steps=args.steps, time_budget_min=args.time_budget_min,
                                               smoke=args.smoke)
                runlog.log("train", "OK" if train_result.status != "skipped" else "WARN",
                           f"{train_result.status} {train_result.steps_done} steps "
                           f"{train_result.seconds_used:.0f}s", run_id=run_id)
                if train_result.status == "skipped":
                    status = "skipped"

            if "build" in stages and train_result and train_result.status != "skipped":
                build_result = build_mod.build_model(train_result.adapter_dir, data_dir,
                                                     tier=args.tier, tag=candidate_tag,
                                                     base_model=train_result.base_model)
                runlog.log("build", "OK" if build_result.status == "ok" else "FAIL",
                           f"{build_result.status} via {build_result.method} -> {build_result.tag}",
                           run_id=run_id)

            if "eval" in stages:
                eval_target = candidate_tag if (build_result and build_result.status == "ok") else args.model
                try:
                    cand_eval = eval_mod.evaluate_model(eval_target, n_per=args.n_per, tier=args.tier)
                    runlog.log("eval", "OK", f"{eval_target} pass {cand_eval.passed}/{cand_eval.n}",
                               run_id=run_id, gates=cand_eval.gates_cleared, invented=cand_eval.invented_total)
                except Exception as e:
                    runlog.log("eval", "FAIL", f"{e}", run_id=run_id)
                if build_result and build_result.status == "ok" and candidate_tag != args.model:
                    try:
                        base_eval = eval_mod.evaluate_model(args.model, n_per=args.n_per, tier=args.tier)
                    except Exception:
                        pass

            if "promote" in stages and cand_eval is not None:
                decision = promote_mod.decide(cand_eval, base_eval)
                runlog.log("promote", "OK", f"promote={decision.promote} — {decision.reason}", run_id=run_id)
    except Exception as e:
        import traceback
        traceback.print_exc()
        runlog.log("run", "FAIL", f"CRASH: {type(e).__name__}: {e}", run_id=run_id)
        report_mod.write_report(args.reports_dir, run_id, status="crash", config=cfg,
                                ds_stats=ds_stats, train_result=train_result, build_result=build_result,
                                candidate_eval=cand_eval, baseline_eval=base_eval, promote_decision=decision)
        return 1

    if status == "ok" and train_result and train_result.status == "partial":
        status = "partial"
    if status == "ok" and build_result and build_result.status in ("error", "degenerate"):
        status = "partial"

    path = report_mod.write_report(args.reports_dir, run_id, status=status, config=cfg,
                                   ds_stats=ds_stats, train_result=train_result, build_result=build_result,
                                   candidate_eval=cand_eval, baseline_eval=base_eval, promote_decision=decision)
    runlog.log("run", "DONE", f"{status.upper()} report={path}", run_id=run_id, result=status)
    print(f"[run {run_id}] report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
Evaluator (Ollama) — serves a model the frozen test tasks and grades each answer
by EXECUTION (pass@1). Same grader as training, so the eval number means "the
model wrote code that actually passes real tests", not a surface score.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

from . import ollama_client as oc
from .contracts import GATES, SYNTHESIS_SYSTEM, TIERS
from .dataset import frozen_test_tasks
from .score import grade


@dataclass
class EvalReport:
    model: str
    n: int = 0
    passed: int = 0
    pass_rate: float = 0.0
    had_code: int = 0
    mean_latency_s: float = 0.0
    gates_cleared: bool = False
    per_item: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        d = asdict(self)
        d.pop("per_item", None)
        return d


def _finish(rep: EvalReport, lat: list[float]) -> EvalReport:
    rep.pass_rate = rep.passed / rep.n if rep.n else 0.0
    rep.mean_latency_s = sum(lat) / len(lat) if lat else 0.0
    rep.gates_cleared = rep.pass_rate >= GATES["pass_rate_min"]
    return rep


def evaluate_model(model, *, host=None, tier="legion-dev:qwen2.5-coder-3b",
                   temperature=0.2, timeout=180.0, exec_timeout=30.0) -> EvalReport:
    host = host or oc.DEFAULT_HOST
    num_ctx = TIERS.get(tier, {}).get("num_ctx", 8192)
    tasks = frozen_test_tasks()
    rep = EvalReport(model=model, n=len(tasks))
    lat: list[float] = []
    for task in tasks:
        t0 = time.monotonic()
        answer = oc.chat(model, SYNTHESIS_SYSTEM, task.render(), host=host,
                         temperature=temperature, num_ctx=num_ctx, timeout=timeout, num_predict=1536)
        lat.append(time.monotonic() - t0)
        v = grade(answer, task, timeout=exec_timeout)
        if v.has_code:
            rep.had_code += 1
        if v.passed:
            rep.passed += 1
        rep.per_item.append({"task": task.name, "passed": v.passed, "reasons": v.reasons,
                             "returncode": v.returncode})
    return _finish(rep, lat)

"""
Evaluator (Ollama) — the critic in eval mode. Serves a model (an Ollama tag) the
frozen test set with the exact synthesis prompt, scores each answer with the same
deterministic scorer, aggregates to the model-card metrics.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field

from . import ollama_client as oc
from .contracts import GATES, SYNTHESIS_SYSTEM, TIERS
from .dataset import frozen_test_pairs
from .score import score_answer


@dataclass
class EvalReport:
    model: str
    n: int = 0
    passed: int = 0
    pass_rate: float = 0.0
    invented_total: int = 0
    grounding: float = 0.0
    format: float = 0.0
    citation_coverage: float = 0.0
    anti_parrot: float = 0.0
    mean_latency_s: float = 0.0
    gates_cleared: bool = False
    per_item: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        d = asdict(self)
        d.pop("per_item", None)
        return d


def _mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def evaluate_model(model, *, n_per=8, host=None, tier="legion-ares:qwen3-4b",
                   temperature=0.3, timeout=120.0) -> EvalReport:
    host = host or oc.DEFAULT_HOST
    num_ctx = TIERS.get(tier, {}).get("num_ctx", 4096)
    pairs = frozen_test_pairs(n_per)
    rep = EvalReport(model=model, n=len(pairs))

    g, f, c, a, lat = [], [], [], [], []
    for bundle, instruction in pairs:
        user = f"{instruction}\n\n{bundle.render()}"
        t0 = time.monotonic()
        answer = oc.chat(model, SYNTHESIS_SYSTEM, user, host=host,
                         temperature=temperature, num_ctx=num_ctx, timeout=timeout)
        dt = time.monotonic() - t0
        res = score_answer(answer, bundle)
        g.append(res.grounding); f.append(res.format)
        c.append(res.citation_coverage); a.append(res.anti_parrot); lat.append(dt)
        rep.invented_total += len(res.invented)
        if res.passed:
            rep.passed += 1
        rep.per_item.append({"scenario": bundle.scenario, "passed": res.passed,
                             "reasons": res.reasons, "metrics": res.as_metrics(), "answer": answer})

    rep.pass_rate = rep.passed / rep.n if rep.n else 0.0
    rep.grounding, rep.format = _mean(g), _mean(f)
    rep.citation_coverage, rep.anti_parrot = _mean(c), _mean(a)
    rep.mean_latency_s = _mean(lat)
    rep.gates_cleared = (rep.invented_total <= GATES["invented_indicators_max"]
                         and rep.grounding >= GATES["grounding_min"]
                         and rep.format >= GATES["format_min"]
                         and rep.citation_coverage >= GATES["citation_coverage_min"]
                         and rep.anti_parrot >= GATES["anti_parrot_min"])
    return rep

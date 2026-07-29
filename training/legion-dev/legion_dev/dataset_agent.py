"""Assemble the AGENTIC SFT dataset: execution-verified tool-use trajectories ->
multi-turn {"messages": [...]} rows train.py can train on directly (with
assistant_only_loss so only the tool-call/summary turns are learned).

Offline (default): gold + starter-fix trajectories — fully grounded, no Ollama.
Teacher (optional): additionally sample a local coder for each task and keep the
FAILING samples as extra fix trajectories (real model errors -> real recoveries).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from . import ollama_client as oc
from .agent_contracts import AGENT_SYSTEM
from .dataset import _write_jsonl, task_to_dict
from .executor import run_task
from .extract import extract_code
from .project_tasks import project_train_tasks
from .tasks import test_tasks, train_tasks
from .trajectory import project_trajectories_for_task, trajectories_for_task


@dataclass
class AgentDatasetStats:
    tasks: int = 0
    trajectories: int = 0
    deduped: int = 0
    train: int = 0
    val: int = 0
    test: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    teacher_wrong: int = 0


def _teacher_wrong_samples(task, *, model, host, attempts, timeout, exec_timeout) -> list[str]:
    """Sample the teacher and keep only code that FAILS the task's tests — real
    model errors to build fix trajectories from. (Passing samples are already
    covered by the single-file track; here we want the recoveries.)"""
    out: list[str] = []
    for n in range(attempts):
        try:
            ans = oc.chat(model, AGENT_SYSTEM, task.render(), host=host,
                          temperature=0.4 + 0.2 * n, num_ctx=8192, timeout=timeout, num_predict=1024)
        except Exception:
            break
        code = extract_code(ans)
        if not code:
            continue
        res = run_task(task, code, timeout=exec_timeout)
        if not res.passed and " ".join(code.split()) != " ".join(task.reference.split()):
            out.append(code)
    return out


def build_agent_dataset(out_dir, *, teacher_backend="reference", model="qwen2.5-coder:7b",
                        host=None, wrong_attempts=2, max_examples=400, val_frac=0.2,
                        exec_timeout=30.0, deadline=None, include_projects=True,
                        include_experience=True) -> AgentDatasetStats:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stats = AgentDatasetStats()
    rows: list[dict] = []
    seen: set[str] = set()

    for task in train_tasks():
        if deadline is not None and time.monotonic() >= deadline:
            break
        stats.tasks += 1
        wrong_samples = []
        if teacher_backend != "reference":
            kw = dict(model=model, attempts=wrong_attempts, timeout=180.0, exec_timeout=exec_timeout)
            kw["host"] = host or oc.DEFAULT_HOST
            wrong_samples = _teacher_wrong_samples(task, **kw)
            stats.teacher_wrong += len(wrong_samples)

        for traj in trajectories_for_task(task, wrong_samples=wrong_samples):
            # dedupe on the assistant tool-call/summary content (the learned part)
            key = " ".join(
                m.get("content", "") + str(m.get("tool_calls", ""))
                for m in traj["messages"] if m["role"] == "assistant").strip()
            key = " ".join(key.split())
            if key in seen:
                stats.deduped += 1
                continue
            seen.add(key)
            rows.append(traj)
            k = traj["meta"]["kind"]
            stats.by_kind[k] = stats.by_kind.get(k, 0) + 1
            if len(rows) >= max_examples:
                break
        if len(rows) >= max_examples:
            break

    # PROJECT tier: multi-file, end-to-end trajectories (the behavior single-file tasks can't
    # teach). Same dedupe + execution gate (project_trajectories_for_task only returns shapes
    # that actually pass). Interleaved into the same dataset so one run trains both tiers.
    if include_projects:
        for task in project_train_tasks():
            if deadline is not None and time.monotonic() >= deadline:
                break
            if len(rows) >= max_examples:
                break
            stats.tasks += 1
            for traj in project_trajectories_for_task(task):
                key = " ".join(
                    m.get("content", "") + str(m.get("tool_calls", ""))
                    for m in traj["messages"] if m["role"] == "assistant").strip()
                key = " ".join(key.split())
                if key in seen:
                    stats.deduped += 1
                    continue
                seen.add(key)
                rows.append(traj)
                k = traj["meta"]["kind"]
                stats.by_kind[k] = stats.by_kind.get(k, 0) + 1
                if len(rows) >= max_examples:
                    break

    # SELF-IMPROVEMENT: fold in VERIFIED experience from real runs (experience.record). This is
    # the recursive loop — the model learns from tasks it actually solved in the field, not only
    # the seed pool. Deduped + already execution-verified when captured; the gate still guards
    # promotion, so bad experience can't stick.
    if include_experience:
        from . import experience as _xp
        for traj in _xp.as_trajectories():
            if len(rows) >= max_examples:
                break
            key = " ".join(
                m.get("content", "") + str(m.get("tool_calls", ""))
                for m in traj["messages"] if m["role"] == "assistant").strip()
            key = " ".join(key.split())
            if key in seen:
                stats.deduped += 1
                continue
            seen.add(key)
            rows.append(traj)
            stats.by_kind["experience"] = stats.by_kind.get("experience", 0) + 1

    stats.trajectories = len(rows)

    val_n = max(1, int(len(rows) * val_frac)) if rows else 0
    step = max(1, len(rows) // val_n) if val_n else 1
    val = [r for i, r in enumerate(rows) if val_n and i % step == 0][:val_n]
    val_ids = {id(r) for r in val}
    train = [r for r in rows if id(r) not in val_ids]

    _write_jsonl(out / "train.jsonl", [{"messages": r["messages"], "meta": r["meta"]} for r in train])
    _write_jsonl(out / "val.jsonl", [{"messages": r["messages"], "meta": r["meta"]} for r in val])
    _write_jsonl(out / "test.jsonl", [{"task": task_to_dict(t)} for t in test_tasks()])

    stats.train, stats.val, stats.test = len(train), len(val), len(test_tasks())
    return stats

"""Tests for the agentic (tool-use) track — trajectory synthesis + dataset.

Offline and execution-grounded: the trajectories' tool results come from the real
executor, so these assert the pytest gate actually ran. No GPU/Ollama.
"""
from __future__ import annotations

import json

from legion_dev import trajectory
from legion_dev.agent_contracts import AGENT_TOOL_NAMES
from legion_dev.dataset_agent import build_agent_dataset
from legion_dev.tasks import get_task, train_tasks


def _tool_calls(msgs):
    return [tc["function"]["name"] for m in msgs if m["role"] == "assistant"
            for tc in m.get("tool_calls", [])]


def test_gold_trajectory_writes_then_runs_and_passes():
    t = get_task("fix_add")
    traj = trajectory.gold_trajectory(t)
    assert traj is not None
    msgs = traj["messages"]
    assert msgs[0]["role"] == "system" and msgs[1]["role"] == "user"
    # write_file -> run_shell in order
    assert _tool_calls(msgs) == ["write_file", "run_shell"]
    # the write carried the real reference solution
    wf = next(tc for m in msgs if m["role"] == "assistant"
              for tc in m.get("tool_calls", []) if tc["function"]["name"] == "write_file")
    assert wf["function"]["arguments"]["content"].strip() == t.reference.strip()
    # the run_shell tool result is a REAL passing pytest run
    run_result = [m for m in msgs if m["role"] == "tool" and m["name"] == "run_shell"][-1]
    assert "[exit 0]" in run_result["content"]
    # ends with a prose summary, no trailing tool call
    assert msgs[-1]["role"] == "assistant" and not msgs[-1].get("tool_calls")


def test_fix_trajectory_fails_then_passes():
    t = get_task("sum_to_n")
    traj = trajectory.fix_trajectory(t, t.starter)  # starter is buggy -> fails
    assert traj is not None
    msgs = traj["messages"]
    # write(wrong) -> run(FAIL) -> write(fix) -> run(PASS)
    assert _tool_calls(msgs) == ["write_file", "run_shell", "write_file", "run_shell"]
    runs = [m["content"] for m in msgs if m["role"] == "tool" and m["name"] == "run_shell"]
    assert "[exit 1]" in runs[0]   # first run fails
    assert "[exit 0]" in runs[1]   # second run passes


def test_fix_trajectory_rejects_a_passing_wrong():
    t = get_task("fix_add")
    # reference passes -> not a valid "fix" first attempt
    assert trajectory.fix_trajectory(t, t.reference) is None


def test_every_train_task_yields_at_least_a_gold():
    for t in train_tasks():
        trajs = trajectory.trajectories_for_task(t)
        kinds = {tr["meta"]["kind"] for tr in trajs}
        assert "gold" in kinds, f"{t.name} produced no gold trajectory"
        # every tool call names a real tool
        for tr in trajs:
            for name in _tool_calls(tr["messages"]):
                assert name in AGENT_TOOL_NAMES


def test_build_agent_dataset_offline(tmp_path):
    stats = build_agent_dataset(tmp_path, teacher_backend="reference", max_examples=100)
    assert stats.trajectories > 0
    assert stats.train > 0
    assert stats.by_kind.get("gold", 0) > 0
    rows = [json.loads(l) for l in (tmp_path / "train.jsonl").read_text().splitlines() if l.strip()]
    assert rows and all(r["messages"][0]["role"] == "system" for r in rows)
    # frozen test set written for the agentic eval
    test_rows = [json.loads(l) for l in (tmp_path / "test.jsonl").read_text().splitlines() if l.strip()]
    assert len(test_rows) == stats.test > 0

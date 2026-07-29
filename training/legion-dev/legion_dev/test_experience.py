"""Guards for the self-improvement loop (experience.py) — CPU-only, temp store, no real state.

The loop is only safe if: unverified runs are refused (no noise), retrieval keys on meaning
(no misleading examples), duplicates don't stack, and verified experience replays as training
rows. These hold it to that.
"""
import tempfile
from pathlib import Path

import pytest

from legion_dev import experience as xp
from legion_dev.project_tasks import project_train_tasks
from legion_dev.trajectory import project_gold_trajectory


@pytest.fixture(autouse=True)
def _temp_store(monkeypatch):
    monkeypatch.setattr(xp, "STORE", Path(tempfile.mkdtemp()) / "runs.jsonl")


def _win():
    return project_gold_trajectory(project_train_tasks()[0])["messages"]


def test_only_verified_is_kept():
    assert xp.record("build a calc package", _win(), passed=True) is True
    assert xp.record("unverified attempt", _win(), passed=False) is False
    assert xp.stats()["verified_experiences"] == 1


def test_duplicates_do_not_stack():
    m = _win()
    assert xp.record("build a calc package", m, passed=True) is True
    assert xp.record("build a calc package again", m, passed=True) is False  # same learned content
    assert xp.stats()["verified_experiences"] == 1


def test_retrieval_keys_on_meaning():
    xp.record("build a calc package with add sub mul div", _win(), passed=True, meta={"task": "calc"})
    assert xp.retrieve("build me a calculator package with add and divide"), "relevant miss"
    assert not xp.retrieve("write a haiku about rain"), "irrelevant request matched (stopword leak)"
    assert not xp.retrieve(""), "empty request should retrieve nothing"


def test_experience_replays_as_training_rows():
    xp.record("build a calc package", _win(), passed=True, meta={"task": "calc"})
    rows = xp.as_trajectories()
    assert len(rows) == 1
    assert rows[0]["meta"]["kind"] == "experience"
    assert rows[0]["messages"][-1]["role"] == "assistant"  # ends on a summary, well-formed

"""Guards for the multi-file PROJECT tier — CPU-only (no model), so it runs in CI.

The project tier is only trustworthy if: every reference actually passes, every starter
actually fails (else the task is trivial and the fix trajectory is a lie), grading can't be
gamed by shipping a fake test, and no held-out project leaks into training. These tests hold
the platform to that.
"""
import pytest

from legion_dev.executor import run_project
from legion_dev.project_tasks import (PROJECT_TASKS, project_test_tasks,
                                       project_train_tasks)
from legion_dev.trajectory import project_trajectories_for_task


@pytest.mark.parametrize("task", PROJECT_TASKS, ids=lambda t: t.name)
def test_reference_passes(task):
    # a reference that doesn't pass its own tests is a poisoned label
    r = run_project(task, task.reference)
    assert r.passed, f"{task.name}: reference FAILED\n{(r.stdout or '') + (r.stderr or '')}"


@pytest.mark.parametrize("task", PROJECT_TASKS, ids=lambda t: t.name)
def test_starter_fails(task):
    # the stub scaffold must NOT already pass — otherwise the task teaches nothing and the
    # fix trajectory (run->FAIL->implement->PASS) would be fabricated
    r = run_project(task, task.starter)
    assert not r.passed, f"{task.name}: starter scaffold already passes; task is trivial"


def test_grading_is_tamper_proof():
    # a candidate that ships its own always-passing copy of a test file must NOT win: the
    # pristine spec is layered last, so the real tests still run and still fail.
    task = PROJECT_TASKS[0]
    fake = {name: "def test_fake():\n    assert True\n" for name in task.test_files}
    forged = {**{k: "" for k in task.reference}, **fake}  # empty impl + fake passing test
    assert not run_project(task, forged).passed, "grading was fooled by a forged test file"


def test_no_train_test_leakage():
    train = {t.name for t in project_train_tasks()}
    held = {t.name for t in project_test_tasks()}
    assert train and held
    assert train.isdisjoint(held), f"project leakage: {train & held}"


@pytest.mark.parametrize("task", project_train_tasks(), ids=lambda t: t.name)
def test_trajectories_are_grounded_and_complete(task):
    trs = project_trajectories_for_task(task)
    assert trs, f"{task.name}: produced no trajectories"
    for tr in trs:
        msgs = tr["messages"]
        # every trajectory must END on a real green test run
        runs = [m for m in msgs if m.get("name") == "run_shell"]
        assert runs and runs[-1]["content"].endswith("[exit 0]"), \
            f"{task.name}/{tr['meta']['kind']}: does not end on passing tests"
        # gold/fix both write every reference file (a project is not one edit)
        writes = [m for m in msgs if m.get("tool_calls")
                  and m["tool_calls"][0]["function"]["name"] == "write_file"]
        assert len(writes) == len(task.reference), \
            f"{task.name}/{tr['meta']['kind']}: wrote {len(writes)} of {len(task.reference)} files"

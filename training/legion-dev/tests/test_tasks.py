"""
The core guarantee: every task's hand-verified reference solution actually PASSES
its own pytest spec, run through the real executor. If this passes, the catalog
and the sandbox are self-consistent and the reference fallback is safe to train on.
"""
import pytest

from legion_dev.executor import run_task
from legion_dev.tasks import TASKS, TEST_NAMES, all_tasks
from legion_dev.tasks import test_tasks as held_out_tasks
from legion_dev.tasks import train_tasks as training_tasks


@pytest.mark.parametrize("task", TASKS, ids=[t.name for t in TASKS])
def test_reference_passes_its_own_tests(task):
    res = run_task(task, task.reference)
    assert res.passed, f"{task.name} reference failed:\n{res.output}"


def test_starter_actually_fails(task=None):
    # sanity: the starters are supposed to be broken, so the reference is meaningful.
    broken = 0
    for t in TASKS:
        if not run_task(t, t.starter).passed:
            broken += 1
    # the vast majority of starters must fail; a couple of "implement" stubs raise, too
    assert broken >= len(TASKS) - 1


def test_split_is_disjoint_and_covers():
    names = {t.name for t in TASKS}
    assert TEST_NAMES <= names
    train, test = {t.name for t in training_tasks()}, {t.name for t in held_out_tasks()}
    assert train.isdisjoint(test)
    assert train | test == names
    assert test == TEST_NAMES


def test_render_shows_task_starter_and_tests():
    for t in all_tasks():
        text = t.render()
        assert "TESTS" in text and "```python" in text
        assert t.prompt in text

import json

from legion_dev.dataset import (build_dataset, read_jsonl, task_from_dict,
                                task_to_dict)
from legion_dev.score import grade
from legion_dev.synth import synthesize
from legion_dev.tasks import get_task
from legion_dev.tasks import test_tasks as held_out_tasks
from legion_dev.tasks import train_tasks as training_tasks


def test_reference_backend_produces_a_passing_candidate():
    for name in ("fix_add", "factorial", "get_token"):
        cand = synthesize(get_task(name), backend="reference")
        assert cand.passed and cand.backend == "reference"


def test_secret_task_reference_does_not_echo_the_secret():
    task = get_task("get_token")
    cand = synthesize(task, backend="reference")
    for s in task.forbidden:
        assert s not in cand.answer
    assert grade(cand.answer, task).passed


def test_build_dataset_reference_backend(tmp_path):
    stats = build_dataset(tmp_path, instructions_per=1, teacher_backend="reference")
    assert stats.rejected == 0                       # every reference passes execution
    assert stats.accepted == len(training_tasks())
    assert stats.train + stats.val == stats.accepted - stats.deduped
    assert stats.test == len(held_out_tasks())
    assert stats.by_backend.get("reference", 0) > 0

    train = read_jsonl(tmp_path / "train.jsonl")
    assert train and [m["role"] for m in train[0]["messages"]] == ["system", "user", "assistant"]

    test = read_jsonl(tmp_path / "test.jsonl")
    assert len(test) == len(held_out_tasks())
    assert all({"task", "user_prompt", "reference_gold"} <= r.keys() for r in test)


def test_task_dict_roundtrip():
    t = get_task("query_user")
    t2 = task_from_dict(json.loads(json.dumps(task_to_dict(t))))
    assert t2.name == t.name and t2.tests == t.tests and t2.render() == t.render()

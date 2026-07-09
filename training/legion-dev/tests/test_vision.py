import pytest

pytest.importorskip("PIL")  # vision track needs Pillow

from legion_dev import render
from legion_dev.dataset_vl import build_vl_dataset, read_jsonl
from legion_dev.tasks import get_task
from legion_dev.tasks import train_tasks as training_tasks


def test_render_produces_an_image():
    img = render.render_text_image("def add(a, b):\n    return a + b\n", title="solution.py")
    w, h = img.size
    assert w > 100 and h > 30


def test_task_screenshot_writes_png(tmp_path):
    path = render.task_screenshot(get_task("fix_add"), tmp_path, kind="code")
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) > 200


def test_build_vl_dataset_reference_backend(tmp_path):
    stats = build_vl_dataset(tmp_path, kind="code", instructions_per=1, teacher_backend="reference")
    assert stats.rejected == 0                       # every reference passes execution
    assert stats.accepted == len(training_tasks())
    assert stats.test > 0

    train = read_jsonl(tmp_path / "train_vl.jsonl")
    assert train
    row = train[0]
    assert {"task", "image", "user_text", "answer"} <= row.keys()
    assert (tmp_path / row["image"]).exists()        # the screenshot was rendered
    assert "```python" in row["answer"]              # verified solution carries code

    test = read_jsonl(tmp_path / "test_vl.jsonl")
    assert all({"task", "image", "user_text", "reference_gold"} <= r.keys() for r in test)

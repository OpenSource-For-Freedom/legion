from legion_dev.extract import extract_code


def test_extracts_python_fence():
    ans = "Here is the fix:\n\n```python\ndef add(a, b):\n    return a + b\n```\n"
    assert extract_code(ans) == "def add(a, b):\n    return a + b"


def test_prefers_largest_python_block():
    ans = ("```python\nx = 1\n```\nand the file:\n```python\n"
           "def add(a, b):\n    return a + b\n```\n")
    assert "def add" in extract_code(ans)


def test_bare_code_without_fence():
    ans = "def add(a, b):\n    return a + b\n"
    assert "def add" in extract_code(ans)


def test_prose_only_returns_empty():
    assert extract_code("I would fix the addition bug in that function.") == ""
    assert extract_code("") == ""

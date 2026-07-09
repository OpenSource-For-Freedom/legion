"""
Pull the solution source out of a model response. The model is asked to return
the complete corrected file in a single fenced ```python block (optionally with a
one-line explanation first). We take the largest python-tagged fence; if nothing
is tagged we take the largest fence; if there are no fences but the whole reply
looks like code, we use it verbatim.
"""

from __future__ import annotations

import re

_FENCE = re.compile(r"```([^\n`]*)\n(.*?)```", re.S)
_LOOKS_LIKE_CODE = re.compile(r"^\s*(?:def |class |import |from |@|#!)", re.M)
_PY_TAGS = {"python", "py", "python3", "py3"}


def extract_code(answer: str) -> str:
    if not answer:
        return ""
    blocks = _FENCE.findall(answer)
    if blocks:
        tagged = [body for info, body in blocks if info.strip().lower() in _PY_TAGS and body.strip()]
        candidates = tagged or [body for _, body in blocks if body.strip()]
        if candidates:
            return max(candidates, key=len).strip("\n")
    text = answer.strip()
    if _LOOKS_LIKE_CODE.search(text):
        return text
    return ""

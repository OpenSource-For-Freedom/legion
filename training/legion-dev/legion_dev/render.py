"""
Screenshot renderer. Turns a task's source or its failing-test terminal output
into a PNG "screenshot", so the vision model trains and is evaluated on *reading*
code/errors from an image while the CODE it produces is still graded by execution.
This gives grounded, execution-verified multimodal data for free (no real
screenshots needed): the image is a rendered view of text we already have.

Requires Pillow (`pip install pillow`).
"""

from __future__ import annotations

from pathlib import Path

# window-chrome-ish palette
_BG = (11, 14, 20)          # terminal/editor background
_FG = (207, 227, 214)       # terminal green-grey
_CODE_FG = (226, 232, 240)  # editor foreground
_TITLE = (148, 163, 184)
_MARGIN = 16
_LINE_H = 20
_FONT_SIZE = 15
_MAX_COLS = 100


def _font():
    from PIL import ImageFont
    for name in ("consola.ttf", "Consolas.ttf", "DejaVuSansMono.ttf",
                 "C:/Windows/Fonts/consola.ttf", "cour.ttf"):
        try:
            return ImageFont.truetype(name, _FONT_SIZE)
        except Exception:
            continue
    return ImageFont.load_default()


def render_text_image(text: str, *, title: str = "", fg=_FG) -> "object":
    """Render monospace text on a dark background; return a PIL.Image."""
    from PIL import Image, ImageDraw

    lines: list[str] = []
    for raw in text.replace("\t", "    ").splitlines() or [""]:
        while len(raw) > _MAX_COLS:
            lines.append(raw[:_MAX_COLS])
            raw = raw[_MAX_COLS:]
        lines.append(raw)
    if title:
        lines = [title, "-" * min(len(title), _MAX_COLS), ""] + lines

    width = _MARGIN * 2 + max((len(ln) for ln in lines), default=1) * 9
    width = max(360, min(width, _MARGIN * 2 + _MAX_COLS * 9))
    height = _MARGIN * 2 + max(len(lines), 1) * _LINE_H

    img = Image.new("RGB", (width, height), _BG)
    draw = ImageDraw.Draw(img)
    font = _font()
    y = _MARGIN
    for i, ln in enumerate(lines):
        color = _TITLE if (title and i < 2) else fg
        draw.text((_MARGIN, y), ln, fill=color, font=font)
        y += _LINE_H
    return img


def save_image(img, path) -> str:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(str(path), format="PNG")
    return str(path)


def render_code_png(text: str, out_path, *, title: str = "") -> str:
    return save_image(render_text_image(text, title=title, fg=_CODE_FG), out_path)


def render_terminal_png(text: str, out_path, *, title: str = "") -> str:
    return save_image(render_text_image(text, title=title, fg=_FG), out_path)


def task_screenshot(task, out_dir, *, kind: str = "code", exec_timeout: float = 30.0) -> str:
    """Render a screenshot for a task. kind='code' shows the current (buggy)
    solution file; kind='terminal' shows the failing pytest output."""
    out = Path(out_dir) / "screenshots"
    dest = out / f"{task.name}.png"
    if kind == "terminal":
        from .executor import run_task
        res = run_task(task, task.starter, timeout=exec_timeout)
        body = f"$ pytest\n{res.output}".strip() or "$ pytest\n(no output)"
        return render_terminal_png(body, dest, title=f"{task.test_file}  —  FAILING")
    return render_code_png(task.starter, dest, title=task.solution_file)

"""Bridge to the Legion Studio skills — the single source of truth.

Skills live in the STUDIO (legiondev-studio/skills/<name>/SKILL.md): they ship with
the app, are versioned with it, and are what the model actually uses at serve time.
Training READS them here so the model is trained on EXACTLY what it will serve — no
divergent copy that can drift. Point at a different studio checkout with the
LEGION_STUDIO_SKILLS env var.
"""
from __future__ import annotations

import os
from pathlib import Path

# Default: the studio checkout next to this training repo on the dev box.
_DEFAULT = Path(r"F:\dev\legiondev-studio\skills")


def skills_dir() -> Path:
    return Path(os.environ.get("LEGION_STUDIO_SKILLS", str(_DEFAULT)))


def _strip_frontmatter(md: str) -> str:
    return md.split("---", 2)[2].strip() if md.startswith("---") else md.strip()


def load_skill(name: str) -> str:
    """The body of one studio skill (frontmatter stripped), or '' if not found."""
    try:
        return _strip_frontmatter((skills_dir() / name / "SKILL.md").read_text(encoding="utf-8"))
    except Exception:
        return ""


def list_skills() -> list[str]:
    d = skills_dir()
    if not d.is_dir():
        return []
    return sorted(x.name for x in d.iterdir() if (x / "SKILL.md").exists())


def catalog() -> str:
    """One-line-per-skill catalog (name + description) for a use_skill-aware prompt."""
    lines = []
    for name in list_skills():
        try:
            head = (skills_dir() / name / "SKILL.md").read_text(encoding="utf-8")
            desc = ""
            for ln in head.splitlines():
                if ln.strip().startswith("description:"):
                    desc = ln.split(":", 1)[1].strip()
                    break
            lines.append(f"  - {name}: {desc}" if desc else f"  - {name}")
        except Exception:
            lines.append(f"  - {name}")
    return "\n".join(lines)

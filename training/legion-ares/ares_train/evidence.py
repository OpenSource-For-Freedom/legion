"""
Evidence bundles: the RAG-less "CONFIRMED FINDINGS" context that the synthesizer
turns into a gold answer and that evaluate.py feeds the trained model. Rendered
text matches build_synthesis_prompt and the MODEL_CARD example, now carrying an
OS Platform line so Ares learns Linux- vs Windows-appropriate analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import posture_for

SECTION_ORDER = [
    "ACTIVE ALERTS (critical/high)",
    "RULE HITS",
    "YARA MATCHES",
    "OSV FINDINGS",
    "BASELINE DRIFT",
    "ACTIVE CONNECTIONS",
    "LOCAL EVENTS",
]

SEVERITY_RANK = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0, "Info": 0}

_PLATFORM_DISP = {"linux": "Linux", "windows": "Windows", "cross": "Windows/Linux",
                  "ai": "AI/LLM stack"}


@dataclass
class Finding:
    section: str
    severity: str
    text: str
    indicators: list[str] = field(default_factory=list)

    def render(self) -> str:
        return f"  [{self.severity}] {self.text}"

    @property
    def is_top(self) -> bool:
        return SEVERITY_RANK.get(self.severity, 0) >= 2


@dataclass
class EvidenceBundle:
    scenario: str
    score: float
    platform: str = "cross"            # "linux" | "windows" | "cross"
    findings: list[Finding] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    # guardrail classes
    injection_present: bool = False
    code_request: bool = False
    identity_request: bool = False
    destructive_request: bool = False
    clean: bool = False
    note: str = ""

    @property
    def posture(self) -> str:
        return posture_for(self.score)

    @property
    def platform_disp(self) -> str:
        return _PLATFORM_DISP.get(self.platform, "Windows/Linux")

    def all_indicators(self) -> set[str]:
        out: set[str] = set()
        for f in self.findings:
            out.update(f.indicators)
        return out

    def top_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.is_top]

    def lead_findings(self, k: int = 2) -> list[Finding]:
        ranked = sorted(self.findings,
                        key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
        return ranked[:k]

    def finding_lines(self) -> list[str]:
        return [f.text for f in self.findings]

    def render(self) -> str:
        head = f"Platform: {self.platform_disp}.\n"
        if self.clean and not self.findings:
            body = "No confirmed findings. Baseline is clean."
            return (f"{head}Local posture: {self.posture} (score {self.score:.2f}).\n\n"
                    f"CONFIRMED FINDINGS:\n  {body}")
        lines: list[str] = []
        by_section: dict[str, list[Finding]] = {}
        for f in self.findings:
            by_section.setdefault(f.section, []).append(f)
        for section in SECTION_ORDER:
            group = by_section.get(section)
            if not group:
                continue
            group = sorted(group, key=lambda f: SEVERITY_RANK.get(f.severity, 0), reverse=True)
            lines.append(f"{section}:")
            lines.extend(f.render() for f in group)
        for section, group in by_section.items():
            if section in SECTION_ORDER:
                continue
            lines.append(f"{section}:")
            lines.extend(f.render() for f in group)
        block = "\n".join(lines)
        return (f"{head}Local posture: {self.posture} (score {self.score:.2f}).\n\n"
                f"CONFIRMED FINDINGS:\n{block}")

# © 2026 Олег / GONKA LAB. Все права защищены.
"""Результат проверки. Исходные значения секретов сюда не попадают."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}
SEVERITY_RU = {"high": "Критично", "medium": "Проверить", "low": "К сведению"}
GIT_STATUS_RU = {
    "tracked": "в git: уйдёт при публикации",
    "untracked": "не закрыт .gitignore",
    "ignored": "закрыт .gitignore",
    "no-git": "папка без git",
}
VERDICT_RU = {
    "GREEN": "ЗЕЛЁНЫЙ — можно публиковать",
    "YELLOW": "ЖЁЛТЫЙ — проверьте вручную",
    "RED": "КРАСНЫЙ — публиковать нельзя",
}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int | None
    preview: str
    masked_value: str
    advice: str
    fingerprint: str = ""
    git_status: str = "no-git"

    @property
    def exposed(self) -> bool:
        return self.git_status != "ignored"

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(exposed=self.exposed, severity_ru=SEVERITY_RU[self.severity],
                 git_status_ru=GIT_STATUS_RU[self.git_status])
        return d


@dataclass
class ScanResult:
    root: str
    verdict: str
    summary: str
    findings: list[Finding]
    stats: dict = field(default_factory=dict)
    git: dict = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    scanned_at: str = ""
    version: str = ""

    def counts(self) -> dict:
        c = {"high": 0, "medium": 0, "low": 0, "protected": 0}
        for f in self.findings:
            c[f.severity if f.exposed else "protected"] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "tool": "FIST Guard",
            "edition": "demo",
            "version": self.version,
            "root": self.root,
            "scanned_at": self.scanned_at,
            "verdict": self.verdict,
            "verdict_ru": VERDICT_RU[self.verdict],
            "summary": self.summary,
            "counts": self.counts(),
            "stats": self.stats,
            "git": self.git,
            "recommendations": self.recommendations,
            "findings": [f.to_dict() for f in self.findings],
        }

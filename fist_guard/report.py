# © 2026 Олег / GONKA LAB. Все права защищены.
"""Отчёты: терминал, JSON, автономный HTML. Значения секретов замаскированы."""
from __future__ import annotations

import json
from pathlib import Path

from .models import GIT_STATUS_RU, SEVERITY_RU, VERDICT_RU, ScanResult

UI_DIR = Path(__file__).parent / "web"
_ICON = {"high": "✖", "medium": "!", "low": "·"}
_ANSI = {"RED": "\033[41;97m", "YELLOW": "\033[43;30m", "GREEN": "\033[42;30m",
         "high": "\033[31m", "medium": "\033[33m", "low": "\033[2m", "reset": "\033[0m", "dim": "\033[2m"}


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)


def to_text(result: ScanResult, color: bool = True) -> str:
    c = _ANSI if color else {k: "" for k in _ANSI}
    n = result.counts()
    out = ["", f"FIST Guard {result.version} (демо-версия) · {result.root}",
           f"{c[result.verdict]}  {VERDICT_RU[result.verdict]}  {c['reset']}", result.summary,
           f"{c['dim']}Файлов проверено: {result.stats['files_scanned']}, критично: {n['high']}, "
           f"проверить: {n['medium']}, закрыто .gitignore: {n['protected']}{c['reset']}", ""]
    for f in result.findings:
        if not f.exposed:
            continue
        where = f.path + (f":{f.line}" if f.line else "")
        out.append(f"{c[f.severity]}{_ICON[f.severity]} {SEVERITY_RU[f.severity]}: {f.title}{c['reset']}")
        out.append(f"   {where}  [{GIT_STATUS_RU[f.git_status]}]")
        if f.preview:
            out.append(f"   {c['dim']}{f.preview}{c['reset']}")
    if result.recommendations:
        out.append("\nЧто сделать:")
        out += [f"  {i}. {r}" for i, r in enumerate(result.recommendations, 1)]
    out.append(f"\n{c['dim']}Проверка локальная: файлы не изменялись и никуда не отправлялись.{c['reset']}")
    return "\n".join(out)


def to_html(result: ScanResult) -> str:
    template = (UI_DIR / "index.html").read_text("utf-8")
    payload = json.dumps(result.to_dict(), ensure_ascii=False).replace("</", "<\\/")
    return (template.replace("/*__FIST_DATA__*/null", payload)
            .replace("__FIST_TOKEN__", "").replace("__FIST_START_PATH__", ""))

# © 2026 Олег / GONKA LAB. Все права защищены.
"""Маскирование: в отчёт попадает только начало и конец значения, никогда целиком."""
from __future__ import annotations

import hashlib

PREVIEW_MAX = 160


def mask_value(value: str) -> str:
    n = len(value)
    if n < 12:
        return f"•••• [{n} симв.]"
    return f"{value[:4]}…{value[-2:]} [{n} симв.]"


def fingerprint(value: str) -> str:
    """Короткий отпечаток: позволяет увидеть один и тот же секрет в разных файлах,
    но не позволяет восстановить значение."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:10]


def build_preview(line: str, spans: list[tuple[int, int]]) -> str:
    """Строка с замаскированными участками, обрезанная вокруг первой находки."""
    out, pos, first_mask = [], 0, None
    for start, end in sorted(spans):
        if start < pos:
            continue
        out.append(line[pos:start])
        if first_mask is None:
            first_mask = sum(len(x) for x in out)
        out.append(mask_value(line[start:end]))
        pos = end
    out.append(line[pos:])
    text = "".join(out)
    lead = len(text) - len(text.lstrip())
    text = text.strip()
    if first_mask is not None:
        first_mask = max(0, first_mask - lead)
    if len(text) <= PREVIEW_MAX:
        return text
    center = first_mask or 0
    start = max(0, center - 60)
    end = min(len(text), start + PREVIEW_MAX)
    return ("…" if start else "") + text[start:end] + ("…" if end < len(text) else "")

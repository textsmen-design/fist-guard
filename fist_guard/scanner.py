# © 2026 Олег / GONKA LAB. Все права защищены.
"""Ядро демонстрационной версии FIST Guard.

Только чтение: файлы не изменяются, не удаляются и никуда не отправляются.
"""
from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .masking import build_preview, fingerprint, mask_value
from .models import SEVERITY_ORDER, Finding, ScanResult
from .rules import (CONTENT_RULES, HIGH, MEDIUM, PASSWORD_ENV_RULE, PASSWORD_RULE,
                    classify_filename, is_env_name)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
             "dist", "build", ".next", ".idea", ".vscode"}
MAX_FILE_BYTES = 1_000_000


class ScanError(Exception):
    pass


def _git(root: Path, *args: str, stdin: bytes | None = None):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        return subprocess.run(["git", "-c", "core.quotepath=off", "-C", str(root), *args],
                              input=stdin, capture_output=True, timeout=60, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _git_status(root: Path, paths: list[str]) -> tuple[bool, dict[str, str]]:
    r = _git(root, "rev-parse", "--is-inside-work-tree")
    if r is None or r.returncode != 0:
        return False, {p: "no-git" for p in paths}
    ls = _git(root, "ls-files", "-z")
    tracked = set(ls.stdout.decode("utf-8", "replace").split("\0")) if ls else set()
    rest = [p for p in paths if p not in tracked]
    ignored: set[str] = set()
    if rest:
        ci = _git(root, "check-ignore", "-z", "--stdin", stdin="\0".join(rest).encode() + b"\0")
        if ci:
            ignored = set(ci.stdout.decode("utf-8", "replace").split("\0"))
    status = {}
    for p in paths:
        status[p] = "tracked" if p in tracked else "ignored" if p in ignored else "untracked"
    return True, status


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if not p.is_symlink() and p.is_file():
                yield p


def _read_text(p: Path) -> str | None:
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", "replace")


def _scan_text(rel: str, text: str) -> list[Finding]:
    rules = CONTENT_RULES + [PASSWORD_ENV_RULE if is_env_name(Path(rel).name) else PASSWORD_RULE]
    out: list[Finding] = []
    for no, line in enumerate(text.splitlines(), 1):
        hits, claimed = [], []
        for rule in rules:
            for m in rule.pattern.finditer(line):
                s, e = m.span(rule.group)
                if any(s < ce and e > cs for cs, ce in claimed):
                    continue
                value = m.group(rule.group)
                if rule.validate and not rule.validate(value, rel):
                    continue
                claimed.append((s, e))
                hits.append((rule, value))
        if hits:
            preview = build_preview(line, claimed)
            for rule, value in hits:
                out.append(Finding(rule.id, rule.title, rule.severity, rel, no, preview,
                                   mask_value(value), rule.advice, fingerprint(value)))
    return out


def _verdict(findings: list[Finding]) -> str:
    exposed = [f for f in findings if f.exposed]
    if any(f.severity == HIGH for f in exposed):
        return "RED"
    if any(f.severity == MEDIUM for f in exposed):
        return "YELLOW"
    return "GREEN"


def _summary(verdict: str, c: dict) -> str:
    if verdict == "RED":
        s = f"Найдено критичных проблем: {c['high']}. В таком виде проект публиковать нельзя."
    elif verdict == "YELLOW":
        s = f"Критичных проблем нет, но {c['medium']} мест(а) нужно проверить вручную."
    else:
        s = "Автоматическая проверка не нашла секретов, которые уйдут при публикации."
    if c["protected"]:
        s += f" Ещё {c['protected']} находок закрыты .gitignore и наружу не попадут."
    return s


def _recommendations(findings: list[Finding], root: Path) -> list[str]:
    exposed = [f for f in findings if f.exposed]
    ids = {f.rule_id for f in exposed}
    rec = []
    if any(f.severity == HIGH for f in exposed):
        rec.append("Перевыпустите найденные ключи и токены: если ключ мог уйти наружу, "
                   "считайте его известным посторонним.")
    if "env_file" in ids:
        rec.append("Добавьте `.env` в .gitignore, а для примера оставьте `.env.example` без значений.")
    if not (root / ".gitignore").is_file():
        rec.append("В проекте нет .gitignore. Создайте его до первой публикации.")
    if any(f.git_status == "tracked" for f in exposed):
        rec.append("Файлы со статусом «в git» уже в репозитории: после исправления выполните "
                   "`git rm --cached <файл>` и закоммитьте. FIST Guard сам ничего не удаляет.")
    return rec


def scan(path) -> ScanResult:
    root = Path(path).expanduser()
    if not root.exists():
        raise ScanError(f"Папка не найдена: {root}")
    if not root.is_dir():
        raise ScanError(f"Это не папка: {root}")
    root = root.resolve()
    t0 = time.monotonic()
    findings: list[Finding] = []
    scanned = 0
    for p in _iter_files(root):
        rel = p.relative_to(root).as_posix()
        fr = classify_filename(rel)
        if fr:
            findings.append(Finding(fr[0], fr[1], fr[2], rel, None, "", "", fr[3]))
        text = _read_text(p)
        if text is not None:
            scanned += 1
            findings += _scan_text(rel, text)

    is_repo, status = _git_status(root, sorted({f.path for f in findings}))
    for f in findings:
        f.git_status = status[f.path]
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], not f.exposed, f.path, f.line or 0))

    verdict = _verdict(findings)
    res = ScanResult(root=str(root), verdict=verdict, summary="", findings=findings,
                     stats={"files_scanned": scanned, "duration_sec": round(time.monotonic() - t0, 2)},
                     git={"is_repo": is_repo},
                     scanned_at=datetime.now().strftime("%Y-%m-%d %H:%M"), version=__version__)
    res.summary = _summary(verdict, res.counts())
    res.recommendations = _recommendations(findings, root)
    return res

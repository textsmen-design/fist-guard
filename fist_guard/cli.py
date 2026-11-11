# © 2026 Олег / GONKA LAB. Все права защищены.
"""FIST Guard (демо-версия): командная строка.

  fist-guard demo [папка]                 создать демо-проект с выдуманными ключами
  fist-guard scan <папка> [--html файл]   проверить папку
  fist-guard ui [папка]                   визуальный интерфейс в браузере

Коды выхода scan: 0 — ЗЕЛЁНЫЙ, 1 — ЖЁЛТЫЙ, 2 — КРАСНЫЙ, 3 — ошибка.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .report import to_html, to_json, to_text
from .scanner import ScanError, scan

EXIT = {"GREEN": 0, "YELLOW": 1, "RED": 2}


def _cmd_scan(a) -> int:
    try:
        res = scan(a.path)
    except ScanError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 3
    if a.format == "json":
        print(to_json(res))
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and not a.no_color
        print(to_text(res, color=color))
    if a.html:
        p = Path(a.html).expanduser()
        p.write_text(to_html(res), "utf-8")
        print(f"Отчёт сохранён: {p}", file=sys.stderr)
    return EXIT[res.verdict]


def _cmd_demo(a) -> int:
    from .demo import build_demo
    try:
        p = build_demo(a.dest)
    except FileExistsError as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 3
    print(f"Демо-проект создан: {p}\nВсе ключи в нём выдуманы. Проверьте его:\n  fist-guard scan {p}")
    return 0


def _cmd_ui(a) -> int:
    from .server import serve
    serve(port=a.port, open_browser=not a.no_browser, start_path=a.path)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fist-guard",
                                description="FIST Guard (демо-версия) — проверка проекта на секреты.")
    p.add_argument("--version", action="version", version=f"FIST Guard {__version__} (демо-версия)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="проверить папку")
    s.add_argument("path")
    s.add_argument("--html", metavar="FILE", help="сохранить HTML-отчёт")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("--no-color", action="store_true")
    s.set_defaults(func=_cmd_scan)

    d = sub.add_parser("demo", help="создать демо-проект с выдуманными ключами")
    d.add_argument("dest", nargs="?", default="./kolosok-demo")
    d.set_defaults(func=_cmd_demo)

    u = sub.add_parser("ui", help="открыть визуальный интерфейс")
    u.add_argument("path", nargs="?", default="")
    u.add_argument("--port", type=int, default=8765)
    u.add_argument("--no-browser", action="store_true")
    u.set_defaults(func=_cmd_ui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)

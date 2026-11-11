# © 2026 Олег / GONKA LAB. Все права защищены.
"""Демо-проект «Пекарня Колосок» с ВЫДУМАННЫМИ ключами.

Ключи собираются из частей при запуске, поэтому в репозитории нет строк,
похожих на настоящие токены. Значения ни к чему не дают доступа.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def _fill(n: int, seed: str) -> str:
    return (("FAKEdemo" + seed + "Z9mK2pLw8RtY4vBn6HcJ3sDf5GaE1uIo0") * 3)[:n]


def fake_values() -> dict[str, str]:
    return {
        "openai": "sk" + "-proj-" + _fill(40, "Op1"),
        "anthropic": "sk" + "-ant-api03-" + _fill(40, "An2"),
        "telegram": "7012345678" + ":AA" + _fill(33, "Tg3"),
        "github": "gh" + "p_" + _fill(36, "Gh4"),
        "google": "AI" + "za" + _fill(35, "Go5"),
        "admin_password": "Pek" + "Demo" + "2026x",
    }


def _files(v: dict[str, str]) -> dict[str, str]:
    return {
        "README.md": "# Пекарня «Колосок»\n\nДемо-проект для FIST Guard. Все ключи ВЫДУМАНЫ.\n",
        "index.html": ("<!doctype html><html lang='ru'><head><meta charset='utf-8'><title>Колосок</title></head>\n"
                       "<body><h1>Свежий хлеб каждое утро</h1>\n"
                       "<script>const GEMINI_KEY = '" + v["google"] + "';</script>\n</body></html>\n"),
        "bot/config.py": ("import os\n\n# правильно: ключ из окружения\n"
                          "OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')\n\n"
                          "# неправильно: токен прямо в коде\n"
                          "TELEGRAM_TOKEN = '" + v["telegram"] + "'\n"),
        "bot/deploy.py": "GITHUB_TOKEN = '" + v["github"] + "'\n",
        ".env": ("OPENAI_API_KEY=" + v["openai"] + "\n"
                 "ANTHROPIC_API_KEY=" + v["anthropic"] + "\n"
                 "ADMIN_PASSWORD=" + v["admin_password"] + "\n"),
        ".env.example": "OPENAI_API_KEY=\nANTHROPIC_API_KEY=\nADMIN_PASSWORD=change-me\n",
        "logs/secret.env": "BOT_TOKEN=" + v["telegram"] + "\n",
        ".gitignore": "logs/\n",
    }


def build_demo(dest) -> Path:
    dest = Path(dest).expanduser().resolve()
    if dest.exists():
        if not (dest / ".fist-demo").exists():
            raise FileExistsError(f"Папка уже существует и это не демо FIST Guard: {dest}")
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    (dest / ".fist-demo").write_text("Демо-проект FIST Guard. Все ключи выдуманы.\n", "utf-8")
    for rel, text in _files(fake_values()).items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, "utf-8")
    cfg = ["-c", "user.name=FIST Demo", "-c", "user.email=demo@example.com",
           "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]
    try:
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "Сайт и бот пекарни"]):
            subprocess.run(["git", *cfg, "-C", str(dest), *args], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        pass  # без git демо тоже работает, статус будет «папка без git»
    return dest

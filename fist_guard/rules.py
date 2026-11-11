# © 2026 Олег / GONKA LAB. Все права защищены.
"""Правила демонстрационной версии FIST Guard.

Набор правил намеренно ограничен: основные форматы ключей популярных сервисов,
закрытые ключи, пароли в настройках и опасные файлы (.env, файлы ключей).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable, Optional

HIGH, MEDIUM, LOW = "high", "medium", "low"

ROTATE = ("Считайте ключ скомпрометированным: перевыпустите его у провайдера, "
          "уберите из кода и храните в .env, закрытом .gitignore.")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: re.Pattern
    advice: str
    group: int = 0
    validate: Optional[Callable[[str, str], bool]] = None


def _has_digit_and_case(value: str, name: str) -> bool:
    return bool(re.search(r"\d", value) and re.search(r"[a-z]", value) and re.search(r"[A-Z]", value))


_PLACEHOLDER = re.compile(r"(?i)(change.?me|your|example|xxx|\*\*\*|<|\$\{|\{\{|placeholder|dummy|^__\w+__$)")


def _real_value(value: str, name: str) -> bool:
    return not _PLACEHOLDER.search(value)


CONTENT_RULES: list[Rule] = [
    Rule("private_key", "Закрытый ключ (private key)", HIGH,
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
         "Закрытый ключ нельзя публиковать. Создайте новую пару ключей, старую отзовите."),
    Rule("anthropic_key", "Ключ Anthropic API", HIGH,
         re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), ROTATE),
    Rule("openai_key", "Ключ OpenAI API", HIGH,
         re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), ROTATE, validate=_has_digit_and_case),
    Rule("github_token", "Токен GitHub", HIGH,
         re.compile(r"\bghp_[A-Za-z0-9]{36,}"), ROTATE),
    Rule("telegram_token", "Токен Telegram-бота", HIGH,
         re.compile(r"(?<![\w])\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![\w-])"),
         "Перевыпустите токен через @BotFather (/revoke) и храните его в .env."),
    Rule("google_api_key", "Ключ Google API (Gemini, Maps и др.)", HIGH,
         re.compile(r"\bAIza[0-9A-Za-z_\-]{35}(?![\w-])"), ROTATE),
]

# Пароль или токен в настройках: в кавычках в любом файле, без кавычек — только в .env.
_PASSWORD_QUOTED = re.compile(
    r"(?i)\b[A-Z0-9_]*(password|passwd|secret|token|api_key)\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']")
_PASSWORD_ENV = re.compile(r"(?i)^\s*[A-Z0-9_]*(password|passwd|secret|token)\s*=\s*([^\s#\"']{6,})\s*$")

PASSWORD_RULE = Rule("password", "Пароль или токен в настройках", MEDIUM, _PASSWORD_QUOTED,
                     "Проверьте вручную. Если это настоящий пароль, вынесите его в .env.",
                     group=2, validate=_real_value)
PASSWORD_ENV_RULE = Rule("password", "Пароль или токен в настройках", MEDIUM, _PASSWORD_ENV,
                         PASSWORD_RULE.advice, group=2, validate=_real_value)


def is_env_name(name: str) -> bool:
    low = name.lower()
    if low.endswith((".example", ".sample", ".template")):
        return False
    return low == ".env" or low.startswith(".env.") or low.endswith(".env")


_KEY_FILES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
_KEY_EXT = {".pem", ".key", ".p12", ".pfx"}


def classify_filename(rel: str):
    """Возвращает (id, название, уровень, совет) или None."""
    p = PurePosixPath(rel)
    if is_env_name(p.name):
        return ("env_file", "Файл окружения .env (обычно в нём ключи)", HIGH,
                "Файл .env не должен попадать в репозиторий. Добавьте .env в .gitignore, "
                "а для примера создайте .env.example без значений.")
    if p.name.lower() in _KEY_FILES or p.suffix.lower() in _KEY_EXT:
        return ("key_file", "Файл ключа или сертификата", HIGH,
                "Такой файл может давать доступ к серверу или сервису. Уберите его из проекта.")
    return None

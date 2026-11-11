"""Тесты демонстрационной версии FIST Guard."""
import json
import os

import pytest

from fist_guard.cli import main
from fist_guard.masking import mask_value
from fist_guard.report import to_html, to_json, to_text
from fist_guard.scanner import ScanError, scan


def rule_ids(res):
    return {f.rule_id for f in res.findings}


# ---------- правила ----------

@pytest.mark.parametrize("key,rule", [
    ("openai", "openai_key"), ("anthropic", "anthropic_key"), ("telegram", "telegram_token"),
    ("github", "github_token"), ("google", "google_api_key"),
])
def test_provider_keys(make_project, fake, key, rule):
    res = scan(make_project({"a.py": f"X = '{fake[key]}'\n"}))
    assert rule_ids(res) == {rule}


def test_private_key(make_project):
    res = scan(make_project({"k.txt": "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n"}))
    assert rule_ids(res) == {"private_key"}


@pytest.mark.parametrize("line", [
    "OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')",
    "password = os.environ['ADMIN_PASSWORD']",
    "PASSWORD = 'change-me'",
    "sk-this-is-just-a-long-css-class-name",
    "Пароль должен быть длиннее 8 символов",
    'var TOKEN = "__FIST_TOKEN__";',
])
def test_no_false_positives(make_project, line):
    assert scan(make_project({"a.py": line + "\n", ".gitignore": ""})).findings == []


def test_password_in_quotes_is_medium(make_project):
    line = "DB_PASS" + "WORD = 'Tr0ub4dor-Horse'\n"  # собрано из частей, чтобы не срабатывать на самом репозитории
    res = scan(make_project({"a.py": line, ".gitignore": ""}))
    assert [f.severity for f in res.findings] == ["medium"]
    assert res.verdict == "YELLOW"


def test_env_example_not_flagged(make_project):
    res = scan(make_project({".env.example": "API_KEY=\nADMIN_PASSWORD=change-me\n", ".gitignore": ""}))
    assert res.findings == []


# ---------- git и .gitignore ----------

def test_clean_project_green(make_project):
    res = scan(make_project({"main.py": "print('ok')\n", ".gitignore": ".env\n"}, use_git=True))
    assert res.verdict == "GREEN" and res.findings == []


def test_ignored_env_is_protected(make_project, fake):
    res = scan(make_project({".env": f"KEY={fake['openai']}\n", ".gitignore": ".env\n"}, use_git=True))
    assert res.verdict == "GREEN"
    assert res.counts()["protected"] == 2


def test_tracked_env_is_red(make_project, fake):
    res = scan(make_project({".env": f"KEY={fake['openai']}\n"}, use_git=True))
    assert res.verdict == "RED"
    assert {f.git_status for f in res.findings} == {"tracked"}


def test_without_git(make_project, fake):
    res = scan(make_project({"bot.py": f"T = '{fake['telegram']}'\n"}))
    assert res.verdict == "RED" and res.findings[0].git_status == "no-git"


# ---------- демо и безопасность ----------

def test_demo_project(demo_dir):
    res = scan(demo_dir)
    assert res.verdict == "RED"
    assert {"env_file", "openai_key", "anthropic_key", "telegram_token", "google_api_key",
            "github_token", "password"} <= rule_ids(res)
    statuses = {f.path: f.git_status for f in res.findings}
    assert statuses["logs/secret.env"] == "ignored"
    assert statuses[".env"] == "tracked"


def test_scan_is_read_only(demo_dir):
    def snap():
        return {os.path.join(d, n): os.stat(os.path.join(d, n)).st_mtime_ns
                for d, _, fs in os.walk(demo_dir) for n in fs}
    before = snap()
    scan(demo_dir)
    assert snap() == before


def test_reports_never_contain_raw_secrets(demo_dir, fake):
    res = scan(demo_dir)
    for out in (to_text(res, color=False), to_json(res), to_html(res)):
        for secret in fake.values():
            assert secret not in out


def test_mask_value():
    assert mask_value("short") == "•••• [5 симв.]"
    assert mask_value("abcdefghijklmnopqrstuvwxyz").startswith("abcd…yz")


def test_symlinks_not_followed(make_project, tmp_path, fake):
    out = tmp_path / "outside"
    out.mkdir()
    (out / "s.py").write_text(f"K='{fake['openai']}'")
    root = make_project({"a.py": "x=1\n", ".gitignore": ""})
    os.symlink(out, root / "link")
    assert scan(root).findings == []


def test_bad_path(tmp_path):
    with pytest.raises(ScanError):
        scan(tmp_path / "nope")


# ---------- CLI ----------

def test_cli(demo_dir, make_project, tmp_path, capsys):
    assert main(["scan", str(demo_dir), "--no-color", "--html", str(tmp_path / "r.html")]) == 2
    assert (tmp_path / "r.html").stat().st_size > 5000
    assert main(["scan", str(make_project({"a.py": "x=1\n", ".gitignore": ""})), "--no-color"]) == 0
    assert main(["scan", str(tmp_path / "missing")]) == 3
    capsys.readouterr()
    main(["scan", str(demo_dir), "--format", "json"])
    assert json.loads(capsys.readouterr().out)["edition"] == "demo"


def test_demo_refuses_foreign_folder(tmp_path):
    (tmp_path / "mine").mkdir()
    (tmp_path / "mine" / "x.txt").write_text("x")
    assert main(["demo", str(tmp_path / "mine")]) == 3
    assert (tmp_path / "mine" / "x.txt").exists()

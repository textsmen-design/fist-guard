import subprocess
from pathlib import Path

import pytest

from fist_guard.demo import build_demo, fake_values

GIT = ["git", "-c", "user.name=T", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
       "-c", "init.defaultBranch=main"]


def git(root: Path, *args: str) -> None:
    subprocess.run([*GIT, "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture
def fake():
    return fake_values()


@pytest.fixture(scope="session")
def demo_dir(tmp_path_factory):
    return build_demo(tmp_path_factory.mktemp("demo") / "kolosok")


@pytest.fixture
def make_project(tmp_path):
    def _make(files: dict, use_git: bool = False) -> Path:
        root = tmp_path / "proj"
        root.mkdir()
        for rel, text in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, "utf-8")
        if use_git:
            git(root, "init", "-q")
            git(root, "add", "-A")
            git(root, "commit", "-q", "-m", "init")
        return root
    return _make

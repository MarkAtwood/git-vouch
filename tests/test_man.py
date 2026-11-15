"""man/git-vouch.1 and man/git-vouch-migrate.1: current, well formed, and what git help shows.

The pages are generated from the tools' parsers by man/mkman.py. These
tests fail if a checked-in page is not what the generator writes now (run
``python3 man/mkman.py``), if groff warns about one, or if ``git help
vouch`` does not find it once installed as the README says. The oracles
for the last two are man-db and git themselves.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
MAN = ROOT / "man"
TOOLS = ("git-vouch", "git-vouch-migrate")
needs_man = pytest.mark.skipif(shutil.which("man") is None, reason="no man")


def _mkman() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("mkman", str(MAN / "mkman.py"))
    spec = importlib.util.spec_from_loader("mkman", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    loader.exec_module(module)
    return module


@pytest.mark.parametrize("tool", TOOLS)
def test_page_is_current(tool: str) -> None:
    page = (MAN / f"{tool}.1").read_text()
    assert page == _mkman().page(tool), "stale: run python3 man/mkman.py"


@pytest.mark.parametrize("tool", TOOLS)
def test_every_command_has_a_section(tool: str) -> None:
    parser = _mkman().load(tool).build_parser()
    page = (MAN / f"{tool}.1").read_text()
    for name in _mkman().subcommands(parser):
        assert f"\n.SS {name.replace('-', chr(92) + '-')}\n" in page, name


@needs_man
@pytest.mark.parametrize("tool", TOOLS)
def test_man_renders_without_warnings(tool: str) -> None:
    proc = subprocess.run(
        ["man", "--warnings", "-l", str(MAN / f"{tool}.1")],
        capture_output=True,
        text=True,
        env={**os.environ, "MANWIDTH": "80", "MANPAGER": "cat"},
        check=False,
    )
    assert proc.returncode == 0 and proc.stderr == "", proc.stderr
    assert f"{tool.upper()}(1)" in proc.stdout


@needs_man
def test_git_help_vouch_shows_the_page(tmp_path: Path) -> None:
    # Installed as the README says: the tool in ~/.local/bin, the page in
    # ~/.local/share/man/man1, which man-db finds from PATH.
    home = tmp_path / "home"
    bin_dir = home / ".local" / "bin"
    man1 = home / ".local" / "share" / "man" / "man1"
    bin_dir.mkdir(parents=True)
    man1.mkdir(parents=True)
    (bin_dir / "git-vouch").symlink_to(ROOT / "git-vouch")
    (man1 / "git-vouch.1").symlink_to(MAN / "git-vouch.1")
    env = {
        "HOME": str(home),
        "PATH": os.pathsep.join((str(bin_dir), "/usr/bin", "/bin")),
        "MANPAGER": "cat",
        "MANWIDTH": "80",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    for args in (["help", "vouch"], ["vouch", "--help"]):
        proc = subprocess.run(
            ["git", *args], capture_output=True, text=True, env=env, check=False
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.startswith("GIT-VOUCH(1)"), proc.stdout[:200]
        assert "git vouch cosign [--sign-with FILE] PATH" in proc.stdout

"""Shared pytest fixtures: load git-vouch as a module, isolate the environment, make keys."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "git-vouch"


class Key(NamedTuple):
    """A throwaway SSH key pair made by ssh-keygen."""

    private: Path
    public: Path
    pubkey: str


@pytest.fixture(scope="session")
def vouch() -> ModuleType:
    """Return the git-vouch script loaded as a module."""
    loader = importlib.machinery.SourceFileLoader("git_vouch", str(SCRIPT))
    spec = importlib.util.spec_from_loader("git_vouch", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True  # keep git-vouch.cpython-*.pyc out of the repo root
    loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests away from the user's git config and SSH agent."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / ".gitconfig"))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    monkeypatch.delenv("GIT_DIR", raising=False)


def make_key(directory: Path, name: str, keygen_args: list[str]) -> Key:
    """Generate an unencrypted throwaway key pair with ssh-keygen."""
    private = directory / name
    subprocess.run(
        ["ssh-keygen", "-q", *keygen_args, "-N", "", "-C", name, "-f", str(private)],
        check=True,
    )
    public = private.with_name(name + ".pub")
    return Key(private, public, public.read_text().strip())


@pytest.fixture
def ed25519_key(tmp_path: Path) -> Key:
    """Return a throwaway ed25519 key pair."""
    return make_key(tmp_path, "ed25519", ["-t", "ed25519"])


@pytest.fixture
def ecdsa_key(tmp_path: Path) -> Key:
    """Return a throwaway ecdsa-sha2-nistp256 key pair."""
    return make_key(tmp_path, "ecdsa", ["-t", "ecdsa", "-b", "256"])


@pytest.fixture(params=["ed25519", "ecdsa"])
def any_key(request: pytest.FixtureRequest) -> Key:
    """Return each supported throwaway key type in turn."""
    return request.getfixturevalue(f"{request.param}_key")


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    """Run git-vouch as a subprocess and capture its output."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
    )

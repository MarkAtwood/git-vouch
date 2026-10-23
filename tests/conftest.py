"""Shared pytest fixtures: load git-vouch as a module, isolate the environment, make keys."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import time
from collections.abc import Collection, Iterator
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "git-vouch"
DAEMONS = {"gpg-agent", "scdaemon", "keyboxd", "dirmngr"}


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


def agents_under(root: Path) -> list[str]:
    """Return the command lines of gpg daemons whose homedir is under ``root``.

    ponytail: reads Linux /proc; another platform would need ps.
    """
    found = []
    for cmdline in Path("/proc").glob("[0-9]*/cmdline"):
        try:
            argv = cmdline.read_bytes().decode(errors="replace").split("\0")
        except OSError:  # the process exited, or is not ours to read
            continue
        if Path(argv[0]).name in DAEMONS and any(
            a.startswith(f"{root}{os.sep}") for a in argv[1:]
        ):
            found.append(" ".join(argv))
    return found


def wait_no_agents(root: Path, before: Collection[str] = ()) -> list[str]:
    """Return the gpg daemons under ``root``, other than ``before``, still running 5s on."""
    deadline = time.monotonic() + 5
    while True:
        left = [a for a in agents_under(root) if a not in before]
        if not left or time.monotonic() > deadline:
            return left
        time.sleep(0.1)


@pytest.fixture(scope="module", autouse=True)
def no_leaked_agents(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """Fail a module whose fixtures leave a gpg daemon running in a test homedir."""
    base = tmp_path_factory.getbasetemp()
    before = agents_under(base)
    yield
    assert wait_no_agents(base, before) == []


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


@pytest.fixture
def rsa_key(tmp_path: Path) -> Key:
    """Return a throwaway 2048-bit ssh-rsa key pair, the smallest accepted."""
    return make_key(tmp_path, "rsa", ["-t", "rsa", "-b", "2048"])


@pytest.fixture(params=["ed25519", "ecdsa", "rsa"])
def any_key(request: pytest.FixtureRequest) -> Key:
    """Return each supported throwaway key type in turn."""
    return request.getfixturevalue(f"{request.param}_key")


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    """Run git-vouch as a subprocess and capture its output."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
    )

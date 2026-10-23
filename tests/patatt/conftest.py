"""Fixtures for the end-to-end patatt tests (DESIGN.md, Patch signing).

Everything runs as a subprocess, as a user would: the registry is written
and synced by the git-vouch CLI, keys and signatures come from real
ssh-keygen, patches from ``git format-patch``, and patatt's own ``sign``
and ``validate`` commands run from source:

- the fork with ``keyringsrc = vouch:`` (github.com/MarkAtwood/patatt,
  branch git-vouch), default ``~/PROJECT/patatt``, or ``PATATT_FORK``;
- stock patatt as the oracle for the signature format, default
  ``~/GIT/patatt``, or ``PATATT_STOCK``.

Selectors are computed here from ``ssh-keygen -l``, never by git-vouch.
patatt needs PyNaCl; a missing tree or PyNaCl fails the run rather than
skipping it, so the gates are::

    python3 -m pytest -q tests/patatt
    uv run --python 3.9 --with pytest --with pynacl python -m pytest -q tests/patatt
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Optional

import pytest

SCRIPT = Path(__file__).resolve().parent.parent.parent / "git-vouch"
FORK = Path(os.environ.get("PATATT_FORK", Path.home() / "PROJECT" / "patatt"))
STOCK = Path(os.environ.get("PATATT_STOCK", Path.home() / "GIT" / "patatt"))

RES_VALID = 0
RES_NOKEY = 8
RES_BADSIG = 32


def run(*args: str, cwd: Optional[Path] = None, stdin: Optional[bytes] = None) -> bytes:
    """Run a command, assert it succeeded, and return its stdout."""
    proc = subprocess.run(args, cwd=cwd, input=stdin, capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    return proc.stdout


def selector(pub: Path) -> str:
    """Return ``k-`` and the first 16 hex digits of ssh-keygen's SHA256 fingerprint."""
    fpr = run("ssh-keygen", "-l", "-E", "sha256", "-f", str(pub)).split()[1]
    return "k-" + base64.b64decode(fpr.decode()[len("SHA256:") :] + "=").hex()[:16]


def patatt(
    tree: Path,
    config: Mapping[str, str],
    *args: str,
    cwd: Path,
    stdin: Optional[bytes] = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run the patatt CLI from ``tree``'s source with ``config`` as git config."""
    env = dict(os.environ, PYTHONPATH=str(tree / "src"))
    env["GIT_CONFIG_COUNT"] = str(len(config))
    for i, (key, value) in enumerate(config.items()):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return subprocess.run(
        [sys.executable, "-c", "import patatt; patatt.command()", *args],
        cwd=cwd,
        env=env,
        input=stdin,
        capture_output=True,
    )


class Registry:
    """A registry checkout written by the git-vouch CLI; ``anchor`` is its anchor."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "registry"
        self.root.mkdir()
        run("git", "init", "-q", "-b", "main", cwd=self.root)
        (self.root / "anchors.json").write_text('["anchor"]')
        self.register("anchor", "anchor@example.org")
        self.synced = False

    def key(self, name: str) -> Path:
        """Return the private key file for ``name``, generating it on first use."""
        path = self.tmp / "keys" / name
        if not path.exists():
            path.parent.mkdir(exist_ok=True)
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path))
        return path

    def vouch(self, *args: str) -> None:
        """Run ``git vouch`` in the registry checkout."""
        run("git", "vouch", *args, cwd=self.root)

    def register(self, handle: str, *emails: str, accountable: str = "") -> None:
        """Register ``handle`` with its own key and ``emails``."""
        key = self.key(handle)
        extra = ["--accountable", accountable] if accountable else []
        for email in emails:
            extra += ["--email", email]
        self.vouch(
            "register",
            "--sign-with",
            str(key),
            "--handle",
            handle,
            "--name",
            handle.title(),
            *extra,
            f"{key}.pub",
        )

    def sync(self) -> None:
        """Commit the checkout and fetch it into the user's registry copy."""
        run("git", "add", "-A", cwd=self.root)
        run("git", "commit", "-q", "--allow-empty", "-m", "r", cwd=self.root)
        if self.synced:
            run("git", "vouch", "sync", cwd=self.tmp)
        else:
            run("git", "vouch", "setup", "--registry", str(self.root), cwd=self.tmp)
            self.synced = True


@pytest.fixture(autouse=True)
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Put this interpreter's git-vouch on PATH and keep patatt's state in tmp_path.

    tests/conftest.py already isolates HOME, git config and the SSH agent.
    """
    for tree in (FORK, STOCK):
        assert (tree / "src" / "patatt" / "__init__.py").is_file(), (
            f"patatt source not found at {tree}; set PATATT_FORK / PATATT_STOCK"
        )
    assert "'vouch:'" in (FORK / "src/patatt/__init__.py").read_text(), (
        f"{FORK} is not the patatt fork with the vouch: keyring source"
    )
    run(sys.executable, "-c", "import nacl")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    wrapper = bindir / "git-vouch"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{SCRIPT}" "$@"\n')
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("GNUPGHOME", str(tmp_path / "gnupg"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    run("git", "config", "--global", "user.name", "Test")
    run("git", "config", "--global", "user.email", "test@example.org")


@pytest.fixture
def reg(tmp_path: Path) -> Registry:
    """Return a synced registry.

    anchor and alice endorse each other; carol is registered, not endorsed;
    dave has two emails and only dave@example.org is endorsed; bot is an
    automation identity accountable to anchor, with its email endorsed.
    """
    reg = Registry(tmp_path)
    anchor = str(reg.key("anchor"))
    reg.register("alice", "alice@example.org")
    reg.register("carol", "carol@example.org")
    reg.register("dave", "dave@example.org", "dave@private.example")
    reg.register("bot", "bot@example.org", accountable="anchor")
    reg.vouch("endorse", "--sign-with", anchor, "alice")
    reg.vouch("endorse", "--sign-with", str(reg.key("alice")), "anchor")
    reg.vouch("endorse", "--sign-with", anchor, "--email", "dave@example.org", "dave")
    reg.vouch("approve", "--sign-with", anchor, "bot", "automation")
    reg.vouch("endorse", "--sign-with", anchor, "bot")
    reg.sync()
    return reg

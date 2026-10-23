"""git-vouch-migrate leaves no gpg daemon running in its temporary keyrings."""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from conftest import agents_under, wait_no_agents

from .conftest import SCRIPT, Pgpkeys


def _port(pgpkeys: Pgpkeys, tmp: Path, signer: str, out: Path) -> int:
    """Run ``port`` with its temporary keyring under ``tmp``; return its exit status."""
    env = dict(
        os.environ,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        TMPDIR=str(tmp),
    )
    env.pop("GNUPGHOME", None)
    cmd = [sys.executable, str(SCRIPT), "port", str(pgpkeys.repo)]
    cmd += ["--commit", pgpkeys.commit, "--signer", signer, "--out", str(out)]
    return subprocess.run(cmd, env=env, capture_output=True).returncode


def _start_agent(home: Path) -> None:
    """Start an agent on ``home`` as gpg does on first use of a secret key."""
    subprocess.run(
        ["gpg-connect-agent", "--homedir", str(home), "/bye"],
        check=True,
        capture_output=True,
    )


def test_port_leaves_no_agent(pgpkeys: Pgpkeys, tmp_path: Path) -> None:
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    assert _port(pgpkeys, tmp, pgpkeys.fprs["signer"], tmp_path / "out") == 0
    assert wait_no_agents(tmp) == []


def test_keyring_kills_its_agent_on_error(
    migrate: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # gpg 2.4's agent exits once its homedir is removed; keep the homedir, as
    # a failed removal or an older gpg-agent would, so only the kill stops it.
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    kept = contextlib.nullcontext(str(home))
    monkeypatch.setattr(migrate.tempfile, "TemporaryDirectory", lambda **_: kept)
    try:
        with pytest.raises(migrate.VouchError, match="boom"):
            with migrate.keyring() as got:
                assert got == home
                _start_agent(home)
                assert agents_under(tmp_path) != []
                raise migrate.VouchError("boom")
        assert wait_no_agents(tmp_path) == []
    finally:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"])


@pytest.mark.parametrize("gpgconf", ["failing", "missing"])
def test_keyring_warns_when_gpgconf_fails(
    migrate: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    gpgconf: str,
) -> None:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if gpgconf == "failing":
        stub = bindir / "gpgconf"
        stub.write_text("#!/bin/sh\necho 'gpgconf: stub failure' >&2\nexit 2\n")
        stub.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    with pytest.raises(migrate.VouchError, match="boom"):
        with migrate.keyring():
            raise migrate.VouchError("boom")
    assert "git-vouch-migrate: warning:" in capsys.readouterr().err
    with migrate.keyring():
        pass
    assert "git-vouch-migrate: warning:" in capsys.readouterr().err

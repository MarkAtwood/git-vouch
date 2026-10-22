"""'git vouch export': allowed-signers and revocation files (DESIGN.md, What git and OpenSSH already do).

The oracle is real git and ssh-keygen: tags are signed with ``git tag -s``
and checked with ``git verify-tag`` against the exported files, and file
signatures with ``ssh-keygen -Y sign``/``-Y verify``.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import Key, run_script
from test_check import AFTER, BEFORE, Registry, keys  # noqa: F401 (keys is a fixture)

BEFORE_ADDED = "2025-06-01T00:00:00Z"


@pytest.fixture
def reg(tmp_path: Path, keys: Callable[[str], Key]) -> Registry:  # noqa: F811
    """Anchor torvalds; maintainer gregkh, whose key gregkh-old retired 2026-06-01;
    contributor alice, whose second key alice2 an anchor revoked; automation bot;
    dave, registered with no tier. Everyone but dave has their email endorsed."""
    r = Registry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", keys("torvalds"))
    r.person("gregkh", keys("gregkh"), retired=(keys("gregkh-old"),))
    r.person("alice", keys("alice"), keys("alice2"))
    r.person("bot", keys("bot"), accountable="gregkh")
    r.person("dave", keys("dave"))
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.tier("alice", "contributor", "gregkh", keys("gregkh"))
    r.tier("bot", "automation", "gregkh", keys("gregkh"))
    r.revoke("alice", keys("alice2"), keys("torvalds"))
    r.endorse("torvalds", keys("torvalds"), "gregkh", keys("gregkh"))
    r.endorse("gregkh", keys("gregkh"), "torvalds", keys("torvalds"))
    r.endorse("alice", keys("alice"), "gregkh", keys("gregkh"))
    r.endorse("bot", keys("bot"), "gregkh", keys("gregkh"))
    return r


class Exported:
    """Paths of one export's output files."""

    def __init__(self, directory: Path) -> None:
        self.signers = directory / "allowed_signers"
        self.revocations = directory / "revoked_keys"


def export(reg: Registry, tmp_path: Path, *options: str) -> Exported:
    out = Exported(tmp_path)
    proc = run_script(
        "export",
        str(reg.root),
        "--allowed-signers",
        str(out.signers),
        "--revocation-file",
        str(out.revocations),
        *options,
    )
    assert proc.returncode == 0, proc.stderr
    return out


def git(repo: Path, *args: str, date: str = BEFORE) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GIT_COMMITTER_DATE": date, "GIT_AUTHOR_DATE": date}
    return subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.org",
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    assert subprocess.run(["git", "init", "-q", str(path)]).returncode == 0
    assert git(path, "commit", "-q", "--allow-empty", "-m", "init").returncode == 0
    return path


def tag(repo: Path, name: str, key: Key, date: str = BEFORE) -> str:
    """Sign tag ``name`` with ``key``, dated ``date``, and return its name."""
    proc = git(
        repo,
        "-c",
        "gpg.format=ssh",
        "-c",
        f"user.signingkey={key.private}",
        "tag",
        "-s",
        "-m",
        name,
        name,
        date=date,
    )
    assert proc.returncode == 0, proc.stderr
    return name


def verifies(repo: Path, name: str, out: Exported) -> bool:
    proc = git(
        repo,
        "-c",
        f"gpg.ssh.allowedSignersFile={out.signers}",
        "-c",
        f"gpg.ssh.revocationFile={out.revocations}",
        "verify-tag",
        name,
    )
    return proc.returncode == 0


def sign_file(tmp_path: Path, key: Key, namespace: str) -> tuple[Path, Path]:
    data = tmp_path / f"release-{key.private.name}.tar"
    data.write_bytes(b"release contents\n")
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-Y",
            "sign",
            "-f",
            str(key.private),
            "-n",
            namespace,
            str(data),
        ],
        check=True,
        capture_output=True,
    )
    return data, Path(str(data) + ".sig")


def ssh_verify(
    data: Path, sig: Path, signers: Path, principal: str, namespace: str, *extra: str
) -> bool:
    cmd = ["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", principal]
    cmd += ["-n", namespace, "-s", str(sig), *extra]
    with data.open("rb") as f:
        return subprocess.run(cmd, stdin=f, capture_output=True).returncode == 0


def test_min_tier_maintainer(
    reg: Registry,
    tmp_path: Path,
    repo: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "v1", keys("gregkh")), out)
    assert verifies(repo, tag(repo, "v2", keys("torvalds")), out)
    assert not verifies(repo, tag(repo, "c1", keys("alice")), out)
    assert not verifies(repo, tag(repo, "d1", keys("dave")), out)


def test_min_tier_anchor(
    reg: Registry,
    tmp_path: Path,
    repo: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path, "--min-tier", "anchor")
    assert verifies(repo, tag(repo, "v1", keys("torvalds")), out)
    assert not verifies(repo, tag(repo, "v2", keys("gregkh")), out)


def test_default_is_contributor(
    reg: Registry,
    tmp_path: Path,
    repo: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path)
    assert verifies(repo, tag(repo, "c1", keys("alice")), out)
    assert verifies(repo, tag(repo, "v1", keys("gregkh")), out)
    assert not verifies(repo, tag(repo, "d1", keys("dave")), out)  # registered, no tier
    assert not verifies(repo, tag(repo, "b1", keys("bot")), out)


def test_automation_signs_files_only(
    reg: Registry,
    tmp_path: Path,
    repo: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path, "--include-automation")
    assert not verifies(repo, tag(repo, "b1", keys("bot")), out)
    data, sig = sign_file(tmp_path, keys("bot"), "file")
    assert ssh_verify(data, sig, out.signers, "bot@example.org", "file")
    data, sig = sign_file(tmp_path, keys("bot"), "git")
    assert not ssh_verify(data, sig, out.signers, "bot@example.org", "git")


def test_automation_left_out_by_default(
    reg: Registry,
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path)
    data, sig = sign_file(tmp_path, keys("bot"), "file")
    assert not ssh_verify(data, sig, out.signers, "bot@example.org", "file")


def test_humans_sign_files(
    reg: Registry,
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path)
    data, sig = sign_file(tmp_path, keys("gregkh"), "file")
    assert ssh_verify(data, sig, out.signers, "gregkh@example.org", "file")


def test_revoked_key_fails(
    reg: Registry,
    tmp_path: Path,
    repo: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path)
    assert not verifies(repo, tag(repo, "c1", keys("alice2")), out)
    assert verifies(repo, tag(repo, "c2", keys("alice")), out)


def test_revocation_file_revokes(
    reg: Registry,
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """The revocation file works on its own, against a hand-written allowed-signers line."""
    out = export(reg, tmp_path)
    expected = " ".join(keys("alice2").pubkey.split()[:2]) + "\n"
    assert out.revocations.read_text() == expected
    trusting = tmp_path / "trusting"
    trusting.write_text(f"alice@example.org {keys('alice2').pubkey}\n")
    data, sig = sign_file(tmp_path, keys("alice2"), "git")
    assert ssh_verify(data, sig, trusting, "alice@example.org", "git")
    assert not ssh_verify(
        data, sig, trusting, "alice@example.org", "git", "-r", str(out.revocations)
    )


def test_retired_key_keeps_earlier_signatures(
    reg: Registry,
    tmp_path: Path,
    repo: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    old = keys("gregkh-old")
    assert verifies(repo, tag(repo, "v1", old, date=BEFORE), out)
    assert not verifies(repo, tag(repo, "v2", old, date=AFTER), out)
    assert not verifies(repo, tag(repo, "v3", old, date=BEFORE_ADDED), out)
    assert verifies(repo, tag(repo, "v4", keys("gregkh"), date=AFTER), out)


def test_refuses_to_export_on_problem(
    reg: Registry,
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    reg.tier("dave", "maintainer", "dave", keys("dave"))  # self-promotion
    signers = tmp_path / "allowed_signers"
    signers.write_text("previous\n")
    proc = run_script(
        "export",
        str(reg.root),
        "--allowed-signers",
        str(signers),
        "--revocation-file",
        str(tmp_path / "revoked_keys"),
    )
    assert proc.returncode == 1
    assert "dave cannot approve themselves" in proc.stderr
    assert signers.read_text() == "previous\n"
    assert not (tmp_path / "revoked_keys").exists()


def test_output_paths_from_git_config(reg: Registry, tmp_path: Path) -> None:
    signers, revocations = tmp_path / "from-config", tmp_path / "revoked-from-config"
    for name, value in (
        ("gpg.ssh.allowedSignersFile", signers),
        ("gpg.ssh.revocationFile", revocations),
    ):
        cmd = ["git", "config", "--global", name, str(value)]
        assert subprocess.run(cmd).returncode == 0
    proc = run_script("export", str(reg.root))
    assert proc.returncode == 0, proc.stderr
    assert "torvalds@example.org" in signers.read_text()
    assert revocations.exists()


def test_no_output_path(reg: Registry) -> None:
    proc = run_script("export", str(reg.root))
    assert proc.returncode == 1
    assert "--allowed-signers" in proc.stderr


def test_only_endorsed_emails_are_principals(
    reg: Registry,
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """DESIGN.md, Person file: principals are the handle, then the endorsed emails."""
    reg.person("dave", keys("dave"), emails=("dave@kernel.org", "Dave@Work.example"))
    reg.tier("dave", "contributor", "gregkh", keys("gregkh"))
    reg.endorse(
        "dave", keys("dave"), "gregkh", keys("gregkh"), emails=("dave@work.example",)
    )
    reg.endorse("dave", keys("dave"), "dave", keys("dave"), emails=("dave@kernel.org",))
    out = export(reg, tmp_path)
    data, sig = sign_file(tmp_path, keys("dave"), "git")
    assert ssh_verify(data, sig, out.signers, "dave", "git")
    assert ssh_verify(data, sig, out.signers, "Dave@Work.example", "git")
    assert not ssh_verify(data, sig, out.signers, "dave@example.org", "git")
    # dave@kernel.org is endorsed only by dave himself.
    assert not ssh_verify(data, sig, out.signers, "dave@kernel.org", "git")


def test_handle_is_a_principal_without_endorsements(
    reg: Registry,
    tmp_path: Path,
    repo: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """An anchor nobody has endorsed still verifies, under its handle."""
    reg.endorse("torvalds", keys("torvalds"), "gregkh", keys("gregkh"), emails=())
    out = export(reg, tmp_path, "--min-tier", "anchor")
    assert verifies(repo, tag(repo, "v1", keys("torvalds")), out)
    data, sig = sign_file(tmp_path, keys("torvalds"), "git")
    assert ssh_verify(data, sig, out.signers, "torvalds", "git")
    assert not ssh_verify(data, sig, out.signers, "torvalds@example.org", "git")


def test_refuses_shared_email(
    reg: Registry,
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """ssh-keygen matches principals case-sensitively, but an email is not case-sensitive."""
    reg.person("alice", keys("alice"), keys("alice2"), emails=("Gregkh@example.org",))
    signers = tmp_path / "allowed_signers"
    proc = run_script(
        "export",
        str(reg.root),
        "--allowed-signers",
        str(signers),
        "--revocation-file",
        str(tmp_path / "revoked_keys"),
    )
    assert proc.returncode == 1
    assert "alice and gregkh both list the email" in proc.stderr
    assert not signers.exists()
    assert not (tmp_path / "revoked_keys").exists()

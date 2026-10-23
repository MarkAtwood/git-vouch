"""Tests for how git-vouch-migrate builds its keyring from keys/ at the freeze commit."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from .conftest import FREEZE_DATE, Gpg, _git, run_migrate
from .test_continuity import AFTER_C, commit_all, ssh_sign, write_person


class Keys(NamedTuple):
    """A signed pgpkeys.git whose keys/ files gpg must import in any order."""

    repo: Path
    commit: str
    attr_commit: str  # child of commit whose .gitattributes export-ignores keys/0-*
    fprs: dict[str, str]
    gpg: Gpg
    env: dict[str, str]  # signs and commits in repo, away from the user's config


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Keys]:
    """Return a pgpkeys.git with revocations filed before and after their keys."""
    base = tmp_path_factory.mktemp("keyring")
    gpg = Gpg(base / "gnupg")
    gpg.home.mkdir(mode=0o700)
    try:
        fprs = {
            n: gpg.new_key(f"{n.title()} Example <{n}@example.org>")
            for n in "signer alice bob carol dan erin frank mallory orla".split()
        }

        def export(name: str) -> bytes:
            return gpg("--armor", "--export", fprs[name])

        # Erin's export already carries her revocation, so the retry of her
        # revocation file applies nothing new.
        (base / "erin.rev").write_bytes(gpg.revocation(fprs["erin"]))
        gpg("--import", str(base / "erin.rev"))
        # No user ID left, so gpg refuses the key.
        frank = gpg("--armor", "--export", "--export-filter",
                    "keep-uid=uid = nobody", fprs["frank"])  # fmt: skip

        repo = base / "pgpkeys.git"
        (repo / "keys").mkdir(parents=True)
        files = {
            # Sorted before bob's key, so gpg first sees it with no key to revoke.
            "0-bob-revocation.asc": gpg.revocation(fprs["bob"]),
            "bob.asc": export("bob"),
            # Alice's key, then a revocation of a key in no keys/ file.
            "alice.asc": export("alice") + gpg.revocation(fprs["orla"]),
            "carol.asc": export("carol"),
            "zz-carol-revocation.asc": gpg.revocation(fprs["carol"]),
            "dan.asc": export("dan"),
            "0-erin-revocation.asc": gpg.revocation(fprs["erin"]),
            "erin.asc": export("erin"),
            "frank.asc": frank,
            "signer.asc": export("signer"),
        }
        for name, data in files.items():
            (repo / "keys" / name).write_bytes(data)
        (gpg.home / "gpg.conf").write_text("faked-system-time 20200601T000000!\n")
        env = dict(
            os.environ,
            GNUPGHOME=str(gpg.home),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_DATE=FREEZE_DATE,
            GIT_COMMITTER_DATE=FREEZE_DATE,
        )
        ident = ["-c", "user.name=Sig Ner", "-c", "user.email=signer@example.org"]
        sign = ["-c", "gpg.format=openpgp", "-c", "gpg.program=gpg"]
        sign += ["-c", f"user.signingkey={fprs['signer']}!"]
        _git(repo, "init", "-q", env=env)
        _git(repo, "add", "keys", env=env)
        _git(repo, *ident, *sign, "commit", "-q", "-S", "-m", "freeze", env=env)
        commit = _git(repo, "rev-parse", "HEAD", env=env)
        (repo / ".gitattributes").write_text("keys/0-*.asc export-ignore\n")
        _git(repo, "add", ".gitattributes", env=env)
        _git(repo, *ident, *sign, "commit", "-q", "-S", "-m", "attrs", env=env)
        attr_commit = _git(repo, "rev-parse", "HEAD", env=env)
        (gpg.home / "gpg.conf").unlink()
        yield Keys(repo, commit, attr_commit, fprs, gpg, env)
    finally:
        subprocess.run(
            ["gpgconf", "--homedir", str(gpg.home), "--kill", "all"], check=False
        )


def migrate(
    k: Keys, cmd: str, *args: str, repo: Path | None = None, commit: str = ""
) -> Any:
    """Run a git-vouch-migrate subcommand on ``k``'s freeze commit."""
    return run_migrate(
        cmd, str(repo or k.repo), *args, "--commit", commit or k.commit,
        "--signer", k.fprs["signer"],
    )  # fmt: skip


def port(
    k: Keys, out: Path, repo: Path | None = None, commit: str = ""
) -> tuple[str, set[str]]:
    """Run ``port``; return its stdout and the drafts' migratedFrom fingerprints."""
    proc = migrate(k, "port", "--out", str(out), repo=repo, commit=commit)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    drafted = {
        json.loads(p.read_bytes())["migratedFrom"].removeprefix("openpgp4fpr:")
        for p in (out / "people").iterdir()
    }
    return proc.stdout, drafted


@pytest.fixture
def registry(keys: Keys, tmp_path: Path, ed25519_key: Any) -> Path:
    """Return a committed registry where bob claims his revoked GPG key."""
    root = tmp_path / "registry"
    path = write_person(
        root, "bob", keys.fprs["bob"], ["bob@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    keys.gpg("--yes", "--armor", "--detach-sign", "-u", keys.fprs["bob"] + "!",
             "-o", f"{path}.asc", str(path), at=AFTER_C)  # fmt: skip
    commit_all(root, "bob")
    return root


def test_revocation_filed_before_its_key_applies(keys: Keys, tmp_path: Path) -> None:
    stdout, drafted = port(keys, tmp_path / "out")
    lines = stdout.splitlines()
    assert f"skip {keys.fprs['bob']}: revoked" in lines
    assert keys.fprs["bob"] not in drafted
    assert not [ln for ln in lines if "0-bob-revocation.asc" in ln]


def test_revocation_filed_after_its_key_is_not_reported(
    keys: Keys, tmp_path: Path
) -> None:
    stdout, drafted = port(keys, tmp_path / "out")
    lines = stdout.splitlines()
    assert f"skip {keys.fprs['carol']}: revoked" in lines
    assert keys.fprs["carol"] not in drafted
    assert not [ln for ln in lines if "zz-carol-revocation.asc" in ln]


def test_revocation_already_applied_is_not_reported(keys: Keys, tmp_path: Path) -> None:
    stdout, drafted = port(keys, tmp_path / "out")
    lines = stdout.splitlines()
    assert f"skip {keys.fprs['erin']}: revoked" in lines
    assert keys.fprs["erin"] not in drafted
    assert not [ln for ln in lines if "erin" in ln and "keys/" in ln]


def test_key_gpg_refuses_is_reported(keys: Keys, tmp_path: Path) -> None:
    stdout, drafted = port(keys, tmp_path / "out")
    assert "skip keys/frank.asc: gpg refused 1 key(s)" in stdout.splitlines()
    assert keys.fprs["frank"] not in drafted


def test_export_ignore_does_not_drop_a_revocation(keys: Keys, tmp_path: Path) -> None:
    # Setup only: git archive leaves out the revocation filed before bob's key.
    archive = _git(keys.repo, "archive", keys.attr_commit, "keys", env=keys.env)
    assert "0-bob-revocation.asc" not in archive
    stdout, drafted = port(keys, tmp_path / "out", commit=keys.attr_commit)
    assert f"skip {keys.fprs['bob']}: revoked" in stdout.splitlines()
    assert keys.fprs["bob"] not in drafted


def test_partly_imported_file_is_reported_partial(keys: Keys, tmp_path: Path) -> None:
    stdout, drafted = port(keys, tmp_path / "out")
    lines = stdout.splitlines()
    assert keys.fprs["alice"] in drafted
    assert not [ln for ln in lines if ln.startswith("skip keys/alice.asc")]
    (partial,) = [ln for ln in lines if ln.startswith("partial keys/alice.asc: ")]
    assert keys.fprs["alice"] in partial and "revocation" in partial


def test_verify_continuity_refuses_key_revoked_before_it_and_reports_files(
    keys: Keys, registry: Path
) -> None:
    proc = migrate(keys, "verify-continuity", str(registry))
    lines = proc.stdout.splitlines()
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert f"fail bob: {keys.fprs['bob']} is revoked" in lines
    assert [ln for ln in lines if ln.startswith("partial keys/alice.asc: ")]


def test_drafts_reports_files(keys: Keys, registry: Path, tmp_path: Path) -> None:
    proc = migrate(
        keys, "drafts", str(registry), "--as", "bob", "--out", str(tmp_path / "o")
    )
    lines = proc.stdout.splitlines()
    assert [ln for ln in lines if ln.startswith("partial keys/alice.asc: ")]


def test_replace_refs_do_not_change_keys(keys: Keys, tmp_path: Path) -> None:
    repo = tmp_path / "pgpkeys.git"
    shutil.copytree(keys.repo, repo)
    mallory = repo / "mallory.asc"
    mallory.write_bytes(keys.gpg("--armor", "--export", keys.fprs["mallory"]))
    dan = _git(repo, "rev-parse", f"{keys.commit}:keys/dan.asc", env=keys.env)
    evil = _git(repo, "hash-object", "-w", str(mallory), env=keys.env)
    _git(repo, "replace", dan, evil, env=keys.env)
    # Setup only: plain git now reads Mallory's key at the freeze commit.
    shown = _git(repo, "show", f"{keys.commit}:keys/dan.asc", env=keys.env)
    assert shown == mallory.read_text().strip()
    _, drafted = port(keys, tmp_path / "out", repo=repo)
    assert keys.fprs["dan"] in drafted
    assert keys.fprs["mallory"] not in drafted


def test_replace_refs_do_not_change_the_freeze_commit(
    keys: Keys, tmp_path: Path
) -> None:
    repo = tmp_path / "pgpkeys.git"
    shutil.copytree(keys.repo, repo)
    # Dated before any key was made: judged then, no key or signature is good.
    env = dict(keys.env, GIT_COMMITTER_DATE="2019-01-01T00:00:00Z")
    ident = ["-c", "user.name=M", "-c", "user.email=m@example.org"]
    tree = f"{keys.commit}^{{tree}}"
    unsigned = _git(repo, *ident, "commit-tree", "-m", "freeze", tree, env=env)
    _git(repo, "replace", keys.commit, unsigned, env=env)
    stdout, drafted = port(keys, tmp_path / "out", repo=repo)
    assert f"pgpkeys at {keys.commit}, signed by {keys.fprs['signer']}" in stdout
    assert keys.fprs["dan"] in drafted

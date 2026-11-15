"""Tests for ``git-vouch-migrate pullers``: the flag day's core set from a tree's merges.

The oracle is git itself: each case builds the merges with ``git tag -s``
and ``git merge``, which write the ``mergetag`` headers pullers reads.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from .conftest import Gpg, run_migrate


def _git(repo: Path, *args: str, env: dict[str, str]) -> None:
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """A tree whose owner pulled OpenPGP and SSH tags, and an unsigned one.

    git records only a signed tag in ``mergetag``, so the unsigned pull is
    not counted. Off the first-parent line, a subsystem merge pulls another
    tag that the owner did not pull directly, so pullers must not count it.
    """
    base = tmp_path_factory.mktemp("pullers")
    gpg = Gpg(base / "gnupg")
    gpg.home.mkdir(mode=0o700)
    try:
        yield _build(base, gpg)
    finally:
        subprocess.run(["gpgconf", "--homedir", str(gpg.home), "--kill", "all"],
                       check=False)  # fmt: skip


def _build(base: Path, gpg: Gpg) -> Path:
    fpr = gpg.new_key("Pat Gpg <pat@example.org>")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f",
                    str(base / "id")], check=True)  # fmt: skip
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GNUPGHOME=str(gpg.home))  # fmt: skip
    repo = base / "tree"
    repo.mkdir()
    owner = ["-c", "user.name=Lin Us", "-c", "user.email=linus@example.org"]

    def commit(msg: str) -> None:
        _git(repo, *owner, "commit", "-q", "--allow-empty", "-m", msg, env=env)

    def tag(name: str, who: list[str], *how: str) -> None:
        _git(repo, "switch", "-q", "-c", f"b-{name}", "main", env=env)
        commit(name)
        _git(repo, *who, "tag", *how, "-m", name, name, env=env)
        _git(repo, "switch", "-q", "main", env=env)

    def merge(name: str) -> None:
        _git(repo, *owner, "merge", "-q", "--no-ff", "--no-edit", name, env=env)

    _git(repo, "init", "-q", "-b", "main", env=env)
    commit("base")
    _git(repo, "tag", "v1", env=env)
    pat = ["-c", "user.name=Pat Gpg", "-c", "user.email=Pat@Example.org"]
    tag("pat-1", [*pat, "-c", f"user.signingkey={fpr}!"], "-s")
    merge("pat-1")
    sam = ["-c", "user.name=Sam Ssh", "-c", "user.email=sam@example.org",
           "-c", "gpg.format=ssh", "-c", f"user.signingkey={base / 'id'}"]  # fmt: skip
    tag("sam-1", sam, "-s")
    merge("sam-1")
    tag("pat-2", [*pat[:2], "-c", "user.email=pat@example.org",
                  "-c", f"user.signingkey={fpr}!"], "-s")  # fmt: skip
    merge("pat-2")
    un = ["-c", "user.name=Una Signed", "-c", "user.email=una@example.org"]
    tag("una-1", un, "-a")
    merge("una-1")
    # A subsystem branch that itself merged a tag; the owner pulls the branch.
    tag("sub-inner", sam, "-s")
    _git(repo, "switch", "-q", "-c", "sub", "main", env=env)
    commit("sub work")
    _git(repo, *owner, "merge", "-q", "--no-ff", "--no-edit", "sub-inner", env=env)
    _git(repo, "switch", "-q", "main", env=env)
    merge("sub")
    _git(repo, "tag", "v2", env=env)
    tag("late", sam, "-s")
    merge("late")
    return repo


def test_lists_each_tagger_most_pulls_first(tree: Path) -> None:
    proc = run_migrate("pullers", str(tree), "--since", "v1", "--until", "v2")
    assert proc.returncode == 0, proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0].startswith("pullers of ")
    # Pat's two tags count once, under the lowercased email, with the name on
    # the newest; sam's tag pulled through the subsystem branch is not counted.
    assert lines[1:] == [
        "2 2 0 pat@example.org Pat Gpg",
        "1 0 1 sam@example.org Sam Ssh",
    ]


def test_range_is_resolved_and_until_defaults_to_head(tree: Path) -> None:
    def rev(name: str) -> str:
        out = subprocess.run(["git", "rev-parse", name], cwd=tree, check=True,
                             capture_output=True, text=True)  # fmt: skip
        return out.stdout.strip()

    proc = run_migrate("pullers", str(tree), "--since", "v2")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        f"pullers of {rev('v2')}..{rev('HEAD')}",
        "1 0 1 sam@example.org Sam Ssh",
    ]


def test_empty_range_prints_only_the_range(tree: Path) -> None:
    proc = run_migrate("pullers", str(tree), "--since", "HEAD")
    assert proc.returncode == 0, proc.stderr
    assert len(proc.stdout.splitlines()) == 1


@pytest.mark.parametrize("flag", ["--since", "--until"])
def test_rejects_a_revision_that_is_not_a_commit(tree: Path, flag: str) -> None:
    args = {"--since": "v1", "--until": "HEAD", flag: "no-such-tag"}
    proc = run_migrate("pullers", str(tree), *(x for kv in args.items() for x in kv))
    assert proc.returncode == 1
    assert f"error: {flag} no-such-tag: not a commit" in proc.stderr


def test_mergetags_reads_every_tag_of_an_octopus(migrate) -> None:  # type: ignore[no-untyped-def]
    raw = (
        b"tree t\nparent a\nparent b\nparent c\nauthor x\ncommitter y\n"
        b"mergetag object b\n type commit\n tag one\n tagger A <a@x> 1 +0000\n \n m\n"
        b"mergetag object c\n type commit\n tag two\n tagger B <b@x> 1 +0000\n \n m\n"
        b"\nMerge tags\n mergetag object fake\n"
    )
    tags = migrate._mergetags(raw)
    assert [t.split(b"\n")[2] for t in tags] == [b"tag one", b"tag two"]

"""Registry history reader (DESIGN.md, The registry: git history is part of the registry).

The oracle is the history each test builds itself with real git: commit ids
from ``git rev-parse``, committer dates fixed with GIT_COMMITTER_DATE, and
the bytes the test wrote.
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest

PATH = "people/alice.json"


def git(repo: Path, *args: str, date: str = "2026-01-01T00:00:00Z") -> str:
    """Run git in ``repo`` with a fixed committer date and return its stdout."""
    env = {**os.environ, "GIT_COMMITTER_DATE": date, "GIT_AUTHOR_DATE": date}
    proc = subprocess.run(
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
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def commit(repo: Path, date: str, files: dict[str, bytes | None]) -> str:
    """Write (or, for None, delete) ``files``, commit at ``date``, and return the commit id."""
    for rel, data in files.items():
        path = repo / rel
        if data is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", date, date=date)
    return git(repo, "rev-parse", "HEAD")


def utc(text: str) -> datetime:
    """Parse an ISO 8601 timestamp to an aware UTC datetime."""
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Return an empty git repository on branch main."""
    path = tmp_path / "registry"
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    return path


def test_versions_in_commit_order(vouch: ModuleType, repo: Path) -> None:
    """Every add, change, deletion and re-add is listed oldest first with its committer date."""
    init = commit(repo, "2026-01-01T00:00:00Z", {"README": b"r\n"})
    c1 = commit(repo, "2026-02-01T10:00:00Z", {PATH: b"v1\n"})
    commit(repo, "2026-02-15T00:00:00Z", {"README": b"other\n"})
    c2 = commit(repo, "2026-03-01T12:30:00+02:00", {PATH: b"v2\n"})
    c3 = commit(repo, "2026-04-01T00:00:00Z", {PATH: None})
    c4 = commit(repo, "2026-05-01T00:00:00Z", {PATH: b"v3\n"})
    assert vouch.file_history(repo, PATH) == [
        vouch.Version(c1, utc("2026-02-01T10:00:00Z"), (init,), b"v1\n"),
        vouch.Version(
            c2,
            utc("2026-03-01T10:30:00Z"),
            (git(repo, "rev-parse", f"{c2}^"),),
            b"v2\n",
        ),
        vouch.Version(c3, utc("2026-04-01T00:00:00Z"), (c2,), None),
        vouch.Version(c4, utc("2026-05-01T00:00:00Z"), (c3,), b"v3\n"),
    ]


def test_root_commit_has_no_parent(vouch: ModuleType, repo: Path) -> None:
    """A path added by the root commit has no parents, even with log.showRoot=false."""
    c1 = commit(repo, "2026-02-01T00:00:00Z", {PATH: b"{}"})
    subprocess.run(["git", "config", "--global", "log.showRoot", "false"], check=True)
    assert vouch.file_history(repo, PATH) == [
        vouch.Version(c1, utc("2026-02-01T00:00:00Z"), (), b"{}")
    ]


def test_untouched_path_has_no_versions(vouch: ModuleType, repo: Path) -> None:
    """A path no commit ever touched has an empty history."""
    commit(repo, "2026-02-01T00:00:00Z", {"README": b"r\n"})
    assert vouch.file_history(repo, PATH) == []


def test_merged_branch_versions_listed(vouch: ModuleType, repo: Path) -> None:
    """Each version made on a merged branch is its own entry; the merge commit is not listed."""
    base = commit(repo, "2026-01-01T00:00:00Z", {PATH: b"v1\n"})
    git(repo, "checkout", "-q", "-b", "mr")
    s1 = commit(repo, "2026-02-01T00:00:00Z", {PATH: b"v2\n"})
    s2 = commit(repo, "2026-02-02T00:00:00Z", {PATH: b"v3\n"})
    git(repo, "checkout", "-q", "main")
    commit(repo, "2026-02-03T00:00:00Z", {"README": b"r\n"})
    git(
        repo, "merge", "-q", "--no-ff", "-m", "merge", "mr", date="2026-02-04T00:00:00Z"
    )
    assert [(v.commit, v.parents, v.data) for v in vouch.file_history(repo, PATH)] == [
        (base, (), b"v1\n"),
        (s1, (base,), b"v2\n"),
        (s2, (s1,), b"v3\n"),
    ]


def test_side_branch_add_then_delete_listed(vouch: ModuleType, repo: Path) -> None:
    """A file added and deleted on a merged branch keeps both versions in history."""
    commit(repo, "2026-01-01T00:00:00Z", {"README": b"r\n"})
    git(repo, "checkout", "-q", "-b", "side")
    add = commit(repo, "2026-02-01T00:00:00Z", {PATH: b"rev\n"})
    delete = commit(repo, "2026-02-02T00:00:00Z", {PATH: None})
    git(repo, "checkout", "-q", "main")
    commit(repo, "2026-02-03T00:00:00Z", {"README": b"main\n"})
    git(repo, "merge", "-q", "-m", "merge", "side", date="2026-02-04T00:00:00Z")
    assert [(v.commit, v.data) for v in vouch.file_history(repo, PATH)] == [
        (add, b"rev\n"),
        (delete, None),
    ]


def test_side_branch_change_and_revert_listed(vouch: ModuleType, repo: Path) -> None:
    """A swap and swap-back on a branch shows up even though the merge equals main."""
    base = commit(repo, "2026-01-01T00:00:00Z", {PATH: b"A\n"})
    git(repo, "checkout", "-q", "-b", "side")
    evil = commit(repo, "2026-02-01T00:00:00Z", {PATH: b"EVIL\n"})
    back = commit(repo, "2026-02-02T00:00:00Z", {PATH: b"A\n"})
    git(repo, "checkout", "-q", "main")
    commit(repo, "2026-02-03T00:00:00Z", {"README": b"r\n"})
    git(repo, "merge", "-q", "--no-ff", "-m", "m", "side", date="2026-02-04T00:00:00Z")
    assert [(v.commit, v.parents, v.data) for v in vouch.file_history(repo, PATH)] == [
        (base, (), b"A\n"),
        (evil, (base,), b"EVIL\n"),
        (back, (evil,), b"A\n"),
    ]


def test_mainline_change_kept_when_merge_takes_side(
    vouch: ModuleType, repo: Path
) -> None:
    """A main-branch version is listed although the merge result takes the side's content."""
    base = commit(repo, "2026-01-01T00:00:00Z", {PATH: b"v1\n"})
    git(repo, "checkout", "-q", "-b", "side")
    side = commit(repo, "2026-02-01T00:00:00Z", {PATH: b"side\n"})
    git(repo, "checkout", "-q", "main")
    main = commit(repo, "2026-02-02T00:00:00Z", {PATH: b"main\n"})
    git(repo, "merge", "-q", "-X", "theirs", "-m", "m", "side")
    history = vouch.file_history(repo, PATH)
    assert [v.commit for v in history][0] == base
    assert sorted((v.commit, v.data) for v in history[1:]) == sorted(
        [(side, b"side\n"), (main, b"main\n")]
    )


def test_conflict_resolved_merge_listed(vouch: ModuleType, repo: Path) -> None:
    """A merge whose content differs from every parent is a version with all its parents."""
    commit(repo, "2026-01-01T00:00:00Z", {PATH: b"v1\n"})
    git(repo, "checkout", "-q", "-b", "side")
    side = commit(repo, "2026-02-01T00:00:00Z", {PATH: b"side\n"})
    git(repo, "checkout", "-q", "main")
    main = commit(repo, "2026-02-02T00:00:00Z", {PATH: b"main\n"})
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge", "-q", "side"], capture_output=True
    )
    assert proc.returncode != 0
    merge = commit(repo, "2026-02-03T00:00:00Z", {PATH: b"resolved\n"})
    last = vouch.file_history(repo, PATH)[-1]
    assert (last.commit, last.parents, last.data) == (
        merge,
        (main, side),
        b"resolved\n",
    )
    assert merge == git(repo, "rev-parse", "HEAD")


def test_replace_refs_ignored(vouch: ModuleType, repo: Path) -> None:
    """A replace ref cannot change the content read from history."""
    commit(repo, "2026-01-01T00:00:00Z", {PATH: b"A\n"})
    blob = git(repo, "rev-parse", f"HEAD:{PATH}")
    forged = (
        subprocess.run(
            ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
            input=b"FORGED\n",
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    git(repo, "replace", blob, forged)
    assert git(repo, "cat-file", "-p", blob) == "FORGED"
    assert [v.data for v in vouch.file_history(repo, PATH)] == [b"A\n"]


def test_symlink_version_refused(vouch: ModuleType, repo: Path) -> None:
    """A symlink in history is not a file, as on disk, even if its target is JSON."""
    (repo / "people").mkdir()
    os.symlink('{"handle": "alice"}', repo / PATH)
    commit(repo, "2026-01-01T00:00:00Z", {})
    assert git(repo, "ls-tree", "HEAD", "--", PATH).startswith("120000 ")
    with pytest.raises(vouch.VouchError, match="not a regular file"):
        vouch.file_history(repo, PATH)


def test_directory_version_refused(vouch: ModuleType, repo: Path) -> None:
    """A directory at the path in history is not a file."""
    commit(repo, "2026-01-01T00:00:00Z", {PATH: b"v1\n"})
    commit(repo, "2026-02-01T00:00:00Z", {PATH: None, f"{PATH}/x": b"x\n"})
    with pytest.raises(vouch.VouchError, match="not a regular file"):
        vouch.file_history(repo, PATH)


def test_rename_not_followed(vouch: ModuleType, repo: Path) -> None:
    """History stops at a rename even when the user's git config sets log.follow."""
    commit(repo, "2026-01-01T00:00:00Z", {"people/bob.json": b"same\n"})
    c2 = commit(
        repo, "2026-02-01T00:00:00Z", {"people/bob.json": None, PATH: b"same\n"}
    )
    subprocess.run(["git", "config", "--global", "log.follow", "true"], check=True)
    subprocess.run(["git", "config", "--global", "diff.renames", "true"], check=True)
    assert [v.commit for v in vouch.file_history(repo, PATH)] == [c2]


def test_shallow_clone_refused(vouch: ModuleType, repo: Path, tmp_path: Path) -> None:
    """A shallow clone lacks history, so reading it is refused with a clear error."""
    commit(repo, "2026-01-01T00:00:00Z", {PATH: b"v1\n"})
    commit(repo, "2026-02-01T00:00:00Z", {PATH: b"v2\n"})
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(shallow)],
        check=True,
    )
    with pytest.raises(vouch.VouchError, match="shallow clone"):
        vouch.file_history(shallow, PATH)


def test_oversized_version_refused(vouch: ModuleType, repo: Path) -> None:
    """A version in history larger than the 64 KiB cap is an error, as on disk."""
    commit(repo, "2026-01-01T00:00:00Z", {PATH: b"x" * (64 * 1024 + 1)})
    commit(repo, "2026-02-01T00:00:00Z", {PATH: b"small\n"})
    with pytest.raises(vouch.VouchError, match="at most 65536 bytes"):
        vouch.file_history(repo, PATH)


@pytest.mark.parametrize(
    "rel", ["../x.json", "people/../x.json", "/etc/passwd", "a\nb"]
)
def test_unsafe_path_refused(vouch: ModuleType, repo: Path, rel: str) -> None:
    """A path that is not a plain relative path is rejected before git runs."""
    with pytest.raises(vouch.VouchError, match="not a plain path"):
        vouch.file_history(repo, rel)

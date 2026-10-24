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


def plumbing_history(
    repo: Path, rel: str
) -> dict[str, tuple[tuple[str, ...], bytes | None]]:
    """Return rel's versions, commit -> (parents, content), read with git plumbing alone.

    The oracle for ``file_histories``: a commit is a version if its entry for
    ``rel`` (``git ls-tree``) differs from that of every parent, or, for a
    root commit, if it has one.
    """

    def entry(commit: str) -> str:
        return git(repo, "ls-tree", "--full-tree", commit, "--", rel)

    found = {}
    for line in git(repo, "rev-list", "--parents", "HEAD").splitlines():
        commit, *parents = line.split()
        here = entry(commit)
        if all(entry(p) != here for p in parents) and (parents or here):
            data = None
            if here:
                data = subprocess.run(
                    ["git", "-C", str(repo), "cat-file", "blob", here.split()[2]],
                    capture_output=True,
                    check=True,
                ).stdout
            found[commit] = (tuple(parents), data)
    return found


def test_combined_log_matches_each_paths_own_history(
    vouch: ModuleType, repo: Path
) -> None:
    """One log over the registry gives every path the versions git plumbing finds.

    The history branches and merges with a conflict, an evil merge, ``-s
    ours``, an octopus, deletions on branches and in a merge, and a re-add.
    """
    a, b, c = "people/a.json", "people/b.json", "people/c.json"
    t, r, s = "tiers/a.json", "revocations/r-1.json", "revocations/s-1.json"
    commit(
        repo, "2026-01-01T00:00:00Z", {a: b"a1\n", b: b"b1\n", c: b"c1\n", t: b"t1\n"}
    )
    git(repo, "checkout", "-q", "-b", "side1")
    commit(repo, "2026-01-02T00:00:00Z", {a: b"a2\n", b: None, r: b"r1\n"})
    git(repo, "checkout", "-q", "main")
    commit(repo, "2026-01-03T00:00:00Z", {b: b"b2\n", t: b"t2\n"})
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge", "-q", "side1"], capture_output=True
    )
    assert proc.returncode != 0  # b: modified on main, deleted on side1
    commit(repo, "2026-01-04T00:00:00Z", {b: b"b3\n"})
    git(repo, "checkout", "-q", "-b", "side2")
    commit(repo, "2026-01-05T00:00:00Z", {a: b"EVIL\n", s: b"s1\n"})
    commit(repo, "2026-01-06T00:00:00Z", {a: b"a2\n"})
    git(repo, "checkout", "-q", "main")
    commit(repo, "2026-01-07T00:00:00Z", {"README": b"r\n"})
    git(repo, "merge", "-q", "-s", "ours", "-m", "ours", "side2")
    git(repo, "checkout", "-q", "-b", "side3")
    commit(repo, "2026-01-08T00:00:00Z", {t: b"t3\n"})
    git(repo, "checkout", "-q", "main")
    commit(repo, "2026-01-09T00:00:00Z", {"README": b"r2\n"})
    git(repo, "merge", "-q", "--no-commit", "side3", date="2026-01-10T00:00:00Z")
    commit(repo, "2026-01-10T00:00:00Z", {a: b"a3\n", c: None})  # evil merge
    for n, rel in enumerate((a, r), 4):
        git(repo, "checkout", "-q", "-b", f"oct{n}", "main")
        commit(repo, f"2026-01-1{n}T00:00:00Z", {rel: f"oct{n}\n".encode()})
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "-m", "octopus", "oct4", "oct5")
    commit(repo, "2026-01-20T00:00:00Z", {c: b"c2\n"})
    rels = [a, b, c, t, r, s, "people/never.json"]
    sources = ["people", "tiers", "revocations"]
    combined = vouch.file_histories(repo, rels, sources)
    assert sorted(combined) == sorted(rels)
    for rel in rels:
        got = {v.commit: (v.parents, v.data) for v in combined[rel]}
        assert got == plumbing_history(repo, rel), rel
        assert combined[rel] == vouch.file_history(repo, rel), rel
        commits = [v.commit for v in combined[rel]]
        for i, earlier in enumerate(commits):
            for later in commits[i + 1 :]:
                proc = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "merge-base",
                        "--is-ancestor",
                        later,
                        earlier,
                    ]
                )
                assert proc.returncode == 1, (rel, earlier, later)
    assert {v.data for v in combined[c]} == {b"c1\n", None, b"c2\n"}
    assert combined["people/never.json"] == []


def test_path_outside_sources_refused(vouch: ModuleType, repo: Path) -> None:
    """A path the combined log does not cover is an error, not an empty history."""
    commit(repo, "2026-01-01T00:00:00Z", {PATH: b"v1\n"})
    with pytest.raises(vouch.VouchError, match="not below tiers"):
        vouch.file_histories(repo, [PATH], ["tiers"])


@pytest.mark.parametrize("n", [2, 12])
def test_registry_history_git_runs_do_not_grow_with_paths(
    vouch: ModuleType, repo: Path, monkeypatch: pytest.MonkeyPatch, n: int
) -> None:
    """Reading the history of n person files costs the same few git runs for any n.

    It used to cost four git runs per file and per .sig (vouch-xlha.2).
    """
    files: dict[str, bytes | None] = {"anchors.json": b"[]"}
    for i in range(n):
        files[f"people/p{i}.json"] = b"{}"
        files[f"people/p{i}.json.sig"] = b"sig"
    commit(repo, "2026-01-01T00:00:00Z", files)
    commit(
        repo, "2026-01-02T00:00:00Z", {f"people/p{i}.json": b"{ }" for i in range(n)}
    )
    runs: list[list[str]] = []
    real = subprocess.run

    def counting(argv: list[str], *args: object, **kwargs: object) -> object:
        runs.append(argv)
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(vouch.subprocess, "run", counting)
    history = vouch.registry_history(repo, [p for p in files if p.endswith(".json")])
    monkeypatch.undo()
    assert len(history.versions) == 2 * n + 1
    assert all(len(history.versions[f"people/p{i}.json"]) == 2 for i in range(n))
    assert len([a for a in runs if a[0] == "git"]) <= 9


def test_gitlink_naming_a_files_blob_is_not_that_file(
    vouch: ModuleType, repo: Path
) -> None:
    """A gitlink whose hash is another file's blob is unreadable, not that file's content.

    Blobs are read once for all paths, so content must be looked up only for
    file entries, both in a commit's own log and in a merge's.
    """
    data = b'{"handle": "carol"}\n'
    commit(repo, "2026-01-01T00:00:00Z", {"README": b"r\n"})
    git(repo, "checkout", "-q", "-b", "side")
    commit(repo, "2026-01-02T00:00:00Z", {"people/carol.json": data})
    blob = git(repo, "rev-parse", "HEAD:people/carol.json")
    git(repo, "update-index", "--add", "--cacheinfo", f"160000,{blob},people/bob.json")
    git(repo, "commit", "-q", "-m", "gitlink", date="2026-01-03T00:00:00Z")
    side = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-q", "main")
    commit(repo, "2026-01-04T00:00:00Z", {"README": b"r2\n"})
    git(
        repo,
        "merge",
        "-q",
        "--no-ff",
        "-m",
        "merge",
        "side",
        date="2026-01-05T00:00:00Z",
    )
    merge = git(repo, "rev-parse", "HEAD")
    assert git(repo, "ls-tree", "HEAD", "--", "people/bob.json").startswith(
        f"160000 commit {blob}\t"
    )
    rels = ["people/bob.json", "people/carol.json"]
    unreadable: list[str] = []
    logs = vouch.file_histories(repo, rels, ["people"], unreadable)
    assert data not in [v.data for v in logs["people/bob.json"]]
    assert [u for u in unreadable if u.startswith("people/bob.json:")] != []
    unreadable = []
    history = vouch.registry_history(repo, rels, unreadable=unreadable)
    assert data in [d for _, d in history.versions["people/carol.json"]]
    assert data not in [d for _, d in history.versions["people/bob.json"]]
    bob = [u for u in unreadable if u.startswith("people/bob.json:")]
    assert any(side in u for u in bob) and any(merge in u for u in bob)

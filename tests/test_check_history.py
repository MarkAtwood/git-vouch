"""'git vouch check' judged by registry history (DESIGN.md, Tier record, Person file, Revocation).

Each fixture registry is a real git repository built commit by commit, with
records signed by real ``ssh-keygen -Y sign``. Expected outcomes follow from
DESIGN.md's rules. Where it matters, the same tree is also checked as a plain
directory with no history, which must reach the snapshot verdict instead.
"""

from __future__ import annotations

import inspect
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest

from conftest import Key, run_script
from test_check import ADDED, AFTER, RETIRED, Registry, did, has, keys  # noqa: F401 (keys is a fixture)
from test_signatures import count_verifies
from test_export import export, repo, sign_file, ssh_verify, tag, verifies  # noqa: F401 (repo is a fixture)


class GitRegistry(Registry):
    """A Registry whose checkout is a git repository, committed step by step."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
        self.day = 0

    def commit(
        self, author: str | None = None, add: bool = True, date: str | None = None
    ) -> None:
        """Commit everything, one day after the previous commit.

        The author date is the committer date unless ``author`` is given.
        With ``add`` false, commit only what is already staged. A ``date``
        is the committer date instead, as a forger sets it; the next commit
        is still the day after the previous one.
        """
        if date is None:
            self.day += 1
            date = f"2026-01-{self.day:02d}T00:00:00Z"
        env = {
            **os.environ,
            "GIT_COMMITTER_DATE": date,
            "GIT_AUTHOR_DATE": author or date,
        }
        for args in (["add", "-A"], ["commit", "-q", "-m", date])[not add :]:
            subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                cwd=self.root,
                env=env,
                check=True,
            )

    def git(self, *args: str, date: str | None = None) -> None:
        """Run a git command in the checkout, e.g. to branch or merge.

        A ``date`` is the committer and author date of any commit it makes.
        """
        dated = {"GIT_COMMITTER_DATE": date, "GIT_AUTHOR_DATE": date} if date else {}
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
            cwd=self.root,
            env={**os.environ, **dated},
            check=True,
            capture_output=True,
        )

    def delete(self, rel: str) -> None:
        """Remove a record and its signature from the working tree."""
        (self.root / rel).unlink()
        (self.root / (rel + ".sig")).unlink()


@pytest.fixture
def key(keys: Callable[[str], Key]) -> Callable[[str], Key]:  # noqa: F811
    """Return test_check's session-wide maker of named throwaway ed25519 keys."""
    return keys


@pytest.fixture
def reg(tmp_path: Path, key: Callable[[str], Key]) -> GitRegistry:
    """First commit: anchor torvalds, maintainer gregkh, contributor alice (keys
    alice and alice2), and dave, registered with no tier."""
    r = GitRegistry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", key("torvalds"))
    r.person("gregkh", key("gregkh"))
    r.person("alice", key("alice"), key("alice2"))
    r.person("dave", key("dave"))
    r.tier("gregkh", "maintainer", "torvalds", key("torvalds"))
    r.tier("alice", "contributor", "gregkh", key("gregkh"))
    r.commit()
    return r


def snapshot(vouch: ModuleType, reg: Registry, tmp_path: Path) -> object:
    """Check a copy of the working tree with no git history."""
    copy = tmp_path / "snapshot"
    shutil.copytree(reg.root, copy, ignore=shutil.ignore_patterns(".git"))
    return vouch.check_registry(copy)


def test_approver_tier_deleted_keeps_grants(
    vouch: ModuleType, reg: GitRegistry, tmp_path: Path
) -> None:
    reg.delete("tiers/gregkh.json")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers == {"torvalds": "anchor", "alice": "contributor"}
    cli = run_script("check", str(reg.root))
    assert cli.returncode == 0, cli.stderr
    assert "alice contributor" in cli.stdout
    assert has(
        snapshot(vouch, reg, tmp_path).problems, "gregkh (no tier) may not grant"
    )


def test_approver_demoted_keeps_grants(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.tier("gregkh", "contributor", "torvalds", key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert result.tiers == {
        "torvalds": "anchor",
        "gregkh": "contributor",
        "alice": "contributor",
    }


def test_anchor_leaving_keeps_grants(vouch: ModuleType, reg: GitRegistry) -> None:
    reg.anchors("dave")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert result.tiers == {
        "dave": "anchor",
        "gregkh": "maintainer",
        "alice": "contributor",
    }


def test_authority_judged_at_the_commit_that_added_the_record(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.person("carol", key("carol"))
    reg.tier("carol", "contributor", "dave", key("dave"))
    reg.commit()
    reg.tier("dave", "maintainer", "torvalds", key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "tiers/carol.json", "dave (no tier) may not grant")
    assert "carol" not in result.tiers
    # Re-signed after dave's promotion, the record is a new version judged anew.
    reg.tier("carol", "contributor", "dave", key("dave"), date="2026-04-01T00:00:00Z")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert result.tiers["carol"] == "contributor"


def test_uncommitted_record_judged_as_the_next_commit(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.delete("tiers/gregkh.json")
    reg.commit()
    reg.person("carol", key("carol"))
    reg.tier("carol", "contributor", "gregkh", key("gregkh"))
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "tiers/carol.json", "gregkh (no tier) may not grant")
    assert result.tiers["alice"] == "contributor"


def test_tier_record_before_person_file_is_ignored(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    reg.tier("carol", "contributor", "gregkh", key("gregkh"))
    reg.commit()
    reg.person("carol", key("carol"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "tiers/carol.json", "before people/carol.json existed")
    assert "carol" not in result.tiers
    cli = run_script("check", str(reg.root))
    assert cli.returncode == 0
    assert "git-vouch: warning: tiers/carol.json" in cli.stderr
    assert "carol none" in cli.stdout
    assert snapshot(vouch, reg, tmp_path).tiers["carol"] == "contributor"
    reg.tier(
        "carol", "contributor", "gregkh", key("gregkh"), date="2026-04-01T00:00:00Z"
    )
    reg.commit()
    assert vouch.check_registry(reg.root).tiers["carol"] == "contributor"


def test_key_belongs_to_the_file_that_listed_it_first(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    # dave rotates away from his key; aaron, holding it, then claims it as current.
    reg.person("dave", key("dave2"), retired=(key("dave"),))
    reg.commit()
    reg.person("aaron", key("dave"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(
        result.problems, "people/aaron.json", did(key("dave")), "listed first by dave"
    )
    assert "dave" in result.people and "aaron" not in result.people
    old = snapshot(vouch, reg, tmp_path)
    assert has(old.problems, "people/dave.json", "a current key of aaron")


def test_current_listing_beats_an_earlier_retired_listing(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    # mallory lists bob's key as one of her retired keys before bob registers.
    reg.person("mallory", key("mallory"), retired=(key("bob"),))
    reg.commit()
    reg.person("bob", key("bob"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [
        f"people/mallory.json: {did(key('bob'))} is listed as a current key of bob"
    ]
    assert "bob" in result.people and "mallory" not in result.people
    assert result.problems == snapshot(vouch, reg, tmp_path).problems
    # bob rotates away from the key; his earlier current listing still wins.
    person_signed_by(reg, "bob", key("bob2"), retired=(key("bob"),), by=(key("bob"),))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(
        result.problems, "people/mallory.json", did(key("bob")), "a current key of bob"
    )
    assert "bob" in result.people and "mallory" not in result.people


def test_current_listing_signed_by_another_key_proves_nothing(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # bob registers with his old key already retired.
    reg.person("bob", key("bob2"), retired=(key("bob"),))
    reg.commit()
    # mallory lists bob's old key as current, but signs with her own key only.
    person_signed_by(reg, "mallory", key("mallory"), key("bob"), by=(key("mallory"),))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [
        f"people/mallory.json: {did(key('bob'))} was listed first by bob"
    ]
    assert "bob" in result.people and "mallory" not in result.people


def test_unsigned_current_listing_proves_nothing(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.person("mallory", key("mallory"), retired=(key("bob"),))
    reg.commit()
    # A middle version of mallory's file lists bob's key as current, unsigned.
    reg.person("mallory", key("mallory"), key("bob"))
    (reg.root / "people/mallory.json.sig").write_bytes(b"garbage\n")
    reg.commit()
    reg.person("mallory", key("mallory"))
    reg.commit()
    reg.person("bob", key("bob"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert "bob" in result.people and "mallory" in result.people


def test_deleted_revocation_still_holds(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    rel = reg.revoke("alice", key("alice"), key("torvalds"))
    reg.commit()
    reg.delete(rel)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert set(result.revoked) == {did(key("alice"))}


@pytest.mark.parametrize("merged", [False, True])
@pytest.mark.parametrize("kind", ["oversized", "symlink", "directory", "submodule"])
def test_unreadable_past_version_is_ignored_and_check_goes_on(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    kind: str,
    merged: bool,
) -> None:
    """A past version git-vouch cannot read is ignored like one that does not
    parse, with a warning naming its commit, so it never blocks the export and
    revocations still count (vouch-xlha.24)."""
    rel = "revocations/zz-1.json"
    path = reg.root / rel
    path.parent.mkdir(exist_ok=True)
    if kind == "directory":
        path.write_bytes(b"{}")  # the name must once be a file to be read at all
        reg.commit()
        path.unlink()
    if merged:
        reg.git("checkout", "-q", "-b", "side")
    if kind == "oversized":
        path.write_bytes(b"x" * (64 * 1024 + 1))
    elif kind == "symlink":
        os.symlink("../people/alice.json", path)
    elif kind == "directory":
        path.mkdir()
        (path / "x").write_bytes(b"x")
    else:
        reg.git("update-index", "--add", "--cacheinfo", f"160000,{'1' * 40},{rel}")
    reg.commit(add=kind != "submodule")
    bad = [head(reg)]
    if merged:
        reg.git("checkout", "-q", "main")
        reg.git("merge", "-q", "--no-ff", "--no-edit", "side")
        bad.append(head(reg))
    if kind == "directory":
        shutil.rmtree(path)
    elif kind == "submodule":
        reg.git("rm", "-q", "--cached", rel)
        if path.is_dir():
            path.rmdir()  # git checks out a submodule it lacks as an empty directory
    else:
        path.unlink()
    reg.revoke("alice", key("alice"), key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    unreadable = [w for w in result.warnings if "not a regular file" in w]
    assert unreadable == [
        f"{rel}: not a regular file of at most 65536 bytes (ignored, at {c})"
        for c in bad
    ]
    assert set(result.revoked) == {did(key("alice"))}
    assert result.tiers["gregkh"] == "maintainer"


def test_revocation_by_key_revoked_later_counts(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.revoke("alice", key("alice2"), key("alice"), n=1)
    reg.commit()
    reg.revoke("alice", key("alice"), key("torvalds"), n=2)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert set(result.revoked) == {did(key("alice")), did(key("alice2"))}


def test_revocation_by_key_revoked_earlier_is_void(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.revoke("alice", key("alice"), key("torvalds"), n=1)
    reg.commit()
    reg.revoke("alice", key("alice2"), key("alice"), n=2)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "revocations/alice-2.json", "revoked in an earlier commit")
    assert set(result.revoked) == {did(key("alice"))}


def test_revocations_in_one_commit_all_count(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.revoke("alice", key("alice2"), key("alice"), n=1)
    reg.revoke("alice", key("alice"), key("alice2"), n=2)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert set(result.revoked) == {did(key("alice")), did(key("alice2"))}


def test_revocation_signer_judged_at_its_commit(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    reg.revoke("alice", key("alice"), key("alice2"))
    reg.commit()
    reg.person("alice", key("alice3"), retired=(key("alice"), key("alice2")))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert set(result.revoked) == {did(key("alice"))}
    old = snapshot(vouch, reg, tmp_path)
    assert has(old.problems, "revocations/alice-1.json", "no valid signature")


def test_revoked_key_still_listed_warns_without_failing(
    reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.revoke("alice", key("alice"), key("torvalds"))
    reg.commit()
    cli = run_script("check", str(reg.root))
    assert cli.returncode == 0, cli.stderr
    assert (
        f"git-vouch: warning: people/alice.json: {did(key('alice'))}"
        " is revoked but not retired"
    ) in cli.stderr
    assert "error" not in cli.stderr
    reg.tier("dave", "maintainer", "dave", key("dave"))
    cli = run_script("check", str(reg.root))
    assert cli.returncode == 1
    assert "git-vouch: warning: people/alice.json" in cli.stderr
    assert "git-vouch: error: tiers/dave.json" in cli.stderr


def test_revoked_approver_voids_grants_after_stepping_down(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.revoke("gregkh", key("gregkh"), key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.voids, "tiers/alice.json", "revoked")
    assert "alice" not in result.tiers
    reg.delete("tiers/gregkh.json")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.voids, "tiers/alice.json", "revoked")
    assert "alice" not in result.tiers


def test_keys_first_listed_in_one_commit_go_to_the_current_listing(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    reg.person("erin", key("erin"), retired=(key("shared"),))
    reg.person("aaron", key("shared"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "people/erin.json", "a current key of aaron")
    assert "aaron" in result.people and "erin" not in result.people
    assert result.problems == snapshot(vouch, reg, tmp_path).problems


def test_automation_keeps_its_tier_after_accountable_steps_down(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "gregkh", key("gregkh"))
    reg.commit()
    reg.delete("tiers/gregkh.json")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert "gregkh" not in result.tiers
    assert result.tiers["bot"] == "automation"
    assert run_script("check", str(reg.root)).returncode == 0
    out = export(reg, tmp_path, "--include-automation")
    data, sig = sign_file(tmp_path, key("bot"), "file")
    assert ssh_verify(data, sig, out.signers, "bot", "file")


def test_automation_grant_concurrent_with_accountable_removal_is_void(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.git("branch", "side")
    reg.delete("tiers/gregkh.json")
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "torvalds", key("torvalds"))
    reg.commit()
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--no-edit", "side")
    result = vouch.check_registry(reg.root)
    # Like a grant concurrent with its approver's demotion (DESIGN.md, Tier record).
    assert result.problems == []
    assert has(result.voids, "tiers/bot.json", "gregkh", "concurrent commit")
    assert "bot" not in result.tiers
    assert run_script("check", str(reg.root)).returncode == 0


def test_automation_accountable_changed_later_voids(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "torvalds", key("torvalds"))
    reg.commit()
    reg.person("bot", key("bot"), accountable="dave")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "tiers/bot.json", "dave", "new approval")
    assert "bot" not in result.tiers
    reg.tier(
        "bot", "automation", "torvalds", key("torvalds"), date="2026-04-01T00:00:00Z"
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "people/bot.json", "dave is not a maintainer")


def test_revoked_accountable_key_keeps_automation(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # The accountable maintainer signed nothing for the bot; only a revoked
    # key under the accountable's own tier voids it (next test).
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "torvalds", key("torvalds"))
    reg.commit()
    reg.revoke("gregkh", key("gregkh"), key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "tiers/alice.json", "revoked")
    assert result.tiers["bot"] == "automation"
    assert result.tiers["gregkh"] == "maintainer"


def test_revoked_key_under_accountables_tier_voids_automation(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.anchors("torvalds", "dave")
    reg.person("kees", key("kees"))
    reg.tier("kees", "maintainer", "dave", key("dave"))
    reg.person("bot", key("bot"), accountable="kees")
    reg.tier("bot", "automation", "torvalds", key("torvalds"))
    reg.commit()
    assert vouch.check_registry(reg.root).tiers["bot"] == "automation"
    reg.revoke("dave", key("dave"), key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.voids, "tiers/kees.json", "revoked")
    assert has(result.voids, "tiers/bot.json", "kees has no valid tier")
    assert "bot" not in result.tiers


def test_merge_that_discarded_a_side_change_keeps_the_grant(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.git("branch", "side")
    reg.git("checkout", "-q", "side")
    reg.tier(
        "alice", "contributor", "gregkh", key("gregkh"), date="2026-04-01T00:00:00Z"
    )
    reg.commit()
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "-s", "ours", "--no-edit", "side")
    reg.delete("tiers/gregkh.json")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers["alice"] == "contributor"


def test_merging_an_old_branch_keeps_grants(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.git("branch", "side")
    reg.person("erin", key("erin"))
    reg.tier("erin", "contributor", "gregkh", key("gregkh"))
    reg.commit()
    reg.delete("tiers/gregkh.json")
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.anchors("torvalds", "dave")
    reg.commit()
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--no-edit", "side")
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers["erin"] == "contributor"


@pytest.mark.parametrize("fast_forward", [True, False])
def test_grant_concurrent_with_approver_demotion_is_void(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], fast_forward: bool
) -> None:
    reg.git("branch", "side")
    reg.delete("tiers/gregkh.json")
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.person("carol", key("carol"))
    reg.tier("carol", "contributor", "gregkh", key("gregkh"))
    reg.commit()
    if fast_forward:  # main merged into the branch, which main then takes as is
        reg.git("merge", "-q", "--no-edit", "main")
        reg.git("checkout", "-q", "main")
        reg.git("merge", "-q", "--ff-only", "side")
    else:
        reg.git("checkout", "-q", "main")
        reg.git("merge", "-q", "--no-edit", "side")
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "tiers/carol.json", "gregkh", "concurrent commit")
    assert "carol" not in result.tiers
    assert result.tiers["alice"] == "contributor"
    assert run_script("check", str(reg.root)).returncode == 0
    reg.git("checkout", "-q", "main")
    reg.tier("carol", "contributor", "torvalds", key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers["carol"] == "contributor"


def test_bad_signature_on_grant_concurrent_with_demotion_fails(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # The signature is judged before the concurrent demotion, so a forged
    # grant is an error, never a warning.
    reg.git("branch", "side")
    reg.delete("tiers/gregkh.json")
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.person("carol", key("carol"))
    reg.tier("carol", "contributor", "gregkh", key("gregkh"))
    path = reg.root / "tiers/carol.json"
    path.write_bytes(path.read_bytes() + b"\n")
    reg.commit()
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--no-edit", "side")
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "tiers/carol.json", "no valid signature")
    assert not has(result.voids, "tiers/carol.json")
    assert "carol" not in result.tiers
    assert run_script("check", str(reg.root)).returncode != 0


def test_grant_by_demoted_approver_after_merge_fails(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.git("branch", "side")
    reg.delete("tiers/gregkh.json")
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.person("carol", key("carol"))
    reg.commit()
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--no-edit", "side")
    reg.tier("carol", "contributor", "gregkh", key("gregkh"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "tiers/carol.json", "gregkh (no tier) may not grant")
    assert "carol" not in result.tiers


def test_mutual_revocations_on_concurrent_branches_both_count(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.git("branch", "side")
    reg.revoke("alice", key("alice2"), key("alice"), n=1)
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.revoke("alice", key("alice"), key("alice2"), n=2)
    reg.commit()
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--no-edit", "side")
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert set(result.revoked) == {did(key("alice")), did(key("alice2"))}
    assert run_script("check", str(reg.root)).returncode == 0


def test_key_listed_on_a_concurrent_branch_is_tied(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.git("branch", "side")
    reg.person("dave", key("dave"), key("dave2"))
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.person("eve", key("eve"), retired=(key("dave2"),))
    reg.commit()
    reg.git("merge", "-q", "--no-edit", "main")
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--ff-only", "side")
    result = vouch.check_registry(reg.root)
    assert has(
        result.problems, "people/eve.json", did(key("dave2")), "a current key of dave"
    )
    assert "dave" in result.people and "eve" not in result.people


def test_revocation_of_a_key_listed_first_by_another_is_ignored(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # dave lists torvalds' key as one of his own retired keys and revokes it,
    # then removes both again.
    reg.person("dave", key("dave"), retired=(key("torvalds"),))
    rel = reg.revoke("dave", key("torvalds"), key("dave"))
    reg.commit()
    reg.person("dave", key("dave"))
    reg.delete(rel)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.revoked == {}
    assert result.problems == [] and result.voids == []
    assert result.tiers == {
        "torvalds": "anchor",
        "gregkh": "maintainer",
        "alice": "contributor",
    }
    assert has(result.warnings, rel, f"{did(key('torvalds'))} is not a key of dave")


def person_signed_by(
    reg: Registry,
    handle: str,
    *current: Key,
    retired: tuple[Key, ...] = (),
    by: tuple[Key, ...],
) -> None:
    """Write a person file like Registry.person, but signed only by ``by``."""
    entries = [
        {"ssh": k.pubkey, "added": ADDED, "retired": RETIRED} for k in retired
    ] + [{"ssh": k.pubkey, "added": ADDED, "retired": None} for k in current]
    record = {
        "handle": handle,
        "name": handle.title(),
        "emails": [f"{handle}@example.org"],
        "keys": entries,
        "accountable": None,
    }
    reg.write(f"people/{handle}.json", record, *by, ns="git-vouch-register")


def head(reg: GitRegistry) -> str:
    """Return the checkout's HEAD commit id, as git reports it."""
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=reg.root,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def key_change_warnings(result: object) -> list[str]:
    """Return the unsigned-key-change warnings in a check result."""
    return [w for w in result.warnings if "WARNING" in w]  # type: ignore[attr-defined]


def test_rotation_signed_by_old_key_does_not_warn(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # dave retires his key and adds dave2; only the outgoing key signs.
    person_signed_by(
        reg, "dave", key("dave2"), retired=(key("dave"),), by=(key("dave"),)
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and key_change_warnings(result) == []
    assert [k.did for k in result.people["dave"].keys] == [
        did(key("dave")),
        did(key("dave2")),
    ]
    cli = run_script("check", str(reg.root))
    assert cli.returncode == 0, cli.stderr
    assert "WARNING" not in cli.stderr


def test_change_signed_by_any_one_previous_key(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # alice adds alice3 signed by alice2 alone; alice stays in the drawer.
    person_signed_by(
        reg, "alice", key("alice"), key("alice2"), key("alice3"), by=(key("alice2"),)
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and key_change_warnings(result) == []
    assert result.tiers["alice"] == "contributor"


@pytest.mark.parametrize("committed", [True, False])
def test_key_swap_signed_only_by_new_key_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], committed: bool
) -> None:
    person_signed_by(reg, "alice", key("mallory"), by=(key("mallory"),))
    where = "the working tree"
    if committed:
        reg.commit()
        where = head(reg)
        # A later, properly signed change does not hide the swap.
        person_signed_by(
            reg, "alice", key("mallory"), key("mallory2"), by=(key("mallory"),)
        )
        reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert (
        result.tiers["alice"] == "contributor"
    )  # review let it through; tier carries over
    warned = key_change_warnings(result)
    assert len(warned) == 1
    assert has(
        warned,
        "people/alice.json",
        where,
        did(key("alice")),
        did(key("alice2")),
        did(key("mallory")),
    )
    cli = run_script("check", str(reg.root))
    assert cli.returncode == 0, cli.stderr
    assert "WARNING" in cli.stderr and where in cli.stderr
    assert did(key("alice")) in cli.stderr and did(key("mallory")) in cli.stderr


def test_recreated_person_file_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.delete("people/dave.json")
    reg.commit()
    reg.person("dave", key("mallory"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(
        key_change_warnings(result),
        "people/dave.json",
        head(reg),
        did(key("dave")),
        did(key("mallory")),
    )


def test_change_to_frozen_person_file_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    person_signed_by(reg, "dave", retired=(key("dave"),), by=(key("dave"),))
    reg.commit()
    assert key_change_warnings(vouch.check_registry(reg.root)) == []
    person_signed_by(
        reg, "dave", key("dave2"), retired=(key("dave"),), by=(key("dave2"),)
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(
        key_change_warnings(result),
        "people/dave.json",
        head(reg),
        did(key("dave")),
        did(key("dave2")),
    )


def test_change_without_sig_then_signed_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # mallory commits the swap with no .sig, then adds one by his own key: the
    # unsigned version still counts as a change, so it cannot launder the swap.
    person_signed_by(reg, "alice", key("mallory"), by=(key("mallory"),))
    (reg.root / "people/alice.json.sig").unlink()
    reg.commit()
    unsigned = head(reg)
    person_signed_by(reg, "alice", key("mallory"), by=(key("mallory"),))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    warned = key_change_warnings(result)
    assert len(warned) == 1
    assert has(warned, unsigned, did(key("alice")), did(key("mallory")))


def test_unrelated_branch_cannot_start_a_person_file_afresh(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # An orphan branch creates its own people/alice.json, self-signed by
    # mallory, and a merge keeps it: alice existed, so it is no first version.
    reg.git("checkout", "-q", "--orphan", "evil")
    reg.git("rm", "-q", "-r", "--cached", ".")
    shutil.rmtree(reg.root / "people")
    shutil.rmtree(reg.root / "tiers")
    (reg.root / "anchors.json").unlink()
    person_signed_by(reg, "alice", key("mallory"), by=(key("mallory"),))
    reg.commit()
    evil = head(reg)
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--allow-unrelated-histories", "-X", "theirs", "evil")
    result = vouch.check_registry(reg.root)
    assert [k.did for k in result.people["alice"].keys] == [did(key("mallory"))]
    assert result.problems == []
    assert has(
        key_change_warnings(result),
        "people/alice.json",
        evil,
        did(key("alice")),
        did(key("mallory")),
    )


@pytest.mark.parametrize("revoked_first", [True, False])
def test_change_signed_by_revoked_key_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], revoked_first: bool
) -> None:
    # DESIGN.md, Retiring a key versus revoking it: every signature by a
    # revoked key, past or future, is invalid, so it chains nothing.
    if revoked_first:
        reg.revoke("alice", key("alice"), key("alice"))
        reg.commit()
    person_signed_by(
        reg, "alice", key("mallory"), retired=(key("alice"),), by=(key("alice"),)
    )
    reg.commit()
    swap = head(reg)
    if not revoked_first:
        reg.revoke("alice", key("alice"), key("torvalds"))  # an anchor
        reg.commit()
    result = vouch.check_registry(reg.root)
    assert did(key("alice")) in result.revoked
    assert has(
        key_change_warnings(result), "people/alice.json", swap, did(key("mallory"))
    )


@pytest.mark.parametrize("signer", ["alice3", "alice4"])
def test_merge_change_needs_a_key_current_at_any_parent(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], signer: str
) -> None:
    # side adds alice3; main drops alice2. The merge resolves to a file that
    # differs from both, signed by alice3 (current at side only) or alice4
    # (current at neither).
    reg.git("checkout", "-q", "-b", "side")
    person_signed_by(reg, "alice", key("alice2"), key("alice3"), by=(key("alice2"),))
    reg.commit()
    reg.git("checkout", "-q", "main")
    person_signed_by(reg, "alice", key("alice"), by=(key("alice"),))
    reg.commit()
    reg.git("merge", "-q", "-s", "ours", "--no-commit", "side")
    person_signed_by(reg, "alice", key(signer), by=(key(signer),))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    warned = key_change_warnings(result)
    if signer == "alice3":
        assert warned == []
    else:
        assert len(warned) == 1
        assert has(warned, head(reg), did(key("alice")), did(key("alice4")))


def test_older_version_signed_by_an_outside_key_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # A version whose .sig is by a key in neither it nor its parent is let
    # through by review, like any unchained change; it fails nothing.
    person_signed_by(reg, "alice", key("alice"), key("alice2"), by=(key("mallory"),))
    reg.commit()
    outside = head(reg)
    person_signed_by(
        reg, "alice", key("alice"), key("alice2"), key("alice3"), by=(key("alice"),)
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    warned = key_change_warnings(result)
    assert len(warned) == 1 and outside in warned[0]
    cli = run_script("check", str(reg.root))
    assert cli.returncode == 0, cli.stderr
    assert outside in cli.stderr


def test_reverted_person_file_is_judged_at_its_latest_version(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # Version A lists dave2, signed by dave3, which dave's first version does
    # not list. Version B lists dave3, signed by dave2. Restoring A's exact
    # bytes is then signed by a key current in B, its previous version.
    person_signed_by(reg, "dave", key("dave2"), by=(key("dave3"),))
    reg.commit()
    first_a = head(reg)
    pair = [
        (reg.root / f).read_bytes()
        for f in ("people/dave.json", "people/dave.json.sig")
    ]
    person_signed_by(reg, "dave", key("dave3"), by=(key("dave2"),))
    reg.commit()
    for f, data in zip(("people/dave.json", "people/dave.json.sig"), pair):
        (reg.root / f).write_bytes(data)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert [k.did for k in result.people["dave"].keys] == [did(key("dave2"))]
    warned = key_change_warnings(result)
    assert len(warned) == 1 and first_a in warned[0]


# DESIGN.md, Tier record: a deleted tier ends at the deleting commit's
# committer date, a demoted one at the new record's date. GitRegistry commits
# day N at 2026-01-0NT00:00:00Z; git verify-tag judges each tag at its date.
DAY1_NOON = "2026-01-01T12:00:00Z"
DAY2_NOON = "2026-01-02T12:00:00Z"
DAY3_NOON = "2026-01-03T12:00:00Z"


def test_deleted_tier_ends_at_the_deleting_commit(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    reg.delete("tiers/gregkh.json")
    reg.commit(author="2026-01-01T06:00:00Z")  # the committer date, day 2, counts
    for min_tier in ("maintainer", "contributor"):
        out = export(reg, tmp_path, "--min-tier", min_tier)
        assert verifies(repo, tag(repo, f"a-{min_tier}", key("gregkh"), DAY1_NOON), out)
        assert not verifies(
            repo, tag(repo, f"b-{min_tier}", key("gregkh"), DAY2_NOON), out
        )
    assert verifies(repo, tag(repo, "alice", key("alice"), DAY2_NOON), out)
    out = export(reg, tmp_path, "--min-tier", "anchor")
    assert not verifies(repo, "a-maintainer", out)


def test_backdated_deletion_ends_the_tier_at_its_parents_date(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    """A deletion dated before its parent ends the tier at the parent's date (vouch-faq3.13)."""
    (reg.root / "README").write_text("unrelated\n")
    reg.commit()  # day 2
    reg.delete("tiers/gregkh.json")
    reg.commit(date="2026-01-01T06:00:00Z")
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "a", key("gregkh"), DAY1_NOON), out)
    assert not verifies(repo, tag(repo, "b", key("gregkh"), DAY2_NOON), out)


def test_deletion_merged_with_no_ff_ends_the_tier_at_the_merge(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    """A backdated deletion on a branch ends the tier when main merged it (vouch-faq3.13)."""
    reg.git("branch", "side")
    (reg.root / "README").write_text("unrelated\n")
    reg.commit()  # day 2
    reg.git("checkout", "-q", "side")
    reg.delete("tiers/gregkh.json")
    reg.commit(date="2026-01-01T06:00:00Z")
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--no-ff", "-m", "m", "side", date="2026-01-03T00:00:00Z")
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "a", key("gregkh"), DAY2_NOON), out)
    assert not verifies(repo, tag(repo, "b", key("gregkh"), DAY3_NOON), out)


def test_merge_counts_from_its_first_parent_not_its_branch(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    """A merge dated before its branch's commit counts from its own date, as
    the later first-parent commit deleting gregkh's tier does (vouch-faq3.13)."""
    reg.git("branch", "side")
    (reg.root / "README").write_text("unrelated\n")
    reg.commit()  # day 2
    reg.git("checkout", "-q", "side")
    (reg.root / "NOTES").write_text("early\n")
    reg.commit(date="2026-01-04T00:00:00Z")
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "--no-ff", "-m", "m", "side", date="2026-01-03T00:00:00Z")
    reg.delete("tiers/gregkh.json")
    reg.commit(date="2026-01-03T06:00:00Z")
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "a", key("gregkh"), "2026-01-03T03:00:00Z"), out)
    assert not verifies(repo, tag(repo, "b", key("gregkh"), DAY3_NOON), out)


def test_commit_dated_in_the_future_is_refused(reg: GitRegistry) -> None:
    """check refuses a commit dated more than five minutes after it runs (vouch-faq3.13)."""
    now = int(time.time())
    (reg.root / "README").write_text("soon\n")
    reg.commit(date=f"@{now + 60} +0000")
    proc = run_script("check", str(reg.root))
    assert proc.returncode == 0, proc.stderr
    (reg.root / "README").write_text("later\n")
    reg.commit(date=f"@{now + 3600} +0000")
    late = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=reg.root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    proc = run_script("check", str(reg.root))
    assert proc.returncode == 1
    assert f"error: commit {late}: committer date is in the future" in proc.stderr


def test_deleted_record_invalid_at_its_parent_ends_nothing(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    reg.tier("dave", "contributor", "alice", key("alice"))  # alice may not grant it
    reg.commit()
    reg.delete("tiers/dave.json")
    reg.commit()
    out = export(reg, tmp_path)
    assert not verifies(repo, tag(repo, "d1", key("dave"), DAY2_NOON), out)


def test_demotion_ends_the_higher_tier_at_the_new_records_date(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    reg.tier(
        "gregkh", "contributor", "torvalds", key("torvalds"), "2026-02-01T00:00:00Z"
    )
    reg.commit()
    early = tag(repo, "early", key("gregkh"), "2026-01-15T00:00:00Z")
    late = tag(repo, "late", key("gregkh"), "2026-02-02T00:00:00Z")
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, early, out)
    assert not verifies(repo, late, out)
    out = export(reg, tmp_path)
    assert verifies(repo, late, out)


def test_tier_deleted_then_regranted_lower_keeps_the_deletion_date(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    reg.delete("tiers/gregkh.json")
    reg.commit()
    reg.tier("gregkh", "contributor", "torvalds", key("torvalds"))
    reg.commit()
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "v1", key("gregkh"), DAY1_NOON), out)
    assert not verifies(repo, tag(repo, "v2", key("gregkh"), DAY2_NOON), out)
    out = export(reg, tmp_path)
    assert verifies(repo, tag(repo, "c1", key("gregkh"), DAY3_NOON), out)


def test_uncommitted_deletion_ends_the_tier_now(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    reg.delete("tiers/gregkh.json")
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "v1", key("gregkh"), DAY1_NOON), out)
    assert not verifies(
        repo, tag(repo, "v2", key("gregkh"), "2099-01-01T00:00:00Z"), out
    )


def test_deleted_automation_tier_ends_its_file_signatures(
    reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "gregkh", key("gregkh"))
    reg.commit()
    reg.delete("tiers/bot.json")
    reg.commit()
    data, sig = sign_file(tmp_path, key("bot"), "file")
    out = export(reg, tmp_path, "--include-automation")
    assert ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260102120000Z"
    )
    assert not ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260103120000Z"
    )
    out = export(reg, tmp_path)
    assert not ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260102120000Z"
    )


def test_tier_replaced_by_a_void_record_ends_at_the_replacing_commit(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    # A record without effect leaves the person as if the record were deleted.
    reg.tier("dave", "maintainer", "torvalds", key("torvalds"))
    reg.commit()
    reg.git("branch", "side")
    reg.delete("tiers/dave.json")
    reg.commit()
    reg.git("checkout", "-q", "side")
    reg.tier("gregkh", "contributor", "dave", key("dave"), "2026-03-01T00:00:00Z")
    reg.commit()  # day 4
    reg.git("checkout", "-q", "main")
    # The replacement counts from when main merged it (vouch-faq3.13).
    reg.git("merge", "-q", "--no-edit", "side", date="2026-01-04T00:00:00Z")
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "tiers/gregkh.json", "concurrent commit")
    assert "gregkh" not in result.tiers
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "v1", key("gregkh"), DAY3_NOON), out)
    assert not verifies(
        repo, tag(repo, "v2", key("gregkh"), "2026-01-04T12:00:00Z"), out
    )


@pytest.mark.parametrize("via_deletion", [False, True])
def test_human_tier_replaced_by_automation(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
    via_deletion: bool,
) -> None:
    if via_deletion:  # ends at the deleting commit's committer date, day 2
        reg.delete("tiers/gregkh.json")
        reg.commit()
        early, late = DAY1_NOON, DAY2_NOON
    else:  # ends at the automation record's date
        early, late = "2026-01-15T00:00:00Z", "2026-02-02T00:00:00Z"
    reg.person("gregkh", key("gregkh"), accountable="torvalds")
    reg.tier(
        "gregkh", "automation", "torvalds", key("torvalds"), "2026-02-01T00:00:00Z"
    )
    reg.commit()
    data, sig = sign_file(tmp_path, key("gregkh"), "file")
    for options in ((), ("--include-automation",)):
        out = export(reg, tmp_path, "--min-tier", "maintainer", *options)
        assert verifies(repo, tag(repo, f"a{len(options)}", key("gregkh"), early), out)
        assert not verifies(
            repo, tag(repo, f"b{len(options)}", key("gregkh"), late), out
        )
        assert ssh_verify(
            data, sig, out.signers, "gregkh", "file", "-Overify-time=20260101120000Z"
        )
        # Only the automation line, exported on request, outlasts the human tier.
        assert ssh_verify(
            data, sig, out.signers, "gregkh", "file", "-Overify-time=20260301000000Z"
        ) == bool(options)


def test_committer_date_out_of_range(reg: GitRegistry) -> None:
    # git stores any timestamp; datetime cannot hold this one.
    def far_commit(message: str) -> None:
        def out(*args: str) -> str:
            return subprocess.run(
                ["git", *args], cwd=reg.root, check=True, capture_output=True, text=True
            ).stdout.strip()

        tree, parent = out("write-tree"), out("rev-parse", "HEAD")
        who = "t <t@example.org> 99999999999999 +0000"
        body = f"tree {tree}\nparent {parent}\nauthor {who}\ncommitter {who}\n\n{message}\n"
        commit = subprocess.run(
            ["git", "hash-object", "-t", "commit", "-w", "--literally", "--stdin"],
            cwd=reg.root,
            input=body,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        out("update-ref", "HEAD", commit)

    (reg.root / "README").write_text("unrelated\n")
    reg.git("add", "README")
    far_commit("unrelated")
    # Unrelated, but it sets every later commit's effective date (vouch-faq3.13).
    proc = run_script("check", str(reg.root))
    assert proc.returncode == 1
    assert "committer date is in the future" in proc.stderr
    assert "Traceback" not in proc.stderr
    far = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=reg.root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    # Dated normally, but its effective date is the far one before it: only
    # the far commit is out of range (vouch-faq3.13).
    reg.delete("tiers/alice.json")
    reg.commit()
    proc = run_script("check", str(reg.root))
    assert proc.returncode == 1
    out_of_range = [
        line for line in proc.stderr.splitlines() if "date out of range" in line
    ]
    assert out_of_range == [
        f"git-vouch: error: commit {far}: committer date out of range"
    ]
    reg.git("rm", "-q", "tiers/gregkh.json", "tiers/gregkh.json.sig")
    far_commit("delete gregkh")
    proc = run_script("check", str(reg.root))
    assert proc.returncode == 1
    assert "committer date out of range" in proc.stderr
    assert "Traceback" not in proc.stderr


# Round 3 (bead vouch-ey47.19): one test per settled item, on real history.


def test_anchor_removal_ends_at_the_removing_commit(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    # Like a deleted tier record: dave's keys end at the committer date of
    # the commit that dropped him from anchors.json (day 3).
    reg.anchors("torvalds", "dave")
    reg.commit()
    reg.anchors("torvalds")
    reg.commit(author="2026-01-02T06:00:00Z")
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and "dave" not in result.tiers
    for min_tier in ("anchor", "contributor"):
        out = export(reg, tmp_path, "--min-tier", min_tier)
        assert verifies(repo, tag(repo, f"a-{min_tier}", key("dave"), DAY2_NOON), out)
        assert not verifies(
            repo, tag(repo, f"b-{min_tier}", key("dave"), DAY3_NOON), out
        )


@pytest.mark.parametrize("then", ["delete", "demote"])
def test_tier_record_that_does_not_verify_ends_nothing(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
    then: str,
) -> None:
    # Day 2 replaces gregkh's maintainer record with one alice may not
    # grant; it has no standing, so the maintainer tier runs on until day 3
    # deletes the record, or until the date of day 3's valid demotion.
    reg.tier("gregkh", "contributor", "alice", key("alice"))
    reg.commit()
    if then == "delete":
        reg.delete("tiers/gregkh.json")
        early, late = DAY2_NOON, DAY3_NOON
    else:
        reg.tier(
            "gregkh", "contributor", "torvalds", key("torvalds"), "2026-02-01T00:00:00Z"
        )
        early, late = "2026-01-15T00:00:00Z", "2026-02-02T00:00:00Z"
    reg.commit()
    assert vouch.check_registry(reg.root).problems == []
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    assert verifies(repo, tag(repo, "early", key("gregkh"), early), out)
    assert not verifies(repo, tag(repo, "late", key("gregkh"), late), out)


def test_automation_replaced_by_human_ends_at_the_new_records_date(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "gregkh", key("gregkh"))
    reg.commit()
    reg.tier("bot", "contributor", "gregkh", key("gregkh"), "2026-02-01T00:00:00Z")
    reg.commit()
    assert vouch.check_registry(reg.root).tiers["bot"] == "contributor"
    data, sig = sign_file(tmp_path, key("bot"), "file")
    out = export(reg, tmp_path, "--min-tier", "maintainer", "--include-automation")
    assert ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260115000000Z"
    )
    assert not ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260202000000Z"
    )
    out = export(reg, tmp_path)  # the contributor tier covers files too
    assert ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260202000000Z"
    )


def test_bot_made_human_still_ends_automation_at_the_new_records_date(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    """As above, but the person file also drops accountable: the automation
    record is judged against the person file of its own commit."""
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "gregkh", key("gregkh"))
    reg.commit()
    reg.person("bot", key("bot"))
    reg.tier("bot", "contributor", "gregkh", key("gregkh"), "2026-02-01T00:00:00Z")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.tiers["bot"] == "contributor"
    data, sig = sign_file(tmp_path, key("bot"), "file")
    out = export(reg, tmp_path, "--min-tier", "maintainer", "--include-automation")
    assert ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260115000000Z"
    )
    assert not ssh_verify(
        data, sig, out.signers, "bot", "file", "-Overify-time=20260202000000Z"
    )


def test_bot_switching_accountable_needs_a_new_tier_record(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    reg.person("bot", key("bot"), accountable="gregkh")
    reg.tier("bot", "automation", "torvalds", key("torvalds"))
    reg.commit()
    reg.person("bot", key("bot"), accountable="torvalds")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "tiers/bot.json", "torvalds", "new approval")
    data, sig = sign_file(tmp_path, key("bot"), "file")
    out = export(reg, tmp_path, "--include-automation")
    assert not ssh_verify(data, sig, out.signers, "bot", "file")
    reg.tier("bot", "automation", "torvalds", key("torvalds"), "2026-04-01T00:00:00Z")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers["bot"] == "automation"
    out = export(reg, tmp_path, "--include-automation")
    assert ssh_verify(data, sig, out.signers, "bot", "file")


def test_record_by_since_revoked_key_is_void_before_any_date_check(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # dave's retired key signs an endorsement dated after its retirement.
    person_signed_by(
        reg, "dave", key("dave2"), retired=(key("dave"),), by=(key("dave"),)
    )
    rel = reg.endorse(
        "alice", key("alice"), "dave", key("dave"), date="2026-09-01T00:00:00Z"
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.problems, rel, "outside the validity")
    reg.revoke("dave", key("dave"), key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, rel, "revoked")


def test_signature_two_hours_after_retirement_fails(
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    # RETIRED is 2026-06-01T00:00:00Z; the export ends the key an hour later
    # (DESIGN.md, Retiring a key versus revoking it). Under DST, OpenSSH 9.6
    # reads git's verify time an hour late, which the minute-before tag
    # shows.
    person_signed_by(
        reg, "gregkh", key("gregkh2"), retired=(key("gregkh"),), by=(key("gregkh"),)
    )
    reg.commit()
    out = export(reg, tmp_path)
    assert 'valid-before="20260601010000Z"' in out.signers.read_text()
    assert verifies(repo, tag(repo, "v1", key("gregkh"), "2026-05-31T23:59:00Z"), out)
    assert not verifies(
        repo, tag(repo, "v2", key("gregkh"), "2026-06-01T02:00:00Z"), out
    )


@pytest.mark.parametrize("side_retires", [True, False])
def test_merge_keeping_a_version_signed_by_a_concurrently_retired_key_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], side_retires: bool
) -> None:
    reg.git("checkout", "-q", "-b", "side")
    if side_retires:  # alice retires her key alice on side
        person_signed_by(
            reg, "alice", key("alice2"), retired=(key("alice"),), by=(key("alice2"),)
        )
    else:  # side changes only someone else's file
        person_signed_by(reg, "dave", key("dave"), key("dave2"), by=(key("dave"),))
    reg.commit()
    reg.git("checkout", "-q", "main")
    person_signed_by(
        reg, "alice", key("alice"), key("alice2"), key("alice3"), by=(key("alice"),)
    )
    reg.commit()
    reg.git("merge", "-q", "-s", "ours", "--no-edit", "side")
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    warned = key_change_warnings(result)
    if side_retires:
        assert len(warned) == 1
        assert has(warned, "people/alice.json", head(reg), did(key("alice2")))
    else:
        assert warned == []


def test_merge_keeping_a_version_signed_by_a_concurrently_revoked_key_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.git("checkout", "-q", "-b", "side")
    reg.revoke("alice", key("alice"), key("torvalds"))
    reg.commit()
    reg.git("checkout", "-q", "main")
    person_signed_by(
        reg, "alice", key("alice"), key("alice2"), key("alice3"), by=(key("alice"),)
    )
    reg.commit()
    change = head(reg)
    reg.git("merge", "-q", "--no-edit", "side")
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert did(key("alice")) in result.revoked
    assert has(key_change_warnings(result), "people/alice.json", change)


def write_unparseable_person(reg: GitRegistry, handle: str, *listed: Key) -> None:
    """Write a person file an older git-vouch accepted but this one rejects."""
    record = {
        "handle": handle,
        "name": handle.title(),
        "emails": [f"{handle}@example.org"],
        "keys": [{"ssh": k.pubkey, "added": ADDED, "retired": None} for k in listed],
        "accountable": None,
        "alsoKnownAs": ["not-a-did"],
    }
    reg.write(f"people/{handle}.json", record, listed[0], ns="git-vouch-register")


def test_unparseable_older_version_still_chains(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    write_unparseable_person(reg, "alice", key("alice"), key("alice2"))
    reg.commit()
    person_signed_by(
        reg, "alice", key("alice"), key("alice2"), key("alice3"), by=(key("alice"),)
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert key_change_warnings(result) == []


def test_unparseable_first_version_does_not_reset_continuity(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    write_unparseable_person(reg, "erin", key("erin"))
    reg.commit()
    person_signed_by(reg, "erin", key("erin2"), by=(key("erin2"),))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    warned = key_change_warnings(result)
    assert len(warned) == 1
    assert has(warned, "people/erin.json", head(reg), did(key("erin")))


def test_endorsement_survives_revoking_the_subjects_key(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.endorse("alice", key("alice"), "gregkh", key("gregkh"))
    reg.commit()
    reg.revoke("alice", key("alice"), key("alice2"))
    person_signed_by(
        reg, "alice", key("alice2"), key("alice3"), retired=(key("alice"),),
        by=(key("alice2"),),
    )  # fmt: skip
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.emails["alice"] == ("alice@example.org",)


@pytest.mark.parametrize("restored", [False, True])
def test_tier_sig_only_change_counts_as_a_change(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
    restored: bool,
) -> None:
    # Day 2 replaces only gregkh's .sig with alice's signature, so that
    # version does not verify and the day 1 record stands behind it; day 3
    # may put the good .sig back. The last day deletes the record, which
    # ends the maintainer tier only if the walk sees the .sig-only commits.
    rel = "tiers/gregkh.json"
    data = (reg.root / rel).read_bytes()
    good = (reg.root / (rel + ".sig")).read_bytes()
    (reg.root / (rel + ".sig")).write_bytes(
        reg.sign(key("alice"), "git-vouch-tier", data)
    )
    reg.commit()
    if restored:
        (reg.root / (rel + ".sig")).write_bytes(good)
        reg.commit()
    reg.delete(rel)
    reg.commit()
    assert vouch.check_registry(reg.root).problems == []
    out = export(reg, tmp_path, "--min-tier", "maintainer")
    early = DAY3_NOON if restored else DAY2_NOON
    late = "2026-01-04T12:00:00Z" if restored else DAY3_NOON
    assert verifies(repo, tag(repo, "early", key("gregkh"), early), out)
    assert not verifies(repo, tag(repo, "late", key("gregkh"), late), out)


def test_merged_unverified_tier_records_are_walked_once(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # 20 merges whose sides and result all hold a tier record that does not
    # verify; walking each path separately would take hours.
    def commit(n: int) -> None:
        date = f"2026-01-01T06:{n:02d}:00Z"
        env = {**os.environ, "GIT_COMMITTER_DATE": date, "GIT_AUTHOR_DATE": date}
        for args in (["add", "-A"], ["commit", "-q", "-m", date]):
            subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                cwd=reg.root,
                env=env,
                check=True,
            )

    record = reg.root / "tiers/gregkh.json"
    n = 0
    for level in range(20):
        reg.git("checkout", "-q", "-b", f"b{level}")
        record.write_bytes(b"side %d" % level)
        commit(n := n + 1)
        reg.git("checkout", "-q", "main")
        record.write_bytes(b"main %d" % level)
        commit(n := n + 1)
        reg.git("merge", "-q", "--no-commit", "-s", "ours", f"b{level}")
        record.write_bytes(b"merge %d" % level)
        commit(n := n + 1)
    reg.tier("gregkh", "maintainer", "torvalds", key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert result.tiers["gregkh"] == "maintainer"


def test_replayed_tier_record_does_not_undo_a_demotion(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # torvalds demotes gregkh; anyone can copy the old signed maintainer
    # record back, and that must not restore the tier torvalds withdrew.
    old = {
        rel: (reg.root / rel).read_bytes()
        for rel in ("tiers/gregkh.json", "tiers/gregkh.json.sig")
    }
    reg.tier("gregkh", "contributor", "torvalds", key("torvalds"), AFTER)
    reg.commit()
    for rel, data in old.items():
        (reg.root / rel).write_bytes(data)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "tiers/gregkh.json", "restores an earlier record")
    assert "gregkh" not in result.tiers
    cli = run_script("check", str(reg.root))
    assert cli.returncode != 0
    assert "gregkh maintainer" not in cli.stdout


def test_record_restored_over_one_that_does_not_verify_stands(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # alice may not grant, so her record changed nothing; putting back the
    # maintainer record it displaced undoes no valid record.
    old = {
        rel: (reg.root / rel).read_bytes()
        for rel in ("tiers/gregkh.json", "tiers/gregkh.json.sig")
    }
    reg.tier("gregkh", "contributor", "alice", key("alice"))
    reg.commit()
    for rel, data in old.items():
        (reg.root / rel).write_bytes(data)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers["gregkh"] == "maintainer"


def test_revocation_dropped_by_merge_ours_still_holds(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], tmp_path: Path
) -> None:
    # The revoking commit is an ancestor of HEAD even though the merge kept
    # main's tree, so the revocation holds like one deleted later.
    reg.git("checkout", "-q", "-b", "side")
    reg.revoke("alice", key("alice"), key("torvalds"))
    reg.commit()
    reg.git("checkout", "-q", "main")
    reg.git("merge", "-q", "-s", "ours", "--no-edit", "side")
    assert not (reg.root / "revocations").exists()
    result = vouch.check_registry(reg.root)
    assert set(result.revoked) == {did(key("alice"))}
    revocations = tmp_path / "revoked"
    cli = run_script(
        "export",
        str(reg.root),
        "--allowed-signers",
        str(tmp_path / "allowed"),
        "--revocation-file",
        str(revocations),
    )
    assert cli.returncode == 0, cli.stderr
    assert revocations.read_text().split() == key("alice").pubkey.split()[:2]


@pytest.mark.parametrize("how", ["delete first", "merge --no-ff", "merge -s ours"])
def test_old_tier_record_brought_back_does_not_undo_a_demotion(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], how: str
) -> None:
    # Deleting the demotion first, or merging a branch that still holds the
    # old record, hides nothing: the demotion is still an ancestor of HEAD.
    old = {
        rel: (reg.root / rel).read_bytes()
        for rel in ("tiers/gregkh.json", "tiers/gregkh.json.sig")
    }
    reg.git("branch", "old")
    reg.tier("gregkh", "contributor", "torvalds", key("torvalds"), AFTER)
    reg.commit()
    if how == "delete first":
        reg.delete("tiers/gregkh.json")
        reg.commit()
        for rel, data in old.items():
            (reg.root / rel).write_bytes(data)
        reg.commit()
    else:
        reg.git("checkout", "-q", "old")
        (reg.root / "README").write_text("unrelated\n")
        reg.commit()
        if how == "merge --no-ff":  # resolved to the old side
            reg.git("checkout", "-q", "main")
            reg.git("merge", "-q", "--no-ff", "--no-commit", "old")
            reg.git("checkout", "old", "--", "tiers")
            reg.commit()
        else:  # the old branch keeps its tree, and main fast-forwards to it
            reg.git("merge", "-q", "-s", "ours", "--no-edit", "main")
            reg.git("checkout", "-q", "main")
            reg.git("merge", "-q", "--ff-only", "old")
    assert (reg.root / "tiers/gregkh.json").read_bytes() == old["tiers/gregkh.json"]
    result = vouch.check_registry(reg.root)
    assert has(result.problems, "tiers/gregkh.json", "restores an earlier record")
    assert "gregkh" not in result.tiers


def test_lower_tier_record_brought_back_over_a_promotion_is_void(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # The old contributor record is gregkh's, and gregkh is not above the
    # maintainer tier it would lower alice from (vouch-xlha.21), so it is void.
    # Putting it back only takes authority away, like deleting the record:
    # a void, not a failed check.
    old = {
        rel: (reg.root / rel).read_bytes()
        for rel in ("tiers/alice.json", "tiers/alice.json.sig")
    }
    reg.tier("alice", "maintainer", "torvalds", key("torvalds"), AFTER)
    reg.commit()
    for rel, data in old.items():
        (reg.root / rel).write_bytes(data)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert has(result.voids, "tiers/alice.json", "may not lower alice from maintainer")
    assert "alice" not in result.tiers


def test_many_versions_of_a_record_do_not_deepen_the_recursion(
    vouch: ModuleType, reg: GitRegistry
) -> None:
    # Anyone can commit as many versions of a record as they like; here the
    # signed one alternates with a copy plus a newline, which does not verify.
    rel = "tiers/gregkh.json"
    signed = (reg.root / rel).read_bytes()
    stream = b""
    for n in range(1, 201):
        data = signed + b"\n" if n % 2 else signed
        stream += (
            (
                f"commit refs/heads/main\ncommitter t <t@example.org>"
                f" {1767225600 + 86400 * n} +0000\ndata 0\n"
                + ("from refs/heads/main^0\n" if n == 1 else "")
                + f"M 100644 inline {rel}\ndata {len(data)}\n"
            ).encode()
            + data
            + b"\n"
        )
    subprocess.run(
        ["git", "fast-import", "--quiet"], input=stream, cwd=reg.root, check=True
    )
    reg.git("reset", "-q", "--hard")
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(len(inspect.stack(0)) + 150)
    try:
        result = vouch.check_registry(reg.root)
    finally:
        sys.setrecursionlimit(limit)
    assert result.problems == []
    assert result.tiers["gregkh"] == "maintainer"


def test_check_verifies_each_signature_once(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One check never runs ssh-keygen twice on the same signature (vouch-xlha.3).

    The history re-signs person files and grants tiers in later commits, so
    the same tier record is judged at many positions.
    """
    reg.person("dave", key("dave"), key("dave2"))
    reg.commit()
    reg.tier("dave", "contributor", "gregkh", key("gregkh"))
    reg.commit()
    reg.person("alice", key("alice2"), retired=(key("alice"),))
    reg.commit()
    runs = count_verifies(vouch, monkeypatch)
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert result.tiers["dave"] == "contributor"
    assert runs and len(runs) == len(set(runs))


def test_check_verifies_a_block_only_against_its_own_key(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Settling a key claimed by two files runs no block against another key (vouch-xlha.3).

    dave and mallory list dave2 as current in the same commit, so check
    proves which files dave2 signed. Each .sig holds one block per current
    key, in the order the keys are listed; a run pairing a block with
    another key could never verify.
    """
    signers = {
        "dave": (key("dave"), key("dave2")),
        "mallory": (key("mallory"), key("dave2")),
    }
    for handle, current in signers.items():
        reg.person(handle, *current)
    reg.commit()
    end = b"-----END SSH SIGNATURE-----\n"
    owner = {}
    for handle, current in signers.items():
        sig = (reg.root / f"people/{handle}.json.sig").read_bytes()
        blocks = [b + end for b in sig.split(end)[:-1]]
        assert len(blocks) == 2
        owner.update((b, k.pubkey.split()[1]) for b, k in zip(blocks, current))
    runs = count_verifies(vouch, monkeypatch)
    result = vouch.check_registry(reg.root)
    assert any(f"{did(key('dave2'))} is listed" in p for p in result.problems)
    people = [r for r in runs if r[1] in owner]
    assert sorted(r[1] for r in people) == sorted(owner)
    assert all(r[3].split()[2] == owner[r[1]] for r in people)


@pytest.mark.parametrize("date", [ADDED, AFTER])
def test_peer_maintainer_cannot_demote_a_maintainer(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], date: str
) -> None:
    """Only someone above a person's current tier may lower it (vouch-xlha.21).

    dave, a maintainer like gregkh, signs gregkh down to contributor. The
    record is void, and replacing the old one only ends gregkh's tier at
    the commit, as a deletion would: dating the record earlier, or later,
    does not move that end.
    """
    reg.tier("dave", "maintainer", "torvalds", key("torvalds"))
    reg.commit()
    reg.tier("gregkh", "contributor", "dave", key("dave"), date)
    reg.commit()  # 2026-01-03
    result = vouch.check_registry(reg.root)
    assert has(
        result.voids, "tiers/gregkh.json", "may not lower gregkh from maintainer"
    )
    assert result.problems == []
    assert "gregkh" not in result.tiers
    assert result.ended["gregkh"]["maintainer"] == datetime(
        2026, 1, 3, tzinfo=timezone.utc
    )


def test_an_anchor_may_demote_a_maintainer(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.tier("gregkh", "contributor", "torvalds", key("torvalds"), AFTER)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.voids == []
    assert result.tiers["gregkh"] == "contributor"

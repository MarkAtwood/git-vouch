"""'git vouch check' judged by registry history (DESIGN.md, Tier record, Person file, Revocation).

Each fixture registry is a real git repository built commit by commit, with
records signed by real ``ssh-keygen -Y sign``. Expected outcomes follow from
DESIGN.md's rules. Where it matters, the same tree is also checked as a plain
directory with no history, which must reach the snapshot verdict instead.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from conftest import Key, run_script
from test_check import ADDED, RETIRED, Registry, did, has, keys  # noqa: F401 (keys is a fixture)
from test_export import export, sign_file, ssh_verify


class GitRegistry(Registry):
    """A Registry whose checkout is a git repository, committed step by step."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
        self.day = 0

    def commit(self) -> None:
        """Commit everything, one day after the previous commit."""
        self.day += 1
        date = f"2026-01-{self.day:02d}T00:00:00Z"
        env = {**os.environ, "GIT_COMMITTER_DATE": date, "GIT_AUTHOR_DATE": date}
        for args in (["add", "-A"], ["commit", "-q", "-m", date]):
            subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
                cwd=self.root,
                env=env,
                check=True,
            )

    def git(self, *args: str) -> None:
        """Run a git command in the checkout, e.g. to branch or merge."""
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
            cwd=self.root,
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


def test_automation_grant_concurrent_with_accountable_removal_fails(
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
    assert has(result.problems, "people/bot.json", "gregkh", "concurrent commit")
    assert "bot" not in result.tiers


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
def test_demoted_approver_cannot_grant_from_an_old_branch(
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
    assert has(result.problems, "tiers/carol.json", "gregkh (no tier) may not grant")
    assert "carol" not in result.tiers
    assert result.tiers["alice"] == "contributor"


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

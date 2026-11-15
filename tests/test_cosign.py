"""Cosigns: two anchors approve the changes that otherwise rest on one merger (DESIGN, Cosign).

Each registry is a real git repository built commit by commit, with records
signed by real ``ssh-keygen -Y sign``, and every export is judged by real
``git verify-tag``. Expected outcomes follow from DESIGN.md: an
``anchors.json`` edit counts only once two anchors in effect before it
cosign its exact bytes, and a person file change no previous key signed
suspends an anchor's or maintainer's tier until two other anchors cosign it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest

from conftest import Key
from test_check import has, keys  # noqa: F401 (keys is a fixture)
from test_check_history import GitRegistry
from test_export import export, repo, tag, verifies  # noqa: F401 (repo is a fixture)

DAY1_NOON = "2026-01-01T12:00:00Z"
DAY3_NOON = "2026-01-03T12:00:00Z"


@pytest.fixture
def key(keys: Callable[[str], Key]) -> Callable[[str], Key]:  # noqa: F811
    return keys


@pytest.fixture
def reg(tmp_path: Path, key: Callable[[str], Key]) -> GitRegistry:
    """First commit (day 1): anchors torvalds, greg and shuah; maintainer kees;
    contributor alice; mallory registered with no tier."""
    r = GitRegistry(tmp_path / "registry")
    r.anchors("torvalds", "greg", "shuah")
    for handle in ("torvalds", "greg", "shuah", "kees", "alice", "mallory"):
        r.person(handle, key(handle))
    r.tier("kees", "maintainer", "torvalds", key("torvalds"))
    r.tier("alice", "contributor", "kees", key("kees"))
    r.commit()
    return r


def test_first_anchors_json_needs_no_cosign(
    vouch: ModuleType, reg: GitRegistry
) -> None:
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers == {
        "torvalds": "anchor",
        "greg": "anchor",
        "shuah": "anchor",
        "kees": "maintainer",
        "alice": "contributor",
    }


@pytest.mark.parametrize("cosigners", [0, 1])
def test_anchor_added_without_two_cosigns_is_not_one(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key], cosigners: int
) -> None:
    # A lone merger, or a merger and one anchor, adds mallory, who then
    # approves herself an accomplice.
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    for handle in ("torvalds",)[:cosigners]:
        reg.cosign("anchors.json", handle, key(handle))
    reg.person("eve", key("eve"))
    reg.tier("eve", "maintainer", "mallory", key("mallory"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert "mallory" not in result.tiers and "eve" not in result.tiers
    assert has(result.voids, "anchors.json: void: not cosigned by two anchors")
    assert has(result.problems, "tiers/eve.json", "mallory (no tier) may not grant")


def test_anchor_added_with_two_cosigns_is_one(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    reg.cosign("anchors.json", "torvalds", key("torvalds"))
    reg.cosign("anchors.json", "greg", key("greg"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.problems == [] and result.voids == []
    assert result.tiers["mallory"] == "anchor"


def test_cosign_landing_later_approves_from_then(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    reg.commit()
    assert "mallory" not in vouch.check_registry(reg.root).tiers
    reg.cosign("anchors.json", "torvalds", key("torvalds"))
    reg.cosign("anchors.json", "greg", key("greg"))
    reg.commit()
    assert vouch.check_registry(reg.root).tiers["mallory"] == "anchor"


def test_anchor_removed_without_cosigns_stays(
    vouch: ModuleType, reg: GitRegistry
) -> None:
    reg.anchors("torvalds")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.tiers["greg"] == "anchor" and result.tiers["shuah"] == "anchor"
    assert has(result.voids, "anchors are still torvalds, greg, shuah")


def test_dropped_anchors_may_approve_their_own_removal(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # Replacing every anchor is no way around the rule: the anchors before
    # the change approve it, and only they.
    reg.anchors("mallory")
    reg.cosign("anchors.json", "mallory", key("mallory"))
    reg.commit()
    assert "mallory" not in vouch.check_registry(reg.root).tiers
    reg.cosign("anchors.json", "greg", key("greg"))
    reg.cosign("anchors.json", "shuah", key("shuah"))
    reg.commit()
    tiers = vouch.check_registry(reg.root).tiers
    assert tiers["mallory"] == "anchor" and "greg" not in tiers


def test_cosign_by_an_unapproved_anchor_does_not_count(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # mallory was put in anchors.json without cosigns, so she is no anchor
    # and cannot be one of the two that approve her accomplice.
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    reg.commit()
    reg.anchors("torvalds", "greg", "shuah", "mallory", "eve")
    reg.person("eve", key("eve"))
    reg.cosign("anchors.json", "mallory", key("mallory"))
    reg.cosign("anchors.json", "torvalds", key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert "eve" not in result.tiers and "mallory" not in result.tiers
    assert has(result.problems, "cosigns/mallory-1.json", "was not an anchor")


def test_cosign_of_other_bytes_does_not_count(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # Cosigned bytes listing mallory, then a merger swaps in eve.
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    reg.person("eve", key("eve"))
    reg.cosign("anchors.json", "torvalds", key("torvalds"))
    reg.cosign("anchors.json", "greg", key("greg"))
    reg.anchors("torvalds", "greg", "shuah", "eve")
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert "eve" not in result.tiers and "mallory" not in result.tiers
    assert has(result.voids, "anchors.json: void")


def test_cosign_by_a_revoked_key_is_void(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    reg.cosign("anchors.json", "torvalds", key("torvalds"))
    reg.cosign("anchors.json", "greg", key("greg"))
    reg.revoke("greg", key("greg"), key("shuah"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert "mallory" not in result.tiers
    assert has(result.voids, "cosigns/greg-1.json: void", "revoked")


def test_cosign_signed_in_another_namespace_fails(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    rel = reg.cosign("anchors.json", "torvalds", key("torvalds"))
    data = (reg.root / rel).read_bytes()
    (reg.root / f"{rel}.sig").write_bytes(
        reg.sign(key("torvalds"), "git-vouch-endorse", data)
    )
    result = vouch.check_registry(reg.root)
    assert has(result.problems, f"{rel}.sig: no valid signature")


def test_revocation_by_an_unapproved_anchor_is_rejected(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # Anchors may revoke anyone's key; one added without cosigns may not.
    reg.anchors("torvalds", "greg", "shuah", "mallory")
    reg.revoke("kees", key("kees"), key("mallory"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.revoked == {}
    assert has(result.problems, "revocations/kees-1.json", "no valid signature")


@pytest.mark.parametrize("handle", ["kees", "greg"])
def test_recovery_without_cosigns_suspends_the_tier(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
    handle: str,
) -> None:
    # Day 2: a merger lets through a change no previous key signed, swapping
    # in a new key whose ``added`` is backdated to day 1.
    old, new = key(handle), key(f"{handle}-swap")
    reg.person(handle, new, retired=(old,), signers=(new,))
    reg.commit()
    result = vouch.check_registry(reg.root)
    tier = "maintainer" if handle == "kees" else "anchor"
    assert handle not in result.tiers
    assert has(result.voids, f"people/{handle}.json: void", f"the {tier} tier")
    out = export(reg, tmp_path)
    # Before the swap, the old key still verifies; the new key never does.
    assert verifies(repo, tag(repo, "old-before", old, DAY1_NOON), out)
    assert not verifies(repo, tag(repo, "new-before", new, DAY1_NOON), out)
    assert not verifies(repo, tag(repo, "new-after", new, DAY3_NOON), out)


def test_two_cosigns_restore_the_tier(
    vouch: ModuleType,
    reg: GitRegistry,
    key: Callable[[str], Key],
    tmp_path: Path,
    repo: Path,  # noqa: F811
) -> None:
    reg.person(
        "kees", key("kees-new"), retired=(key("kees"),), signers=(key("kees-new"),)
    )
    reg.commit()
    reg.cosign("people/kees.json", "torvalds", key("torvalds"))
    reg.cosign("people/kees.json", "greg", key("greg"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.tiers["kees"] == "maintainer" and result.voids == []
    assert has(result.warnings, "people/kees.json: WARNING: changed at")
    out = export(reg, tmp_path)
    assert verifies(repo, tag(repo, "new", key("kees-new"), DAY3_NOON), out)
    # Grants kees made stay valid, the suspension having been lifted.
    assert result.tiers["alice"] == "contributor"


def test_suspended_maintainer_cannot_grant(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    swap = key("kees-swap")
    reg.person("kees", swap, retired=(key("kees"),), signers=(swap,))
    reg.commit()
    reg.tier("mallory", "contributor", "kees", swap)
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert "mallory" not in result.tiers
    assert has(result.voids, "tiers/mallory.json: void: kees has no valid tier")


def test_a_new_tier_record_does_not_lift_the_suspension(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    swap = key("kees-swap")
    reg.person("kees", swap, retired=(key("kees"),), signers=(swap,))
    reg.commit()
    reg.tier(
        "kees", "maintainer", "torvalds", key("torvalds"), date="2026-03-02T00:00:00Z"
    )
    reg.commit()
    assert "kees" not in vouch.check_registry(reg.root).tiers


def test_own_cosign_does_not_count(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    swap = key("greg-swap")
    reg.person("greg", swap, retired=(key("greg"),), signers=(swap,))
    reg.cosign("people/greg.json", "greg", key("greg"))
    reg.cosign("people/greg.json", "torvalds", key("torvalds"))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert "greg" not in result.tiers
    assert has(result.problems, "cosigns/greg-1.json", "cannot cosign their own file")


def test_contributor_recovery_only_warns(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    swap = key("alice-swap")
    reg.person("alice", swap, retired=(key("alice"),), signers=(swap,))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.tiers["alice"] == "contributor" and result.voids == []
    assert has(result.warnings, "people/alice.json: WARNING: changed at")


def test_revoking_a_key_later_does_not_suspend(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    # kees rotates with his old key, then loses that key and revokes it. The
    # rotation was signed before the revocation, so it is no recovery.
    reg.person("kees", key("kees"), key("kees-next"), signers=(key("kees"),))
    reg.commit()
    reg.revoke("kees", key("kees"), key("kees-next"))
    reg.person(
        "kees", key("kees-next"), retired=(key("kees"),), signers=(key("kees-next"),)
    )
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.tiers["kees"] == "maintainer"
    assert not has(result.voids, "people/kees.json")


def test_sole_anchor_needs_only_the_other_anchors(
    vouch: ModuleType, tmp_path: Path, key: Callable[[str], Key]
) -> None:
    # With fewer than two other anchors, every other anchor must cosign; a
    # sole anchor's change rests on review, so a registry is never stuck.
    reg = GitRegistry(tmp_path / "registry")
    reg.anchors("torvalds")
    reg.person("torvalds", key("torvalds"))
    reg.person("greg", key("greg"))
    reg.commit()
    swap = key("torvalds-swap")
    reg.person("torvalds", swap, retired=(key("torvalds"),), signers=(swap,))
    reg.commit()
    assert vouch.check_registry(reg.root).tiers["torvalds"] == "anchor"
    reg.anchors("torvalds", "greg")
    reg.commit()
    assert "greg" not in vouch.check_registry(reg.root).tiers
    reg.cosign("anchors.json", "torvalds", swap)
    reg.commit()
    assert vouch.check_registry(reg.root).tiers["greg"] == "anchor"


def test_held_at_ends_the_tier_at_the_recovery(
    vouch: ModuleType, reg: GitRegistry, key: Callable[[str], Key]
) -> None:
    swap = key("kees-swap")
    reg.person("kees", swap, retired=(key("kees"),), signers=(swap,))
    reg.commit()
    result = vouch.check_registry(reg.root)
    assert result.held_at("kees", _utc(DAY1_NOON)).tier == "maintainer"
    assert result.held_at("kees", _utc(DAY3_NOON)).tier is None
    assert result.held_at("kees", None).tier is None


def _utc(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

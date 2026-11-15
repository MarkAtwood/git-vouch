"""'git vouch show': one person's standing, with endorsements from outside the kernel graph marked.

An endorsement is from outside when its endorser holds no tier and lists
identities elsewhere in ``alsoKnownAs`` (DESIGN.md, Endorsement). The
registry is written with real ``ssh-keygen -Y sign`` signatures; the
expected classification follows from each endorser's tier and person file
as the fixture writes them, not from git-vouch's output.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import Key, run_script
from test_check import Registry, did, keys  # noqa: F401 (keys is a fixture)

APACHE = "did:web:apache.org:people:sam"
PLC = "did:plc:ewvi7nxzyoun6zhxrhs64oiz"


@pytest.fixture
def reg(tmp_path: Path, keys: Callable[[str], Key]) -> Registry:  # noqa: F811
    """Anchor torvalds; maintainer gregkh, who also lists a DID elsewhere; contributor
    alice. sam (no tier, two DIDs elsewhere) and pat (no tier, none) are registered.

    alice is endorsed by torvalds (anchor: inside), gregkh (maintainer with a
    DID elsewhere: inside, he has a tier), pat (no tier and no other identity:
    inside) and sam (outside).
    """
    r = Registry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", keys("torvalds"))
    r.person("gregkh", keys("gregkh"), also_known_as=("did:web:kroah.com",))
    r.person("alice", keys("alice"), emails=("alice@work.example",))
    r.person("sam", keys("sam"), also_known_as=(APACHE, PLC))
    r.person("pat", keys("pat"))
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.tier("alice", "contributor", "gregkh", keys("gregkh"))
    for endorser in ("torvalds", "gregkh", "pat", "sam"):
        r.endorse("alice", keys("alice"), endorser, keys(endorser))
    return r


def show(reg: Registry, handle: str) -> list[str]:
    proc = run_script("show", handle, str(reg.root))
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.splitlines()


def test_show_lists_the_person_and_marks_outside_endorsements(
    reg: Registry,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    assert show(reg, "alice") == [
        "handle: alice",
        "name: Alice",
        "tier: contributor",
        f"key: {did(keys('alice'))} current",
        "email: alice@example.org endorsed",
        "email: alice@work.example not endorsed",
        (
            "endorsement: endorsements/alice/gregkh-1.json by gregkh (maintainer),"
            " inside, 2026-03-01T00:00:00Z"
        ),
        "  emails: alice@example.org",
        (
            "endorsement: endorsements/alice/pat-1.json by pat (no tier), inside,"
            " 2026-03-01T00:00:00Z"
        ),
        "  emails: alice@example.org",
        (
            "endorsement: endorsements/alice/sam-1.json by sam (no tier), outside,"
            " 2026-03-01T00:00:00Z"
        ),
        "  emails: alice@example.org",
        f"  endorser also known as: {APACHE}, {PLC}",
        f"  endorser key: {did(keys('sam'))}",
        (
            "endorsement: endorsements/alice/torvalds-1.json by torvalds (anchor),"
            " inside, 2026-03-01T00:00:00Z"
        ),
        "  emails: alice@example.org",
        "endorsements: 4, 1 from outside the kernel graph",
    ]


def test_show_prints_own_also_known_as(reg: Registry) -> None:
    assert "also known as: did:web:kroah.com" in show(reg, "gregkh")


def test_invalid_endorsement_is_not_listed(
    reg: Registry,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    # sam's second endorsement names a key alice does not hold: invalid, so not shown.
    reg.endorse("alice", keys("pat"), "sam", keys("sam"), n=2)
    out = show(reg, "alice")
    assert not any("sam-2" in line for line in out)
    assert out[-1] == "endorsements: 4, 1 from outside the kernel graph"


def test_outside_endorser_who_gains_a_tier_is_inside(
    reg: Registry,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    reg.tier("sam", "contributor", "gregkh", keys("gregkh"))
    out = show(reg, "alice")
    assert any("by sam (contributor), inside" in line for line in out)
    assert out[-1] == "endorsements: 4, 0 from outside the kernel graph"


def test_note_is_printed_with_control_characters_escaped(
    reg: Registry,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    rel = reg.endorse("alice", keys("alice"), "pat", keys("pat"), n=2)
    path = reg.root / rel
    record = json.loads(path.read_text())
    record["note"] = "met at LPC\x1b[2J"
    del record["@context"]
    reg.write(rel, record, keys("pat"), ns="git-vouch-endorse")
    assert "  note: met at LPC\\x1b[2J" in show(reg, "alice")


def test_unknown_person_fails(reg: Registry) -> None:
    proc = run_script("show", "nobody", str(reg.root))
    assert proc.returncode == 1
    assert "nobody: no valid person file" in proc.stderr

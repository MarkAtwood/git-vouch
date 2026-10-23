"""'git vouch query <did> [--at TIME]' (DESIGN.md, Commands and TRQP bridge).

Fixture registries are signed by real ``ssh-keygen -Y sign``; did:keys
come from test_check's ``did``, which does not use git-vouch's encoder.
Every expected answer is stated by hand from the fixture's dates
(ADDED 2026-01-01, RETIRED 2026-06-01).
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import SCRIPT, Key
from test_check import AFTER, BEFORE, Registry, did, keys  # noqa: F401 (keys is a fixture)
from test_check_history import GitRegistry
from test_export import BEFORE_ADDED, reg  # noqa: F401 (reg is a fixture)


def query(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git-vouch query in ``root``, the default registry before setup has run."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), "query", *args],
        cwd=root,
        capture_output=True,
        text=True,
    )


def answer(root: Path, *args: str) -> dict[str, object]:
    proc = query(root, *args)
    assert proc.returncode == 0, proc.stderr
    result: dict[str, object] = json.loads(proc.stdout)
    return result


def test_full_answer(reg: Registry, keys: Callable[[str], Key]) -> None:  # noqa: F811
    alice = did(keys("alice"))
    assert answer(reg.root, alice, "--at", BEFORE) == {
        "did": alice,
        "at": "2026-03-01T00:00:00Z",
        "handle": "alice",
        "tier": "contributor",
        "automation": False,
        "emails": ["alice@example.org"],
        "added": "2026-01-01T00:00:00Z",
        "retired": None,
        "revoked": False,
        "valid": True,
    }


@pytest.mark.parametrize(
    ("name", "handle", "tier", "automation", "emails"),
    [
        ("torvalds", "torvalds", "anchor", False, ["torvalds@example.org"]),
        ("gregkh", "gregkh", "maintainer", False, ["gregkh@example.org"]),
        ("alice", "alice", "contributor", False, ["alice@example.org"]),
        ("bot", "bot", "automation", True, ["bot@example.org"]),
        ("dave", "dave", None, False, []),  # no tier, no endorsed email
    ],
)
def test_tiers(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    name: str,
    handle: str,
    tier: str | None,
    automation: bool,
    emails: list[str],
) -> None:
    got = answer(reg.root, did(keys(name)))
    assert (got["handle"], got["tier"], got["automation"], got["emails"]) == (
        handle,
        tier,
        automation,
        emails,
    )
    assert got["valid"] is True


def test_accountable_human_tier_is_automation(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """carol names an accountable maintainer, so she is a bot whatever her tier."""
    reg.person("carol", keys("carol"), accountable="gregkh")
    reg.tier("carol", "contributor", "gregkh", keys("gregkh"))
    reg.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    got = answer(reg.root, did(keys("carol")))
    assert (got["tier"], got["automation"], got["valid"]) == (
        "contributor",
        True,
        True,
    )


@pytest.mark.parametrize(
    ("at", "valid"),
    [
        (BEFORE_ADDED, False),
        ("2026-01-01T00:00:00Z", True),  # added is inclusive
        (BEFORE, True),
        ("2026-05-31T23:59:59Z", True),
        ("2026-06-01T00:00:00Z", False),  # retired is exclusive
        ("2026-05-31T19:59:59-04:00", True),
        ("2026-05-31T20:00:00-04:00", False),  # the retirement, in another offset
        (AFTER, False),
        (None, False),  # now: 2026-06-01 is past
    ],
)
def test_retired_key(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    at: str | None,
    valid: bool,
) -> None:
    got = answer(reg.root, did(keys("gregkh-old")), *(["--at", at] if at else []))
    assert got["handle"] == "gregkh" and got["tier"] == "maintainer"
    assert got["retired"] == "2026-06-01T00:00:00Z" and got["revoked"] is False
    assert got["valid"] is valid


@pytest.mark.parametrize("at", [BEFORE_ADDED, BEFORE, AFTER, None])
def test_revoked_key_never_valid(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    at: str | None,
) -> None:
    got = answer(reg.root, did(keys("alice2")), *(["--at", at] if at else []))
    assert got["handle"] == "alice" and got["revoked"] is True
    assert got["valid"] is False


@pytest.mark.parametrize("name", ["stranger", None])
def test_unknown_did_exits_1(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    name: str | None,
) -> None:
    subject = did(keys(name)) if name else "did:key:zNotAKey"
    proc = query(reg.root, subject)
    assert proc.returncode == 1, proc.stderr
    got = json.loads(proc.stdout)
    assert got["did"] == subject and got["handle"] is None and got["tier"] is None
    assert got["valid"] is False


def test_tier_at_time_follows_demotion(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """gregkh, maintainer from day 1, is demoted to contributor by a record dated 2026-02-01."""
    r = GitRegistry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", keys("torvalds"))
    r.person("gregkh", keys("gregkh"))
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.commit()
    r.tier(
        "gregkh", "contributor", "torvalds", keys("torvalds"), "2026-02-01T00:00:00Z"
    )
    r.commit()
    gregkh = did(keys("gregkh"))
    assert answer(r.root, gregkh, "--at", "2026-01-15T00:00:00Z")["tier"] == (
        "maintainer"
    )
    assert answer(r.root, gregkh, "--at", "2026-01-31T23:59:59Z")["tier"] == (
        "maintainer"
    )
    assert answer(r.root, gregkh, "--at", "2026-02-01T00:00:00Z")["tier"] == (
        "contributor"
    )  # the end is exclusive
    assert answer(r.root, gregkh, "--at", "2026-02-02T00:00:00Z")["tier"] == (
        "contributor"
    )
    assert answer(r.root, gregkh)["tier"] == "contributor"


def test_refuses_on_registry_problem(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    reg.tier("dave", "maintainer", "alice", keys("alice"))  # alice may not grant it
    proc = query(reg.root, did(keys("alice")))
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "registry check failed" in proc.stderr


@pytest.mark.parametrize(
    "at",
    [
        "2026-03-01T00:00:00",
        "2026-03-01",
        "yesterday",
        "2026-13-01T00:00:00Z",
        "0001-01-01T00:00:00+01:00",  # UTC falls before year 1
        "9999-12-31T23:59:59-01:00",  # UTC falls after year 9999
    ],
)
def test_rejects_bad_time(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    at: str,
) -> None:
    proc = query(reg.root, did(keys("alice")), "--at", at)
    assert proc.returncode == 2
    assert proc.stdout == "" and "RFC 3339" in proc.stderr

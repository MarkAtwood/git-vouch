"""'git vouch query <did> [--at TIME]' (DESIGN.md, Commands and TRQP bridge).

Fixture registries are signed by real ``ssh-keygen -Y sign``; did:keys
come from test_check's ``did``, which does not use git-vouch's encoder.
Every expected answer is stated by hand from the fixture's dates
(ADDED 2026-01-01, RETIRED 2026-06-01).
"""

from __future__ import annotations

import json
import os
import shutil
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
        ("2026-06-01T00:00:00Z", True),  # the retirement second, as check has it
        ("2026-06-01T00:00:00.500Z", True),  # still that second, as OpenSSH sees it
        ("2026-06-01T00:00:01Z", False),
        ("2026-05-31T19:59:59-04:00", True),
        ("2026-05-31T20:00:00-04:00", True),  # the retirement, in another offset
        ("2026-05-31T20:00:01-04:00", False),
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


T0 = "2026-01-01T12:00:00Z"  # after the first commit, before the second
T1 = "2026-01-02T00:00:00Z"  # the second commit


def base(tmp_path: Path, keys: Callable[[str], Key]) -> GitRegistry:  # noqa: F811
    """Return an uncommitted registry: anchor torvalds and maintainer gregkh."""
    r = GitRegistry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", keys("torvalds"))
    r.person("gregkh", keys("gregkh"))
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    return r


def promoted_bot(tmp_path: Path, keys: Callable[[str], Key]) -> GitRegistry:  # noqa: F811
    """bot is automation with an endorsed email from the first commit until
    the second, which drops its accountable maintainer and makes it a
    contributor."""
    r = base(tmp_path, keys)
    r.person("bot", keys("bot"), accountable="gregkh")
    r.tier("bot", "automation", "gregkh", keys("gregkh"))
    r.endorse("bot", keys("bot"), "gregkh", keys("gregkh"))
    r.commit()
    r.person("bot", keys("bot"))
    r.tier("bot", "contributor", "gregkh", keys("gregkh"), T1)
    r.commit()
    return r


def test_promoted_after_time_reads_old_tier(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    r = base(tmp_path, keys)
    r.tier("gregkh", "contributor", "torvalds", keys("torvalds"))
    r.commit()
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.commit()
    gregkh = did(keys("gregkh"))
    assert answer(r.root, gregkh, "--at", T0)["tier"] == "contributor"
    assert answer(r.root, gregkh, "--at", T1)["tier"] == "maintainer"
    assert answer(r.root, gregkh)["tier"] == "maintainer"


def test_backdated_promotion_counts_from_its_parents_date(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """The commit making gregkh a maintainer claims 2026-01-01T06:00:00Z, before
    the README commit of day 2 it follows (vouch-faq3.13)."""
    r = base(tmp_path, keys)
    r.tier("gregkh", "contributor", "torvalds", keys("torvalds"))
    r.commit()
    (r.root / "README").write_text("unrelated\n")
    r.commit()
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.commit(date="2026-01-01T06:00:00Z")
    gregkh = did(keys("gregkh"))
    assert answer(r.root, gregkh, "--at", "2026-01-01T06:00:00Z")["tier"] == (
        "contributor"
    )
    assert answer(r.root, gregkh, "--at", T0)["tier"] == "contributor"
    assert answer(r.root, gregkh, "--at", T1)["tier"] == "maintainer"


def test_automation_until_promotion(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    r = promoted_bot(tmp_path, keys)
    bot = did(keys("bot"))
    then = answer(r.root, bot, "--at", T0)
    assert (then["tier"], then["automation"], then["emails"], then["valid"]) == (
        "automation",
        True,
        ["bot@example.org"],
        True,
    )
    now = answer(r.root, bot)
    assert (now["tier"], now["automation"]) == ("contributor", False)


def test_demoted_after_time_reads_old_tier(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    r = base(tmp_path, keys)
    r.commit()
    r.tier("gregkh", "contributor", "torvalds", keys("torvalds"), T1)
    r.commit()
    gregkh = did(keys("gregkh"))
    assert answer(r.root, gregkh, "--at", T0)["tier"] == "maintainer"
    assert answer(r.root, gregkh, "--at", T1)["tier"] == "contributor"


def test_demotion_dated_before_its_commit_ends_the_old_tier_at_its_date(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """The contributor record is dated 06:00 on the first day but committed on
    the second: maintainer ends at 06:00 (DESIGN.md, Demotion), and at T0 the
    contributor record is not in the history yet, so no tier is held."""
    r = base(tmp_path, keys)
    r.commit()
    r.tier(
        "gregkh", "contributor", "torvalds", keys("torvalds"), "2026-01-01T06:00:00Z"
    )
    r.commit()
    gregkh = did(keys("gregkh"))
    assert (
        answer(r.root, gregkh, "--at", "2026-01-01T05:00:00Z")["tier"] == "maintainer"
    )
    assert answer(r.root, gregkh, "--at", T0)["tier"] is None
    assert answer(r.root, gregkh, "--at", T1)["tier"] == "contributor"


def test_dropped_accountable_does_not_revive_an_ended_tier(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """alice, a maintainer, is made automation on the second day (ending
    maintainer then), drops her accountable maintainer on the third and
    restores it on the fourth. On the third the automation record does not
    verify, but maintainer has still ended."""
    r = base(tmp_path, keys)
    r.person("alice", keys("alice"))
    r.tier("alice", "maintainer", "torvalds", keys("torvalds"))
    r.commit()
    r.person("alice", keys("alice"), accountable="gregkh")
    r.tier("alice", "automation", "gregkh", keys("gregkh"), T1)
    r.commit()
    r.person("alice", keys("alice"))
    r.commit()
    r.person("alice", keys("alice"), accountable="gregkh")
    r.commit()
    alice = did(keys("alice"))
    got = answer(r.root, alice, "--at", "2026-01-03T12:00:00Z")
    assert (got["tier"], got["automation"]) == (None, False)
    got = answer(r.root, alice, "--at", "2026-01-04T12:00:00Z")
    assert (got["tier"], got["automation"]) == ("automation", True)


def test_emails_come_from_the_person_file_at_time(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """alice lists a@example.org in the first commit and b@example.org in the
    second; gregkh endorses each."""
    r = base(tmp_path, keys)
    r.person("alice", keys("alice"), emails=("a@example.org",))
    r.tier("alice", "contributor", "gregkh", keys("gregkh"))
    r.endorse(
        "alice", keys("alice"), "gregkh", keys("gregkh"), 1, emails=("a@example.org",)
    )
    r.commit()
    r.person("alice", keys("alice"), emails=("b@example.org",))
    r.endorse(
        "alice", keys("alice"), "gregkh", keys("gregkh"), 2, emails=("b@example.org",)
    )
    r.commit()
    alice = did(keys("alice"))
    assert answer(r.root, alice, "--at", T0)["emails"] == ["a@example.org"]
    assert answer(r.root, alice)["emails"] == ["b@example.org"]


def test_endorsement_committed_after_time_does_not_count(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """carol, a contributor from the first commit, is endorsed in the second."""
    r = base(tmp_path, keys)
    r.person("carol", keys("carol"))
    r.tier("carol", "contributor", "gregkh", keys("gregkh"))
    r.commit()
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    carol = did(keys("carol"))
    assert answer(r.root, carol, "--at", T0)["emails"] == []
    assert answer(r.root, carol, "--at", T1)["emails"] == ["carol@example.org"]
    assert answer(r.root, carol)["emails"] == ["carol@example.org"]


def test_endorsement_removed_after_time_counts_then(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """carol is endorsed in the first commit; the second deletes the endorsement."""
    r = base(tmp_path, keys)
    r.person("carol", keys("carol"))
    r.tier("carol", "contributor", "gregkh", keys("gregkh"))
    rel = r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    r.delete(rel)
    r.commit()
    carol = did(keys("carol"))
    assert answer(r.root, carol, "--at", T0)["emails"] == ["carol@example.org"]
    assert answer(r.root, carol, "--at", T1)["emails"] == []
    assert answer(r.root, carol)["emails"] == []


def carol(tmp_path: Path, keys: Callable[[str], Key], *emails: str) -> GitRegistry:  # noqa: F811
    """Return ``base`` plus carol, a contributor listing ``emails`` too, uncommitted."""
    r = base(tmp_path, keys)
    r.person("carol", keys("carol"), emails=emails)
    r.tier("carol", "contributor", "torvalds", keys("torvalds"))
    return r


def test_endorsement_edited_after_time_reads_the_old_version(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """gregkh endorses carol@ in the first commit and re-signs it adding x@ in the second."""
    r = carol(tmp_path, keys, "x@example.org")
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    both = ("carol@example.org", "x@example.org")
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"), emails=both)
    r.commit()
    who = did(keys("carol"))
    assert answer(r.root, who, "--at", T0)["emails"] == ["carol@example.org"]
    assert answer(r.root, who, "--at", T1)["emails"] == list(both)
    assert answer(r.root, who)["emails"] == list(both)


def test_endorsement_on_a_branch_counts_from_the_merge(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """carol is endorsed on a side branch committed 2026-01-02, merged 2026-01-03."""
    r = carol(tmp_path, keys)
    r.commit()
    r.git("checkout", "-q", "-b", "side")
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    r.git("checkout", "-q", "main")
    merged = "2026-01-03T00:00:00Z"
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.org"]
        + ["merge", "-q", "--no-ff", "--no-edit", "side"],
        cwd=r.root,
        env={**os.environ, "GIT_COMMITTER_DATE": merged, "GIT_AUTHOR_DATE": merged},
        check=True,
    )
    who = did(keys("carol"))
    assert answer(r.root, who, "--at", "2026-01-02T12:00:00Z")["emails"] == []
    assert answer(r.root, who, "--at", merged)["emails"] == ["carol@example.org"]
    assert answer(r.root, who)["emails"] == ["carol@example.org"]


def test_endorser_key_revoked_after_time_voids_it_then(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """gregkh endorses carol in the first commit; torvalds revokes that key in the second."""
    r = carol(tmp_path, keys)
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    r.revoke("gregkh", keys("gregkh"), keys("torvalds"))
    r.commit()
    assert answer(r.root, did(keys("carol")), "--at", T0)["emails"] == []


def test_person_emails_changed_after_time_read_the_old_list(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """One endorsement covers all three addresses; carol lists old@ first, then new@."""
    r = carol(tmp_path, keys, "old@example.org")
    every = ("carol@example.org", "old@example.org", "new@example.org")
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"), emails=every)
    r.commit()
    r.person("carol", keys("carol"), emails=("new@example.org",))
    r.commit()
    who = did(keys("carol"))
    then = ["carol@example.org", "old@example.org"]
    assert answer(r.root, who, "--at", T0)["emails"] == then
    assert answer(r.root, who)["emails"] == ["carol@example.org", "new@example.org"]


def test_unreadable_past_endorsement_fails_the_query_closed(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """The first commit has a 70,000-byte endorsement (over git-vouch's 64 KiB
    cap); the second replaces it with a valid one. Check judges the tree."""
    r = carol(tmp_path, keys)
    rel = "endorsements/carol/gregkh-1.json"
    (r.root / "endorsements/carol").mkdir(parents=True)
    for name in (rel, rel + ".sig"):
        (r.root / name).write_bytes(b" " * 70_000)
    r.commit()
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    proc = query(r.root, did(keys("carol")), "--at", T0)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["emails"] == []
    assert "65536 bytes" in proc.stderr and "endorsed" in proc.stderr
    assert answer(r.root, did(keys("carol")))["emails"] == ["carol@example.org"]
    check = subprocess.run(
        [sys.executable, str(SCRIPT), "check", str(r.root)],
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr


def test_check_does_not_read_endorsement_history(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """A git on PATH logs its arguments: check never names endorsements; query --at does."""
    r = carol(tmp_path, keys)
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    shim, log = tmp_path / "bin", tmp_path / "git.log"
    shim.mkdir()
    real = shutil.which("git")
    (shim / "git").write_text(f'#!/bin/sh\necho "$*" >> "{log}"\nexec "{real}" "$@"\n')
    (shim / "git").chmod(0o755)
    env = {**os.environ, "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}"}

    def logged(*args: str) -> str:
        log.write_text("")
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            cwd=r.root,
            env=env,
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr
        return log.read_text()

    assert "log" in logged("check", str(r.root))
    assert "endorsements" not in logged("check", str(r.root))
    assert "endorsements/carol" in logged("query", did(keys("carol")), "--at", T0)


def test_time_before_the_handle_existed_is_unknown(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """gregkh's person file arrives in the second commit; torvalds's in the first."""
    r = GitRegistry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", keys("torvalds"))
    r.commit()
    r.person("gregkh", keys("gregkh"))
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.commit()
    for name, at in [("gregkh", T0), ("torvalds", "2025-12-31T23:59:59Z")]:
        proc = query(r.root, did(keys(name)), "--at", at)
        assert proc.returncode == 1, proc.stderr
        got = json.loads(proc.stdout)
        assert (got["handle"], got["tier"], got["emails"]) == (None, None, [])
    assert answer(r.root, did(keys("gregkh")), "--at", T1)["tier"] == "maintainer"
    assert answer(r.root, did(keys("torvalds")), "--at", T0)["tier"] == "anchor"


def test_later_revocation_voids_a_past_tier(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """alice's tier was approved with the gregkh key that torvalds revokes later."""
    r = base(tmp_path, keys)
    r.person("alice", keys("alice"))
    r.tier("alice", "contributor", "gregkh", keys("gregkh"))
    r.commit()
    r.revoke("gregkh", keys("gregkh"), keys("torvalds"))
    r.commit()
    assert answer(r.root, did(keys("alice")), "--at", T0)["tier"] is None


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


FIXTURE_KEYS = ("torvalds", "gregkh", "gregkh-old", "alice", "alice2", "bot", "dave")


def same_answer(
    entry: object, one: subprocess.CompletedProcess[str], at: str | None
) -> None:
    """Assert ``entry`` is the answer ``one`` printed, with its exit status.

    For now (``at`` None) the ``at`` member is left out: each run reads the clock.
    """
    alone = json.loads(one.stdout)
    assert isinstance(entry, dict)
    assert one.returncode == (0 if entry["handle"] is not None else 1), one.stderr
    if at is None:
        alone.pop("at")
        entry = {k: v for k, v in entry.items() if k != "at"}
    assert entry == alone


@pytest.mark.parametrize("at", [BEFORE_ADDED, BEFORE, AFTER, None])
def test_all_answers_as_each_query_does(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    at: str | None,
) -> None:
    """A current, retired, revoked, automation and unendorsed key, and an anchor's."""
    options = ["--at", at] if at else []
    proc = query(reg.root, "--all", *options)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert set(got) == {did(keys(name)) for name in FIXTURE_KEYS}
    assert len({entry["at"] for entry in got.values()}) == 1
    for subject, entry in got.items():
        same_answer(entry, query(reg.root, subject, *options), at)


def test_all_answers_a_key_whose_person_had_no_file_then(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """gregkh's person file arrives in the second commit, so at T0 he is unknown."""
    r = GitRegistry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", keys("torvalds"))
    r.commit()
    r.person("gregkh", keys("gregkh"))
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.commit()
    got = answer(r.root, "--all", "--at", T0)
    gregkh, torvalds = did(keys("gregkh")), did(keys("torvalds"))
    assert set(got) == {gregkh, torvalds}
    assert got[gregkh]["handle"] is None and got[torvalds]["tier"] == "anchor"
    for subject, entry in got.items():
        same_answer(entry, query(r.root, subject, "--at", T0), T0)


def test_all_refuses_on_registry_problem(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    reg.tier("dave", "maintainer", "alice", keys("alice"))  # alice may not grant it
    proc = query(reg.root, "--all")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "registry check failed" in proc.stderr


@pytest.mark.parametrize("args", [[], ["--all", "did:key:zNotAKey"]])
def test_wants_one_did_or_all(reg: Registry, args: list[str]) -> None:  # noqa: F811
    proc = query(reg.root, *args)
    assert proc.returncode == 2
    assert proc.stdout == "" and "--all" in proc.stderr

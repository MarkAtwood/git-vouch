"""'git vouch check' on ``migratedFrom`` (DESIGN.md, Person file and Flag day, D3).

Records are signed by real ``ssh-keygen`` through test_check's ``Registry``.
The fingerprint is Linus Torvalds' published key in pgpkeys.git; expected
outcomes follow from DESIGN.md, never from git-vouch's own output.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from conftest import SCRIPT, Key, make_key, run_script
from test_check import ADDED, CONTEXT, Registry

FPR = "ABAF11C65A2970B130ABE3C479BE3E4300411886"
OTHER_FPR = "647F28654894E3BD457199BE38DBBDC86092693E"


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> Callable[[str], Key]:
    """Return a function that makes (once per module) a named throwaway ed25519 key."""
    directory = tmp_path_factory.mktemp("keys")
    made: dict[str, Key] = {}

    def get(name: str) -> Key:
        if name not in made:
            made[name] = make_key(directory, name, ["-t", "ed25519"])
        return made[name]

    return get


def ported(reg: Registry, handle: str, key: Key, migrated: object) -> None:
    """Write a signed person file for ``handle`` carrying ``migratedFrom``."""
    record = {
        "handle": handle,
        "name": handle.title(),
        "emails": [f"{handle}@example.org"],
        "keys": [{"ssh": key.pubkey, "added": ADDED, "retired": None}],
        "accountable": None,
        "migratedFrom": migrated,
    }
    reg.write(f"people/{handle}.json", record, key, ns="git-vouch-register")


@pytest.fixture
def reg(tmp_path: Path, keys: Callable[[str], Key]) -> Registry:
    """A registry with anchor torvalds and nothing else."""
    reg = Registry(tmp_path / "registry")
    reg.anchors("torvalds")
    reg.person("torvalds", keys("torvalds"))
    return reg


@pytest.mark.parametrize("fpr", [FPR, FPR.lower()])
def test_valid_migrated_from(
    vouch: ModuleType, reg: Registry, keys: Callable[[str], Key], fpr: str
) -> None:
    ported(reg, "alice", keys("alice"), "openpgp4fpr:" + fpr)
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert "alice" in result.people
    assert not any("migratedFrom" in w for w in result.warnings)


@pytest.mark.parametrize(
    "bad",
    [
        FPR,  # no prefix
        "openpgp4fpr:" + FPR[:-1],  # 39 hex
        "openpgp4fpr:" + FPR + "0",  # 41 hex
        "openpgp4fpr:" + FPR[:-1] + "G",  # not hex
        "OPENPGP4FPR:" + FPR,  # the prefix is lowercase
        "openpgp4fpr: " + FPR,
        "openpgp4fpr:" + FPR + "\n",
        "openpgp4fpr:" + FPR[:16],  # a long key id, not a fingerprint
        "",
        42,
        ["openpgp4fpr:" + FPR],
    ],
)
def test_bad_migrated_from_rejected(
    vouch: ModuleType, reg: Registry, keys: Callable[[str], Key], bad: object
) -> None:
    ported(reg, "alice", keys("alice"), bad)
    result = vouch.check_registry(reg.root)
    assert "alice" not in result.people
    assert any(
        p.startswith("people/alice.json") and "migratedFrom" in p
        for p in result.problems
    ), result.problems
    proc = run_script("check", str(reg.root))
    assert proc.returncode == 1
    assert "git-vouch: error: people/alice.json" in proc.stderr
    assert "migratedFrom" in proc.stderr


def test_null_migrated_from_is_absent(
    vouch: ModuleType, reg: Registry, keys: Callable[[str], Key]
) -> None:
    ported(reg, "alice", keys("alice"), None)
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert "alice" in result.people


def test_duplicate_fingerprint_flags_both(
    vouch: ModuleType, reg: Registry, keys: Callable[[str], Key]
) -> None:
    """D3: two files claiming one fingerprint (in either case) are both flagged, not failed."""
    ported(reg, "alice", keys("alice"), "openpgp4fpr:" + FPR)
    ported(reg, "mallory", keys("mallory"), "openpgp4fpr:" + FPR.lower())
    ported(reg, "bob", keys("bob"), "openpgp4fpr:" + OTHER_FPR)
    result = vouch.check_registry(reg.root)
    assert result.problems == []
    assert {"alice", "mallory", "bob"} <= set(result.people)
    flagged = [w for w in result.warnings if FPR in w]
    assert len(flagged) == 2
    assert any(w.startswith("people/alice.json") and "mallory" in w for w in flagged)
    assert any(w.startswith("people/mallory.json") and "alice" in w for w in flagged)
    assert [w for w in result.warnings if "migratedFrom" in w] == flagged

    proc = run_script("check", str(reg.root))
    assert proc.returncode == 0, proc.stderr
    lines = [ln for ln in proc.stderr.splitlines() if FPR in ln]
    assert len(lines) == 2
    assert any("people/alice.json" in ln and "mallory" in ln for ln in lines)
    assert any("people/mallory.json" in ln and "alice" in ln for ln in lines)
    assert all(ln.startswith("git-vouch: warning: ") for ln in lines)


def test_register_refuses_a_draft_with_bad_migrated_from(
    reg: Registry, keys: Callable[[str], Key], tmp_path: Path
) -> None:
    draft = tmp_path / "alice-draft.json"
    obj = {
        "@context": [CONTEXT],
        "handle": "alice",
        "name": "Alice",
        "emails": ["alice@example.org"],
        "keys": [],
        "migratedFrom": "openpgp4fpr:" + FPR[:-1],  # 39 hex
    }
    draft.write_text(json.dumps(obj))
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "register", "--from", str(draft)]
        + [str(keys("alice").public)],
        cwd=reg.root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1
    assert "migratedFrom" in proc.stderr
    assert not (reg.root / "people/alice.json").exists()
    assert not (reg.root / "people/alice.json.sig").exists()

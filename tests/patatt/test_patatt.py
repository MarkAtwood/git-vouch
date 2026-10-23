"""End-to-end: patch emails signed with patatt, checked against the registry.

The verifier is the patatt fork with ``keyringsrc = vouch:``; stock patatt
is the independent oracle for the signature format. See conftest.py.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from .conftest import (
    FORK,
    RES_BADSIG,
    RES_NOKEY,
    RES_VALID,
    STOCK,
    Registry,
    patatt,
    run,
    selector,
)


def patch(tmp: Path, identity: str) -> bytes:
    """Return a ``git format-patch`` email authored by ``identity``."""
    repo = tmp / "src"
    if not repo.exists():
        run("git", "init", "-q", str(repo))
    with open(repo / "file", "a") as f:
        f.write(f"{identity}\n")
    run("git", "add", "file", cwd=repo)
    run("git", "commit", "-q", "--author", f"Someone <{identity}>", "-m", "x", cwd=repo)
    return run("git", "format-patch", "-1", "--stdout", cwd=repo)


def sign(tree: Path, tmp: Path, key: Path, identity: str, sel: str) -> Path:
    """Sign a patch from ``identity`` with ``tree``'s patatt; return the file."""
    config = {
        "patatt.signingkey": f"openssh:{key}",
        "patatt.identity": identity,
        "patatt.selector": sel,
    }
    proc = patatt(tree, config, "sign", cwd=tmp, stdin=patch(tmp, identity))
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    assert b"X-Developer-Signature: v=1; a=openssh-sha256;" in proc.stdout
    path = tmp / f"{identity}.{sel}.eml"
    path.write_bytes(proc.stdout)
    return path


def validate(
    tree: Path, tmp: Path, msg: Path, keyringsrc: str = "vouch:"
) -> subprocess.CompletedProcess[bytes]:
    """Run ``patatt -v validate`` with one keyring source, outside any git repo."""
    return patatt(
        tree, {"patatt.keyringsrc": keyringsrc}, "-v", "validate", str(msg), cwd=tmp
    )


def signed_by(reg: Registry, name: str, identity: str, tree: Path = FORK) -> Path:
    """Sign as ``identity`` with ``name``'s key under its own selector."""
    key = reg.key(name)
    return sign(tree, reg.tmp, key, identity, selector(Path(f"{key}.pub")))


def assert_passes(
    proc: subprocess.CompletedProcess[bytes], identity: str, sel: str
) -> None:
    err = proc.stderr.decode(errors="replace")
    assert proc.returncode == RES_VALID, err
    assert f"PASS | {identity}," in err
    assert f"key: vouch:{identity}/{sel}" in err
    assert "legacy keyring" not in err


def assert_nokey(proc: subprocess.CompletedProcess[bytes], identity: str) -> None:
    err = proc.stderr.decode(errors="replace")
    assert proc.returncode == RES_NOKEY, err
    assert f"NOKEY | {identity}," in err


def test_endorsed_email_current_key_passes(reg: Registry) -> None:
    msg = signed_by(reg, "alice", "alice@example.org")
    sel = selector(Path(f"{reg.key('alice')}.pub"))
    assert_passes(validate(FORK, reg.tmp, msg), "alice@example.org", sel)


def test_automation_key_with_endorsed_email_passes(reg: Registry) -> None:
    """DESIGN.md: automation identities sign patches when their email is endorsed."""
    msg = signed_by(reg, "bot", "bot@example.org")
    sel = selector(Path(f"{reg.key('bot')}.pub"))
    assert_passes(validate(FORK, reg.tmp, msg), "bot@example.org", sel)


def test_revoked_key_fails(reg: Registry) -> None:
    """A patch that passed stops verifying once the key is revoked and synced."""
    msg = signed_by(reg, "alice", "alice@example.org")
    assert validate(FORK, reg.tmp, msg).returncode == RES_VALID
    pub = f"{reg.key('alice')}.pub"
    reg.vouch("revoke", "--sign-with", str(reg.key("anchor")), pub)
    reg.sync()
    assert_nokey(validate(FORK, reg.tmp, msg), "alice@example.org")


def test_retired_key_fails(reg: Registry) -> None:
    """Only current keys verify (DESIGN.md, Patch signing: Which keys).

    alice-old signs no registry record, so its retirement in the same
    second as the fixture's records cannot void them.
    """
    alice = str(reg.key("alice"))
    old_pub = f"{reg.key('alice-old')}.pub"
    reg.vouch("add-key", "--sign-with", alice, old_pub)
    reg.sync()
    msg = signed_by(reg, "alice-old", "alice@example.org")
    assert_passes(
        validate(FORK, reg.tmp, msg), "alice@example.org", selector(Path(old_pub))
    )
    reg.vouch("retire-key", "--sign-with", alice, old_pub)
    reg.sync()
    # A key is valid through its retirement second (vouch-ey47.24).
    time.sleep(1)
    assert_nokey(validate(FORK, reg.tmp, msg), "alice@example.org")


def test_unendorsed_person_fails(reg: Registry) -> None:
    msg = signed_by(reg, "carol", "carol@example.org")
    assert_nokey(validate(FORK, reg.tmp, msg), "carol@example.org")


def test_unendorsed_email_of_endorsed_person_fails(reg: Registry) -> None:
    ok = signed_by(reg, "dave", "dave@example.org")
    assert validate(FORK, reg.tmp, ok).returncode == RES_VALID
    msg = signed_by(reg, "dave", "dave@private.example")
    assert_nokey(validate(FORK, reg.tmp, msg), "dave@private.example")


def test_endorsed_key_signing_as_another_endorsed_person_fails(reg: Registry) -> None:
    ok = signed_by(reg, "anchor", "anchor@example.org")
    assert validate(FORK, reg.tmp, ok).returncode == RES_VALID
    msg = signed_by(reg, "alice", "anchor@example.org")
    assert_nokey(validate(FORK, reg.tmp, msg), "anchor@example.org")


def test_key_not_in_registry_fails(reg: Registry) -> None:
    msg = signed_by(reg, "stranger", "alice@example.org")
    assert_nokey(validate(FORK, reg.tmp, msg), "alice@example.org")


def test_key_not_in_registry_under_registry_selector_is_badsig(reg: Registry) -> None:
    sel = selector(Path(f"{reg.key('alice')}.pub"))
    msg = sign(FORK, reg.tmp, reg.key("stranger"), "alice@example.org", sel)
    proc = validate(FORK, reg.tmp, msg)
    assert proc.returncode == RES_BADSIG, proc.stderr.decode(errors="replace")
    assert b"BADSIG | alice@example.org," in proc.stderr


def test_stock_signed_patch_verifies_in_fork(reg: Registry) -> None:
    msg = signed_by(reg, "alice", "alice@example.org", tree=STOCK)
    sel = selector(Path(f"{reg.key('alice')}.pub"))
    assert_passes(validate(FORK, reg.tmp, msg), "alice@example.org", sel)


def test_fork_signed_patch_verifies_in_stock(reg: Registry) -> None:
    """Stock patatt reads a keyring directory laid out as DESIGN.md describes."""
    pub = Path(f"{reg.key('alice')}.pub")
    sel = selector(pub)
    keyring = reg.tmp / "keyring"
    keyfile = keyring / "openssh" / "example.org" / "alice" / sel
    keyfile.parent.mkdir(parents=True)
    keyfile.write_text(pub.read_text())
    msg = signed_by(reg, "alice", "alice@example.org")
    proc = validate(STOCK, reg.tmp, msg, keyringsrc=str(keyring))
    assert proc.returncode == RES_VALID, proc.stderr.decode(errors="replace")
    assert f"key: {keyring}/openssh/example.org/alice/{sel}".encode() in proc.stderr


def test_stock_patatt_does_not_read_the_registry(reg: Registry) -> None:
    """The passes above come from the fork's vouch: source, not from stock patatt."""
    msg = signed_by(reg, "alice", "alice@example.org")
    assert_nokey(validate(STOCK, reg.tmp, msg), "alice@example.org")

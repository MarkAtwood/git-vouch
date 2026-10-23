"""Tests for ``git-vouch-migrate verify-continuity``: GPG continuity proofs against pgpkeys at C."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, Optional

import pytest

from .conftest import Pgpkeys, run_migrate

AFTER_C = "20250101T000000"  # when holders sign their new person files


def write_person(
    registry: Path,
    handle: str,
    fpr: Optional[str],
    emails: Sequence[str],
    keys: Sequence[str],
    retired: Sequence[str] = (),
) -> Path:
    """Write people/<handle>.json claiming GPG key ``fpr`` (none if None); return its path.

    Keys in ``retired`` are listed after ``keys``, retired in 2025.
    """
    obj: dict[str, Any] = {
        "@context": ["https://w3id.org/git-vouch/v1"],
        "handle": handle,
        "name": handle.title(),
        "emails": list(emails),
        "keys": [
            {"ssh": k, "added": "2024-01-01T00:00:00Z", "retired": None} for k in keys
        ]
        + [
            {
                "ssh": k,
                "added": "2024-01-01T00:00:00Z",
                "retired": "2025-01-01T00:00:00Z",
            }
            for k in retired
        ],  # fmt: skip
    }
    if fpr is not None:
        obj["migratedFrom"] = "openpgp4fpr:" + fpr
    path = registry / "people" / f"{handle}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n")
    return path


def ssh_sign(path: Path, key_file: Path, env: Optional[dict[str, str]] = None) -> None:
    """Write ``path``.sig with ssh-keygen, from a private key file or the agent."""
    sig = path.with_name(path.name + ".sig")
    sig.unlink(missing_ok=True)
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key_file), "-n", "git-vouch-register",
         str(path)],
        check=True, capture_output=True, env=env,
    )  # fmt: skip


def ssh_sign_by(
    path: Path,
    signers: Sequence[tuple[Path, Optional[dict[str, str]]]],
    namespace: str = "git-vouch-register",
) -> None:
    """Write ``path``.sig holding one signature block per (key file, env) in ``signers``."""
    sig = path.with_name(path.name + ".sig")
    blocks = b""
    for key_file, env in signers:
        sig.unlink(missing_ok=True)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_file), "-n", namespace,
             str(path)],
            check=True, capture_output=True, env=env,
        )  # fmt: skip
        blocks += sig.read_bytes()
    sig.write_bytes(blocks)


def commit_all(registry: Path, message: str) -> None:
    """Commit the whole registry tree, away from the user's git config."""
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    ident = ["-c", "user.name=T", "-c", "user.email=t@example.org"]
    for args in (
        ["init", "-q"],
        ["add", "-A"],
        [*ident, "commit", "-q", "-m", message],
    ):
        subprocess.run(["git", *args], cwd=registry, env=env, check=True,
                       capture_output=True)  # fmt: skip


def auth_ssh_key(pgp: Pgpkeys, fpr: str, tmp_path: Path) -> tuple[str, Path]:
    """Return gpg's SSH export of ``fpr``'s auth subkey and a .pub file holding it."""
    ssh = " ".join(pgp.gpg("--export-ssh-key", fpr).decode().split()[:2])
    pub = tmp_path / "auth.pub"
    pub.write_text(ssh + "\n")
    return ssh, pub


def gpg_sign(
    pgp: Pgpkeys, path: Path, fpr: str, at: str = AFTER_C, *extra: str
) -> None:
    """Write ``path``.asc, a detached armored signature by GPG key ``fpr``."""
    asc = path.with_name(path.name + ".asc")
    pgp.gpg("--yes", "--armor", "--detach-sign", *extra, "-u", fpr + "!",
            "-o", str(asc), str(path), at=at)  # fmt: skip


def verify(pgp: Pgpkeys, registry: Path, *handles: str) -> Any:
    """Run ``git-vouch-migrate verify-continuity`` on the synthetic pgpkeys."""
    return run_migrate(
        "verify-continuity", "--commit", pgp.commit, "--signer", pgp.fprs["signer"],
        str(pgp.repo), str(registry), *handles,
    )  # fmt: skip


def auth_subkey(pgp: Pgpkeys, fpr: str) -> tuple[str, str]:
    """Return the fingerprint and keygrip of key ``fpr``'s auth subkey, as gpg lists them."""
    out = pgp.gpg("--with-colons", "--with-keygrip", "--list-keys", fpr).decode()
    found: list[str] = []
    in_auth = False
    for line in out.splitlines():
        f = line.split(":")
        if f[0] in ("pub", "sub"):
            in_auth = f[0] == "sub" and "a" in f[11]
        elif in_auth and f[0] in ("fpr", "grp"):
            found.append(f[9])
    fingerprint, grip = found
    return fingerprint, grip


@pytest.fixture(scope="module")
def agent(pgpkeys: Pgpkeys) -> dict[str, str]:
    """Serve alice's GPG auth subkey through gpg-agent's SSH socket; return the env."""
    home = str(pgpkeys.gpg.home)
    _, grip = auth_subkey(pgpkeys, pgpkeys.fprs["alice"])
    (pgpkeys.gpg.home / "sshcontrol").write_text(grip + "\n")
    (pgpkeys.gpg.home / "gpg-agent.conf").write_text("enable-ssh-support\n")
    subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], check=True)
    subprocess.run(
        ["gpg-connect-agent", "--homedir", home, "/bye"],
        check=True,
        capture_output=True,
    )
    sock = subprocess.run(
        ["gpgconf", "--homedir", home, "--list-dirs", "agent-ssh-socket"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()  # fmt: skip
    return dict(os.environ, SSH_AUTH_SOCK=sock)


@pytest.fixture
def registry(tmp_path: Path) -> Path:
    """Return an empty registry directory."""
    path = tmp_path / "registry"
    path.mkdir()
    return path


def test_asc_by_the_gpg_key_passes(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org", "alice@kernel.org"],
        [ed25519_key.pubkey],
    )  # fmt: skip
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok alice: openpgp4fpr:{alice} by .asc" in proc.stdout.splitlines()


def test_asc_by_a_key_not_in_pgpkeys_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    outsider = pgpkeys.gpg.new_key("Oscar Outsider <oscar@example.org>", at=AFTER_C)
    path = write_person(
        registry, "alice", pgpkeys.fprs["alice"], ["alice@example.org"],
        [ed25519_key.pubkey],
    )  # fmt: skip
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, outsider)
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 1
    assert "fail alice: people/alice.json.asc: gpg reports NO_PUBKEY" in proc.stdout


def test_swapped_ssh_key_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any, ecdsa_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    gpg_sign(pgpkeys, path, alice)
    # Someone else swaps in their own key and signs, keeping alice's .asc.
    write_person(registry, "alice", alice, ["alice@example.org"], [ecdsa_key.pubkey])
    ssh_sign(path, ecdsa_key.private)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert "fail alice: people/alice.json.asc: gpg reports BADSIG" in proc.stdout


def test_asc_by_key_expired_at_c_passes(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    eve = pgpkeys.fprs["eve"]  # expired 2019-01-02, before C (D9)
    path = write_person(registry, "eve", eve, ["eve@example.org"], [ed25519_key.pubkey])
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, eve, "20190101T120000")
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok eve: openpgp4fpr:{eve} by .asc" in proc.stdout


def test_asc_by_key_revoked_at_c_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    frank = pgpkeys.fprs["frank"]
    path = write_person(
        registry, "frank", frank, ["frank@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, frank)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert f"fail frank: {frank} is revoked" in proc.stdout


def test_textmode_asc_fails(pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice, AFTER_C, "--textmode")
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert "not a binary signature over the exact bytes" in proc.stdout


def test_auth_subkey_reuse_passes(
    pgpkeys: Pgpkeys, registry: Path, agent: dict[str, str], tmp_path: Path
) -> None:
    alice = pgpkeys.fprs["alice"]
    sub, _ = auth_subkey(pgpkeys, alice)
    ssh = " ".join(pgpkeys.gpg("--export-ssh-key", alice).decode().split()[:2])
    pub = tmp_path / "auth.pub"
    pub.write_text(ssh + "\n")
    path = write_person(registry, "alice", alice, ["alice@kernel.org"], [ssh])
    ssh_sign(path, pub, env=agent)  # signed by the auth subkey, through gpg-agent
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok alice: openpgp4fpr:{alice} by auth subkey {sub}" in proc.stdout


def test_auth_subkey_listed_but_not_signing_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    ssh = " ".join(pgpkeys.gpg("--export-ssh-key", alice).decode().split()[:2])
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ssh, ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)  # anyone can copy a public auth subkey
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert (
        f"fail alice: no people/alice.json.asc, and no signature by an auth subkey "
        f"of {alice}" in proc.stdout
    )


def test_two_key_person_file_signed_by_either_key_passes(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any, ecdsa_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"],
        [ed25519_key.pubkey, ecdsa_key.pubkey],
    )  # fmt: skip
    ssh_sign(path, ecdsa_key.private)  # the backup key stays in the drawer
    gpg_sign(pgpkeys, path, alice)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok alice: openpgp4fpr:{alice} by .asc" in proc.stdout


def test_duplicate_fingerprint_claims_fail_both(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any, ecdsa_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    for handle, email, key in [
        ("alice", "alice@example.org", ed25519_key),
        ("alice2", "alice@kernel.org", ecdsa_key),
    ]:
        path = write_person(registry, handle, alice.lower(), [email], [key.pubkey])
        ssh_sign(path, key.private)
        gpg_sign(pgpkeys, path, alice)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    lines = proc.stdout.splitlines()
    assert f"duplicate {alice}: alice, alice2" in lines
    assert f"fail alice: {alice} is also claimed by alice2" in lines
    assert f"fail alice2: {alice} is also claimed by alice" in lines


def test_email_not_on_an_unrevoked_uid_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@old.example"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert (
        f"fail alice: alice@old.example is not on an unrevoked user ID of {alice}"
        in proc.stdout
    )


def test_unregistered_handle_fails(pgpkeys: Pgpkeys, registry: Path) -> None:
    proc = verify(pgpkeys, registry, "nobody")
    assert proc.returncode == 1
    assert "fail nobody: no validly signed person file" in proc.stdout


def test_asc_by_another_pgpkeys_key_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    alice, bob = pgpkeys.fprs["alice"], pgpkeys.fprs["bob"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, bob)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert (
        f"fail alice: people/alice.json.asc: signed by {bob}, not {alice}"
        in proc.stdout
    )


def test_migrated_from_key_not_in_pgpkeys_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    outsider = pgpkeys.gpg.new_key("Olga Outsider <alice@example.org>", at=AFTER_C)
    path = write_person(
        registry, "alice", outsider, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, outsider)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert f"fail alice: {outsider} is not in pgpkeys at C" in proc.stdout


def test_malformed_migrated_from_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    path = write_person(
        registry, "alice", "XYZ", ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert (
        "fail alice: migratedFrom: must be openpgp4fpr: and a 40-hex fingerprint"
        in proc.stdout
    )


def test_named_handle_without_migrated_from_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    path = write_person(
        registry, "bob", None, ["bob@example.net"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    proc = verify(pgpkeys, registry, "bob")
    assert proc.returncode == 1
    assert "fail bob: no migratedFrom" in proc.stdout


def test_only_named_handles_are_reported(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any, ecdsa_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)
    bob = pgpkeys.fprs["bob"]
    path = write_person(registry, "bob", bob, ["bob@example.net"], [ecdsa_key.pubkey])
    ssh_sign(path, ecdsa_key.private)
    gpg_sign(pgpkeys, path, bob)  # bob's claim is good too, but not asked about
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok alice: openpgp4fpr:{alice} by .asc" in proc.stdout
    assert "bob" not in proc.stdout


def test_auth_subkey_retired_but_signing_fails(
    pgpkeys: Pgpkeys,
    registry: Path,
    agent: dict[str, str],
    ed25519_key: Any,
    tmp_path: Path,
) -> None:
    alice = pgpkeys.fprs["alice"]
    ssh, pub = auth_ssh_key(pgpkeys, alice, tmp_path)
    # v1 lists the auth subkey, but only ed25519_key signs it: no proof yet.
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ssh, ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    commit_all(registry, "v1")
    # v2 retires the auth subkey; git-vouch lets it sign, as current in v1.
    write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey],
        retired=[ssh],
    )  # fmt: skip
    ssh_sign_by(path, [(ed25519_key.private, None), (pub, agent)])
    commit_all(registry, "v2")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 1
    assert (
        f"fail alice: no people/alice.json.asc, and no signature by an auth subkey "
        f"of {alice}" in proc.stdout
    )


def test_auth_subkey_revoked_in_registry_fails(
    pgpkeys: Pgpkeys,
    registry: Path,
    agent: dict[str, str],
    ed25519_key: Any,
    tmp_path: Path,
    migrate: ModuleType,
) -> None:
    alice = pgpkeys.fprs["alice"]
    ssh, pub = auth_ssh_key(pgpkeys, alice, tmp_path)
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ssh, ed25519_key.pubkey]
    )
    ssh_sign_by(path, [(ed25519_key.private, None), (pub, agent)])
    commit_all(registry, "register")
    # Setup only: a wrong did:key leaves the revocation void and the test failing.
    person = migrate.vouch.parse_record("people/alice.json", path.read_bytes())
    (did,) = [k.did for k in person.keys if k.ssh == ssh]
    rev = registry / "revocations" / "alice-1.json"
    rev.parent.mkdir()
    rev.write_text(json.dumps({
        "@context": ["https://w3id.org/git-vouch/v1"], "subject": "alice",
        "key": did, "reason": "compromise", "date": "2025-01-01T00:00:00Z",
    }) + "\n")  # fmt: skip
    ssh_sign_by(rev, [(ed25519_key.private, None)], "git-vouch-revoke")
    commit_all(registry, "revoke")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 1
    assert (
        f"fail alice: no people/alice.json.asc, and no signature by an auth subkey "
        f"of {alice}" in proc.stdout
    )


def test_asc_with_two_signatures_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    alice, bob = pgpkeys.fprs["alice"], pgpkeys.fprs["bob"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    asc = path.with_name(path.name + ".asc")
    gpg_sign(pgpkeys, path, bob)
    second = asc.read_bytes()
    gpg_sign(pgpkeys, path, alice)
    asc.write_bytes(asc.read_bytes() + second)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert "fail alice: people/alice.json.asc: not one good signature" in proc.stdout


def test_asc_by_signing_subkey_revoked_at_c_fails(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    carol = pgpkeys.fprs["carol"]
    path = write_person(
        registry, "carol", carol, ["carol@example.com"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, pgpkeys.revoked_subkey)
    proc = verify(pgpkeys, registry)
    assert proc.returncode == 1
    assert "fail carol: people/carol.json.asc: gpg reports REVKEYSIG" in proc.stdout


def test_auth_subkey_proof_survives_retiring_it(
    pgpkeys: Pgpkeys,
    registry: Path,
    agent: dict[str, str],
    ed25519_key: Any,
    tmp_path: Path,
) -> None:
    alice = pgpkeys.fprs["alice"]
    sub, _ = auth_subkey(pgpkeys, alice)
    ssh, pub = auth_ssh_key(pgpkeys, alice, tmp_path)
    path = write_person(registry, "alice", alice, ["alice@example.org"], [ssh])
    ssh_sign(path, pub, env=agent)  # the proof, made for v1
    commit_all(registry, "v1")
    write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey],
        retired=[ssh],
    )  # fmt: skip
    ssh_sign_by(path, [(ed25519_key.private, None), (pub, agent)])
    commit_all(registry, "v2")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok alice: openpgp4fpr:{alice} by auth subkey {sub}" in proc.stdout


def test_asc_for_an_earlier_version_survives_add_key_and_email_change(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any, ecdsa_key: Any, tmp_path: Path
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)  # the proof, made for v1
    commit_all(registry, "v1")
    # v2 adds a key and an email the GPG key never had; the .asc is now stale.
    write_person(
        registry, "alice", alice, ["alice@example.org", "alice@new.example"],
        [ed25519_key.pubkey, ecdsa_key.pubkey],
    )  # fmt: skip
    ssh_sign(path, ed25519_key.private)
    commit_all(registry, "v2")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok alice: openpgp4fpr:{alice} by .asc" in proc.stdout
    # The same files without their history do not prove it.
    bare = tmp_path / "bare"
    shutil.copytree(registry, bare, ignore=shutil.ignore_patterns(".git"))
    proc = verify(pgpkeys, bare, "alice")
    assert proc.returncode == 1
    assert "alice@new.example is not on an unrevoked user ID" in proc.stdout


def test_earlier_version_claiming_another_key_does_not_count(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    alice, bob = pgpkeys.fprs["alice"], pgpkeys.fprs["bob"]
    path = write_person(
        registry, "alice", bob, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)  # alice's .asc over a version claiming bob's key
    commit_all(registry, "v1")
    write_person(registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey])
    ssh_sign(path, ed25519_key.private)
    commit_all(registry, "v2")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 1
    assert "fail alice: people/alice.json.asc: gpg reports BADSIG" in proc.stdout


def test_earlier_version_with_an_email_off_the_key_does_not_count(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@old.example"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)  # alice@old.example is a revoked user ID
    commit_all(registry, "v1")
    write_person(registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey])
    ssh_sign(path, ed25519_key.private)
    commit_all(registry, "v2")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 1
    assert "fail alice: people/alice.json.asc: gpg reports BADSIG" in proc.stdout


def test_email_shared_with_a_differently_named_key_passes(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any
) -> None:
    # mallory's key also holds victor@example.com, under a different primary
    # name; port drafts neither, but victor can still prove continuity.
    victor = pgpkeys.fprs["victor"]
    path = write_person(
        registry, "victor", victor, ["victor@example.com"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, victor)
    proc = verify(pgpkeys, registry, "victor")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"ok victor: openpgp4fpr:{victor} by .asc" in proc.stdout


def test_earlier_proof_does_not_survive_an_unsigned_key_replacement(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any, ecdsa_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)  # the proof, made for v1
    commit_all(registry, "v1")
    # v2 swaps in a key no v1 key signed for: only review lets it through.
    write_person(registry, "alice", alice, ["alice@example.org"], [ecdsa_key.pubkey])
    ssh_sign(path, ecdsa_key.private)
    commit_all(registry, "v2")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 1
    assert "fail alice: people/alice.json.asc: gpg reports BADSIG" in proc.stdout


def test_earlier_proof_does_not_survive_re_registration(
    pgpkeys: Pgpkeys, registry: Path, ed25519_key: Any, ecdsa_key: Any
) -> None:
    alice = pgpkeys.fprs["alice"]
    path = write_person(
        registry, "alice", alice, ["alice@example.org"], [ed25519_key.pubkey]
    )
    ssh_sign(path, ed25519_key.private)
    gpg_sign(pgpkeys, path, alice)  # the proof, made for v1
    commit_all(registry, "v1")
    for f in path.parent.glob("alice.json*"):
        f.unlink()
    commit_all(registry, "delete")
    # Someone else registers the handle again, claiming the same GPG key.
    write_person(registry, "alice", alice, ["alice@example.org"], [ecdsa_key.pubkey])
    ssh_sign(path, ecdsa_key.private)
    commit_all(registry, "v2")
    proc = verify(pgpkeys, registry, "alice")
    assert proc.returncode == 1
    assert "fail alice: no people/alice.json.asc" in proc.stdout

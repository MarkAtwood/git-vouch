"""Signing commands: register, add-key, retire-key, endorse, approve, revoke.

Each command runs as a subprocess in a fixture registry. Its output is
checked by real ``ssh-keygen -Y verify`` in the namespace DESIGN.md gives
each kind of record, by did:keys derived independently (test_check.did),
and by ``git vouch check``, as the acceptance criteria ask.

tests/fixtures/sk-ed25519.* were written once by the real ssh-keygen
(OpenSSH 9.6p1) with OpenSSH's software security key, regress/misc/sk-dummy:
``SSH_SK_PROVIDER=sk-dummy.so ssh-keygen -t ed25519-sk -O challenge=<file>
-O write-attestation=<file>``. sk-dummy writes a degenerate attestation:
its certificate, signature and authenticator data are all empty. It is
valid only as an opaque blob for the base64 round trip, not as a vector
for verifying attestations.
"""

from __future__ import annotations

import base64
import json
import os
import pty
import select
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from conftest import SCRIPT, Key, make_key
from test_check import did

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SK_PUB = FIXTURES / "sk-ed25519.pub"
SK_ATTEST = FIXTURES / "sk-ed25519.attest"
SK_CHALLENGE = FIXTURES / "sk-ed25519.challenge"
CONTEXT = "https://w3id.org/git-vouch/v1"


def vouch(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git-vouch in ``cwd`` with no stdin; a prompt would fail the timeout."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )


def ok(cwd: Path, *args: str) -> str:
    """Run git-vouch and return its stdout, failing the test on a non-zero exit."""
    result = vouch(cwd, *args)
    assert result.returncode == 0, result.stderr
    return result.stdout


def git(cwd: Path, *args: str) -> None:
    """Run git in ``cwd``, failing the test on a non-zero exit."""
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.org", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def commit(cwd: Path) -> None:
    """Commit everything in the registry."""
    git(cwd, "add", "-A")
    git(cwd, "commit", "-q", "-m", "change")


def verify(path: Path, key: Key, namespace: str) -> None:
    """Check with ssh-keygen alone that ``path``.sig is ``key``'s signature in ``namespace``."""
    allowed = path.parent / "allowed-for-test"
    allowed.write_text(f"signer {key.pubkey}\n")
    try:
        subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "signer"]
            + ["-n", namespace, "-s", f"{path}.sig"],
            input=path.read_bytes(),
            check=True,
            capture_output=True,
        )
    finally:
        allowed.unlink()


def base64_w0(path: Path) -> str:
    """Return coreutils ``base64 -w0`` of ``path``."""
    out = subprocess.run(
        ["base64", "-w0", str(path)], check=True, capture_output=True, text=True
    )
    return out.stdout


def load(path: Path) -> dict[str, object]:
    """Return the JSON object in ``path``."""
    obj = json.loads(path.read_text())
    assert isinstance(obj, dict)
    return obj


def check(reg: Path) -> subprocess.CompletedProcess[str]:
    """Run 'git vouch check' on ``reg``."""
    return vouch(reg, "check", ".")


def tiers(reg: Path) -> dict[str, str]:
    """Return the tiers 'git vouch check' prints, failing the test if it fails."""
    result = check(reg)
    assert result.returncode == 0, result.stderr
    return dict(line.split() for line in result.stdout.splitlines())


@pytest.fixture
def keys(tmp_path: Path) -> dict[str, Key]:
    """Throwaway ed25519 keys for each person in the fixture registry."""
    directory = tmp_path / "keys"
    directory.mkdir()
    names = ["torvalds", "gregkh", "alice", "alice2", "mallory"]
    return {n: make_key(directory, n, ["-t", "ed25519"]) for n in names}


@pytest.fixture
def reg(tmp_path: Path) -> Path:
    """An empty registry git repository whose anchor is torvalds."""
    root = tmp_path / "registry"
    root.mkdir()
    git(root, "init", "-q")
    (root / "anchors.json").write_text('["torvalds"]\n')
    return root


def register(reg: Path, handle: str, key: Key) -> None:
    """Register ``handle`` with ``key``, signing with its private key file."""
    ok(
        reg,
        "register",
        str(key.public),
        "--handle",
        handle,
        "--name",
        handle.title(),
        "--email",
        f"{handle}@example.org",
        "--sign-with",
        str(key.private),
    )


@pytest.fixture
def tree(reg: Path, keys: dict[str, Key]) -> Path:
    """A committed registry: anchor torvalds, maintainer gregkh, contributor alice,
    all made by the signing commands; every email is endorsed."""
    for handle in ("torvalds", "gregkh", "alice"):
        register(reg, handle, keys[handle])
    commit(reg)
    ok(
        reg,
        "approve",
        "gregkh",
        "maintainer",
        "--sign-with",
        str(keys["torvalds"].private),
    )
    ok(
        reg,
        "approve",
        "alice",
        "contributor",
        "--sign-with",
        str(keys["gregkh"].private),
    )
    for subject, endorser in [("torvalds", "gregkh"), ("gregkh", "torvalds")]:
        ok(reg, "endorse", subject, "--sign-with", str(keys[endorser].private))
    ok(
        reg,
        "endorse",
        "alice",
        "--note",
        "met at LPC",
        "--sign-with",
        str(keys["gregkh"].private),
    )
    commit(reg)
    return reg


def test_register_writes_a_signed_person_file(reg: Path, any_key: Key) -> None:
    out = ok(
        reg,
        "register",
        str(any_key.public),
        "--handle",
        "torvalds",
        "--name",
        "Linus Torvalds",
        "--email",
        "torvalds@example.org",
        "--email",
        "linus@example.org",
        "--sign-with",
        str(any_key.private),
    )
    person = reg / "people/torvalds.json"
    assert out.split() == ["people/torvalds.json", "people/torvalds.json.sig"]
    verify(person, any_key, "git-vouch-register")
    obj = load(person)
    assert obj["@context"] == [CONTEXT]
    assert obj["handle"] == "torvalds"
    assert obj["name"] == "Linus Torvalds"
    assert obj["emails"] == ["torvalds@example.org", "linus@example.org"]
    [entry] = obj["keys"]  # type: ignore[misc]
    assert entry["ssh"] == " ".join(any_key.pubkey.split()[:2])
    assert entry["retired"] is None
    result = check(reg)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "torvalds anchor\n"


def test_records_pass_check_with_the_right_signatures(
    tree: Path, keys: dict[str, Key]
) -> None:
    assert tiers(tree) == {
        "torvalds": "anchor",
        "gregkh": "maintainer",
        "alice": "contributor",
    }
    assert "warning" not in check(tree).stderr
    tier = tree / "tiers/gregkh.json"
    verify(tier, keys["torvalds"], "git-vouch-tier")
    obj = load(tier)
    assert (obj["subject"], obj["tier"], obj["approver"]) == (
        "gregkh",
        "maintainer",
        "torvalds",
    )
    assert obj["approverKey"] == did(keys["torvalds"])
    endorsement = tree / "endorsements/alice/gregkh-1.json"
    verify(endorsement, keys["gregkh"], "git-vouch-endorse")
    obj = load(endorsement)
    assert obj["endorserKey"] == did(keys["gregkh"])
    assert obj["subjectKey"] == did(keys["alice"])
    assert obj["subjectName"] == "Alice"
    assert obj["subjectEmails"] == ["alice@example.org"]
    assert obj["note"] == "met at LPC"


def test_endorse_numbers_each_endorsement(tree: Path, keys: dict[str, Key]) -> None:
    out = ok(tree, "endorse", "alice", "--sign-with", str(keys["gregkh"].private))
    assert out.split()[0] == "endorsements/alice/gregkh-2.json"
    assert check(tree).returncode == 0


def test_endorse_email_restricts_and_must_be_listed(
    tree: Path, keys: dict[str, Key]
) -> None:
    sign = ["--sign-with", str(keys["torvalds"].private)]
    ok(tree, "endorse", "alice", "--email", "ALICE@example.org", *sign)
    obj = load(tree / "endorsements/alice/torvalds-1.json")
    assert obj["subjectEmails"] == ["ALICE@example.org"]
    result = vouch(tree, "endorse", "alice", "--email", "eve@example.org", *sign)
    assert result.returncode == 1
    assert "does not list eve@example.org" in result.stderr
    assert not (tree / "endorsements/alice/torvalds-2.json").exists()


def test_cannot_endorse_or_approve_yourself(tree: Path, keys: dict[str, Key]) -> None:
    sign = ["--sign-with", str(keys["alice"].private)]
    assert vouch(tree, "endorse", "alice", *sign).returncode == 1
    assert vouch(tree, "approve", "alice", "maintainer", *sign).returncode == 1
    assert not (tree / "endorsements/alice/alice-1.json").exists()


def test_unregistered_signer_is_refused(tree: Path, keys: dict[str, Key]) -> None:
    result = vouch(
        tree, "endorse", "alice", "--sign-with", str(keys["mallory"].private)
    )
    assert result.returncode == 1
    assert "no person file" in result.stderr


def endorsement_draft(
    tmp_path: Path, endorser: str, endorser_key: Key, alice: Key
) -> Path:
    """Write an unsigned endorsement of alice shaped like a git-vouch-migrate draft,
    dated now as drafts are: after every key in the fixture registry was added."""
    path = tmp_path / "drafts" / "alice.json"
    path.parent.mkdir(exist_ok=True)
    obj = {
        "@context": [CONTEXT],
        "endorser": endorser,
        "endorserKey": did(endorser_key),
        "subject": "alice",
        "subjectKey": did(alice),
        "subjectName": "Alice",
        "subjectEmails": ["alice@example.org"],
        "note": "Certified GPG key 0123 on 2020-01-02.",
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path.write_text(json.dumps(obj, indent=2) + "\n")
    return path


def test_endorse_from_a_draft_signs_it_with_the_matching_key(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    path = endorsement_draft(tmp_path, "torvalds", keys["torvalds"], keys["alice"])
    before = path.read_bytes()
    sign = ["--sign-with", str(keys["torvalds"].private)]
    out = ok(tree, "endorse", "--from", str(path), *sign)
    rel = tree / "endorsements/alice/torvalds-1.json"
    assert out.split() == [
        "endorsements/alice/torvalds-1.json",
        "endorsements/alice/torvalds-1.json.sig",
    ]
    verify(rel, keys["torvalds"], "git-vouch-endorse")
    assert rel.read_bytes() == before
    assert path.read_bytes() == before
    assert check(tree).returncode == 0


@pytest.mark.parametrize(
    "endorser, key, signer, refusal",
    [
        ("torvalds", "gregkh", "torvalds", "endorserKey is not"),
        ("gregkh", "torvalds", "torvalds", "endorser is not torvalds"),
        ("alice", "alice", "alice", "nobody can endorse themselves"),
    ],
)
def test_endorse_from_a_draft_for_another_signer_is_refused(
    tree: Path,
    keys: dict[str, Key],
    tmp_path: Path,
    endorser: str,
    key: str,
    signer: str,
    refusal: str,
) -> None:
    path = endorsement_draft(tmp_path, endorser, keys[key], keys["alice"])
    sign = ["--sign-with", str(keys[signer].private)]
    result = vouch(tree, "endorse", "--from", str(path), *sign)
    assert result.returncode == 1
    assert refusal in result.stderr
    assert not list((tree / "endorsements/alice").glob(f"{signer}-*"))


@pytest.mark.parametrize(
    "spoil",
    [
        lambda o: o.pop("subjectKey"),
        lambda o: o.update(date="2026-11-03"),
        lambda o: o.update(subjectEmails="alice@example.org"),
    ],
    ids=["no-subjectKey", "date-without-time", "emails-not-a-list"],
)
def test_endorse_from_a_schema_invalid_draft_is_refused(
    tree: Path,
    keys: dict[str, Key],
    tmp_path: Path,
    spoil: Callable[[dict[str, object]], object],
) -> None:
    """The right endorser and key do not excuse a draft that breaks the
    DESIGN.md endorsement schema: every term but note, an RFC 3339 date."""
    path = endorsement_draft(tmp_path, "torvalds", keys["torvalds"], keys["alice"])
    obj = json.loads(path.read_text())
    spoil(obj)
    path.write_text(json.dumps(obj, indent=2) + "\n")
    sign = ["--sign-with", str(keys["torvalds"].private)]
    result = vouch(tree, "endorse", "--from", str(path), *sign)
    assert result.returncode == 1
    assert "endorsements/alice/torvalds-1.json" in result.stderr
    assert not list((tree / "endorsements/alice").glob("torvalds-*"))


def test_endorse_from_a_draft_that_is_not_an_object_is_refused(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    path = endorsement_draft(tmp_path, "torvalds", keys["torvalds"], keys["alice"])
    path.write_text(json.dumps([json.loads(path.read_text())]) + "\n")
    sign = ["--sign-with", str(keys["torvalds"].private)]
    result = vouch(tree, "endorse", "--from", str(path), *sign)
    assert result.returncode == 1
    assert "not an endorsement draft" in result.stderr
    assert not list((tree / "endorsements/alice").glob("torvalds-*"))


def test_endorse_from_a_draft_refuses_overrides(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    path = endorsement_draft(tmp_path, "torvalds", keys["torvalds"], keys["alice"])
    sign = ["--sign-with", str(keys["torvalds"].private)]
    for extra in (["alice"], ["--note", "x"], ["--email", "alice@example.org"]):
        result = vouch(tree, "endorse", "--from", str(path), *extra, *sign)
        assert result.returncode == 1
        assert "come from the draft" in result.stderr
    assert vouch(tree, "endorse", *sign).returncode == 1
    assert not (tree / "endorsements/alice/torvalds-1.json").exists()


def test_check_help_says_to_pass_a_dot_for_a_checkout() -> None:
    result = vouch(Path("."), "check", "--help")
    assert result.returncode == 0
    assert "pass . to check a checkout" in " ".join(result.stdout.split())


def test_add_key_then_retire_key_chain(tree: Path, keys: dict[str, Key]) -> None:
    ok(
        tree,
        "add-key",
        str(keys["alice2"].public),
        "--sign-with",
        str(keys["alice"].private),
    )
    person = tree / "people/alice.json"
    verify(person, keys["alice"], "git-vouch-register")
    entries = load(person)["keys"]
    assert (
        [e["ssh"] for e in entries]
        == [  # type: ignore[union-attr,index]
            " ".join(keys[k].pubkey.split()[:2]) for k in ("alice", "alice2")
        ]
    )
    assert tiers(tree)["alice"] == "contributor"
    assert "WARNING" not in check(tree).stderr
    commit(tree)
    ok(
        tree,
        "retire-key",
        str(keys["alice"].public),
        "--sign-with",
        str(keys["alice2"].private),
    )
    verify(person, keys["alice2"], "git-vouch-register")
    first, second = load(person)["keys"]  # type: ignore[misc]
    assert first["retired"] is not None and second["retired"] is None
    assert tiers(tree)["alice"] == "contributor"
    assert "WARNING" not in check(tree).stderr


def test_retire_key_takes_a_did(tree: Path, keys: dict[str, Key]) -> None:
    ok(
        tree,
        "add-key",
        str(keys["alice2"].public),
        "--sign-with",
        str(keys["alice"].private),
    )
    commit(tree)
    ok(
        tree,
        "retire-key",
        did(keys["alice2"]),
        "--sign-with",
        str(keys["alice"].private),
    )
    assert load(tree / "people/alice.json")["keys"][1]["retired"]  # type: ignore[index]
    again = vouch(
        tree,
        "retire-key",
        did(keys["alice2"]),
        "--sign-with",
        str(keys["alice"].private),
    )
    assert again.returncode == 1
    assert "already retired" in again.stderr


def test_add_key_signed_by_a_key_not_in_the_file_is_refused(
    tree: Path, keys: dict[str, Key]
) -> None:
    person = tree / "people/alice.json"
    before = person.read_bytes()
    result = vouch(
        tree,
        "add-key",
        str(keys["alice2"].public),
        "--sign-with",
        str(keys["mallory"].private),
    )
    assert result.returncode == 1
    assert person.read_bytes() == before


def resign(path: Path, key: Key) -> None:
    """Replace ``path``.sig with ``key``'s signature, made by ssh-keygen directly."""
    Path(f"{path}.sig").unlink()
    subprocess.run(
        ["ssh-keygen", "-q", "-Y", "sign", "-f", str(key.private)]
        + ["-n", "git-vouch-register", str(path)],
        check=True,
        capture_output=True,
    )


def test_add_key_without_an_existing_keys_signature(
    tree: Path, keys: dict[str, Key]
) -> None:
    ok(
        tree,
        "add-key",
        str(keys["alice2"].public),
        "--sign-with",
        str(keys["alice"].private),
    )
    person = tree / "people/alice.json"
    # Signed by a key in neither version: check fails.
    resign(person, keys["mallory"])
    result = check(tree)
    assert result.returncode == 1
    assert "people/alice.json.sig" in result.stderr
    # Signed only by the key being added: DESIGN.md lets review decide, with a WARNING.
    resign(person, keys["alice2"])
    result = check(tree)
    assert result.returncode == 0, result.stderr
    assert "people/alice.json: WARNING" in result.stderr


def test_revoke_by_the_key_itself_and_by_an_anchor(
    tree: Path, keys: dict[str, Key]
) -> None:
    ok(
        tree,
        "add-key",
        str(keys["alice2"].public),
        "--sign-with",
        str(keys["alice"].private),
    )
    commit(tree)
    out = ok(
        tree,
        "revoke",
        str(keys["alice2"].public),
        "--sign-with",
        str(keys["alice2"].private),
    )
    rel = out.split()[0]
    assert rel == "revocations/alice-1.json"
    verify(tree / rel, keys["alice2"], "git-vouch-revoke")
    obj = load(tree / rel)
    assert (obj["subject"], obj["key"], obj["reason"]) == (
        "alice",
        did(keys["alice2"]),
        "compromise",
    )
    ok(
        tree,
        "revoke",
        did(keys["alice"]),
        "--reason",
        "lost",
        "--sign-with",
        str(keys["torvalds"].private),
    )
    assert load(tree / "revocations/alice-2.json")["reason"] == "lost"
    result = check(tree)
    assert result.returncode == 0, result.stderr
    signers = tree / "allowed_signers"
    revoked = tree / "revoked"
    ok(
        tree,
        "export",
        ".",
        "--allowed-signers",
        str(signers),
        "--revocation-file",
        str(revoked),
    )
    assert sorted(revoked.read_text().splitlines()) == sorted(
        " ".join(keys[k].pubkey.split()[:2]) for k in ("alice", "alice2")
    )


def test_revoke_unknown_key_is_refused(tree: Path, keys: dict[str, Key]) -> None:
    result = vouch(
        tree,
        "revoke",
        str(keys["mallory"].public),
        "--sign-with",
        str(keys["torvalds"].private),
    )
    assert result.returncode == 1
    assert not (tree / "revocations").exists()


def draft(directory: Path, handle: str, key_entries: list[dict[str, object]]) -> Path:
    """Write a draft person file as git-vouch-migrate port does: unsigned, with migratedFrom."""
    path = directory / f"{handle}-draft.json"
    obj = {
        "@context": [CONTEXT],
        "handle": handle,
        "name": "Alice Example",
        "emails": ["alice@example.org"],
        "keys": key_entries,
        "migratedFrom": "openpgp4fpr:" + "AB" * 20,
        "foaf:homepage": "https://alice.example.org/",
    }
    path.write_text(json.dumps(obj, indent=2) + "\n")
    return path


def test_register_from_a_draft_keeps_migrated_from(
    reg: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    path = draft(tmp_path, "alice", [])
    ok(reg, "register", "--from", str(path), str(keys["alice"].public))
    person = reg / "people/alice.json"
    verify(person, keys["alice"], "git-vouch-register")
    obj = load(person)
    assert obj["migratedFrom"] == "openpgp4fpr:" + "AB" * 20
    assert obj["foaf:homepage"] == "https://alice.example.org/"
    assert obj["name"] == "Alice Example"
    assert (
        [e["ssh"] for e in obj["keys"]]
        == [  # type: ignore[union-attr,index]
            " ".join(keys["alice"].pubkey.split()[:2])
        ]
    )
    register(reg, "torvalds", keys["torvalds"])
    assert tiers(reg) == {"alice": "none", "torvalds": "anchor"}


def test_register_from_draft_refuses_overrides_and_existing_files(
    reg: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    path = draft(tmp_path, "alice", [])
    sign = [str(keys["alice"].public)]
    assert (
        vouch(reg, "register", "--from", str(path), "--name", "X", *sign).returncode
        == 1
    )
    ok(reg, "register", "--from", str(path), *sign)
    result = vouch(reg, "register", "--from", str(path), *sign)
    assert result.returncode == 1
    assert "already exists" in result.stderr


def test_register_attestation_is_base64_of_the_files(
    reg: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    # The draft already holds an ed25519 key (as for a reused GPG auth
    # subkey), which signs; the FIDO key is added with its attestation.
    alice = keys["alice"]
    entry = {"ssh": alice.pubkey, "added": "2026-01-01T00:00:00Z", "retired": None}
    path = draft(tmp_path, "alice", [entry])
    ok(
        reg,
        "register",
        "--from",
        str(path),
        str(SK_PUB),
        "--attestation",
        str(SK_ATTEST),
        "--challenge",
        str(SK_CHALLENGE),
        "--sign-with",
        str(alice.private),
    )
    person = reg / "people/alice.json"
    verify(person, alice, "git-vouch-register")
    sk = load(person)["keys"][1]  # type: ignore[index]
    assert sk["ssh"] == " ".join(SK_PUB.read_text().split()[:2])
    assert sk["attestation"] == {
        "blob": base64_w0(SK_ATTEST),
        "challenge": base64_w0(SK_CHALLENGE),
    }
    register(reg, "torvalds", keys["torvalds"])
    assert check(reg).returncode == 0


def test_add_key_attestation_is_base64_of_the_files(
    tree: Path, keys: dict[str, Key]
) -> None:
    ok(
        tree,
        "add-key",
        str(SK_PUB),
        "--attestation",
        str(SK_ATTEST),
        "--challenge",
        str(SK_CHALLENGE),
        "--sign-with",
        str(keys["alice"].private),
    )
    sk = load(tree / "people/alice.json")["keys"][1]  # type: ignore[index]
    assert sk["attestation"] == {
        "blob": base64_w0(SK_ATTEST),
        "challenge": base64_w0(SK_CHALLENGE),
    }
    assert tiers(tree)["alice"] == "contributor"


def test_attestation_needs_its_challenge(tree: Path, keys: dict[str, Key]) -> None:
    result = vouch(
        tree,
        "add-key",
        str(SK_PUB),
        "--attestation",
        str(SK_ATTEST),
        "--sign-with",
        str(keys["alice"].private),
    )
    assert result.returncode == 1
    assert "go together" in result.stderr


@pytest.fixture
def locked(tmp_path: Path) -> Path:
    """A private key file that needs the passphrase 'secret'."""
    key = tmp_path / "locked"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "secret", "-f", str(key)],
        check=True,
    )
    return key


def test_never_prompts_for_a_passphrase(
    reg: Path, locked: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With a display and no tty, ssh-keygen would run SSH_ASKPASS (a GUI
    # prompt on a desktop) unless told not to.
    marker = tmp_path / "askpass-ran"
    askpass = tmp_path / "askpass"
    askpass.write_text(f"#!/bin/sh\ntouch '{marker}'\necho wrong\n")
    askpass.chmod(0o755)
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setenv("SSH_ASKPASS", str(askpass))
    monkeypatch.delenv("SSH_ASKPASS_REQUIRE", raising=False)
    key = locked
    result = vouch(
        reg,
        "register",
        f"{key}.pub",
        "--handle",
        "alice",
        "--name",
        "Alice",
        "--email",
        "alice@example.org",
        "--sign-with",
        str(key),
    )
    assert result.returncode == 1
    assert "could not sign" in result.stderr
    assert not (reg / "people").exists()
    assert not marker.exists()


def run_in_pty(cwd: Path, *args: str) -> tuple[int, str]:
    """Run git-vouch in ``cwd`` with a pty as its controlling terminal.

    Return its exit code, or -9 if it was killed after 30 seconds of
    waiting (as at a passphrase prompt), and what it wrote to the pty.
    """
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(cwd)
            os.execv(sys.executable, [sys.executable, str(SCRIPT), *args])
        finally:
            os._exit(127)
    out = b""
    deadline = time.monotonic() + 30
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], deadline - time.monotonic())
            if not ready:
                os.kill(pid, signal.SIGKILL)
                break
            try:
                chunk = os.read(fd, 4096)
            except OSError:  # EIO once the child has exited
                break
            if not chunk:
                break
            out += chunk
    finally:
        _, status = os.waitpid(pid, 0)
        os.close(fd)
    return os.waitstatus_to_exitcode(status), out.decode(errors="replace")


def test_never_prompts_on_the_terminal(reg: Path, locked: Path) -> None:
    code, out = run_in_pty(
        reg,
        "register",
        f"{locked}.pub",
        "--handle",
        "alice",
        "--name",
        "Alice",
        "--email",
        "alice@example.org",
        "--sign-with",
        str(locked),
    )
    assert code == 1, out
    assert "could not sign" in out
    assert not (reg / "people").exists()


def test_writes_over_a_symlink_not_through_it(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    victim = tmp_path / "victim"
    victim.write_text("VICTIM ORIGINAL\n")
    sig = tree / "tiers/alice.json.sig"
    sig.unlink()
    sig.symlink_to(victim)
    ok(
        tree,
        "approve",
        "alice",
        "contributor",
        "--sign-with",
        str(keys["gregkh"].private),
    )
    assert victim.read_text() == "VICTIM ORIGINAL\n"
    assert not sig.is_symlink()
    verify(tree / "tiers/alice.json", keys["gregkh"], "git-vouch-tier")


def test_never_writes_below_a_symlinked_directory(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    for path in (tree / "tiers").iterdir():
        path.unlink()
    (tree / "tiers").rmdir()
    (tree / "tiers").symlink_to(outside)
    result = vouch(
        tree,
        "approve",
        "alice",
        "contributor",
        "--sign-with",
        str(keys["gregkh"].private),
    )
    assert result.returncode == 1
    assert "cannot write tiers/alice.json" in result.stderr
    assert list(outside.iterdir()) == []


def test_no_signing_key_is_an_error(tree: Path) -> None:
    result = vouch(tree, "endorse", "alice")
    assert result.returncode == 1
    assert "user.signingKey" in result.stderr


@pytest.fixture
def agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Run a real ssh-agent for the test, exported through SSH_AUTH_SOCK."""
    sock = tmp_path / "agent.sock"
    proc = subprocess.Popen(
        ["ssh-agent", "-D", "-a", str(sock)], stdout=subprocess.DEVNULL
    )
    try:
        for _ in range(100):
            if sock.exists():
                break
            subprocess.run(["sleep", "0.05"], check=True)
        monkeypatch.setenv("SSH_AUTH_SOCK", str(sock))
        yield
    finally:
        proc.terminate()
        proc.wait()


def test_signs_through_the_agent(
    agent: None, reg: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    # Only public keys stay on disk, so ssh-keygen must use the agent.
    alice, gregkh = keys["alice"], keys["gregkh"]
    for key in (alice, gregkh):
        subprocess.run(
            ["ssh-add", "-q", str(key.private)], check=True, capture_output=True
        )
        key.private.unlink()
    path = draft(tmp_path, "alice", [])
    ok(reg, "register", "--from", str(path), str(alice.public))
    verify(reg / "people/alice.json", alice, "git-vouch-register")
    ok(
        reg,
        "register",
        str(gregkh.public),
        "--handle",
        "gregkh",
        "--name",
        "Gregkh",
        "--email",
        "gregkh@example.org",
    )
    # git's own "key::" form of user.signingKey, used by default.
    git(reg, "config", "user.signingKey", "key::" + gregkh.pubkey)
    ok(reg, "endorse", "alice")
    verify(reg / "endorsements/alice/gregkh-1.json", gregkh, "git-vouch-endorse")
    register(reg, "torvalds", keys["torvalds"])
    # git still reads a bare "ssh-..." value as "key::ssh-...".
    git(reg, "config", "user.signingKey", gregkh.pubkey)
    ok(reg, "endorse", "torvalds")
    verify(reg / "endorsements/torvalds/gregkh-1.json", gregkh, "git-vouch-endorse")
    result = check(reg)
    assert result.returncode == 0, result.stderr


def fingerprint(public: Path) -> str:
    """Return the SHA256 fingerprint ``ssh-keygen -l`` prints for the key in ``public``."""
    out = subprocess.run(
        ["ssh-keygen", "-l", "-f", str(public)],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.split()[1]


def shown(stderr: str) -> dict[str, str]:
    """Return the fields endorse printed before signing."""
    lines = stderr.splitlines()
    start = next(i for i, x in enumerate(lines) if "signing an endorsement" in x)
    fields = (x.split(":", 1) for x in lines[start + 1 : start + 4])
    return {name.strip(): value.strip() for name, value in fields}


def test_endorse_shows_the_subject_it_signs(tree: Path, keys: dict[str, Key]) -> None:
    """alice has two current keys: endorse names the one it signs (vouch-xlha.26)."""
    ok(
        tree,
        "add-key",
        str(keys["alice2"].public),
        "--sign-with",
        str(keys["alice"].private),
    )
    commit(tree)
    result = vouch(
        tree, "endorse", "alice", "--sign-with", str(keys["torvalds"].private)
    )
    assert result.returncode == 0, result.stderr
    assert "signing an endorsement of alice" in result.stderr
    obj = load(tree / "endorsements/alice/torvalds-1.json")
    signed = (
        keys["alice"] if obj["subjectKey"] == did(keys["alice"]) else keys["alice2"]
    )
    assert obj["subjectKey"] == did(signed)
    assert shown(result.stderr) == {
        "key": f"{fingerprint(signed.public)} {did(signed)}",
        "name": "Alice",
        "emails": "alice@example.org",
    }
    verify(
        tree / "endorsements/alice/torvalds-1.json",
        keys["torvalds"],
        "git-vouch-endorse",
    )


def test_endorse_from_a_draft_shows_the_subject_it_signs(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    path = endorsement_draft(tmp_path, "torvalds", keys["torvalds"], keys["alice"])
    result = vouch(
        tree,
        "endorse",
        "--from",
        str(path),
        "--sign-with",
        str(keys["torvalds"].private),
    )
    assert result.returncode == 0, result.stderr
    assert shown(result.stderr) == {
        "key": f"{fingerprint(keys['alice'].public)} {did(keys['alice'])}",
        "name": "Alice",
        "emails": "alice@example.org",
    }
    assert (
        tree / "endorsements/alice/torvalds-1.json"
    ).read_bytes() == path.read_bytes()


def sk_did(public: Path) -> str:
    """Return the did:key of the sk-ssh-ed25519 key in ``public``.

    The blob is type, key, application; the 32-byte key is put in a plain
    ssh-ed25519 line for test_check.did, which reads its last 32 bytes.
    """
    blob = base64.b64decode(public.read_text().split()[1])
    fields = []
    while blob:
        n = int.from_bytes(blob[:4], "big")
        fields.append(blob[4 : 4 + n])
        blob = blob[4 + n :]
    assert fields[0] == b"sk-ssh-ed25519@openssh.com" and len(fields[1]) == 32
    plain = b"".join(len(f).to_bytes(4, "big") + f for f in (b"ssh-ed25519", fields[1]))
    line = "ssh-ed25519 " + base64.b64encode(plain).decode()
    return did(Key(public, public, line))


def endorse_draft_of(
    tree: Path, keys: dict[str, Key], tmp_path: Path, subject_key: str
) -> subprocess.CompletedProcess[str]:
    """Sign torvalds' draft endorsement of alice, naming ``subject_key``."""
    path = endorsement_draft(tmp_path, "torvalds", keys["torvalds"], keys["alice"])
    obj = load(path)
    obj["subjectKey"] = subject_key
    path.write_text(json.dumps(obj, indent=2) + "\n")
    sign = ["--sign-with", str(keys["torvalds"].private)]
    return vouch(tree, "endorse", "--from", str(path), *sign)


def test_endorse_shows_a_fido_key_as_ssh_keygen_does(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    """A did:key drops the sk- type, so the fingerprint comes from the person file."""
    ok(tree, "add-key", str(SK_PUB), "--sign-with", str(keys["alice"].private))
    commit(tree)
    result = endorse_draft_of(tree, keys, tmp_path, sk_did(SK_PUB))
    assert result.returncode == 0, result.stderr
    assert shown(result.stderr)["key"] == f"{fingerprint(SK_PUB)} {sk_did(SK_PUB)}"


def test_endorse_says_when_the_key_is_not_in_the_person_file(
    tree: Path, keys: dict[str, Key], tmp_path: Path
) -> None:
    result = endorse_draft_of(tree, keys, tmp_path, did(keys["alice2"]))
    assert result.returncode == 0, result.stderr
    assert shown(result.stderr)["key"] == (
        f"{fingerprint(keys['alice2'].public)} {did(keys['alice2'])}"
        " (not in people/alice.json; shown as ssh-ed25519)"
    )

"""Record signature verification (DESIGN.md, The registry).

Every signature is made by real ``ssh-keygen -Y sign`` on throwaway keys, so
whether a signature is genuine never depends on git-vouch's own output.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from conftest import Key, make_key
from test_did import CCG_ED25519_SEEDS

CONTEXT = "https://w3id.org/git-vouch/v1"
OUTSIDE_DID = next(iter(CCG_ED25519_SEEDS))  # a CCG vector, not a test key
NAMESPACE = {
    "people/alice.json": "git-vouch-register",
    "tiers/alice.json": "git-vouch-tier",
    "endorsements/alice/gregkh-1.json": "git-vouch-endorse",
    "revocations/alice-1.json": "git-vouch-revoke",
}
OTHER_NAMESPACES = ["git", "file", *NAMESPACE.values()]


def sign(key: Key, namespace: str, data: bytes, tmp_path: Path) -> bytes:
    """Return the armored signature ssh-keygen makes over ``data``."""
    msg = tmp_path / "msg"
    msg.write_bytes(data)
    sig = tmp_path / "msg.sig"
    sig.unlink(missing_ok=True)
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-Y",
            "sign",
            "-f",
            str(key.private),
            "-n",
            namespace,
            str(msg),
        ],
        check=True,
        capture_output=True,
    )
    return sig.read_bytes()


def person_bytes(*keys: Key, retired: Key | None = None) -> bytes:
    """Return a person file for alice listing ``keys``; ``retired`` is listed as retired."""
    entries = [{"ssh": k.pubkey, "added": "2026-11-01T00:00:00Z"} for k in keys]
    if retired is not None:
        entries.insert(
            0,
            {
                "ssh": retired.pubkey,
                "added": "2026-01-01T00:00:00Z",
                "retired": "2026-11-01T00:00:00Z",
            },
        )
    return json.dumps(
        {
            "@context": [CONTEXT],
            "handle": "alice",
            "name": "Alice Example",
            "emails": ["alice@example.org"],
            "keys": entries,
        }
    ).encode()


def approval_bytes(rel: str, did: str) -> bytes:
    """Return a tier record or endorsement by gregkh naming signer key ``did``."""
    if rel.startswith("tiers/"):
        record = {"approver": "gregkh", "approverKey": did, "tier": "maintainer"}
    else:
        record = {
            "endorser": "gregkh",
            "endorserKey": did,
            "subjectKey": OUTSIDE_DID,
            "subjectName": "Alice Example",
        }
    record.update(
        {"@context": [CONTEXT], "subject": "alice", "date": "2026-11-05T00:00:00Z"}
    )
    return json.dumps(record).encode()


def gregkh(vouch: ModuleType, *keys: Key) -> object:
    """Return gregkh's parsed person file listing ``keys``."""
    data = person_bytes(*keys).replace(b'"alice"', b'"gregkh"')
    return vouch.parse_record("people/gregkh.json", data)


@pytest.fixture
def second_key(tmp_path: Path) -> Key:
    return make_key(tmp_path, "second", ["-t", "ed25519"])


@pytest.fixture
def third_key(tmp_path: Path) -> Key:
    return make_key(tmp_path, "third", ["-t", "ecdsa", "-b", "256"])


def person_key(vouch: ModuleType, key: Key) -> object:
    return vouch.parse_record("people/alice.json", person_bytes(key)).keys[0]


@pytest.mark.parametrize("rel", list(NAMESPACE))
def test_signer_of_accepts_own_namespace(
    vouch: ModuleType, any_key: Key, second_key: Key, tmp_path: Path, rel: str
) -> None:
    data = b'{"any": "bytes"}\n'
    sig = sign(any_key, NAMESPACE[rel], data, tmp_path)
    keys = [person_key(vouch, second_key), person_key(vouch, any_key)]
    assert vouch.signer_of(rel, data, sig, keys) == keys[1]


@pytest.mark.parametrize(
    ("rel", "namespace"),
    [(r, n) for r in NAMESPACE for n in OTHER_NAMESPACES if n != NAMESPACE[r]],
)
def test_cross_namespace_rejected(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path, rel: str, namespace: str
) -> None:
    data = b"record"
    sig = sign(ed25519_key, namespace, data, tmp_path)
    with pytest.raises(vouch.VouchError, match="no valid signature"):
        vouch.signer_of(rel, data, sig, [person_key(vouch, ed25519_key)])


@pytest.mark.parametrize("offset", [0, 7, -1])
def test_one_byte_edit_rejected(
    vouch: ModuleType, any_key: Key, tmp_path: Path, offset: int
) -> None:
    rel = "tiers/alice.json"
    data = bytearray(b'{"tier": "maintainer"}\n')
    sig = sign(any_key, NAMESPACE[rel], bytes(data), tmp_path)
    data[offset] ^= 0x01
    with pytest.raises(vouch.VouchError, match="no valid signature"):
        vouch.signer_of(rel, bytes(data), sig, [person_key(vouch, any_key)])


def test_key_not_allowed_rejected(
    vouch: ModuleType, ed25519_key: Key, second_key: Key, tmp_path: Path
) -> None:
    rel = "revocations/alice-1.json"
    sig = sign(second_key, NAMESPACE[rel], b"x", tmp_path)
    with pytest.raises(vouch.VouchError, match="no valid signature"):
        vouch.signer_of(rel, b"x", sig, [person_key(vouch, ed25519_key)])


@pytest.mark.parametrize(
    "sig",
    [
        b"",
        b"garbage",
        b"-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----",  # no newline
        b"-----BEGIN SSH SIGNATURE-----\nAA AA\n-----END SSH SIGNATURE-----\n",
    ],
)
def test_malformed_sig_file_rejected(
    vouch: ModuleType, ed25519_key: Key, sig: bytes
) -> None:
    with pytest.raises(vouch.VouchError, match="armored SSH signatures"):
        vouch.signer_of("tiers/alice.json", b"x", sig, [person_key(vouch, ed25519_key)])


def test_trailing_junk_rejected(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path
) -> None:
    sig = sign(ed25519_key, "git-vouch-tier", b"x", tmp_path)
    with pytest.raises(vouch.VouchError, match="armored SSH signatures"):
        vouch.signer_of(
            "tiers/alice.json", b"x", sig + b"\n", [person_key(vouch, ed25519_key)]
        )


def test_two_signatures_on_single_signer_record_rejected(
    vouch: ModuleType, ed25519_key: Key, second_key: Key, tmp_path: Path
) -> None:
    sig = sign(ed25519_key, "git-vouch-tier", b"x", tmp_path)
    sig += sign(second_key, "git-vouch-tier", b"x", tmp_path)
    keys = [person_key(vouch, ed25519_key), person_key(vouch, second_key)]
    with pytest.raises(vouch.VouchError, match="exactly one signature"):
        vouch.signer_of("tiers/alice.json", b"x", sig, keys)


@pytest.mark.parametrize("reverse", [False, True])
def test_person_signed_by_every_current_key(
    vouch: ModuleType, ed25519_key: Key, third_key: Key, tmp_path: Path, reverse: bool
) -> None:
    data = person_bytes(ed25519_key, third_key)
    sigs = [
        sign(k, "git-vouch-register", data, tmp_path) for k in (ed25519_key, third_key)
    ]
    if reverse:
        sigs.reverse()
    person = vouch.parse_record("people/alice.json", data)
    vouch.verify_person(person, data, b"".join(sigs))


@pytest.mark.parametrize("signer", ["first", "second"])
def test_person_signed_by_any_one_current_key(
    vouch: ModuleType, ed25519_key: Key, third_key: Key, tmp_path: Path, signer: str
) -> None:
    # DESIGN.md, Person file: one signature is enough, so backup keys stay in a drawer.
    data = person_bytes(ed25519_key, third_key)
    by = ed25519_key if signer == "first" else third_key
    sig = sign(by, "git-vouch-register", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    assert vouch.verify_person(person, data, sig) is True


def test_person_rotation_signed_by_previous_key_only(
    vouch: ModuleType, ed25519_key: Key, second_key: Key, tmp_path: Path
) -> None:
    # second_key retires, ed25519_key is added; only the outgoing key signs.
    data = person_bytes(ed25519_key, retired=second_key)
    sig = sign(second_key, "git-vouch-register", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    previous = [person_key(vouch, second_key)]
    assert vouch.verify_person(person, data, sig, previous) is True
    with pytest.raises(vouch.VouchError, match="by a non-current key"):
        vouch.verify_person(person, data, sig)  # as a first version


def test_person_change_signed_only_by_new_key_is_not_chained(
    vouch: ModuleType, ed25519_key: Key, second_key: Key, tmp_path: Path
) -> None:
    data = person_bytes(ed25519_key)
    sig = sign(ed25519_key, "git-vouch-register", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    previous = [person_key(vouch, second_key)]
    assert vouch.verify_person(person, data, sig, previous) is False
    assert vouch.verify_person(person, data, sig, []) is False  # a frozen file


def test_person_signed_by_revoked_previous_key_is_not_chained(
    vouch: ModuleType, ed25519_key: Key, second_key: Key, tmp_path: Path
) -> None:
    # DESIGN.md: a revoked key's signatures are invalid, past or future, but
    # a revocation never fails check, so the signature chains nothing.
    data = person_bytes(ed25519_key, retired=second_key)
    sig = sign(second_key, "git-vouch-register", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    previous = [person_key(vouch, second_key)]
    assert vouch.verify_person(person, data, sig, previous, {previous[0].did}) is False


def test_person_retired_key_needs_no_signature(
    vouch: ModuleType, ed25519_key: Key, second_key: Key, tmp_path: Path
) -> None:
    data = person_bytes(ed25519_key, retired=second_key)
    sig = sign(ed25519_key, "git-vouch-register", data, tmp_path)
    vouch.verify_person(vouch.parse_record("people/alice.json", data), data, sig)


@pytest.mark.parametrize("extra", ["retired", "outsider", "repeat"])
def test_person_extra_signature_rejected(
    vouch: ModuleType,
    ed25519_key: Key,
    second_key: Key,
    third_key: Key,
    tmp_path: Path,
    extra: str,
) -> None:
    data = person_bytes(ed25519_key, retired=second_key)
    sig = sign(ed25519_key, "git-vouch-register", data, tmp_path)
    by = {"retired": second_key, "outsider": third_key, "repeat": ed25519_key}[extra]
    sig += sign(by, "git-vouch-register", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    with pytest.raises(
        vouch.VouchError, match="invalid, by a non-current key, or repeated"
    ):
        vouch.verify_person(person, data, sig)


def test_person_one_byte_edit_rejected(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path
) -> None:
    data = person_bytes(ed25519_key)
    sig = sign(ed25519_key, "git-vouch-register", data, tmp_path)
    edited = data.replace(b"Alice Example", b"Alice Examplf")
    person = vouch.parse_record("people/alice.json", edited)
    with pytest.raises(vouch.VouchError, match="invalid"):
        vouch.verify_person(person, edited, sig)


def test_person_wrong_namespace_rejected(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path
) -> None:
    data = person_bytes(ed25519_key)
    sig = sign(ed25519_key, "git-vouch-endorse", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    with pytest.raises(vouch.VouchError, match="invalid"):
        vouch.verify_person(person, data, sig)


def test_person_without_current_key_rejected(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path
) -> None:
    data = person_bytes(retired=ed25519_key)
    sig = sign(ed25519_key, "git-vouch-register", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    with pytest.raises(vouch.VouchError, match="no current key"):
        vouch.verify_person(person, data, sig)


APPROVALS = ["tiers/alice.json", "endorsements/alice/gregkh-1.json"]


@pytest.mark.parametrize("rel", APPROVALS)
def test_approval_signed_by_named_key(
    vouch: ModuleType, any_key: Key, second_key: Key, tmp_path: Path, rel: str
) -> None:
    signer = gregkh(vouch, second_key, any_key)
    data = approval_bytes(rel, signer.keys[1].did)
    sig = sign(any_key, NAMESPACE[rel], data, tmp_path)
    record = vouch.parse_record(rel, data)
    assert vouch.verify_approval(rel, record, data, sig, signer) == signer.keys[1]


@pytest.mark.parametrize("rel", APPROVALS)
def test_approval_signed_by_other_own_key_rejected(
    vouch: ModuleType, ed25519_key: Key, second_key: Key, tmp_path: Path, rel: str
) -> None:
    signer = gregkh(vouch, ed25519_key, second_key)
    data = approval_bytes(rel, signer.keys[1].did)  # names second_key...
    sig = sign(ed25519_key, NAMESPACE[rel], data, tmp_path)  # ...signed by the other
    record = vouch.parse_record(rel, data)
    with pytest.raises(vouch.VouchError, match="no valid signature"):
        vouch.verify_approval(rel, record, data, sig, signer)


@pytest.mark.parametrize("rel", APPROVALS)
def test_approval_did_not_signers_key_rejected(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path, rel: str
) -> None:
    signer = gregkh(vouch, ed25519_key)
    data = approval_bytes(rel, OUTSIDE_DID)
    sig = sign(ed25519_key, NAMESPACE[rel], data, tmp_path)
    record = vouch.parse_record(rel, data)
    with pytest.raises(vouch.VouchError, match="is not a key of gregkh"):
        vouch.verify_approval(rel, record, data, sig, signer)


def test_approval_wrong_signer_person_rejected(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path
) -> None:
    rel = "tiers/alice.json"
    alice = vouch.parse_record("people/alice.json", person_bytes(ed25519_key))
    data = approval_bytes(rel, alice.keys[0].did)
    sig = sign(ed25519_key, NAMESPACE[rel], data, tmp_path)
    record = vouch.parse_record(rel, data)
    with pytest.raises(vouch.VouchError, match="signed by gregkh, not alice"):
        vouch.verify_approval(rel, record, data, sig, alice)


def test_missing_ssh_keygen_is_an_error_not_a_bad_signature(
    vouch: ModuleType,
    ed25519_key: Key,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = person_bytes(ed25519_key)
    sig = sign(ed25519_key, "git-vouch-register", data, tmp_path)
    person = vouch.parse_record("people/alice.json", data)
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(vouch.VouchError, match="cannot run ssh-keygen"):
        vouch.signer_of("people/alice.json", data, sig, person.keys)
    with pytest.raises(vouch.VouchError, match="cannot run ssh-keygen"):
        vouch.verify_person(person, data, sig)


def count_verifies(
    vouch: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> list[tuple[bytes, bytes, str, str]]:
    """Record (data, signature, namespace, allowed key) for each ssh-keygen -Y verify run.

    The verification cache is cleared first, so runs earlier in the process
    do not hide any.
    """
    vouch._ssh_verifies.cache_clear()
    runs: list[tuple[bytes, bytes, str, str]] = []
    real = subprocess.run

    def recording(argv: list[str], *args: object, **kwargs: object) -> object:
        if argv[:3] == ["ssh-keygen", "-Y", "verify"]:
            opt = dict(zip(argv[3::2], argv[4::2]))
            runs.append(
                (
                    kwargs["input"],
                    Path(opt["-s"]).read_bytes(),
                    opt["-n"],
                    Path(opt["-f"]).read_text(),
                )
            )
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(vouch.subprocess, "run", recording)
    return runs


def test_each_block_is_verified_once_by_the_key_it_names(
    vouch: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Four keys signing in reverse order cost four ssh-keygen runs, not ten (vouch-xlha.3, .25).

    Each block is checked only against the key its SSHSIG blob names, and a
    signature already verified is not verified again.
    """
    keys = [make_key(tmp_path, f"k{i}", ["-t", "ed25519"]) for i in range(4)]
    data = person_bytes(*keys)
    person = vouch.parse_record("people/alice.json", data)
    sig = b"".join(
        sign(k, "git-vouch-register", data, tmp_path) for k in reversed(keys)
    )
    runs = count_verifies(vouch, monkeypatch)
    assert vouch.verify_person(person, data, sig) is True
    assert vouch.verify_person(person, data, sig) is True
    assert len(runs) == 4
    assert sorted(r[3] for r in runs) == sorted(
        f"signer {' '.join(k.pubkey.split()[:2])}\n" for k in keys
    )


def test_block_naming_no_allowed_key_runs_no_ssh_keygen(
    vouch: ModuleType,
    ed25519_key: Key,
    second_key: Key,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A signature by a key not on the allowed list is refused without trying each key."""
    data = person_bytes(ed25519_key)
    person = vouch.parse_record("people/alice.json", data)
    sig = sign(second_key, "git-vouch-register", data, tmp_path)
    runs = count_verifies(vouch, monkeypatch)
    with pytest.raises(vouch.VouchError, match="invalid, by a non-current key"):
        vouch.verify_person(person, data, sig)
    assert runs == []


def test_block_naming_the_key_still_needs_ssh_keygen(
    vouch: ModuleType, ed25519_key: Key, tmp_path: Path
) -> None:
    """Picking the key from the blob proves nothing: a tampered record still fails."""
    data = person_bytes(ed25519_key)
    person = vouch.parse_record("people/alice.json", data)
    sig = sign(ed25519_key, "git-vouch-register", data, tmp_path)
    with pytest.raises(vouch.VouchError, match="invalid, by a non-current key"):
        vouch.verify_person(person, data.replace(b"Alice", b"Mallory"), sig)


def test_more_than_sixteen_current_keys_refused(
    vouch: ModuleType, tmp_path: Path
) -> None:
    """A person file may list at most 16 current keys; retired ones do not count (vouch-xlha.25)."""
    keys = [make_key(tmp_path, f"k{i}", ["-t", "ed25519"]) for i in range(17)]
    person = vouch.parse_record(
        "people/alice.json", person_bytes(*keys[:16], retired=keys[16])
    )
    assert len(person.keys) == 17
    with pytest.raises(vouch.VouchError, match="keys: more than 16 current"):
        vouch.parse_record("people/alice.json", person_bytes(*keys))


def test_more_than_four_signature_blocks_refused(
    vouch: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A .sig file may hold at most four blocks, and five are refused unverified (vouch-xlha.25)."""
    keys = [make_key(tmp_path, f"k{i}", ["-t", "ed25519"]) for i in range(5)]
    data = person_bytes(*keys)
    person = vouch.parse_record("people/alice.json", data)
    blocks = [sign(k, "git-vouch-register", data, tmp_path) for k in keys]
    assert vouch.verify_person(person, data, b"".join(blocks[:4])) is True
    runs = count_verifies(vouch, monkeypatch)
    with pytest.raises(vouch.VouchError, match="more than 4 signatures"):
        vouch.verify_person(person, data, b"".join(blocks))
    assert runs == []

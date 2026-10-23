"""Table-driven tests for record parsing and strict validation (DESIGN.md, The registry).

Keys and did:keys come from the W3C CCG vectors and the independently derived
P-256 vector in test_did, never from git-vouch's own output.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest

from test_did import (
    CCG_ED25519_SEED5_JWK_X,
    CCG_ED25519_SEEDS,
    CCG_P256_JWKS,
    DSA_SSH,
    CCG_UNSUPPORTED_DIDS,
    EVEN_Y_P256_DID,
    EVEN_Y_P256_SSH,
    b64url,
    ssh_line,
)

CONTEXT = "https://w3id.org/git-vouch/v1"
ED_DID = "did:key:z6MkwYMhwTvsq376YBAcJHy3vyRWzBgn5vKfVqqDCgm7XVKU"  # CCG seed 05
ED_RAW = b64url(CCG_ED25519_SEED5_JWK_X)
ED_SSH = ssh_line(b"ssh-ed25519", ED_RAW)
SK_ED_SSH = ssh_line(b"sk-ssh-ed25519@openssh.com", ED_RAW, b"ssh:")
DID_A, DID_B = list(CCG_ED25519_SEEDS)[:2]
DID_P256 = next(iter(CCG_P256_JWKS))
RSA_DID = CCG_UNSUPPORTED_DIDS[0]
# Base64 of an ssh-keygen attestation header: uint32 length 17 + "ssh-sk-attest-v01"
# (cross-checked with: printf "\x00\x00\x00\x11ssh-sk-attest-v01" | base64).
ATTESTATION_BLOB = "AAAAEXNzaC1zay1hdHRlc3QtdjAx"
# printf 'git-vouch registration challenge' | base64
ATTESTATION_CHALLENGE = "Z2l0LXZvdWNoIHJlZ2lzdHJhdGlvbiBjaGFsbGVuZ2U="
ATTESTATION = {"blob": ATTESTATION_BLOB, "challenge": ATTESTATION_CHALLENGE}

KEY = {"ssh": EVEN_Y_P256_SSH + " alice@laptop", "added": "2026-11-01T00:00:00Z"}
PERSON = {
    "@context": [CONTEXT, {"foaf": "http://xmlns.com/foaf/0.1/"}],
    "handle": "alice",
    "name": "Alice Example",
    "emails": ["alice@example.org"],
    "keys": [KEY],
    "accountable": None,
    "alsoKnownAs": ["did:web:example.org", "did:plc:abc123"],
    "foaf:homepage": "http://example.org/",
}
TIER = {
    "@context": [CONTEXT],
    "subject": "alice",
    "tier": "maintainer",
    "approver": "torvalds",
    "approverKey": DID_A,
    "date": "2026-11-05T00:00:00Z",
}
ENDORSEMENT = {
    "@context": [CONTEXT],
    "endorser": "gregkh",
    "endorserKey": DID_A,
    "subject": "alice",
    "subjectKey": DID_P256,
    "subjectName": "Alice Example",
    "note": "Met at LPC 2026.",
    "date": "2026-11-03T00:00:00Z",
}
REVOCATION = {
    "@context": [CONTEXT],
    "subject": "alice",
    "key": DID_B,
    "reason": "compromise",
    "date": "2026-12-01T00:00:00Z",
}

PERSON_REL = "people/alice.json"
TIER_REL = "tiers/alice.json"
ENDORSEMENT_REL = "endorsements/alice/gregkh-1.json"
REVOCATION_REL = "revocations/alice-1.json"
KINDS = [
    pytest.param(PERSON_REL, PERSON, id="person"),
    pytest.param(TIER_REL, TIER, id="tier"),
    pytest.param(ENDORSEMENT_REL, ENDORSEMENT, id="endorsement"),
    pytest.param(REVOCATION_REL, REVOCATION, id="revocation"),
]


def drop(record: dict[str, object], key: str) -> dict[str, object]:
    """Return ``record`` without ``key``."""
    return {k: v for k, v in record.items() if k != key}


def with_key(**changes: object) -> dict[str, object]:
    """Return PERSON whose only key has ``changes`` applied."""
    return {**PERSON, "keys": [{**KEY, **changes}]}


def encode(record: object) -> bytes:
    return json.dumps(record).encode()


UTC = timezone.utc


def test_person_fields(vouch: ModuleType) -> None:
    person = vouch.parse_record(PERSON_REL, encode(PERSON))
    assert person == vouch.Person(
        handle="alice",
        name="Alice Example",
        emails=("alice@example.org",),
        keys=(
            vouch.PersonKey(
                ssh=EVEN_Y_P256_SSH,  # comment dropped
                did=EVEN_Y_P256_DID,
                added=datetime(2026, 11, 1, tzinfo=UTC),
                retired=None,
            ),
        ),
        accountable=None,
    )


def test_person_retired_sk_key_and_accountable(vouch: ModuleType) -> None:
    record = {
        **PERSON,
        "keys": [
            {**KEY, "retired": "2027-01-02T03:04:05Z"},
            {"ssh": SK_ED_SSH, "added": "2027-01-01T00:00:00Z"},  # no "retired" at all
        ],
        "accountable": "gregkh",
    }
    person = vouch.parse_record(PERSON_REL, encode(record))
    assert person.keys[0].retired == datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert person.keys[1] == vouch.PersonKey(
        SK_ED_SSH, ED_DID, datetime(2027, 1, 1, tzinfo=UTC), None
    )
    assert person.accountable == "gregkh"


def test_person_attestation_carried(vouch: ModuleType) -> None:
    record = {
        **PERSON,
        "keys": [{"ssh": SK_ED_SSH, "added": KEY["added"], "attestation": ATTESTATION}],
    }
    key = vouch.parse_record(PERSON_REL, encode(record)).keys[0]
    assert key.attestation == (ATTESTATION_BLOB, ATTESTATION_CHALLENGE)
    assert key.attestation.blob == ATTESTATION_BLOB
    assert key.attestation.challenge == ATTESTATION_CHALLENGE
    assert vouch.parse_record(PERSON_REL, encode(PERSON)).keys[0].attestation is None
    nulled = {**PERSON, "keys": [{**KEY, "attestation": None}]}
    assert vouch.parse_record(PERSON_REL, encode(nulled)).keys[0].attestation is None


def test_person_key_comment_cannot_inject_lines(vouch: ModuleType) -> None:
    evil = EVEN_Y_P256_SSH + " c\nssh-ed25519 AAAA evil\tx"
    person = vouch.parse_record(PERSON_REL, encode(with_key(ssh=evil)))
    assert person.keys[0].ssh == EVEN_Y_P256_SSH


def test_tier_fields(vouch: ModuleType) -> None:
    assert vouch.parse_record(TIER_REL, encode(TIER)) == vouch.Tier(
        "alice", "maintainer", "torvalds", DID_A, datetime(2026, 11, 5, tzinfo=UTC)
    )


def test_endorsement_fields(vouch: ModuleType) -> None:
    assert vouch.parse_record(
        ENDORSEMENT_REL, encode(ENDORSEMENT)
    ) == vouch.Endorsement(
        "gregkh",
        DID_A,
        "alice",
        DID_P256,
        "Alice Example",
        "Met at LPC 2026.",
        datetime(2026, 11, 3, tzinfo=UTC),
    )


def test_endorsement_subject_emails(vouch: ModuleType) -> None:
    record = {
        **ENDORSEMENT,
        "subjectEmails": ["alice@example.org", "Alice@Work.example"],
    }
    parsed = vouch.parse_record(ENDORSEMENT_REL, encode(record))
    assert parsed.subject_emails == ("alice@example.org", "Alice@Work.example")


def test_revocation_fields(vouch: ModuleType) -> None:
    assert vouch.parse_record(REVOCATION_REL, encode(REVOCATION)) == vouch.Revocation(
        "alice", DID_B, "compromise", datetime(2026, 12, 1, tzinfo=UTC)
    )


@pytest.mark.parametrize(
    ("rel", "record"),
    [
        pytest.param(PERSON_REL, drop(PERSON, "alsoKnownAs"), id="person-no-aka"),
        pytest.param(
            PERSON_REL, drop(PERSON, "accountable"), id="person-no-accountable"
        ),
        pytest.param(
            PERSON_REL,
            {**PERSON, "emails": ["a.b+c@x.example", "x_y%z-1@sub.example.org"]},
            id="person-emails",
        ),
        pytest.param(
            PERSON_REL, {**PERSON, "keys": [{"ssh": ED_SSH, **drop(KEY, "ssh")}]}
        ),
        pytest.param(PERSON_REL, {**PERSON, "alsoKnownAs": []}, id="person-empty-aka"),
        pytest.param(
            PERSON_REL,
            {**PERSON, "alsoKnownAs": ["did:webvh:Qm1:example.com%3A8080:a"]},
            id="person-aka-colons",
        ),
        pytest.param(
            PERSON_REL,
            {**PERSON, "name": "Jürgen Ölçer 李"},
            id="person-unicode-name",
        ),
        pytest.param(
            PERSON_REL,
            {**PERSON, "keys": [{**KEY, "label": "laptop", "x": [1, {"y": None}]}]},
            id="person-unknown-key-terms",
        ),
        pytest.param(
            PERSON_REL, {**PERSON, "unknown": [1, 2.5, True, {}]}, id="unknown"
        ),
        pytest.param(TIER_REL, {**TIER, "tier": "contributor"}, id="tier-contributor"),
        pytest.param(TIER_REL, {**TIER, "tier": "automation"}, id="tier-automation"),
        pytest.param(TIER_REL, {**TIER, "approverKey": DID_P256}, id="tier-p256"),
        pytest.param(ENDORSEMENT_REL, drop(ENDORSEMENT, "note"), id="no-note"),
        pytest.param(ENDORSEMENT_REL, {**ENDORSEMENT, "note": None}, id="null-note"),
        pytest.param(ENDORSEMENT_REL, {**ENDORSEMENT, "note": ""}, id="empty-note"),
        pytest.param(
            ENDORSEMENT_REL,
            {**ENDORSEMENT, "note": "line 1\nline 2"},
            id="multiline-note",
        ),
        pytest.param(
            "endorsements/alice/greg-kh-12.json",
            {**ENDORSEMENT, "endorser": "greg-kh"},
            id="hyphenated-endorser",
        ),
        pytest.param(
            "endorsements/alice/" + "e" * 39 + "-1.json",
            {**ENDORSEMENT, "endorser": "e" * 39},
            id="longest-endorser",
        ),
        pytest.param(
            ENDORSEMENT_REL,
            {**ENDORSEMENT, "subjectEmails": []},
            id="endorsement-no-emails",
        ),
        pytest.param(
            "revocations/a-b-20.json", {**REVOCATION, "subject": "a-b"}, id="hyphen-rev"
        ),
        pytest.param(
            REVOCATION_REL,
            {**REVOCATION, "date": "2028-02-29T23:59:59Z"},
            id="leap-day",
        ),
        pytest.param(
            TIER_REL, {**TIER, "date": "1970-01-01T00:00:00Z"}, id="first-year"
        ),
        pytest.param(
            PERSON_REL, with_key(retired="9998-12-31T23:59:59Z"), id="last-year"
        ),
        pytest.param(
            REVOCATION_REL,
            {
                "@context": [CONTEXT, "https://example.org/ctx"],
                **drop(REVOCATION, "@context"),
            },
            id="extra-context",
        ),
    ],
)
def test_valid_records(vouch: ModuleType, rel: str, record: dict[str, object]) -> None:
    vouch.parse_record(rel, encode(record))


BAD_DATES = [
    "2026-11-05",
    "2026-11-05T00:00:00",
    "2026-11-05T00:00:00+00:00",
    "2026-11-05T00:00:00.5Z",
    "2026-11-05 00:00:00Z",
    "2026-13-01T00:00:00Z",
    "2027-02-29T00:00:00Z",
    "2026-11-05T24:00:00Z",
    "2026-11-05T00:00:60Z",
    "２026-11-05T00:00:00Z",  # fullwidth digit
    "2026-11-05T00:00:00z",
    "9999-01-01T00:00:00Z",  # END_SLACK past it overflows datetime
    "1969-12-31T23:59:59Z",
    "0999-01-01T00:00:00Z",  # strftime writes 999 for OpenSSH
    20261105,
    "",
]

INVALID = [
    # Person file.
    (PERSON_REL, drop(PERSON, "handle"), "handle: required"),
    (PERSON_REL, {**PERSON, "handle": 7}, "handle: invalid handle"),
    (PERSON_REL, {**PERSON, "handle": ["alice"]}, "handle: invalid handle"),
    (PERSON_REL, {**PERSON, "handle": "bob"}, "does not match the file name"),
    (PERSON_REL, {**PERSON, "handle": "Alice"}, "handle: invalid handle"),
    (PERSON_REL, {**PERSON, "handle": "alice "}, "handle: invalid handle"),
    (PERSON_REL, drop(PERSON, "name"), "name: required"),
    (PERSON_REL, {**PERSON, "name": None}, "name: required"),
    (PERSON_REL, {**PERSON, "name": ""}, "name: must be"),
    (PERSON_REL, {**PERSON, "name": 42}, "name: must be"),
    (PERSON_REL, {**PERSON, "name": "Eve\x1b[31m"}, "name: must be"),
    (PERSON_REL, {**PERSON, "name": "Eve\nMallory"}, "name: must be"),
    (PERSON_REL, drop(PERSON, "emails"), "emails: required"),
    (PERSON_REL, {**PERSON, "emails": []}, "emails: must be a non-empty list"),
    (PERSON_REL, {**PERSON, "emails": "alice@example.org"}, "emails: must be"),
    (PERSON_REL, {**PERSON, "emails": ["*"]}, "emails: invalid address"),
    (PERSON_REL, {**PERSON, "emails": ["*@example.org"]}, "emails: invalid address"),
    (PERSON_REL, {**PERSON, "emails": ["a@x,b@y"]}, "emails: invalid address"),
    (PERSON_REL, {**PERSON, "emails": ["!a@x"]}, "emails: invalid address"),
    (PERSON_REL, {**PERSON, "emails": ["a b@x"]}, "emails: invalid address"),
    (PERSON_REL, {**PERSON, "emails": ["a@x\nb@y"]}, "emails: invalid address"),
    (PERSON_REL, {**PERSON, "emails": ["alice"]}, "emails: invalid address"),
    (PERSON_REL, {**PERSON, "emails": [1]}, "emails: invalid address"),
    (PERSON_REL, drop(PERSON, "keys"), "keys: required"),
    (PERSON_REL, {**PERSON, "keys": []}, "keys: must be a non-empty list"),
    (PERSON_REL, {**PERSON, "keys": KEY}, "keys: must be a non-empty list"),
    (PERSON_REL, {**PERSON, "keys": [EVEN_Y_P256_SSH]}, "keys[0]: must be an object"),
    (PERSON_REL, {**PERSON, "keys": [KEY, KEY]}, "listed twice"),
    (
        PERSON_REL,
        {**PERSON, "keys": [{**KEY, "ssh": ED_SSH}, {**KEY, "ssh": SK_ED_SSH}]},
        "listed twice",
    ),
    (PERSON_REL, with_key(ssh=None), "keys[0].ssh: required"),
    (PERSON_REL, with_key(ssh=["ssh-ed25519"]), "keys[0].ssh: must be"),
    (PERSON_REL, with_key(ssh=DSA_SSH), "unsupported key type"),
    (PERSON_REL, with_key(ssh="ssh-rsa AAAAB3NzaC1yc2E="), "malformed"),
    (PERSON_REL, with_key(ssh="ssh-ed25519 !!!"), "invalid base64"),
    (PERSON_REL, with_key(ssh="ssh-ed25519"), "not an SSH public key line"),
    (PERSON_REL, with_key(ssh="ecdsa-sha2-nistp256 " + ED_SSH.split()[1]), "malformed"),
    (PERSON_REL, {**PERSON, "keys": [drop(KEY, "added")]}, "keys[0].added: required"),
    (PERSON_REL, with_key(retired="soon"), "keys[0].retired: must be a UTC time"),
    (PERSON_REL, with_key(retired=False), "keys[0].retired: must be a UTC time"),
    (PERSON_REL, with_key(attestation=12345), "keys[0].attestation: must be an object"),
    (PERSON_REL, with_key(attestation=["x"]), "keys[0].attestation: must be an object"),
    (
        PERSON_REL,
        with_key(attestation=ATTESTATION_BLOB),
        "keys[0].attestation: must be an object",
    ),
    (
        PERSON_REL,
        with_key(attestation={"challenge": ATTESTATION_CHALLENGE}),
        "keys[0].attestation.blob: required",
    ),
    (
        PERSON_REL,
        with_key(attestation={"blob": ATTESTATION_BLOB}),
        "keys[0].attestation.challenge: required",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "blob": None}),
        "keys[0].attestation.blob: required",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "blob": 12345}),
        "keys[0].attestation.blob: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "blob": ["x"]}),
        "keys[0].attestation.blob: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "blob": ""}),
        "keys[0].attestation.blob: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "blob": "not base64 !!!"}),
        "keys[0].attestation.blob: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "blob": "AAAAEXNz="}),
        "keys[0].attestation.blob: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "blob": "Zm9v\u00e9"}),
        "keys[0].attestation.blob: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "challenge": 7}),
        "keys[0].attestation.challenge: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "challenge": ""}),
        "keys[0].attestation.challenge: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "challenge": "Zm9vYg"}),
        "keys[0].attestation.challenge: must be",
    ),
    (
        PERSON_REL,
        with_key(attestation={**ATTESTATION, "challenge": "Zm9vYh=="}),
        "keys[0].attestation.challenge: must be",
    ),
    (PERSON_REL, {**PERSON, "accountable": "Bob"}, "accountable: invalid handle"),
    (PERSON_REL, {**PERSON, "accountable": 3}, "accountable: invalid handle"),
    (PERSON_REL, {**PERSON, "alsoKnownAs": "did:web:x"}, "alsoKnownAs: must be"),
    (PERSON_REL, {**PERSON, "alsoKnownAs": ["https://x"]}, "alsoKnownAs: must be"),
    (PERSON_REL, {**PERSON, "alsoKnownAs": ["did:web:"]}, "alsoKnownAs: must be"),
    (PERSON_REL, {**PERSON, "alsoKnownAs": ["did:Web:x"]}, "alsoKnownAs: must be"),
    (PERSON_REL, {**PERSON, "alsoKnownAs": ["did:web:x y"]}, "alsoKnownAs: must be"),
    (
        PERSON_REL,
        {**PERSON, "alsoKnownAs": [{"id": "did:web:x"}]},
        "alsoKnownAs: must be",
    ),
    # Tier record.
    (TIER_REL, {**TIER, "subject": "bob"}, "does not match the file name"),
    (TIER_REL, drop(TIER, "subject"), "subject: required"),
    (TIER_REL, {**TIER, "tier": "anchor"}, "tier: must be one of"),
    (TIER_REL, {**TIER, "tier": "Maintainer"}, "tier: must be one of"),
    (TIER_REL, {**TIER, "tier": ["maintainer"]}, "tier: must be one of"),
    (TIER_REL, {**TIER, "tier": 1}, "tier: must be one of"),
    (TIER_REL, drop(TIER, "tier"), "tier: required"),
    (TIER_REL, {**TIER, "approver": "Linus Torvalds"}, "approver: invalid handle"),
    (TIER_REL, drop(TIER, "approver"), "approver: required"),
    (TIER_REL, {**TIER, "approverKey": RSA_DID}, "approverKey: not an ed25519"),
    (TIER_REL, {**TIER, "approverKey": "did:web:kernel.org"}, "approverKey: not an"),
    (TIER_REL, {**TIER, "approverKey": DID_A[:-1]}, "approverKey: not an"),
    (TIER_REL, {**TIER, "approverKey": DID_A + "0"}, "approverKey: invalid base58"),
    (TIER_REL, {**TIER, "approverKey": EVEN_Y_P256_SSH}, "approverKey: not an"),
    (TIER_REL, {**TIER, "approverKey": 5}, "approverKey: must be a did:key"),
    (TIER_REL, drop(TIER, "approverKey"), "approverKey: required"),
    (TIER_REL, drop(TIER, "date"), "date: required"),
    # Endorsement.
    (
        ENDORSEMENT_REL,
        {**ENDORSEMENT, "subject": "bob"},
        "subject: 'bob' does not match",
    ),
    (
        ENDORSEMENT_REL,
        {**ENDORSEMENT, "endorser": "bob"},
        "endorser: 'bob' does not match",
    ),
    (ENDORSEMENT_REL, drop(ENDORSEMENT, "endorser"), "endorser: required"),
    (ENDORSEMENT_REL, {**ENDORSEMENT, "endorserKey": RSA_DID}, "endorserKey: not an"),
    (ENDORSEMENT_REL, {**ENDORSEMENT, "subjectKey": "z6Mk"}, "subjectKey: not an"),
    (ENDORSEMENT_REL, drop(ENDORSEMENT, "subjectKey"), "subjectKey: required"),
    (ENDORSEMENT_REL, drop(ENDORSEMENT, "subjectName"), "subjectName: required"),
    (ENDORSEMENT_REL, {**ENDORSEMENT, "subjectName": ""}, "subjectName: must be"),
    (
        ENDORSEMENT_REL,
        {**ENDORSEMENT, "subjectName": ["Alice"]},
        "subjectName: must be",
    ),
    (ENDORSEMENT_REL, {**ENDORSEMENT, "note": 5}, "note: must be a string"),
    (
        ENDORSEMENT_REL,
        {**ENDORSEMENT, "subjectEmails": "alice@example.org"},
        "subjectEmails: must be a list",
    ),
    (
        ENDORSEMENT_REL,
        {**ENDORSEMENT, "subjectEmails": ["a@x,b@y"]},
        "subjectEmails: invalid address",
    ),
    (
        ENDORSEMENT_REL,
        {**ENDORSEMENT, "subjectEmails": [None]},
        "subjectEmails: invalid address",
    ),
    (ENDORSEMENT_REL, {**ENDORSEMENT, "note": ["a"]}, "note: must be a string"),
    # Revocation.
    (REVOCATION_REL, {**REVOCATION, "subject": "bob"}, "does not match the file name"),
    (REVOCATION_REL, drop(REVOCATION, "key"), "key: required"),
    (REVOCATION_REL, {**REVOCATION, "key": RSA_DID}, "key: not an ed25519"),
    (REVOCATION_REL, drop(REVOCATION, "reason"), "reason: required"),
    (REVOCATION_REL, {**REVOCATION, "reason": ""}, "reason: must be"),
    (REVOCATION_REL, {**REVOCATION, "reason": 1}, "reason: must be"),
    (REVOCATION_REL, {**REVOCATION, "reason": "a\x00b"}, "reason: must be"),
    # Dates, on every kind.
    *[
        (PERSON_REL, with_key(added=d), "keys[0].added: must be a UTC time")
        for d in BAD_DATES
    ],
    *[(TIER_REL, {**TIER, "date": d}, "date: must be a UTC time") for d in BAD_DATES],
    *[
        (ENDORSEMENT_REL, {**ENDORSEMENT, "date": d}, "date: must be")
        for d in BAD_DATES
    ],
    *[(REVOCATION_REL, {**REVOCATION, "date": d}, "date: must be") for d in BAD_DATES],
]


@pytest.mark.parametrize(("rel", "record", "message"), INVALID)
def test_invalid_records(
    vouch: ModuleType, rel: str, record: dict[str, object], message: str
) -> None:
    with pytest.raises(vouch.VouchError) as e:
        vouch.parse_record(rel, encode(record))
    assert str(e.value).startswith(rel + ": ")
    assert message in str(e.value)


@pytest.mark.parametrize(
    ("context", "drop_it"),
    [
        (None, True),
        (None, False),
        (CONTEXT, False),
        ([], False),
        (["https://www.w3.org/ns/did/v1", CONTEXT], False),
        ([{"foaf": "http://xmlns.com/foaf/0.1/"}, CONTEXT], False),
        (["https://w3id.org/git-vouch/v2"], False),
        ([CONTEXT + "/"], False),
        ({"@vocab": CONTEXT}, False),
    ],
)
@pytest.mark.parametrize(("rel", "record"), KINDS)
def test_context_must_list_git_vouch_first(
    vouch: ModuleType,
    rel: str,
    record: dict[str, object],
    context: object,
    drop_it: bool,
) -> None:
    bad = drop(record, "@context") if drop_it else {**record, "@context": context}
    with pytest.raises(
        vouch.VouchError, match="@context: must be a list starting with"
    ):
        vouch.parse_record(rel, encode(bad))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b'["alice"]', "must be a JSON object"),
        (b'"alice"', "must be a JSON object"),
        (b"null", "must be a JSON object"),
        (b"", "not valid JSON"),
        (b"{", "not valid JSON"),
        (b"\xff\xfe{}", "not valid JSON"),  # not UTF-8
        (b"\xef\xbb\xbf{}", "not valid JSON"),  # UTF-8 BOM
        ('{"a": 1}'.encode("utf-16"), "not valid JSON"),
        (b'{"x": NaN}', "not valid JSON"),
        (b'{"x": -Infinity}', "not valid JSON"),
        (b'{"x": 1, "x": 2}', "duplicate key 'x'"),
        (b'{"x": {"y": 1, "y": 1}}', "duplicate key 'y'"),
        (b"[" * 30000 + b"]" * 30000, "not valid JSON"),
    ],
)
@pytest.mark.parametrize(("rel", "record"), KINDS)
def test_malformed_json(
    vouch: ModuleType, rel: str, record: dict[str, object], data: bytes, message: str
) -> None:
    with pytest.raises(vouch.VouchError, match=rel + ": " + message):
        vouch.parse_record(rel, data)


def test_duplicate_own_term_rejected(vouch: ModuleType) -> None:
    data = encode(PERSON)[:-1] + b', "handle": "bob"}'
    with pytest.raises(vouch.VouchError, match="duplicate key 'handle'"):
        vouch.parse_record(PERSON_REL, data)


@pytest.mark.parametrize(
    ("rel", "message"),
    [
        ("people/Alice.json", "invalid file name 'Alice'"),
        ("people/-alice.json", "invalid file name"),
        ("people/" + "a" * 40 + ".json", "invalid file name"),
        ("people/alice.json.sig", "not a registry record path"),
        ("people/alice", "not a registry record path"),
        ("people/.json", "invalid file name ''"),
        ("people/sub/alice.json", "not a registry record path"),
        ("person/alice.json", "not a registry record path"),
        ("alice.json", "not a registry record path"),
        ("anchors.json", "not a registry record path"),
        ("tiers/al ice.json", "invalid file name"),
        ("endorsements/alice.json", "not a registry record path"),
        ("endorsements/alice/x/gregkh-1.json", "not a registry record path"),
        ("endorsements/Alice/gregkh-1.json", "invalid file name 'Alice'"),
        ("endorsements/alice/gregkh.json", "is not <handle>-<n>"),
        ("endorsements/alice/gregkh-0.json", "is not <handle>-<n>"),
        ("endorsements/alice/gregkh-01.json", "is not <handle>-<n>"),
        ("endorsements/alice/gregkh-1a.json", "is not <handle>-<n>"),
        ("endorsements/alice/-1.json", "is not <handle>-<n>"),
        ("endorsements/alice/Gregkh-1.json", "invalid file name 'Gregkh'"),
        ("endorsements/alice/" + "e" * 40 + "-1.json", "invalid file name"),
        ("revocations/alice.json", "is not <handle>-<n>"),
        ("revocations/alice-.json", "is not <handle>-<n>"),
        ("revocations/alice-١.json", "is not <handle>-<n>"),  # Arabic-Indic digit one
    ],
)
def test_bad_paths(vouch: ModuleType, rel: str, message: str) -> None:
    # A record that would otherwise be valid for its directory, if any.
    record = {"people": PERSON, "tiers": TIER, "revocations": REVOCATION}.get(
        rel.split("/")[0], ENDORSEMENT
    )
    with pytest.raises(vouch.VouchError) as e:
        vouch.parse_record(rel, encode(record))
    assert str(e.value).startswith(rel + ": ")
    assert message in str(e.value)


@pytest.mark.parametrize(("rel", "record"), KINDS)
def test_size_cap(
    vouch: ModuleType, tmp_path: Path, rel: str, record: dict[str, object]
) -> None:
    data = encode(record)
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_bytes(data + b" " * (64 * 1024 - len(data)))
    vouch.parse_record(rel, vouch.read_capped(tmp_path, rel))
    path.write_bytes(data + b" " * (64 * 1024 + 1 - len(data)))
    with pytest.raises(vouch.VouchError, match="larger than 65536 bytes"):
        vouch.read_capped(tmp_path, rel)


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b'["torvalds"]', ("torvalds",)),
        (b'["torvalds", "gregkh", "a-b_9"]', ("torvalds", "gregkh", "a-b_9")),
    ],
)
def test_valid_anchors(
    vouch: ModuleType, data: bytes, expected: tuple[str, ...]
) -> None:
    assert vouch.parse_anchors(data) == expected


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b"{}",
        b'{"anchors": ["torvalds"]}',
        b'"torvalds"',
        b'["Torvalds"]',
        b'["torvalds", 1]',
        b'["torvalds", null]',
        b'["torvalds", "torvalds"]',
        b'["torvalds", ["gregkh"]]',
        b'["torvalds"',
        b"\xff",
    ],
)
def test_invalid_anchors(vouch: ModuleType, data: bytes) -> None:
    with pytest.raises(vouch.VouchError, match="^anchors.json: "):
        vouch.parse_anchors(data)


def test_automation_requires_accountable(vouch: ModuleType) -> None:
    with_maintainer = vouch.parse_record(
        PERSON_REL, encode({**PERSON, "accountable": "gregkh"})
    )
    vouch.require_accountable(with_maintainer)
    for record in (PERSON, drop(PERSON, "accountable")):
        person = vouch.parse_record(PERSON_REL, encode(record))
        with pytest.raises(
            vouch.VouchError, match="accountable: required for automation"
        ):
            vouch.require_accountable(person)

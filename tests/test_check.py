"""'git vouch check': registry validation and tier computation (DESIGN.md, How trust maps).

Every fixture registry is signed by real ``ssh-keygen -Y sign`` on throwaway
keys, and the expected tiers follow from DESIGN.md's rules, never from
git-vouch's own output.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from conftest import SCRIPT, Key, make_key, run_script

CONTEXT = "https://w3id.org/git-vouch/v1"
ADDED = "2026-01-01T00:00:00Z"
RETIRED = "2026-06-01T00:00:00Z"
RETIRED_PLUS_1 = "2026-06-01T00:00:01Z"
BEFORE = "2026-03-01T00:00:00Z"
AFTER = "2026-09-01T00:00:00Z"


@pytest.fixture(scope="session")
def keys(tmp_path_factory: pytest.TempPathFactory) -> Callable[[str], Key]:
    """Return a function that makes (once per session) a named throwaway ed25519 key."""
    directory = tmp_path_factory.mktemp("keys")
    made: dict[str, Key] = {}

    def get(name: str) -> Key:
        if name not in made:
            made[name] = make_key(directory, name, ["-t", "ed25519"])
        return made[name]

    return get


def did(key: Key) -> str:
    """Return the did:key of ``key``, derived by ssh-keygen + the CCG multicodec rule.

    The raw 32-byte ed25519 key is read from ssh-keygen's own public key
    file, so this does not use git-vouch's encoder.
    """
    blob = base64.b64decode(key.pubkey.split()[1])
    raw = blob[-32:]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b"\xed\x01" + raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return "did:key:z" + out


class Registry:
    """Writes a registry checkout whose records are signed by ssh-keygen."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()
        self.scratch = root.parent / (root.name + "-scratch")
        self.scratch.mkdir()

    def sign(self, key: Key, namespace: str, data: bytes) -> bytes:
        msg = self.scratch / "msg"
        msg.write_bytes(data)
        sig = self.scratch / "msg.sig"
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

    def write(
        self, rel: str, record: dict[str, object], *signers: Key, ns: str
    ) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"@context": [CONTEXT], **record}, indent=2).encode()
        path.write_bytes(data)
        Path(str(path) + ".sig").write_bytes(
            b"".join(self.sign(k, ns, data) for k in signers)
        )

    def anchors(self, *handles: str) -> None:
        (self.root / "anchors.json").write_text(json.dumps(list(handles)))

    def person(
        self,
        handle: str,
        *current: Key,
        retired: tuple[Key, ...] = (),
        accountable: str | None = None,
        emails: tuple[str, ...] = (),
        signers: tuple[Key, ...] = (),
    ) -> None:
        """Write ``handle``'s person file, signed by ``signers`` or else every current key."""
        entries = [
            {"ssh": k.pubkey, "added": ADDED, "retired": RETIRED} for k in retired
        ] + [{"ssh": k.pubkey, "added": ADDED, "retired": None} for k in current]
        record = {
            "handle": handle,
            "name": handle.title(),
            "emails": [f"{handle}@example.org", *emails],
            "keys": entries,
            "accountable": accountable,
        }
        signers = signers or current
        self.write(f"people/{handle}.json", record, *signers, ns="git-vouch-register")

    def tier(
        self, subject: str, tier: str, approver: str, key: Key, date: str = BEFORE
    ) -> None:
        record = {
            "subject": subject,
            "tier": tier,
            "approver": approver,
            "approverKey": did(key),
            "date": date,
        }
        self.write(f"tiers/{subject}.json", record, key, ns="git-vouch-tier")

    def endorse(
        self,
        subject: str,
        subject_key: Key,
        endorser: str,
        key: Key,
        n: int = 1,
        date: str = BEFORE,
        emails: tuple[str, ...] | None = None,
    ) -> str:
        rel = f"endorsements/{subject}/{endorser}-{n}.json"
        record = {
            "endorser": endorser,
            "endorserKey": did(key),
            "subject": subject,
            "subjectKey": did(subject_key),
            "subjectName": subject.title(),
            "subjectEmails": list(
                (f"{subject}@example.org",) if emails is None else emails
            ),
            "date": date,
        }
        self.write(rel, record, key, ns="git-vouch-endorse")
        return rel

    def revoke(self, subject: str, revoked: Key, signer: Key, n: int = 1) -> str:
        rel = f"revocations/{subject}-{n}.json"
        record = {
            "subject": subject,
            "key": did(revoked),
            "reason": "compromise",
            "date": AFTER,
        }
        self.write(rel, record, signer, ns="git-vouch-revoke")
        return rel


@pytest.fixture
def tree(tmp_path: Path, keys: Callable[[str], Key]) -> Registry:
    """A valid registry: anchor torvalds, maintainer gregkh, contributor alice,
    automation bot (accountable gregkh), and dave, a registered human with no tier
    who endorses alice. Every person's email is endorsed."""
    reg = Registry(tmp_path / "registry")
    reg.anchors("torvalds")
    reg.person("torvalds", keys("torvalds"))
    reg.person("gregkh", keys("gregkh"))
    reg.person("alice", keys("alice"), keys("alice2"))
    reg.person("bot", keys("bot"), accountable="gregkh")
    reg.person("dave", keys("dave"))
    reg.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    reg.tier("alice", "contributor", "gregkh", keys("gregkh"))
    reg.tier("bot", "automation", "gregkh", keys("gregkh"))
    reg.endorse("alice", keys("alice"), "gregkh", keys("gregkh"))
    reg.endorse("alice", keys("alice"), "dave", keys("dave"))
    reg.endorse("torvalds", keys("torvalds"), "gregkh", keys("gregkh"))
    reg.endorse("gregkh", keys("gregkh"), "torvalds", keys("torvalds"))
    reg.endorse("bot", keys("bot"), "gregkh", keys("gregkh"))
    reg.endorse("dave", keys("dave"), "alice", keys("alice"))
    return reg


TREE_TIERS = {
    "torvalds": "anchor",
    "gregkh": "maintainer",
    "alice": "contributor",
    "bot": "automation",
}


def check(vouch: ModuleType, reg: Registry) -> object:
    return vouch.check_registry(reg.root)


def has(messages: list[str], *parts: str) -> bool:
    return any(all(p in m for p in parts) for m in messages)


def test_valid_tree(vouch: ModuleType, tree: Registry) -> None:
    result = check(vouch, tree)
    assert result.problems == []
    assert result.voids == []
    assert result.tiers == TREE_TIERS
    assert set(result.people) == {*TREE_TIERS, "dave"}
    assert result.revoked == {}


def test_valid_tree_cli(tree: Registry) -> None:
    result = run_script("check", str(tree.root))
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "alice contributor",
        "bot automation",
        "dave none",
        "gregkh maintainer",
        "torvalds anchor",
    ]
    assert result.stderr == ""


def test_cli_fails_on_problem(tree: Registry, keys: Callable[[str], Key]) -> None:
    tree.tier("dave", "maintainer", "dave", keys("dave"))
    result = run_script("check", str(tree.root))
    assert result.returncode == 1
    assert "git-vouch: error: tiers/dave.json:" in result.stderr
    assert "dave none" in result.stdout


def test_self_promotion(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.tier("dave", "maintainer", "dave", keys("dave"))
    result = check(vouch, tree)
    assert has(result.problems, "tiers/dave.json", "cannot approve themselves")
    assert "dave" not in result.tiers


@pytest.mark.parametrize(
    ("approver", "granted"),
    [
        ("gregkh", "maintainer"),  # maintainer granting maintainer
        ("alice", "contributor"),  # contributor granting contributor
        ("alice", "automation"),  # contributor granting automation
        ("dave", "contributor"),  # no tier at all
    ],
)
def test_approver_below_tier(
    vouch: ModuleType,
    tree: Registry,
    keys: Callable[[str], Key],
    approver: str,
    granted: str,
) -> None:
    tree.person("carol", keys("carol"), accountable="gregkh")
    tree.tier("carol", granted, approver, keys(approver))
    result = check(vouch, tree)
    assert has(result.problems, "tiers/carol.json", f"may not grant {granted}")
    assert "carol" not in result.tiers


def test_automation_cannot_approve(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("carol", keys("carol"))
    tree.tier("carol", "contributor", "bot", keys("bot"))
    result = check(vouch, tree)
    assert has(result.problems, "tiers/carol.json", "bot (automation) may not grant")
    assert "carol" not in result.tiers


def test_automation_cannot_endorse(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    rel = tree.endorse("alice", keys("alice"), "bot", keys("bot"))
    assert has(check(vouch, tree).problems, rel, "automation and cannot endorse")


def test_automation_needs_accountable_maintainer(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("bot", keys("bot"))
    result = check(vouch, tree)
    assert has(result.problems, "people/bot.json", "accountable: required")
    assert "bot" not in result.tiers
    tree.person("bot", keys("bot"), accountable="alice")
    result = check(vouch, tree)
    assert has(result.problems, "people/bot.json", "alice is not a maintainer")


def test_revoked_approver_voids_tiers(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.revoke("gregkh", keys("gregkh"), keys("gregkh"))
    result = check(vouch, tree)
    assert (
        result.problems == []
    )  # a revocation must not block the export that spreads it
    assert result.revoked == {
        did(keys("gregkh")): " ".join(keys("gregkh").pubkey.split()[:2])
    }
    assert result.tiers == {"torvalds": "anchor", "gregkh": "maintainer"}
    assert has(result.voids, "tiers/alice.json", "revoked")
    assert has(result.voids, "tiers/bot.json", "revoked")
    assert has(result.voids, "endorsements/alice/gregkh-1.json", "revoked")


def test_void_approver_voids_its_grants(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.revoke("torvalds", keys("torvalds"), keys("torvalds"))
    result = check(vouch, tree)
    assert result.problems == []
    assert result.tiers == {"torvalds": "anchor"}
    assert has(result.voids, "tiers/gregkh.json", "revoked")
    assert has(result.voids, "tiers/alice.json", "gregkh has no valid tier")


def test_retired_keys_keep_earlier_records(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("dave", keys("dave2"), retired=(keys("dave"),))
    tree.person("gregkh", keys("gregkh2"), retired=(keys("gregkh"),))
    result = check(vouch, tree)
    assert result.problems == []
    assert result.voids == []
    assert result.tiers == TREE_TIERS


def test_retired_endorser_key_after_retirement(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("dave", keys("dave2"), retired=(keys("dave"),))
    rel = tree.endorse("alice", keys("alice"), "dave", keys("dave"), n=2, date=AFTER)
    assert has(check(vouch, tree).problems, rel, "outside the validity")


def test_endorsement_by_untiered_human_needs_valid_signature(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    rel = tree.endorse("alice", keys("alice"), "dave", keys("dave"), n=2)
    Path(tree.root, rel).write_bytes(Path(tree.root, rel).read_bytes() + b"\n")
    assert has(check(vouch, tree).problems, rel, "no valid signature")


def test_endorsement_of_foreign_key(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    rel = tree.endorse("alice", keys("dave"), "gregkh", keys("gregkh"), n=2)
    assert has(check(vouch, tree).problems, rel, "is not a key of alice")


@pytest.mark.parametrize(
    ("signer", "signer_name"),
    [
        ("torvalds", "anchor"),
        ("alice2", "another own current key"),
        ("alice", "the key itself"),
    ],
)
def test_revocation_accepted(
    vouch: ModuleType,
    tree: Registry,
    keys: Callable[[str], Key],
    signer: str,
    signer_name: str,
) -> None:
    tree.revoke("alice", keys("alice"), keys(signer))
    result = check(vouch, tree)
    assert result.problems == [], signer_name
    assert did(keys("alice")) in result.revoked
    # Revoking the subject's key voids no endorsement of it (DESIGN.md,
    # Endorsement): they carry over to the person's other keys. Only what
    # the revoked key itself signed, alice's endorsement of dave, is void.
    assert not has(result.voids, "endorsements/alice/")
    assert has(result.voids, "endorsements/dave/alice-1.json", "revoked")
    assert result.emails["alice"] == ("alice@example.org",)


@pytest.mark.parametrize("signer", ["gregkh", "dave"])
def test_revocation_by_non_anchor_rejected(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key], signer: str
) -> None:
    rel = tree.revoke("alice", keys("alice"), keys(signer))
    result = check(vouch, tree)
    assert has(result.problems, rel, "no valid signature by an allowed key")
    assert result.revoked == {}


def test_revocation_by_retired_own_key_rejected(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("alice", keys("alice2"), retired=(keys("alice"),))
    rel = tree.revoke("alice", keys("alice2"), keys("alice"))
    assert has(check(vouch, tree).problems, rel, "no valid signature")


def test_claiming_anothers_current_key_rejected(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    # Listing a retired key needs no signature by it, so carol's claim proves
    # nothing; gregkh's file is signed by the key and stays his.
    tree.person("carol", keys("carol"), retired=(keys("gregkh"),))
    result = check(vouch, tree)
    assert has(result.problems, "people/carol.json", "a current key of gregkh")
    assert "carol" not in result.people
    assert result.tiers == TREE_TIERS
    assert not has(result.voids, "gregkh")


def test_unsigned_person_file_cannot_claim_a_key(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("mallory", keys("gregkh"))
    (tree.root / "people/mallory.json.sig").write_text("garbage")
    result = check(vouch, tree)
    assert has(result.problems, "people/mallory.json.sig")
    assert result.tiers == TREE_TIERS
    assert result.voids == []


def test_key_current_in_two_person_files(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("dave2", keys("dave"))
    result = check(vouch, tree)
    assert has(result.problems, "people/dave.json", "a current key of dave2")
    assert has(result.problems, "people/dave2.json", "a current key of dave")
    assert "dave" not in result.people and "dave2" not in result.people


def test_key_retired_in_two_person_files(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("dave", keys("dave2"), retired=(keys("dave"),))
    tree.person("carol", keys("carol"), retired=(keys("dave"),))
    result = check(vouch, tree)
    assert has(result.problems, "people/carol.json", "also listed by dave")
    assert {"carol", "dave"} <= set(result.people)


def test_anchor_with_tier_record_rejected(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.anchors("torvalds", "gregkh")
    result = check(vouch, tree)
    assert has(result.problems, "tiers/gregkh.json", "is an anchor")
    assert result.tiers["gregkh"] == "anchor"


def test_missing_people(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.anchors("torvalds", "linus2")
    tree.tier("ghost", "contributor", "gregkh", keys("gregkh"))
    result = check(vouch, tree)
    assert has(result.problems, "anchors.json", "no person file for linus2")
    assert has(result.problems, "tiers/ghost.json", "no person file for ghost")


def test_invalid_person_file_voids_its_records(
    vouch: ModuleType, tree: Registry
) -> None:
    path = tree.root / "people/gregkh.json"
    path.write_bytes(path.read_bytes() + b"\n")
    result = check(vouch, tree)
    assert has(result.problems, "people/gregkh.json.sig")
    assert has(result.voids, "tiers/alice.json", "person file of gregkh is invalid")
    assert "alice" not in result.tiers


def test_unexpected_and_orphan_files(vouch: ModuleType, tree: Registry) -> None:
    (tree.root / "tiers/stray.txt").write_text("x")
    (tree.root / "tiers/nobody.json.sig").write_text("x")
    (tree.root / "people/alice.json.asc").write_text("cue only")
    (tree.root / "people/alice.json.sig").rename(
        tree.root / "people/alice.json.sig.bak"
    )
    problems = check(vouch, tree).problems
    assert has(problems, "tiers/stray.txt: unexpected file")
    assert has(problems, "tiers/nobody.json.sig: unexpected file")
    assert has(problems, "people/alice.json.sig.bak: unexpected file")
    assert has(problems, "people/alice.json.sig: cannot read")
    assert not has(problems, "alice.json.asc")


def test_symlinked_directory_rejected(vouch: ModuleType, tree: Registry) -> None:
    (tree.root / "tiers").rename(tree.root / "real-tiers")
    os.symlink("real-tiers", tree.root / "tiers")
    result = check(vouch, tree)
    assert has(result.problems, "tiers: cannot list")
    assert "gregkh" not in result.tiers


def test_missing_anchors_file(vouch: ModuleType, tmp_path: Path) -> None:
    result = vouch.check_registry(tmp_path)
    assert has(result.problems, "anchors.json: cannot read")


def test_record_in_retirement_second(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("dave", keys("dave2"), retired=(keys("dave"),))
    tree.endorse("alice", keys("alice"), "dave", keys("dave"), n=2, date=RETIRED)
    result = check(vouch, tree)
    assert result.problems == []
    assert result.voids == []


def test_record_a_second_after_retirement(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("dave", keys("dave2"), retired=(keys("dave"),))
    rel = tree.endorse(
        "alice", keys("alice"), "dave", keys("dave"), n=2, date=RETIRED_PLUS_1
    )
    assert has(check(vouch, tree).problems, rel, "outside the validity")


def test_record_dated_before_key_added(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    rel = tree.endorse(
        "alice", keys("alice"), "dave", keys("dave"), n=2, date="2025-12-01T00:00:00Z"
    )
    assert has(check(vouch, tree).problems, rel, "outside the validity")


def test_endorsement_of_another_name_is_void(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    rel = "people/alice.json"
    record = json.loads((tree.root / rel).read_bytes())
    record["name"] = "Alice Renamed"
    del record["@context"]
    tree.write(rel, record, keys("alice"), keys("alice2"), ns="git-vouch-register")
    result = check(vouch, tree)
    assert result.problems == []
    assert has(result.voids, "endorsements/alice/dave-1.json", "endorses the name")
    assert has(result.voids, "endorsements/alice/gregkh-1.json", "endorses the name")


@pytest.mark.parametrize("email", ["gregkh@example.org", "GregKH@Example.ORG"])
def test_email_in_two_person_files_fails(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key], email: str
) -> None:
    """DESIGN.md, Person file: an email may appear in only one file, ignoring case."""
    tree.person("dave", keys("dave"), emails=(email,))
    result = check(vouch, tree)
    assert has(
        result.problems, "people/gregkh.json: dave and gregkh both list the email"
    )
    proc = run_script("check", str(tree.root))
    assert proc.returncode == 1
    assert "dave and gregkh both list the email" in proc.stderr


def test_endorsed_emails(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("alice", keys("alice"), keys("alice2"), emails=("Alice@Work.example",))
    tree.endorse(
        "alice",
        keys("alice2"),
        "gregkh",
        keys("gregkh"),
        n=2,
        emails=("alice@work.example", "nobody@example.org"),
    )
    result = check(vouch, tree)
    assert result.problems == []
    assert result.emails["alice"] == ("alice@example.org", "Alice@Work.example")
    assert not has(result.warnings, "alice")


def test_unendorsed_email_warns(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("dave", keys("dave"), emails=("dave@kernel.org",))
    result = check(vouch, tree)
    assert result.problems == []
    assert result.emails["dave"] == ("dave@example.org",)
    assert has(result.warnings, "people/dave.json", "dave@kernel.org", "not endorsed")
    proc = run_script("check", str(tree.root))
    assert proc.returncode == 0, proc.stderr
    assert "warning: people/dave.json: dave@kernel.org is not endorsed" in proc.stderr


def test_void_endorsement_endorses_no_email(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    """A revoked endorser key, a renamed subject or a self-endorsement vouches for nothing."""
    tree.person("dave", keys("dave"), keys("dave2"), emails=("a@x.example",))
    tree.person("carol", keys("carol"))
    tree.endorse("dave", keys("dave"), "carol", keys("carol"), emails=("a@x.example",))
    tree.revoke("carol", keys("carol"), keys("torvalds"))
    tree.endorse(
        "dave", keys("dave"), "dave", keys("dave2"), n=2, emails=("a@x.example",)
    )
    tree.endorse(
        "dave", keys("dave"), "gregkh", keys("gregkh"), n=3, emails=("a@x.example",)
    )
    rel = "endorsements/dave/gregkh-3.json"
    record = json.loads((tree.root / rel).read_bytes())
    record["subjectName"] = "Not Dave"
    del record["@context"]
    tree.write(rel, record, keys("gregkh"), ns="git-vouch-endorse")
    result = check(vouch, tree)
    assert result.problems == []
    assert has(result.voids, "endorsements/dave/carol-1.json", "revoked")
    assert has(
        result.voids, "endorsements/dave/dave-2.json", "cannot endorse themselves"
    )
    assert has(result.voids, rel, "endorses the name")
    assert result.emails["dave"] == ("dave@example.org",)
    assert has(result.warnings, "people/dave.json", "a@x.example", "not endorsed")


def test_accountable_person_is_automation(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("carol", keys("carol"), accountable="gregkh")
    rel = tree.endorse("alice", keys("alice"), "carol", keys("carol"))
    assert has(check(vouch, tree).problems, rel, "automation and cannot endorse")


def test_automation_tier_claim_is_automation(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.person("bot", keys("bot"))
    rel = tree.endorse("alice", keys("alice"), "bot", keys("bot"))
    assert has(check(vouch, tree).problems, rel, "automation and cannot endorse")


def test_invalid_subject_person_file_voids_its_tier(
    vouch: ModuleType, tree: Registry
) -> None:
    path = tree.root / "people/alice.json"
    path.write_bytes(path.read_bytes() + b"\n")
    result = check(vouch, tree)
    assert has(result.voids, "tiers/alice.json", "person file of alice is invalid")
    assert "alice" not in result.tiers


def test_accountable_without_valid_tier_voids_automation(
    vouch: ModuleType, tree: Registry, keys: Callable[[str], Key]
) -> None:
    tree.tier("bot", "automation", "torvalds", keys("torvalds"))
    path = tree.root / "people/gregkh.json"
    path.write_bytes(path.read_bytes() + b"\n")
    result = check(vouch, tree)
    assert has(result.voids, "tiers/bot.json", "gregkh has no valid tier")
    assert "bot" not in result.tiers


def test_unprintable_file_name_escaped(tree: Registry) -> None:
    (tree.root / "tiers/x\x1b[2K\rfake.json").write_text("x")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "check", str(tree.root)], capture_output=True
    )
    assert result.returncode == 1
    assert b"\x1b" not in result.stderr and b"\r" not in result.stderr
    assert b"tiers/'x\\x1b[2K\\rfake.json': unexpected file" in result.stderr

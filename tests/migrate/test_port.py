"""Tests for ``git-vouch-migrate port``: person-file drafts from a frozen pgpkeys.git."""

from __future__ import annotations

import base64
import json
import re
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from .conftest import Ported, Pgpkeys, run_migrate

# Real `gpg --with-colons --fixed-list-mode --list-keys` output for key 4A55C497F744F705
# in kernel.org pgpkeys.git at af88128 (gpg 2.4.4). The second user ID is stored as
# Latin-1, which gpg prints as raw bytes; the last subkey is an RSA auth subkey.
TOKE_LISTING = (
    b"pub:-:4096:1:4A55C497F744F705:1254224384:::-:::scESCA::::::23::0:\n"
    b"fpr:::::::::DE6162B5616BA9C9CAAC03074A55C497F744F705:\n"
    b"uid:-::::1254225361::DAE1213A33A1912544622223DEA25CE02D212561::"
    b"Toke H\xc3\xb8iland-J\xc3\xb8rgensen <toke@toke.dk>::::::::::0:\n"
    b"uid:-::::1254436103::F9CE85F6CBFD7011C8318DBF4E373959E9324987::"
    b"Toke H\xf8iland-J\xf8rgensen <toke@tohojo.dk>::::::::::0:\n"
    b"uid:-::::1254225297::2639847E42B838E0E5114670190C51AFC09B1E7E::"
    b"Toke H\xc3\xb8iland-J\xc3\xb8rgensen <tohojo@ruc.dk>::::::::::0:\n"
    b"uid:-::::1254436708::5BB9504785E4BDFB1A528C5657D2548881DE3267::"
    b"Toke H\xc3\xb8iland-J\xc3\xb8rgensen <toke@tohojo.dk>::::::::::0:\n"
    b"sub:-:2048:1:435E106CF5FAEB4F:1348853434::::::s::::::23:\n"
    b"fpr:::::::::10B21313305272727D6AD09B435E106CF5FAEB4F:\n"
    b"sub:-:2048:1:1DB11C119F80C56F:1562170323::::::a::::::23:\n"
    b"fpr:::::::::76D02A1074A147D4C80C0C2B1DB11C119F80C56F:\n"
)
TOKE = "Toke H\u00f8iland-J\u00f8rgensen"


def drafts(ported: Ported) -> dict[str, dict[str, Any]]:
    """Return the written drafts by their migratedFrom fingerprint."""
    out = {}
    for path in (ported.out / "people").iterdir():
        obj = json.loads(path.read_bytes())
        assert path.name == obj["handle"] + ".json"
        out[obj["migratedFrom"].removeprefix("openpgp4fpr:")] = obj
    return out


def ssh_fields(line: str) -> list[bytes]:
    """Split an SSH public key line's base64 blob into its length-prefixed strings."""
    blob = base64.b64decode(line.split()[1])
    fields = []
    while blob:
        n = int.from_bytes(blob[:4], "big")
        fields.append(blob[4 : 4 + n])
        blob = blob[4 + n :]
    return fields


def test_parse_listing_decodes_latin1_uid(migrate: ModuleType) -> None:
    (key,) = migrate.parse_listing(TOKE_LISTING)
    assert key.fpr == "DE6162B5616BA9C9CAAC03074A55C497F744F705"
    assert key.created == 1254224384
    assert key.uids[1] == f"{TOKE} <toke@tohojo.dk>"
    # Its live 2048-bit RSA auth subkey is an accepted SSH key.
    assert key.auth == ("76D02A1074A147D4C80C0C2B1DB11C119F80C56F",)


def test_name_and_emails_dedupes_across_encodings(migrate: ModuleType) -> None:
    (key,) = migrate.parse_listing(TOKE_LISTING)
    name, emails = migrate._name_and_emails(key)
    assert name == TOKE
    assert emails == ["toke@toke.dk", "toke@tohojo.dk", "tohojo@ruc.dk"]


def _key(migrate: ModuleType, fpr_char: str) -> Any:
    return migrate.GpgKey(fpr_char * 40, 0, "-", (), ())


def test_handles_lowest_fingerprint_wins_then_numbered(migrate: ModuleType) -> None:
    a, b, c, d = (_key(migrate, ch) for ch in "ABCD")
    handles = migrate.assign_handles(
        [
            (c, ["sam@example.org"]),
            (a, ["sam@example.com"]),
            (b, ["sam-2@example.net"]),  # already wants the first suffix
            (d, ["sam@example.edu"]),
        ]
    )
    assert handles == {a.fpr: "sam", b.fpr: "sam-2", c.fpr: "sam-3", d.fpr: "sam-4"}


def test_handles_kernel_org_address_preferred_and_wins(migrate: ModuleType) -> None:
    a, b = _key(migrate, "A"), _key(migrate, "B")
    handles = migrate.assign_handles(
        [(a, ["kim@example.com"]), (b, ["k.b+x@example.org", "kim@kernel.org"])]
    )
    assert handles == {b.fpr: "kim", a.fpr: "kim-2"}


def test_handles_from_awkward_local_parts(migrate: ModuleType) -> None:
    a, b = _key(migrate, "A"), _key(migrate, "B")
    handles = migrate.assign_handles(
        [(a, ["first.last+lkml@example.org"]), (b, ["_x" + "y" * 50 + "@example.org"])]
    )
    assert handles == {a.fpr: "first-last-lkml", b.fpr: "x" + "y" * 38}


def test_port_report_counts(ported: Ported) -> None:
    summary = ported.stdout.splitlines()[-1]
    assert summary == (
        "keys 24, live 19, expired 4, kernel.org list keys 1 (1 live), people 16, "
        "drafts 16, "
        "live keys with a reusable auth subkey 6 (6 in drafts)"
    )
    fprs = ported.pgp.fprs
    assert f"skip {fprs['frank']}: revoked" in ported.stdout
    assert f"skip {fprs['fireant']}: not a person" in ported.stdout
    assert (
        f"merge {fprs['dave_old']}: same person as {fprs['dave_new']}" in ported.stdout
    )


def test_port_writes_one_draft_per_person(ported: Ported) -> None:
    fprs = ported.pgp.fprs
    got = drafts(ported)
    want = {"signer", "alice", "bob", "carol", "dave_new", "eve", "gina_old"}
    want |= {"sam1", "sam2", "hank_new", "rhea", "boris", "tim", "pia", "olga_old"}
    want |= {"nora"}
    assert set(got) == {fprs[k] for k in want}
    assert got[fprs["dave_new"]]["handle"] == "dave"
    assert set(got[fprs["dave_new"]]["emails"]) == {
        "dave@example.net",
        "dave@kernel.org",
    }
    low, high = sorted([fprs["sam1"], fprs["sam2"]])
    assert (got[low]["handle"], got[high]["handle"]) == ("sam", "sam-2")


def test_port_drafts_expired_but_not_revoked_key(ported: Ported) -> None:
    fprs = ported.pgp.fprs
    eve = drafts(ported)[fprs["eve"]]
    assert eve["migratedFrom"] == "openpgp4fpr:" + fprs["eve"]
    assert (eve["handle"], eve["emails"]) == ("eve", ["eve@example.org"])
    assert eve["keys"] == []  # its auth subkey expired with the primary
    assert f"skip {fprs['eve']}" not in ported.stdout
    assert fprs["frank"] not in drafts(ported)
    assert not any("frank@example.org" in d["emails"] for d in drafts(ported).values())


def test_port_prefers_unexpired_key_of_one_person(ported: Ported) -> None:
    fprs = ported.pgp.fprs
    assert fprs["gina_new"] not in drafts(ported)
    assert drafts(ported)[fprs["gina_old"]]["handle"] == "gina"
    assert (
        f"merge {fprs['gina_new']}: same person as {fprs['gina_old']}" in ported.stdout
    )


def test_port_uses_newest_key_when_all_expired(ported: Ported) -> None:
    fprs = ported.pgp.fprs
    assert fprs["hank_old"] not in drafts(ported)
    assert drafts(ported)[fprs["hank_new"]]["handle"] == "hank"
    assert (
        f"merge {fprs['hank_old']}: same person as {fprs['hank_new']}" in ported.stdout
    )


def test_port_drafts_neither_key_when_names_differ(ported: Ported) -> None:
    fprs = ported.pgp.fprs
    for who in ("victor", "mallory"):
        assert f"conflict {fprs[who]}: shares an email" in ported.stdout
        assert fprs[who] not in drafts(ported)
    assert not any("victor@example.com" in d["emails"] for d in drafts(ported).values())


def test_port_names_and_unrevoked_emails(ported: Ported) -> None:
    alice = drafts(ported)[ported.pgp.fprs["alice"]]
    assert alice["@context"] == ["https://w3id.org/git-vouch/v1"]
    assert alice["handle"] == "alice"
    assert alice["name"] == "Alice Example"
    assert alice["emails"] == [
        "alice@example.org",
        "alice@kernel.org",
    ]  # primary UID first


def _auth_subkey(pgp: Pgpkeys, primary: str) -> bytes:
    (point,) = [p for f, p in pgp.points[primary].items() if f != primary]
    return point


@pytest.mark.parametrize(
    ("person", "key_type", "point_prefix"),
    [("alice", "ssh-ed25519", b"\x40"), ("bob", "ecdsa-sha2-nistp256", b"")],
)
def test_port_derives_ssh_key_from_auth_subkey(
    ported: Ported, tmp_path: Path, person: str, key_type: str, point_prefix: bytes
) -> None:
    fpr = ported.pgp.fprs[person]
    (key,) = drafts(ported)[fpr]["keys"]
    assert key["added"] == "2020-06-01T00:00:00Z"
    assert key["retired"] is None
    assert key["ssh"].split()[0] == key_type
    # The SSH key's point must be the one in gpg's own dump of the subkey packet.
    assert point_prefix + ssh_fields(key["ssh"])[-1] == _auth_subkey(ported.pgp, fpr)
    pub = tmp_path / "k.pub"
    pub.write_text(key["ssh"] + "\n")
    subprocess.run(
        ["ssh-keygen", "-l", "-f", str(pub)], check=True, capture_output=True
    )


def test_port_skips_auth_subkey_on_other_curves(ported: Ported) -> None:
    assert drafts(ported)[ported.pgp.fprs["carol"]]["keys"] == []


def test_port_derives_ssh_key_from_rsa_auth_subkey(
    ported: Ported, tmp_path: Path
) -> None:
    fpr = ported.pgp.fprs["rhea"]
    (key,) = drafts(ported)[fpr]["keys"]
    assert key["ssh"].split()[0] == "ssh-rsa"
    # e and n must be the ones in gpg's own dump of the subkey packet.
    out = ported.pgp.gpg("--with-colons", "--with-key-data", "--list-keys", fpr)
    rows = [ln.split(":") for ln in out.decode().splitlines()]
    sub = next(i for i, f in enumerate(rows) if f[0] == "sub")
    pkd = {f[1]: int(f[3], 16) for f in rows[sub:] if f[0] == "pkd"}
    _, e, n = ssh_fields(key["ssh"])
    assert (int.from_bytes(e, "big"), int.from_bytes(n, "big")) == (pkd["1"], pkd["0"])
    pub = tmp_path / "k.pub"
    pub.write_text(key["ssh"] + "\n")
    subprocess.run(
        ["ssh-keygen", "-l", "-f", str(pub)], check=True, capture_output=True
    )


def test_port_prefers_ed25519_over_rsa_auth_subkey(ported: Ported) -> None:
    (key,) = drafts(ported)[ported.pgp.fprs["boris"]]["keys"]
    assert key["ssh"].split()[0] == "ssh-ed25519"


def test_port_derives_ssh_key_from_auth_capable_primary(ported: Ported) -> None:
    fpr = ported.pgp.fprs["pia"]
    (key,) = drafts(ported)[fpr]["keys"]
    assert key["ssh"].split()[0] == "ssh-ed25519"
    # The point must be the primary's, from gpg's own dump of the key packet.
    assert b"\x40" + ssh_fields(key["ssh"])[-1] == ported.pgp.points[fpr][fpr]


def test_port_prefers_key_with_auth_over_newer_key(ported: Ported) -> None:
    fprs = ported.pgp.fprs
    got = drafts(ported)
    assert fprs["olga_new"] not in got
    (key,) = got[fprs["olga_old"]]["keys"]
    assert key["ssh"].split()[0] == "ssh-ed25519"
    assert f"merge {fprs['olga_new']}: same person as {fprs['olga_old']}" in (
        ported.stdout
    )


def test_port_joins_name_only_and_email_only_uids(
    ported: Ported, migrate: ModuleType
) -> None:
    fpr = ported.pgp.fprs["nora"]
    draft = drafts(ported)[fpr]
    assert draft["name"] == "Nora Nameonly"
    assert draft["emails"] == ["nora@example.org", "nora2@example.org"]
    # Continuity checks emails against the same user IDs, so it must see both.
    (key,) = migrate.parse_listing(
        ported.pgp.gpg("--with-colons", "--fixed-list-mode", "--list-keys", fpr)
    )
    assert set(draft["emails"]) <= migrate._all_emails(key)


def test_port_skips_and_names_unimportable_files(ported: Ported) -> None:
    lines = ported.stdout.splitlines()
    v3 = "skip keys/v3key.asc: 1 PGP-2 (v3) key(s), which gpg no longer imports"
    assert v3 in lines
    (orphan,) = [
        ln for ln in lines if ln.startswith("skip keys/orphan-revocation.asc: ")
    ]
    assert "gpg failed: " in orphan and "revocation" in orphan
    assert "faked system time" not in orphan


def test_gpg_error_skips_exit_notices(migrate: ModuleType) -> None:
    # gpg 2.4's stderr importing an Apache KEYS file with an orphan revocation
    # certificate (key id replaced): the agent notice comes after the cause.
    stderr = (
        b"gpg: WARNING: running with faked system time: 2026-10-23 03:27:40\n"
        b"gpg: key 0123456789ABCDEF: no public key - can't apply revocation"
        b" certificate\n"
        b"gpg: no gpg-agent running in this session\n"
    )
    assert migrate.gpg_error(stderr) == (
        "gpg: key 0123456789ABCDEF: no public key - can't apply revocation certificate"
    )


def test_port_skips_rsa_auth_subkey_below_2048(ported: Ported) -> None:
    assert drafts(ported)[ported.pgp.fprs["tim"]]["keys"] == []


# sam1 is revoked, sam2 expired at the freeze commit.
@pytest.mark.parametrize("person", ["sam1", "sam2"])
def test_port_skips_auth_subkey_not_live_at_freeze_commit(
    ported: Ported, person: str
) -> None:
    assert drafts(ported)[ported.pgp.fprs[person]]["keys"] == []


def test_every_draft_is_a_valid_person_file(
    ported: Ported, vouch: ModuleType, ed25519_key: Any
) -> None:
    emails: list[str] = []
    for obj in drafts(ported).values():
        emails += obj["emails"]
        if not obj["keys"]:  # the holder adds their SSH key before signing
            obj["keys"] = [{"ssh": ed25519_key.pubkey, "added": "2026-11-01T00:00:00Z"}]
        data = json.dumps(obj, indent=2, ensure_ascii=False).encode()
        vouch.parse_record(f"people/{obj['handle']}.json", data)
    assert len(emails) == len(set(emails))


def test_port_refuses_unsigned_commit(pgpkeys: Pgpkeys, tmp_path: Path) -> None:
    proc = run_migrate(
        "port", str(pgpkeys.repo), "--commit", pgpkeys.unsigned,
        "--signer", pgpkeys.fprs["signer"], "--out", str(tmp_path / "out"),
    )  # fmt: skip
    assert proc.returncode == 1
    assert "has no good signature" in proc.stderr
    assert not (tmp_path / "out").exists()


def test_port_refuses_other_signer(pgpkeys: Pgpkeys, tmp_path: Path) -> None:
    proc = run_migrate(
        "port", str(pgpkeys.repo), "--commit", pgpkeys.commit,
        "--signer", pgpkeys.fprs["alice"].lower(), "--out", str(tmp_path / "out"),
    )  # fmt: skip
    assert proc.returncode == 1
    assert re.search(
        f"signed by {pgpkeys.fprs['signer']}, not {pgpkeys.fprs['alice']}", proc.stderr
    )


def test_port_refuses_signing_subkey_as_signer(
    pgpkeys: Pgpkeys, tmp_path: Path
) -> None:
    proc = run_migrate(
        "port", str(pgpkeys.repo), "--commit", pgpkeys.commit,
        "--signer", pgpkeys.signing_subkey, "--out", str(tmp_path / "out"),
    )  # fmt: skip
    assert proc.returncode == 1
    assert (
        f"signed by {pgpkeys.fprs['signer']}, not {pgpkeys.signing_subkey}"
        in proc.stderr
    )


@pytest.mark.parametrize(
    ("signer", "make_out", "message"),
    [
        ("B6C41CE35664996C", False, "--signer: must be a 40-hex fingerprint"),
        ("0" * 40, True, "already exists"),
    ],
)
def test_port_argument_errors(
    pgpkeys: Pgpkeys, tmp_path: Path, signer: str, make_out: bool, message: str
) -> None:
    out = tmp_path / "out"
    if make_out:
        out.mkdir()
    proc = run_migrate(
        "port", str(pgpkeys.repo), "--commit", pgpkeys.commit,
        "--signer", signer, "--out", str(out),
    )  # fmt: skip
    assert proc.returncode == 1
    assert message in proc.stderr

"""Tests for ``git-vouch-migrate drafts --as``: endorsement drafts from GPG certifications."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

import pytest

from .conftest import C_DATE, T0, Gpg, _created, _git, run_migrate
from .test_continuity import gpg_sign, ssh_sign, write_person

VOUCH = Path(__file__).resolve().parent.parent.parent / "git-vouch"
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


class Certified(NamedTuple):
    """A signed pgpkeys.git whose keys certify each other, and a registry built on it."""

    repo: Path
    commit: str
    fprs: dict[str, str]
    gpg: Gpg
    ssh: dict[str, tuple[Path, str]]  # handle -> (private key file, public key text)
    registry: Path


def _certify(gpg: Gpg, by: str, fpr: str, at: str, *extra: str) -> None:
    gpg("-u", by + "!", *extra, "--quick-sign-key", fpr, at=at)


def _edit_key(gpg: Gpg, fpr: str, script: str, *extra: str, at: str = T0) -> None:
    """Run gpg --edit-key on ``fpr``, answering its prompts from ``script``."""
    cmd = ["gpg", "--homedir", str(gpg.home), "--batch", "--no-tty", "--quiet"]
    cmd += ["--passphrase", "", "--pinentry-mode", "loopback", "--faked-system-time"]
    cmd += [at + "!", *extra, "--command-fd", "0", "--edit-key", fpr]
    subprocess.run(cmd, input=script.encode(), check=True, capture_output=True)


def _forge(gpg: Gpg, relay: Gpg, by: str, fpr: str) -> bytes:
    """Certify ``fpr`` as ``by``, then return the key armored with that signature broken.

    The certification is the only packet the export gains, and an RSA
    signature packet ends with its signature MPI, so flipping the last bit
    breaks the signature and leaves the packet parseable.
    """
    before = gpg("--export", fpr)
    _certify(gpg, by, fpr, "20200102T000000")
    after = gpg("--export", fpr)
    at = next((i for i, (x, y) in enumerate(zip(before, after)) if x != y), len(before))
    end = at + len(after) - len(before)
    assert after[:at] + after[end:] == before
    broken = bytearray(after)
    broken[end - 1] ^= 1
    path = relay.home / "broken.gpg"
    path.write_bytes(broken)
    relay("--import", str(path))
    return relay("--armor", "--export", fpr)


@pytest.fixture(scope="module")
def certified(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Certified]:
    """Return pgpkeys at a signed C where cora certified some keys, and a registry."""
    base = tmp_path_factory.mktemp("certified")
    home = base / "gnupg"
    home.mkdir(mode=0o700)
    gpg = Gpg(home)
    try:
        # cora's key is RSA, so it can make a SHA-1 certification (EdDSA cannot).
        cora = _created(
            gpg("--status-fd", "1", "--yes", "--quick-gen-key",
                "Cora Certifier <cora@example.org>", "rsa2048", "cert,sign", "never")
        )  # fmt: skip
        fprs = {
            "signer": gpg.new_key("Sig Ner <signer@kernel.org>", expire="1y"),
            "cora": cora,
            "alice": gpg.new_key("Alice Example <alice@example.org>"),
            "bob": gpg.new_key("Bob Builder <bob@example.net>"),
            "carol": gpg.new_key("Carol Jones <carol@example.com>"),
            "dave": gpg.new_key("Dave Davis <dave@example.net>"),
            "erin": gpg.new_key("Erin Noproof <erin@example.org>"),
            "frank": gpg.new_key("Frank Twice <frank@example.org>"),
            "gus": gpg.new_key("Gus Uncertified <gus@example.org>"),
            "hank": gpg.new_key("Hank Photo <hank@example.org>"),
            "ivan": gpg.new_key("Ivan Forged <ivan@example.org>"),
            "judy": gpg.new_key("Judy Revoked <judy@example.org>"),
            "kim": gpg.new_key("Kim Tied <kim@example.org>"),
            "nell": gpg.new_key("Nell Split"),
            # Another GPG key of erin's, not the one in her migratedFrom.
            "erin_alt": gpg.new_key("Erin Noproof <erin@example.net>"),
            "lou": gpg.new_key("Lou Live <lou@example.org>"),
            "max": gpg.new_key("Max Lapsed <max@example.org>"),
        }
        # erin, who has no continuity proof, certifies lou, and max with a
        # certification that expired before C; her other key certifies nell.
        _certify(gpg, fprs["erin"], fprs["lou"], "20200102T000000")
        _certify(gpg, fprs["erin"], fprs["max"], "20200102T000000",
                 "--default-cert-expire", "1d")  # fmt: skip
        _certify(gpg, fprs["erin_alt"], fprs["nell"], "20200102T000000")
        # Only nell's bare-address user ID is certified.
        gpg("--quick-add-uid", fprs["nell"], "nell@example.org")
        gpg("-u", cora + "!", "--quick-sign-key", fprs["nell"], "nell@example.org",
            at="20200102T000000")  # fmt: skip
        gpg("--quick-add-uid", fprs["alice"], "Alice Example <alice@kernel.org>")
        gpg("--quick-add-uid", fprs["frank"], "Frank Twice <frank@kernel.org>")
        # Only alice's first user ID is certified.
        gpg("-u", cora + "!", "--quick-sign-key", fprs["alice"],
            "Alice Example <alice@example.org>", at="20200102T000000")  # fmt: skip
        _certify(gpg, cora, fprs["bob"], "20200103T000000",
                 "--cert-digest-algo", "SHA1", "--allow-weak-key-signatures")  # fmt: skip
        _certify(gpg, cora, fprs["carol"], "20200102T000000")
        gpg("--quick-revoke-sig", fprs["carol"], cora, at="20200104T000000")
        _certify(gpg, cora, fprs["dave"], "20200102T000000")
        gpg("--quick-revoke-sig", fprs["dave"], cora, at="20200103T000000")
        _certify(gpg, cora, fprs["dave"], "20200104T000000", "--force-sign-key")
        for name in ("erin", "frank"):
            _certify(gpg, cora, fprs[name], "20200102T000000")
        _certify(gpg, fprs["alice"], fprs["gus"], "20200102T000000")
        # Only hank's photo ID (his second user ID slot) is certified.
        photo = base / "photo.jpg"  # a minimal JFIF file, which gpg accepts
        photo.write_bytes(bytes.fromhex("ffd8ffe000104a46494600010100000100010000ffd9"))
        _edit_key(gpg, fprs["hank"], f"addphoto\n{photo}\ny\nsave\n")
        _edit_key(gpg, fprs["hank"], "uid 2\nsign\ny\nsave\n", "-u", cora + "!",
                  at="20200102T000000")  # fmt: skip
        relay = Gpg(base / "relay")
        relay.home.mkdir(mode=0o700)
        forged = _forge(gpg, relay, cora, fprs["ivan"])
        # judy revokes her second user ID after cora certified both.
        gpg("--quick-add-uid", fprs["judy"], "Judy Revoked <judy@kernel.org>")
        _certify(gpg, cora, fprs["judy"], "20200102T000000")
        gpg("--quick-revoke-uid", fprs["judy"], "Judy Revoked <judy@kernel.org>",
            at="20200105T000000")  # fmt: skip
        _certify(gpg, cora, fprs["kim"], "20200102T000000")
        gpg("--quick-revoke-sig", fprs["kim"], cora, at="20200102T000000")

        repo = base / "pgpkeys.git"
        (repo / "keys").mkdir(parents=True)
        for fpr in fprs.values():
            armored = forged if fpr == fprs["ivan"] else gpg("--armor", "--export", fpr)
            (repo / "keys" / f"{fpr[-16:]}.asc").write_bytes(armored)
        env = dict(
            os.environ,
            GNUPGHOME=str(home),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_DATE=C_DATE,
            GIT_COMMITTER_DATE=C_DATE,
        )
        (home / "gpg.conf").write_text("faked-system-time 20200601T000000!\n")
        ident = ["-c", "user.name=Sig Ner", "-c", "user.email=signer@kernel.org"]
        sign = ["-c", "gpg.format=openpgp", "-c", "gpg.program=gpg"]
        sign += ["-c", f"user.signingkey={fprs['signer']}!"]
        _git(repo, "init", "-q", env=env)
        _git(repo, "add", "keys", env=env)
        _git(repo, *ident, *sign, "commit", "-q", "-S", "-m", "freeze", env=env)
        commit = _git(repo, "rev-parse", "HEAD", env=env)
        (home / "gpg.conf").unlink()

        ssh: dict[str, tuple[Path, str]] = {}
        registry = base / "registry"
        people = [  # handle, claimed key, emails, whether a .asc proves it
            ("cora", "cora", ["cora@example.org"], True),
            ("alice", "alice", ["alice@example.org", "alice@kernel.org"], True),
            ("bob", "bob", ["bob@example.net"], True),
            ("carol", "carol", ["carol@example.com"], True),
            ("dave", "dave", ["dave@example.net"], True),
            ("erin", "erin", ["erin@example.org"], False),
            ("frank", "frank", ["frank@example.org"], True),
            ("frank2", "frank", ["frank@kernel.org"], True),
            ("gus", "gus", ["gus@example.org"], True),
            ("hank", "hank", ["hank@example.org"], True),
            ("ivan", "ivan", ["ivan@example.org"], True),
            ("judy", "judy", ["judy@example.org"], True),
            ("kim", "kim", ["kim@example.org"], True),
            ("nell", "nell", ["nell@example.org"], True),
            ("lou", "lou", ["lou@example.org"], True),
            ("max", "max", ["max@example.org"], True),
            ("zoe", None, ["zoe@example.org"], False),  # registered fresh
        ]
        for handle, owner, emails, has_proof in people:
            private = base / f"{handle}.ssh"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", handle,
                 "-f", str(private)],
                check=True,
            )  # fmt: skip
            pub = private.with_name(private.name + ".pub").read_text().split()
            ssh[handle] = (private, " ".join(pub[:2]))
            fpr = None if owner is None else fprs[owner]
            path = write_person(registry, handle, fpr, emails, [ssh[handle][1]])
            ssh_sign(path, private)
            if has_proof and fpr is not None:
                gpg_sign(Certified(repo, commit, fprs, gpg, ssh, registry), path, fpr)
        yield Certified(repo, commit, fprs, gpg, ssh, registry)
    finally:
        for gnupg in (home, base / "relay"):
            subprocess.run(
                ["gpgconf", "--homedir", str(gnupg), "--kill", "all"], check=False
            )


def run_drafts(
    c: Certified, registry: Path, handle: str, out: Path
) -> subprocess.CompletedProcess[str]:
    """Run ``git-vouch-migrate drafts`` on the synthetic pgpkeys."""
    return run_migrate(
        "drafts", "--commit", c.commit, "--signer", c.fprs["signer"],
        "--as", handle, "--out", str(out), str(c.repo), str(registry),
    )  # fmt: skip


def drafted(out: Path) -> set[str]:
    """Return every draft path below ``out``, relative to it."""
    return {p.relative_to(out).as_posix() for p in out.rglob("*.json")}


@pytest.fixture(scope="module")
def cora_drafts(certified: Certified, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Run ``drafts --as cora`` once on the registry; return the output directory."""
    out = tmp_path_factory.mktemp("drafts") / "out"
    proc = run_drafts(certified, certified.registry, "cora", out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


def test_drafts_only_for_certified_subjects_with_proven_continuity(
    cora_drafts: Path,
) -> None:
    # carol: certification revoked; erin: no proof; frank, frank2: duplicate
    # claim; gus: certified only by alice; hank: only his photo ID certified;
    # ivan: certification does not verify; kim: revoked at the same second;
    # cora: herself.
    assert drafted(cora_drafts) == {
        "endorsements/alice/cora-1.json",
        "endorsements/bob/cora-1.json",
        "endorsements/dave/cora-1.json",
        "endorsements/judy/cora-1.json",
        "endorsements/nell/cora-1.json",
    }


def test_draft_binds_certified_emails_and_notes_the_certification(
    certified: Certified, cora_drafts: Path, vouch: ModuleType
) -> None:
    alice = certified.fprs["alice"]
    draft = json.loads((cora_drafts / "endorsements/alice/cora-1.json").read_text())
    date = draft.pop("date")
    assert DATE_RE.fullmatch(date)
    assert draft == {
        "@context": ["https://w3id.org/git-vouch/v1"],
        "endorser": "cora",
        "endorserKey": vouch.ssh_to_did(certified.ssh["cora"][1]),
        "subject": "alice",
        "subjectKey": vouch.ssh_to_did(certified.ssh["alice"][1]),
        "subjectName": "Alice",
        "subjectEmails": ["alice@example.org"],
        "note": f'Certified GPG key {alice} user ID "Alice Example '
        f'<alice@example.org>" on 2020-01-02.',
    }


def _cora_sigs(c: Certified, subject: str) -> list[list[str]]:
    """Return gpg's own listing of cora's signatures on ``subject``'s user IDs."""
    out = c.gpg("--with-colons", "--fixed-list-mode", "--list-sigs", c.fprs[subject])
    rows = [ln.split(":") for ln in out.decode().splitlines()]
    return [f for f in rows if f[0] in ("sig", "rev") and f[4] == c.fprs["cora"][-16:]]


def test_bare_address_certification_is_drafted(
    certified: Certified, cora_drafts: Path
) -> None:
    # nell's other user ID has no email, so only the bare one can yield a draft.
    draft = json.loads((cora_drafts / "endorsements/nell/cora-1.json").read_text())
    assert draft["subjectEmails"] == ["nell@example.org"]


def test_sha1_certification_is_drafted(certified: Certified, cora_drafts: Path) -> None:
    # gpg's hash algorithm 2 is SHA-1 (RFC 4880, 9.4).
    assert [f[15] for f in _cora_sigs(certified, "bob")] == ["2"]
    draft = json.loads((cora_drafts / "endorsements/bob/cora-1.json").read_text())
    assert draft["subjectEmails"] == ["bob@example.net"]
    assert draft["note"].endswith(" on 2020-01-03.")


def test_revoked_certification_is_not_drafted(
    certified: Certified, cora_drafts: Path
) -> None:
    assert sorted(f[10][:3] for f in _cora_sigs(certified, "carol")) == ["10x", "30x"]
    assert not (cora_drafts / "endorsements/carol").exists()


def test_certification_renewed_after_revocation_is_drafted(
    certified: Certified, cora_drafts: Path
) -> None:
    kinds = sorted(f[10][:3] for f in _cora_sigs(certified, "dave"))
    assert kinds == ["10x", "10x", "30x"]
    draft = json.loads((cora_drafts / "endorsements/dave/cora-1.json").read_text())
    assert draft["note"].endswith(" on 2020-01-04.")


def test_photo_id_certification_is_not_drafted(
    certified: Certified, cora_drafts: Path
) -> None:
    out = certified.gpg(
        "--with-colons", "--fixed-list-mode", "--list-sigs", certified.fprs["hank"]
    )
    parent, signed = "", []
    for f in (ln.split(":") for ln in out.decode().splitlines()):
        if f[0] in ("uid", "uat"):
            parent = f[0]
        elif f[0] == "sig" and f[4] == certified.fprs["cora"][-16:]:
            signed.append(parent)
    assert signed == ["uat"]
    assert not (cora_drafts / "endorsements/hank").exists()


def test_unverified_certification_is_not_drafted(
    certified: Certified, cora_drafts: Path, tmp_path: Path
) -> None:
    fresh = Gpg(tmp_path / "gnupg")
    fresh.home.mkdir(mode=0o700)
    try:
        for path in sorted((certified.repo / "keys").glob("*.asc")):
            fresh("--import", str(path))
        out = fresh(
            "--with-colons", "--fixed-list-mode", "--check-sigs",
            certified.fprs["ivan"],
        )  # fmt: skip
    finally:
        subprocess.run(
            ["gpgconf", "--homedir", str(fresh.home), "--kill", "all"], check=False
        )
    rows = [ln.split(":") for ln in out.decode().splitlines()]
    cora = [
        f[1] for f in rows if f[0] == "sig" and f[4] == certified.fprs["cora"][-16:]
    ]
    assert cora == ["-"]
    assert not (cora_drafts / "endorsements/ivan").exists()


def test_certification_on_revoked_user_id_is_not_drafted(
    certified: Certified, cora_drafts: Path
) -> None:
    out = certified.gpg(
        "--with-colons", "--fixed-list-mode", "--list-sigs", certified.fprs["judy"]
    )
    uids = [f for f in (ln.split(":") for ln in out.decode().splitlines())
            if f[0] == "uid"]  # fmt: skip
    assert [(f[1], f[9]) for f in uids] == [
        ("u", "Judy Revoked <judy@example.org>"),
        ("r", "Judy Revoked <judy@kernel.org>"),
    ]
    assert len(_cora_sigs(certified, "judy")) == 2
    draft = json.loads((cora_drafts / "endorsements/judy/cora-1.json").read_text())
    assert draft["subjectEmails"] == ["judy@example.org"]
    assert "kernel.org" not in draft["note"]


def test_revocation_as_new_as_certification_cancels_it(
    certified: Certified, cora_drafts: Path
) -> None:
    sigs = sorted((f[10][:3], f[5]) for f in _cora_sigs(certified, "kim"))
    assert [kind for kind, _ in sigs] == ["10x", "30x"]
    assert sigs[0][1] == sigs[1][1]
    assert not (cora_drafts / "endorsements/kim").exists()


def test_certifier_without_proven_continuity_drafts_from_migrated_from_key(
    certified: Certified, tmp_path: Path
) -> None:
    proc = run_migrate(
        "verify-continuity", "--commit", certified.commit,
        "--signer", certified.fprs["signer"], str(certified.repo),
        str(certified.registry), "erin",
    )  # fmt: skip
    assert proc.returncode == 1
    assert "fail erin: no people/erin.json.asc" in proc.stdout
    out = tmp_path / "out"
    proc = run_drafts(certified, certified.registry, "erin", out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # Not nell: erin_alt, erin's other GPG key, certified her.
    assert drafted(out) == {
        "endorsements/lou/erin-1.json",
        "endorsements/max/erin-1.json",
    }


def test_certification_expired_by_c_is_drafted(
    certified: Certified, tmp_path: Path
) -> None:
    erin = certified.fprs["erin"]
    out = certified.gpg("--with-colons", "--fixed-list-mode", "--list-sigs",
                        certified.fprs["max"])  # fmt: skip
    sigs = [
        f for f in (ln.split(":") for ln in out.decode().splitlines())
        if f[0] == "sig" and f[4] == erin[-16:]
    ]  # fmt: skip
    c_time = int(_git(certified.repo, "show", "-s", "--format=%ct",
                      certified.commit, env=dict(os.environ)))  # fmt: skip
    assert len(sigs) == 1 and sigs[0][6] and int(sigs[0][6]) < c_time
    out_dir = tmp_path / "out"
    proc = run_drafts(certified, certified.registry, "erin", out_dir)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    draft = json.loads((out_dir / "endorsements/max/erin-1.json").read_text())
    assert draft["subjectEmails"] == ["max@example.org"]
    assert "on 2020-01-02." in draft["note"]


def test_certifier_without_migrated_from_fails(
    certified: Certified, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    proc = run_drafts(certified, certified.registry, "zoe", out)
    assert proc.returncode == 1
    assert "--as zoe: no migratedFrom" in proc.stderr
    assert not out.exists()


def test_unregistered_certifier_fails(certified: Certified, tmp_path: Path) -> None:
    out = tmp_path / "out"
    proc = run_drafts(certified, certified.registry, "nobody", out)
    assert proc.returncode == 1
    assert "--as nobody: no validly signed person file" in proc.stderr
    assert not out.exists()


def test_existing_out_directory_is_refused(
    certified: Certified, tmp_path: Path
) -> None:
    proc = run_drafts(certified, certified.registry, "cora", tmp_path)
    assert proc.returncode == 1
    assert "already exists" in proc.stderr


def test_drafts_signed_as_endorsements_pass_check(
    certified: Certified, cora_drafts: Path, tmp_path: Path
) -> None:
    registry = tmp_path / "registry"
    shutil.copytree(certified.registry, registry)
    shutil.copytree(cora_drafts / "endorsements", registry / "endorsements")
    (registry / "anchors.json").write_text('["cora"]\n')
    for path in (registry / "endorsements").rglob("*.json"):
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(certified.ssh["cora"][0]),
             "-n", "git-vouch-endorse", str(path)],
            check=True, capture_output=True,
        )  # fmt: skip
    proc = subprocess.run(
        [sys.executable, str(VOUCH), "check", str(registry)],
        capture_output=True, text=True,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert "error" not in proc.stderr and "void" not in proc.stderr
    for email in ("alice@example.org", "bob@example.net", "dave@example.net",
                  "judy@example.org"):  # fmt: skip
        assert f"{email} is not endorsed" not in proc.stderr
    assert "alice@kernel.org is not endorsed" in proc.stderr

    # A second run numbers the new drafts after the endorsements now present.
    out = tmp_path / "again"
    proc = run_drafts(certified, registry, "cora", out)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert drafted(out) == {
        "endorsements/alice/cora-2.json",
        "endorsements/bob/cora-2.json",
        "endorsements/dave/cora-2.json",
        "endorsements/judy/cora-2.json",
        "endorsements/nell/cora-2.json",
    }

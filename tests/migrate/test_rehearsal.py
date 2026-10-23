"""Flag-day rehearsal: run rehearsal.sh, the runbook, on a synthetic pgpkeys keyring.

The fixture builds the world as it stands on the freeze: a pgpkeys.git of
throwaway GPG keys, with certifications (one SHA-1) and an expired key,
frozen at a commit C that its signer signed; an empty registry; a kernel
tree; and one home per person. rehearsal.sh then runs every runbook step
as those people, and the tests check what came out: gpg made the
certifications and git verify-tag judges the tags, so neither oracle is
git-vouch's own code.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

from .conftest import C_DATE, Gpg, _created, _git

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = Path(__file__).with_name("rehearsal.sh")
OLD = "20180101T000000"  # before every certification below
CERTIFIED = "20200102T000000"  # when lena certifies alice (SHA-1) and dave
BOB_MADE = "20190101T000000"  # bob's key expires a day later, long before C
BOB_CERTIFIED = "20190101T120000"  # while bob's key was still valid
# A line of git vouch check output: a handle and its tier.
TIER_RE = re.compile(r"[a-z0-9_-]+ (anchor|maintainer|contributor|automation|none)")


class Rehearsal(NamedTuple):
    """The world after rehearsal.sh ran, and what it printed."""

    world: Path
    fprs: dict[str, str]
    proc: subprocess.CompletedProcess[str]


def _home(world: Path, handle: str, name: str, email: str, ssh: bool = True) -> Gpg:
    """Make ``handle``'s home with a git identity, an SSH key if ``ssh``; return their gpg."""
    home = world / handle
    (home / ".ssh").mkdir(parents=True)
    (home / "gnupg").mkdir(mode=0o700)
    (home / ".gitconfig").write_text(
        f"[user]\n\tname = {name}\n\temail = {email}\n[init]\n\tdefaultBranch = main\n"
    )
    if ssh:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", email,
             "-f", str(home / ".ssh" / "id_ed25519")],
            check=True,
        )  # fmt: skip
    return Gpg(home / "gnupg")


def _build(world: Path) -> tuple[dict[str, str], str]:
    """Build the frozen pgpkeys.git, the registry and the kernel tree; return (fprs, C)."""
    korg = _home(world, "korg", "Kay Org", "korg@kernel.org", ssh=False)
    lena = _home(world, "lena", "Lena Anchor", "lena@example.org")
    alice = _home(world, "alice", "Alice Example", "alice@example.org")
    bob = _home(world, "bob", "Bob Builder", "bob@example.net")
    dave = _home(world, "dave", "Dave Davis", "dave@example.org", ssh=False)
    _home(world, "carol", "Carol Fresh", "carol@example.com")
    # RSA, so lena can make a SHA-1 certification (EdDSA cannot).
    lena_rsa = _created(lena("--status-fd", "1", "--yes", "--quick-gen-key",
        "Lena Anchor <lena@example.org>", "rsa2048", "cert,sign", "never", at=OLD))  # fmt: skip
    fprs = {
        "korg": korg.new_key("Kay Org <korg@kernel.org>", at=OLD),
        "lena": lena_rsa,
        "alice": alice.new_key("Alice Example <alice@example.org>"),
        "bob": bob.new_key("Bob Builder <bob@example.net>", expire="1d", at=BOB_MADE),
        "dave": dave.new_key("Dave Davis <dave@example.org>"),
    }
    dave.add_key(fprs["dave"], "ed25519", "auth")
    for holder, gpg in (("alice", alice), ("bob", bob), ("dave", dave)):
        exported = world / f"{holder}.gpg"
        exported.write_bytes(gpg("--export", fprs[holder]))
        lena("--import", str(exported))
    certify = ["-u", fprs["lena"] + "!", "--quick-sign-key"]
    lena("--cert-digest-algo", "SHA1", "--allow-weak-key-signatures", *certify,
         fprs["alice"], at=CERTIFIED)  # fmt: skip
    lena(*certify, fprs["bob"], at=BOB_CERTIFIED)
    lena(*certify, fprs["dave"], at=CERTIFIED)
    certified = world / "alice-certified.gpg"
    certified.write_bytes(lena("--export", fprs["alice"]))
    packets = lena("--list-packets", str(certified))
    assert b"digest algo 2," in packets  # 2 is SHA-1 (RFC 4880 9.4)

    repo = world / "pgpkeys.git"
    (repo / "keys").mkdir(parents=True)
    for holder, fpr in fprs.items():
        gpg = korg if holder == "korg" else lena  # lena holds the certified copies
        (repo / "keys" / f"{fpr[-16:]}.asc").write_bytes(
            gpg("--armor", "--export", fpr)
        )
    (korg.home / "gpg.conf").write_text("faked-system-time 20200601T000000!\n")
    env = dict(
        os.environ,
        GNUPGHOME=str(korg.home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_DATE=C_DATE,
        GIT_COMMITTER_DATE=C_DATE,
    )
    ident = ["-c", "user.name=Kay Org", "-c", "user.email=korg@kernel.org"]
    sign = ["-c", "gpg.format=openpgp", "-c", "gpg.program=gpg"]
    sign += ["-c", f"user.signingkey={fprs['korg']}!"]
    _git(repo, "init", "-q", env=env)
    _git(repo, "add", "keys", env=env)
    _git(repo, *ident, *sign, "commit", "-q", "-S", "-m", "freeze", env=env)
    commit = _git(repo, "rev-parse", "HEAD", env=env)

    linux = world / "linux-src"
    linux.mkdir()
    (linux / "README").write_text("Linux kernel\n")
    _git(linux, "init", "-q", "-b", "main", env=env)
    _git(linux, "add", "README", env=env)
    _git(linux, *ident, "commit", "-q", "-m", "Linux 6.98", env=env)
    _git(world, "clone", "-q", "--bare", str(linux), "linux.git", env=env)
    _git(world, "init", "-q", "--bare", "-b", "main", "registry.git", env=env)
    return fprs, commit


@pytest.fixture(scope="module")
def rehearsal(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Rehearsal]:
    """Build the world and run rehearsal.sh in it once."""
    world = tmp_path_factory.mktemp("flagday")
    try:
        fprs, commit = _build(world)
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("GIT_CONFIG_GLOBAL", "GNUPGHOME", "SSH_AUTH_SOCK",
                         "SSH_AGENT_PID", "GPG_AGENT_INFO", "XDG_DATA_HOME",
                         "XDG_CONFIG_HOME", "GIT_DIR")
        }  # fmt: skip
        env.update(
            # The tools on PATH as installed, run by this interpreter's python3.
            PATH=os.pathsep.join(
                (str(ROOT), str(Path(sys.executable).parent), env["PATH"])
            ),
            GIT_CONFIG_NOSYSTEM="1",
            WORLD=str(world),
            C=commit,
            SIGNER=fprs["korg"],
            PGPKEYS=str(world / "pgpkeys.git"),
            REGISTRY=str(world / "registry.git"),
            LINUX=str(world / "linux.git"),
        )
        version = subprocess.run(
            ["python3", "-c", "import sys; print(sys.version_info[:2])"],
            env=env, capture_output=True, text=True, check=True,
        ).stdout.strip()  # fmt: skip
        assert version == str(sys.version_info[:2]), "python3 on PATH is not this one"
        proc = subprocess.run(
            ["bash", str(RUNBOOK)], env=env, capture_output=True, text=True
        )
        yield Rehearsal(world, fprs, proc)
    finally:
        for home in world.glob("*/gnupg"):
            subprocess.run(
                ["gpgconf", "--homedir", str(home), "--kill", "all"], check=False
            )


def test_runbook_completes(rehearsal: Rehearsal) -> None:
    proc = rehearsal.proc
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_every_continuity_proof_holds(rehearsal: Rehearsal) -> None:
    f = rehearsal.fprs
    out = rehearsal.proc.stdout
    assert f"ok lena: openpgp4fpr:{f['lena']} by .asc" in out
    assert f"ok alice: openpgp4fpr:{f['alice']} by .asc" in out
    # bob's key expired before C; his proof was made after extending it locally.
    assert f"ok bob: openpgp4fpr:{f['bob']} by .asc" in out
    assert f"ok dave: openpgp4fpr:{f['dave']} by auth subkey " in out
    assert "fail " not in out


def test_drafts_come_from_the_certifications(rehearsal: Rehearsal) -> None:
    f = rehearsal.fprs
    out = rehearsal.proc.stdout
    assert f"certified by {f['lena']}: 3 drafts" in out
    drafts = rehearsal.world / "lena" / "endorsement-drafts" / "endorsements"
    alice = json.loads((drafts / "alice" / "lena-1.json").read_text())
    assert alice["subjectEmails"] == ["alice@example.org"]
    assert alice["note"] == (
        f'Certified GPG key {f["alice"]} user ID "Alice Example <alice@example.org>"'
        " on 2020-01-02."
    )  # the SHA-1 certification, which GnuPG 2.4 rejects by default
    bob = json.loads((drafts / "bob" / "lena-1.json").read_text())
    assert bob["note"] == (
        f'Certified GPG key {f["bob"]} user ID "Bob Builder <bob@example.net>"'
        " on 2019-01-01."
    )
    assert (drafts / "dave" / "lena-1.json").is_file()


def test_registry_holds_the_signed_records(rehearsal: Rehearsal) -> None:
    files = _git(
        rehearsal.world / "korg" / "registry", "ls-files",
        env=dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull),
    ).split()  # fmt: skip
    for rel in (
        "anchors.json",
        "people/lena.json.asc",
        "people/carol.json.sig",
        "endorsements/alice/lena-1.json.sig",
        "endorsements/bob/lena-1.json.sig",
        "endorsements/dave/lena-1.json.sig",
        "endorsements/carol/alice-1.json.sig",
        "tiers/alice.json.sig",
        "tiers/bob.json.sig",
        "tiers/carol.json.sig",
    ):
        assert rel in files
    assert "people/carol.json.asc" not in files


def test_registry_holds_the_reviewed_drafts(
    rehearsal: Rehearsal, tmp_path: Path
) -> None:
    lena = rehearsal.world / "lena"
    drafts = lena / "endorsement-drafts" / "endorsements"
    signers = tmp_path / "allowed_signers"
    signers.write_text("lena " + (lena / ".ssh" / "id_ed25519.pub").read_text())
    for subject in ("alice", "bob", "dave"):
        signed = rehearsal.world / "korg" / "registry" / "endorsements" / subject
        draft = drafts / subject / "lena-1.json"
        assert (signed / "lena-1.json").read_bytes() == draft.read_bytes()
        subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "lena",
             "-n", "git-vouch-endorse", "-s", str(signed / "lena-1.json.sig")],
            input=draft.read_bytes(), check=True, capture_output=True,
        )  # fmt: skip


def test_check_computes_the_tiers(rehearsal: Rehearsal) -> None:
    tier_lines = [
        ln for ln in rehearsal.proc.stdout.splitlines() if TIER_RE.fullmatch(ln)
    ]
    assert tier_lines[-5:] == [
        "alice maintainer",
        "bob contributor",
        "carol contributor",
        "dave none",
        "lena anchor",
    ]


def test_git_verifies_tags_by_tier(rehearsal: Rehearsal) -> None:
    err = rehearsal.proc.stderr
    assert 'Good "git" signature for alice with ED25519 key' in err
    assert 'Good "git" signature for lena with ED25519 key' in err
    # bob's tag is rejected at maintainer tier and accepted at contributor tier.
    assert err.count('Good "git" signature for bob with ED25519 key') == 1
    assert err.count("No principal matched") == 2  # bob's tag, then alice's for release

"""Fixtures for git-vouch-migrate tests: a throwaway pgpkeys.git made with real gpg."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

import pytest

SCRIPT = Path(__file__).resolve().parent.parent.parent / "git-vouch-migrate"
T0 = "20200101T000000"  # when most synthetic keys are made
FREEZE_DATE = "2020-06-01T00:00:00Z"  # committer date of the freeze commit


class Gpg:
    """A throwaway gpg home for making synthetic keys at faked times."""

    def __init__(self, home: Path) -> None:
        """Use ``home`` as GNUPGHOME."""
        self.home = home

    def __call__(self, *args: str, at: str = T0) -> bytes:
        """Run gpg with the clock frozen at ``at`` and return its stdout.

        Frozen (the ``!``), since gpg keeps a running faked clock in whole
        seconds: a key made at T0 could be stamped T0+1, and a later call at
        T0 would then refuse it as created in the future.
        """
        cmd = ["gpg", "--homedir", str(self.home), "--batch", "--no-tty", "--quiet"]
        cmd += ["--passphrase", "", "--pinentry-mode", "loopback"]
        cmd += ["--faked-system-time", at + "!", *args]
        return subprocess.run(cmd, check=True, capture_output=True).stdout

    def new_key(
        self, uid: str, expire: str = "never", at: str = T0, usage: str = "sign"
    ) -> str:
        """Make an ed25519 primary key with one user ID; return its fingerprint."""
        out = self(
            "--status-fd",
            "1",
            "--yes",
            "--quick-gen-key",
            uid,
            "ed25519",
            usage,
            expire,
            at=at,
        )
        return _created(out)

    def add_key(
        self, fpr: str, algo: str, usage: str, expire: str = "never", at: str = T0
    ) -> str:
        """Add a subkey to key ``fpr``; return the subkey's fingerprint."""
        out = self(
            "--status-fd", "1", "--quick-add-key", fpr, algo, usage, expire, at=at
        )
        return _created(out)

    def revoke_subkey(self, fpr: str, sub: str) -> None:
        """Revoke subkey ``sub`` of key ``fpr`` (gpg has no quick command for it)."""
        cmd = ["gpg", "--homedir", str(self.home), "--batch", "--no-tty", "--quiet"]
        cmd += ["--passphrase", "", "--pinentry-mode", "loopback"]
        cmd += ["--faked-system-time", T0 + "!", "--command-fd", "0", "--edit-key", fpr]
        script = f"key {sub}\nrevkey\ny\n0\n\ny\nsave\n"
        subprocess.run(cmd, input=script.encode(), check=True, capture_output=True)

    def revocation(self, fpr: str) -> bytes:
        """Return the revocation certificate gpg wrote when it made the key, importable."""
        cert = (self.home / "openpgp-revocs.d" / f"{fpr}.rev").read_text()
        return cert.replace(":-----BEGIN", "-----BEGIN").encode()

    def key_data(self, fpr: str) -> dict[str, bytes]:
        """Return each subkey fingerprint's public point, from gpg's key packet dump."""
        out = self("--with-colons", "--with-key-data", "--list-keys", fpr).decode()
        points: dict[str, bytes] = {}
        current = ""
        for line in out.splitlines():
            f = line.split(":")
            if f[0] == "fpr":
                current = f[9]
            elif f[0] == "pkd" and f[1] == "1":
                points[current] = bytes.fromhex(f[3])
        return points


def _v3_key() -> bytes:
    """Return a PGP-2 style (v3) RSA public key and user ID, which gpg 2.4 skips.

    Built from RFC 4880 5.5.2 and 5.11 by hand, since gpg can no longer make
    one; gpg reports it as a skipped PGP-2 key, as it does real ones.
    """

    def mpi(v: int) -> bytes:
        return v.bit_length().to_bytes(2, "big") + v.to_bytes(
            (v.bit_length() + 7) // 8, "big"
        )

    body = bytes([3]) + (946684800).to_bytes(4, "big") + bytes(2) + bytes([1])
    body += mpi((1 << 1023) | 1) + mpi(65537)
    uid = b"Vic Version3 <vic@example.org>"
    return b"\x99" + len(body).to_bytes(2, "big") + body + bytes([0xB4, len(uid)]) + uid


def _created(status: bytes) -> str:
    """Return the fingerprint in gpg's KEY_CREATED status line."""
    (line,) = [ln for ln in status.decode().splitlines() if "KEY_CREATED" in ln]
    return line.split()[-1]


class Pgpkeys(NamedTuple):
    """A synthetic pgpkeys.git and what went into it."""

    repo: Path
    commit: str  # the freeze commit, signed by signing_subkey of fprs["signer"]
    signing_subkey: str
    unsigned: str  # an unsigned commit on top of the freeze commit
    fprs: dict[str, str]
    points: dict[
        str, dict[str, bytes]
    ]  # primary -> {key or subkey fpr: point}, from gpg
    gpg: Gpg  # holds every secret key; frank is revoked only in pgpkeys
    revoked_subkey: str  # carol's signing subkey, revoked only in pgpkeys


class Ported(NamedTuple):
    """The result of running ``git-vouch-migrate port`` on the synthetic pgpkeys."""

    pgp: Pgpkeys
    out: Path
    stdout: str


def run_migrate(*args: str) -> subprocess.CompletedProcess[str]:
    """Run git-vouch-migrate as a subprocess, away from the user's git and gpg config."""
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    env.pop("GNUPGHOME", None)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env
    )


@pytest.fixture(scope="session")
def migrate() -> ModuleType:
    """Return the git-vouch-migrate script loaded as a module."""
    loader = importlib.machinery.SourceFileLoader("git_vouch_migrate", str(SCRIPT))
    spec = importlib.util.spec_from_loader("git_vouch_migrate", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    loader.exec_module(module)
    return module


def _git(repo: Path, *args: str, env: dict[str, str]) -> str:
    out = subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True, capture_output=True
    )
    return out.stdout.decode().strip()


@pytest.fixture(scope="module")
def pgpkeys(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Pgpkeys]:
    """Return a pgpkeys.git whose keys/ cover each case the port must handle."""
    base = tmp_path_factory.mktemp("pgpkeys")
    home = base / "gnupg"
    home.mkdir(mode=0o700)
    gpg = Gpg(home)
    revoker = Gpg(base / "gnupg-revoker")
    revoker.home.mkdir(mode=0o700)
    try:
        fprs = {
            # Expires after the freeze commit but before today: live at the freeze
            # commit, and the freeze commit's signature is good then.
            "signer": gpg.new_key("Sig Ner <signer@kernel.org>", expire="1y"),
            "alice": gpg.new_key("Alice Example <alice@example.org>"),
            "bob": gpg.new_key("Bob Builder <bob@example.net>"),
            "carol": gpg.new_key("Carol Jones <carol@example.com>"),
            "dave_old": gpg.new_key("Dave Davis <dave@example.net>"),
            "dave_new": gpg.new_key(
                "Dave Davis <dave@example.net>", at="20200201T000000"
            ),
            "eve": gpg.new_key(
                "Eve Expired <eve@example.org>", expire="1d", at="20190101T000000"
            ),
            "frank": gpg.new_key("Frank Revoked <frank@example.org>"),
            # One person: an older live key and a newer key expired at the freeze
            # commit.
            "gina_old": gpg.new_key("Gina Green <gina@example.org>"),
            "gina_new": gpg.new_key(
                "Gina Green <gina@example.org>", expire="1d", at="20200201T000000"
            ),
            # One person whose keys both expired before the freeze commit: the
            # newer one is used.
            "hank_old": gpg.new_key(
                "Hank Hill <hank@example.org>", expire="1d", at="20190101T000000"
            ),
            "hank_new": gpg.new_key(
                "Hank Hill <hank@example.org>", expire="1d", at="20190201T000000"
            ),
            "fireant": gpg.new_key("Flippant Fireant <flippant-fireant@kernel.org>"),
            # RSA auth subkeys: only RSA, RSA beside ed25519, and too small.
            "rhea": gpg.new_key("Rhea Rivest <rhea@example.org>"),
            "boris": gpg.new_key("Boris Both <boris@example.org>"),
            "tim": gpg.new_key("Tim Tiny <tim@example.org>"),
            # One person: an older key with an auth subkey, a newer one without.
            "olga_old": gpg.new_key("Olga Older <olga@example.org>"),
            "olga_new": gpg.new_key(
                "Olga Older <olga@example.org>", at="20200201T000000"
            ),
            # Name and emails in separate user IDs, as some Debian keys have.
            "nora": gpg.new_key("Nora Nameonly"),
            # Auth on the primary itself, with no auth subkey.
            "pia": gpg.new_key("Pia Primary <pia@example.org>", usage="sign,auth"),
            "sam1": gpg.new_key("Sam One <sam@example.com>"),
            "sam2": gpg.new_key("Sam Two <sam@example.org>"),
            "victor": gpg.new_key("Victor Victim <victor@example.com>"),
            # Newer than victor's key, and claims his email on a second user ID.
            "mallory": gpg.new_key(
                "Mallory Mal <mallory@example.org>", at="20200301T000000"
            ),
        }
        gpg(
            "--quick-add-uid",
            fprs["mallory"],
            "Victor Victim <victor@example.com>",
            at="20200301T000000",
        )
        gpg(
            "--quick-set-primary-uid",
            fprs["mallory"],
            "Mallory Mal <mallory@example.org>",
            at="20200302T000000",
        )
        # pgpkeys' signer signs with a subkey, so VALIDSIG's key and primary differ.
        signing_subkey = gpg.add_key(fprs["signer"], "ed25519", "sign", "1y")
        gpg("--quick-add-uid", fprs["alice"], "Alice Example (work) <Alice@Kernel.ORG>")
        gpg("--quick-add-uid", fprs["alice"], "Alice Example <alice@old.example>")
        gpg("--quick-revoke-uid", fprs["alice"], "Alice Example <alice@old.example>")
        gpg(
            "--quick-set-primary-uid",
            fprs["alice"],
            "Alice Example <alice@example.org>",
            at="20200102T000000",
        )
        gpg("--quick-add-key", fprs["alice"], "ed25519", "auth", "never")
        gpg("--quick-add-key", fprs["bob"], "nistp256/ecdsa", "auth", "never")
        gpg("--quick-add-key", fprs["carol"], "brainpoolP256r1/ecdsa", "auth", "never")
        gpg.add_key(fprs["rhea"], "rsa2048", "auth")
        gpg.add_key(fprs["boris"], "rsa2048", "auth")
        gpg.add_key(fprs["boris"], "ed25519", "auth")
        gpg.add_key(fprs["tim"], "rsa1024", "auth")
        gpg.add_key(fprs["olga_old"], "ed25519", "auth")
        gpg("--quick-add-uid", fprs["nora"], "<Nora@Example.org>")
        gpg("--quick-add-uid", fprs["nora"], "nora2@example.org")
        gpg(
            "--quick-add-uid",
            fprs["dave_new"],
            "Dave Davis <dave@kernel.org>",
            at="20200201T000000",
        )
        # Reusable-curve auth subkeys that are not live at the freeze commit:
        # revoked, and expired.
        gpg.revoke_subkey(fprs["sam1"], gpg.add_key(fprs["sam1"], "ed25519", "auth"))
        gpg.add_key(fprs["sam2"], "ed25519", "auth", "1d")
        # A non-expiring auth subkey under a primary that expired before the
        # freeze commit.
        gpg.add_key(fprs["eve"], "ed25519", "auth", at="20190101T000000")
        # A signing subkey revoked in pgpkeys but live in this home: revoke it
        # in a copy of carol's key.
        revoked_subkey = gpg.add_key(fprs["carol"], "ed25519", "sign")
        secret = base / "carol.key"
        secret.write_bytes(gpg("--export-secret-keys", fprs["carol"]))
        revoker("--import", str(secret))
        revoker.revoke_subkey(fprs["carol"], revoked_subkey)

        repo = base / "pgpkeys.git"
        (repo / "keys").mkdir(parents=True)
        for name, fpr in fprs.items():
            armored = gpg("--armor", "--export", fpr)
            if name == "frank":  # revoked in pgpkeys, but still signs in this home
                armored += gpg.revocation(fpr)
            if name == "carol":
                armored = revoker("--armor", "--export", fpr)
            (repo / "keys" / f"{fpr[-16:]}.asc").write_bytes(armored)
        # Files gpg will not fully import: port must skip and name them.
        (repo / "keys" / "v3key.asc").write_bytes(_v3_key())
        orphan = gpg.new_key("Orla Orphan <orla@example.org>")
        (repo / "keys" / "orphan-revocation.asc").write_bytes(gpg.revocation(orphan))
        (home / "gpg.conf").write_text("faked-system-time 20200601T000000!\n")
        env = dict(
            os.environ,
            GNUPGHOME=str(home),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_DATE=FREEZE_DATE,
            GIT_COMMITTER_DATE=FREEZE_DATE,
        )
        ident = ["-c", "user.name=Sig Ner", "-c", "user.email=signer@kernel.org"]
        _git(repo, "init", "-q", env=env)
        _git(repo, "add", "keys", env=env)
        sign = ["-c", "gpg.format=openpgp", "-c", "gpg.program=gpg"]
        sign += ["-c", f"user.signingkey={signing_subkey}!"]
        _git(repo, *ident, *sign, "commit", "-q", "-S", "-m", "freeze", env=env)
        commit = _git(repo, "rev-parse", "HEAD", env=env)
        _git(repo, *ident, "commit", "-q", "--allow-empty", "-m", "after", env=env)
        unsigned = _git(repo, "rev-parse", "HEAD", env=env)
        points = {fpr: gpg.key_data(fpr) for fpr in fprs.values()}
        yield Pgpkeys(
            repo, commit, signing_subkey, unsigned, fprs, points, gpg, revoked_subkey
        )
    finally:
        for h in (home, revoker.home):
            subprocess.run(
                ["gpgconf", "--homedir", str(h), "--kill", "all"], check=False
            )


@pytest.fixture(scope="module")
def ported(pgpkeys: Pgpkeys, tmp_path_factory: pytest.TempPathFactory) -> Ported:
    """Run ``git-vouch-migrate port`` once on the synthetic pgpkeys."""
    out = tmp_path_factory.mktemp("port") / "drafts"
    proc = run_migrate(
        "port", str(pgpkeys.repo), "--commit", pgpkeys.commit,
        "--signer", pgpkeys.fprs["signer"], "--out", str(out),
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    return Ported(pgpkeys, out, proc.stdout)

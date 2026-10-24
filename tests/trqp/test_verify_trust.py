"""End to end: OpenVTC's own verify-trust checks commits against git-vouch-trqp.

verify-trust is the independent oracle. It is not part of this tree: build it
from OpenVTC verifiable-git-infrastructure (tested at commit 5d9b9b6) with
``cargo build --locked --release -p verify-trust`` and point ``VERIFY_TRUST``
at the binary, or put it on PATH. Without it these tests skip.

The run is offline. verify-trust resolves did:web only from public hosts, so
it cannot discover a local bridge from the registry's DID document; it is
pointed at the bridge with its own ``--registry-url`` override instead (the
document itself is checked in test_did_document.py). Signer did:keys resolve
inside verify-trust with no network.

Commits are signed by git with real ``ssh-keygen``, except sk-ssh-ed25519,
for which there is no token in a test run: sk_sign.py signs those, and real
``git verify-commit`` (ssh-keygen) accepts each one before verify-trust sees
it. P-256 and RSA did:keys are derived here from ssh-keygen's own output.

OpenVTC issue #169 (open): verify-trust accepts only plain ssh-ed25519
signatures. The sk-ssh-ed25519, P-256 and RSA cases assert today's refusal
of a signer the bridge authorizes; they must flip to trusted once #169 is
fixed. verify-trust also never sends context.time, so a retired key is judged
as of now, even for commits made before it retired.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

import pytest

from conftest import Key, make_key
from test_check import AFTER, BEFORE, Registry, did, keys  # noqa: F401 (keys is a fixture)
from trqp.conftest import DID, Bridge
from trqp.test_trqp import RESOURCE, authorized, request

SK_SIGN = Path(__file__).resolve().parent / "sk_sign.py"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
P256_PUB = b"\x80\x24"  # multicodec 0x1200, varint
RSA_PUB = b"\x85\x24"  # multicodec 0x1205, varint


VERIFY_TRUST = os.environ.get("VERIFY_TRUST") or shutil.which("verify-trust") or ""
pytestmark = pytest.mark.skipif(
    not os.access(VERIFY_TRUST, os.X_OK),
    reason="verify-trust not built: cargo build --locked --release -p verify-trust "
    "in OpenVTC verifiable-git-infrastructure, then set VERIFY_TRUST to the binary",
)


class Report(NamedTuple):
    """verify-trust's exit code and the one commit verdict of its JSON report."""

    code: int
    status: str
    detail: object


def multikey_did(codec: bytes, raw: bytes) -> str:
    """Return the did:key for multicodec-prefixed key bytes, base58btc."""
    data = codec + raw
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = BASE58[r] + out
    return "did:key:z" + "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def ssh_strings(blob: bytes) -> list[bytes]:
    """Split an SSH wire-format blob into its strings."""
    out = []
    while blob:
        n = int.from_bytes(blob[:4], "big")
        out.append(blob[4 : 4 + n])
        blob = blob[4 + n :]
    return out


def p256_did(key: Key) -> str:
    """Return the did:key of an ecdsa-sha2-nistp256 key: its compressed point."""
    point = ssh_strings(base64.b64decode(key.pubkey.split()[1]))[2]
    x, y = point[1:33], point[33:]
    return multikey_did(P256_PUB, bytes([2 + y[-1] % 2]) + x)


def rsa_did(key: Key) -> str:
    """Return the did:key of an ssh-rsa key: its PKCS#1 DER, as ssh-keygen exports it."""
    pem = subprocess.run(
        ["ssh-keygen", "-e", "-m", "PEM", "-f", str(key.public)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    der = base64.b64decode("".join(pem.strip().splitlines()[1:-1]))
    return multikey_did(RSA_PUB, der)


def sk_key(directory: Path) -> Key:
    """Return a software sk-ssh-ed25519 key made by sk_sign.py."""
    private = directory / "alice-sk"
    subprocess.run([sys.executable, str(SK_SIGN), "keygen", str(private)], check=True)
    public = directory / "alice-sk.pub"
    return Key(private, public, public.read_text().strip())


def sk_did(key: Key) -> str:
    """Return the did:key of an sk-ssh-ed25519 key: that of its Ed25519 key."""
    raw = ssh_strings(base64.b64decode(key.pubkey.split()[1]))[1]
    return multikey_did(b"\xed\x01", raw)


class SkRegistry(Registry):
    """A Registry that signs with sk_sign.py for sk-ssh-ed25519 keys."""

    def sign(self, key: Key, namespace: str, data: bytes) -> bytes:
        if not key.pubkey.startswith("sk-"):
            return super().sign(key, namespace, data)
        msg = self.scratch / "msg"
        msg.write_bytes(data)
        subprocess.run(
            [sys.executable, str(SK_SIGN), "-Y", "sign", "-n", namespace]
            + ["-f", str(key.private), str(msg)],
            check=True,
        )
        return Path(str(msg) + ".sig").read_bytes()


class Extra(NamedTuple):
    """alice's keys of the types verify-trust refuses, each with its did:key."""

    ecdsa: tuple[Key, str]
    rsa: tuple[Key, str]
    sk: tuple[Key, str]


@pytest.fixture
def extra(tmp_path: Path) -> Extra:
    """Return fresh P-256, RSA and software sk-ssh-ed25519 keys for alice."""
    directory = tmp_path / "extra-keys"
    directory.mkdir()
    ecdsa = make_key(directory, "alice-ecdsa", ["-t", "ecdsa", "-b", "256"])
    rsa = make_key(directory, "alice-rsa", ["-t", "rsa", "-b", "2048"])
    sk = sk_key(directory)
    return Extra((ecdsa, p256_did(ecdsa)), (rsa, rsa_did(rsa)), (sk, sk_did(sk)))


@pytest.fixture
def bridge(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
    extra: Extra,
    serve: Callable[..., Bridge],
) -> Bridge:
    """Serve test_export's registry, with alice also holding the ``extra`` keys.

    Anchor torvalds; maintainer gregkh, whose key gregkh-old retired
    2026-06-01; contributor alice, whose key alice2 an anchor revoked;
    automation bot; dave, registered with no tier or endorsement.
    """
    r = SkRegistry(tmp_path / "registry")
    r.anchors("torvalds")
    r.person("torvalds", keys("torvalds"))
    r.person("gregkh", keys("gregkh"), retired=(keys("gregkh-old"),))
    alice = (keys("alice"), keys("alice2"), extra.ecdsa[0], extra.rsa[0], extra.sk[0])
    # One current key signs: a .sig holds at most 4 blocks (DESIGN.md).
    r.person("alice", *alice, signers=(keys("alice"),))
    r.person("bot", keys("bot"), accountable="gregkh")
    r.person("dave", keys("dave"))
    r.tier("gregkh", "maintainer", "torvalds", keys("torvalds"))
    r.tier("alice", "contributor", "gregkh", keys("gregkh"))
    r.tier("bot", "automation", "gregkh", keys("gregkh"))
    r.revoke("alice", keys("alice2"), keys("torvalds"))
    r.endorse("torvalds", keys("torvalds"), "gregkh", keys("gregkh"))
    r.endorse("gregkh", keys("gregkh"), "torvalds", keys("torvalds"))
    r.endorse("alice", keys("alice"), "gregkh", keys("gregkh"))
    r.endorse("bot", keys("bot"), "gregkh", keys("gregkh"))
    return serve(r.root)


def git(repo: Path, *args: str, date: str = BEFORE) -> str:
    """Run git in ``repo`` with fixed identity and dates; return its stdout."""
    env = {**os.environ, "GIT_COMMITTER_DATE": date, "GIT_AUTHOR_DATE": date}
    proc = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@example.org"]
        + list(args),
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def signed_repo(tmp_path: Path, key: Key, signer: str, date: str = BEFORE) -> Path:
    """Return a repository whose one commit past an unsigned root ``key`` signs.

    The commit claims ``signer`` in a Signed-by-DID trailer, which plain git
    config produces (docs/trqp-interop.md, section 3). Real ssh-keygen must
    verify the signature, whatever made it.
    """
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    git(repo, "commit", "-q", "--allow-empty", "-m", "root")
    git(repo, "tag", "root")
    program = []
    if key.pubkey.startswith("sk-"):
        wrapper = tmp_path / "sk-signer"
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{SK_SIGN}" "$@"\n')
        wrapper.chmod(0o755)
        program = ["-c", f"gpg.ssh.program={wrapper}"]
    git(
        repo,
        *program,
        "-c",
        "gpg.format=ssh",
        "-c",
        f"user.signingkey={key.private}",
        "commit",
        "-q",
        "-S",
        "--allow-empty",
        "-m",
        "change",
        "--trailer",
        f"Signed-by-DID: {signer}",
        date=date,
    )
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f"t@example.org {key.pubkey}\n")
    git(repo, "-c", f"gpg.ssh.allowedSignersFile={allowed}", "verify-commit", "HEAD")
    return repo


def verify_trust(repo: Path, url: str) -> Report:
    """Run verify-trust on ``root..HEAD`` against the registry at ``url``."""
    proc = subprocess.run(
        [
            VERIFY_TRUST,
            "--range",
            "root..HEAD",
            "--repo-dir",
            str(repo),
            "--registry-url",
            url,
            "--registry-did",
            DID,
            "--vtc-did",
            DID,
            "--resource",
            RESOURCE,
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode in (0, 1), proc.stderr
    report = json.loads(proc.stdout)
    assert report["ok"] is (proc.returncode == 0)
    [verdict] = report["commits"]
    assert verdict["sha"] == git(repo, "rev-parse", "HEAD")
    return Report(proc.returncode, verdict["status"], verdict.get("detail"))


def url(bridge: Bridge) -> str:
    """Return the bridge's base URL; verify-trust appends /trust-tasks."""
    return f"http://127.0.0.1:{bridge.port}"


@pytest.mark.parametrize(
    ("name", "date", "trusted"),
    [
        ("torvalds", BEFORE, True),  # anchor
        ("gregkh", BEFORE, True),  # maintainer
        ("alice", BEFORE, True),  # contributor
        ("alice2", BEFORE, False),  # revoked
        ("gregkh-old", AFTER, False),  # signed after its 2026-06-01 retirement
        # No context.time from verify-trust: judged now, so refused even
        # though the key was current when it signed.
        ("gregkh-old", BEFORE, False),
        ("bot", BEFORE, False),  # automation never signs commits
        ("dave", BEFORE, False),  # registered, no tier or endorsed email
        ("mallory", BEFORE, False),  # not in the registry
    ],
)
def test_verify_trust_asks_the_bridge(
    tmp_path: Path,
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    name: str,
    date: str,
    trusted: bool,
) -> None:
    signer = did(keys(name))
    report = verify_trust(signed_repo(tmp_path, keys(name), signer, date), url(bridge))
    if trusted:
        assert report == Report(
            0, "trusted", {"signer_did": signer, "resource": RESOURCE}
        )
    else:
        assert report == Report(1, "unauthorized", {"signer_did": signer})


def test_forged_signer_did_is_refused(
    tmp_path: Path,
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """mallory signs but the trailer claims alice, whom the bridge authorizes.

    verify-trust must check the signature against the claimed DID's key
    before it asks the bridge about that DID.
    """
    signer = did(keys("alice"))
    assert authorized(bridge, request(signer))[0] is True
    report = verify_trust(signed_repo(tmp_path, keys("mallory"), signer), url(bridge))
    # verify-trust's "fingerprint" is the hex of the raw Ed25519 key that signed.
    raw = ssh_strings(base64.b64decode(keys("mallory").pubkey.split()[1]))[1]
    assert report == Report(1, "unknownKey", {"did": signer, "fingerprint": raw.hex()})


@pytest.mark.parametrize(
    ("kind", "algorithm"),
    [
        ("sk", "sk-ssh-ed25519@openssh.com"),
        ("ecdsa", "ecdsa-sha2-nistp256"),
        ("rsa", "rsa-sha2-512"),
    ],
)
def test_only_plain_ed25519_passes_openvtc_169(
    tmp_path: Path, bridge: Bridge, extra: Extra, kind: str, algorithm: str
) -> None:
    """The bridge authorizes alice's key; verify-trust refuses its signature today.

    When OpenVTC #169 is fixed this must become trusted.
    """
    key, signer = getattr(extra, kind)
    assert authorized(bridge, request(signer))[0] is True
    report = verify_trust(signed_repo(tmp_path, key, signer), url(bridge))
    assert report == Report(
        1, "malformed", f"unsupported signature algorithm: {algorithm}"
    )


def test_bridge_down_fails_closed(
    tmp_path: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    signer = did(keys("alice"))
    report = verify_trust(
        signed_repo(tmp_path, keys("alice"), signer), f"http://127.0.0.1:{port}"
    )
    assert report.code == 1
    assert report.status == "registryUnavailable"
    assert isinstance(report.detail, dict) and report.detail["signer_did"] == signer


def test_stale_bridge_fails_closed(
    tmp_path: Path,
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """A bridge synced over 24h ago answers a bare 503; verify-trust refuses.

    With no Trust Task document trql-client sees a transport error, so
    verify-trust reports registryUnavailable, as for a bridge that is down,
    not a denial (vouch-faq3.16).
    """
    stamp = tmp_path / "registry" / ".git" / "vouch-fetched"
    old = stamp.stat().st_mtime - 25 * 3600
    os.utime(stamp, (old, old))
    signer = did(keys("alice"))
    report = verify_trust(signed_repo(tmp_path, keys("alice"), signer), url(bridge))
    assert report.code == 1
    assert report.status == "registryUnavailable"
    assert isinstance(report.detail, dict) and report.detail["signer_did"] == signer

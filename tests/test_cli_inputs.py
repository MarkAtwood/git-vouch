"""'git vouch did' with a .pub path or key text, and check/export without DIR.

did:key oracles are the W3C CCG vectors from test_did (key lines built from
the vectors' own key material). The DIR oracles are the fixture registry's
known tiers and ssh-keygen verifying a signature against the exported files.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import SCRIPT, Key, run_script
from test_check import Registry, keys  # noqa: F401 (keys is a fixture)
from test_did import CCG_P256_JWKS, ed25519_lines, p256_point, ssh_line
from test_export import reg  # noqa: F401 (reg is a fixture)
from test_sync import data_dir, home, remote, verifies  # noqa: F401 (fixtures)

P256_DID = next(iter(CCG_P256_JWKS))
P256_POINT = p256_point(CCG_P256_JWKS[P256_DID])
VECTORS = [
    ed25519_lines()[0],
    (
        P256_DID,
        ssh_line(b"ecdsa-sha2-nistp256", b"nistp256", P256_POINT),
        ssh_line(
            b"sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", P256_POINT, b"ssh:"
        ),
    ),
]
FIXTURE_TIERS = (
    "alice contributor\nbot automation\ndave none\ngregkh maintainer\ntorvalds anchor\n"
)


def run_in(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git-vouch as a subprocess in ``cwd``."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, cwd=cwd
    )


@pytest.mark.parametrize("did, plain, sk", VECTORS, ids=["ed25519", "p256"])
@pytest.mark.parametrize("kind", ["plain", "sk"])
def test_did_path_and_text_agree(
    tmp_path: Path, did: str, plain: str, sk: str, kind: str
) -> None:
    line = (plain if kind == "plain" else sk) + " alice@example.org"
    pub = tmp_path / "id.pub"
    pub.write_text(line + "\n")
    for arg in (str(pub), line):
        proc = run_script("did", arg)
        assert (proc.returncode, proc.stdout, proc.stderr) == (0, did + "\n", "")


@pytest.mark.parametrize("did, plain, sk", VECTORS, ids=["ed25519", "p256"])
def test_did_reverse_of_sk_key_is_plain_form(did: str, plain: str, sk: str) -> None:
    assert run_script("did", sk).stdout == did + "\n"
    proc = run_script("did", did)
    assert (proc.returncode, proc.stdout, proc.stderr) == (0, plain + "\n", "")


def test_did_missing_path_fails(tmp_path: Path) -> None:
    proc = run_script("did", str(tmp_path / "missing.pub"))
    assert proc.returncode == 1
    assert "not an SSH public key line" in proc.stderr


def test_check_without_dir_uses_synced_copy(
    home: Path,  # noqa: F811
    remote: Path,  # noqa: F811
    tmp_path: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    proc = run_in(elsewhere, "check")
    assert (proc.returncode, proc.stdout) == (0, FIXTURE_TIERS), proc.stderr


def test_export_without_dir_uses_synced_copy(
    home: Path,  # noqa: F811
    remote: Path,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    for name in ("allowed_signers", "revoked_keys"):
        (data_dir(home) / name).unlink()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    proc = run_in(elsewhere, "export")
    assert proc.returncode == 0, proc.stderr
    assert verifies(home, keys("alice"), tmp_path)


def test_check_without_dir_before_setup_uses_cwd(reg: Registry) -> None:  # noqa: F811
    proc = run_in(reg.root, "check")
    assert (proc.returncode, proc.stdout) == (0, FIXTURE_TIERS), proc.stderr


def test_check_without_dir_after_setup_needs_a_copy(home: Path, tmp_path: Path) -> None:  # noqa: F811
    subprocess.run(
        ["git", "config", "--global", "vouch.registry", str(tmp_path / "none.git")],
        check=True,
    )
    out = ["--allowed-signers", "a", "--revocation-file", "r"]
    for args in (["check"], ["export", *out]):
        proc = run_in(tmp_path, *args)
        assert proc.returncode == 1
        assert "run git vouch sync, or pass DIR" in proc.stderr


def test_check_dir_wins_over_synced_copy(
    home: Path,  # noqa: F811
    remote: Path,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    other = Registry(tmp_path / "other")
    other.anchors("torvalds")
    other.person("torvalds", keys("torvalds"))
    proc = run_in(tmp_path, "check", str(other.root))
    assert (proc.returncode, proc.stdout) == (0, "torvalds anchor\n"), proc.stderr

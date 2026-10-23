"""'git vouch keys <email>' and the patatt selector in 'git vouch status' (DESIGN.md, Patch signing).

The selector oracle is ``ssh-keygen -l -E sha256``: its base64 SHA256
fingerprint, turned into hex here, never git-vouch's own hashing. The
fixture registry is test_export's ``reg``, signed by real ssh-keygen.
"""

from __future__ import annotations

import base64
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from conftest import SCRIPT, Key, run_script
from test_check import Registry, keys  # noqa: F401 (keys is a fixture)
from test_export import git, reg  # noqa: F401 (reg is a fixture)
from test_sync import home, remote  # noqa: F401 (fixtures)

# Made once by ssh-keygen -t ed25519. "ssh-keygen -l -E sha256" printed
# SHA256:9CWJ3MkzBa9Q184IBJUhf6uaT6n119Pve9Ad4Psco9Y, which is hex
# f42589dcc93305af50d7ce080495217fab9a4fa9f5d7d3ef7bd01de0fb1ca3d6.
VECTOR_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILxGQVo3QGqPGOCX6JOnDF1url8CJByxyVLZHO4hIdV8"
)
VECTOR_SELECTOR = "k-f42589dcc93305af"


def selector(key: Key) -> str:
    """Return ``k-`` and the first 16 hex digits of ssh-keygen's SHA256 fingerprint."""
    out = subprocess.run(
        ["ssh-keygen", "-l", "-E", "sha256", "-f", str(key.public)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    fingerprint = out.split()[1].removeprefix("SHA256:")
    return "k-" + base64.b64decode(fingerprint + "=").hex()[:16]


def line(key: Key) -> str:
    return f"{selector(key)} {' '.join(key.pubkey.split()[:2])}"


@pytest.fixture
def sync(
    home: Path,  # noqa: F811
    reg: Registry,  # noqa: F811
) -> Callable[[], subprocess.CompletedProcess[str]]:
    """Return a function that commits ``reg`` and runs setup on it, syncing the copy."""
    assert git(reg.root, "init", "-q", "-b", "main").returncode == 0

    def run() -> subprocess.CompletedProcess[str]:
        for args in (["add", "-A"], ["commit", "-q", "--allow-empty", "-m", "r"]):
            assert git(reg.root, *args).returncode == 0
        return run_script("setup", "--registry", str(reg.root))

    return run


def keys_cmd(cwd: Path, email: str) -> subprocess.CompletedProcess[str]:
    """Run git-vouch keys in ``cwd``."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), "keys", email],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def test_selector_vector(vouch: ModuleType) -> None:
    assert vouch.patatt_selector(VECTOR_KEY) == VECTOR_SELECTOR


def test_selector_matches_ssh_keygen(vouch: ModuleType, any_key: Key) -> None:
    assert vouch.patatt_selector(any_key.pubkey) == selector(any_key)


@pytest.mark.parametrize(
    ("email", "name"),
    [
        ("torvalds@example.org", "torvalds"),  # anchor
        ("alice@example.org", "alice"),  # contributor
        ("ALICE@Example.ORG", "alice"),  # emails match ignoring case
        ("bot@example.org", "bot"),  # automation counts
    ],
)
def test_endorsed_email_prints_current_keys(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    sync: Callable[[], subprocess.CompletedProcess[str]],
    home: Path,  # noqa: F811
    email: str,
    name: str,
) -> None:
    assert sync().returncode == 0
    proc = keys_cmd(home, email)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == line(keys(name)) + "\n"


def test_retired_key_absent(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    sync: Callable[[], subprocess.CompletedProcess[str]],
    home: Path,  # noqa: F811
) -> None:
    """gregkh-old retired 2026-06-01, which is past."""
    assert sync().returncode == 0
    proc = keys_cmd(home, "gregkh@example.org")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == line(keys("gregkh")) + "\n"


def test_revoked_key_absent(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    sync: Callable[[], subprocess.CompletedProcess[str]],
    home: Path,  # noqa: F811
) -> None:
    """alice2 is current in alice's file but revoked by an anchor."""
    assert sync().returncode == 0
    proc = keys_cmd(home, "alice@example.org")
    assert proc.returncode == 0, proc.stderr
    assert selector(keys("alice2")) not in proc.stdout


def test_several_current_keys_each_get_a_line(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    sync: Callable[[], subprocess.CompletedProcess[str]],
    home: Path,  # noqa: F811
) -> None:
    reg.person("torvalds", keys("torvalds"), keys("torvalds-backup"))
    assert sync().returncode == 0
    proc = keys_cmd(home, "torvalds@example.org")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        line(keys("torvalds")),
        line(keys("torvalds-backup")),
    ]


@pytest.mark.parametrize(
    "email",
    [
        "dave@example.org",  # registered, email not endorsed
        "nobody@example.org",  # unknown
    ],
)
def test_unendorsed_or_unknown_email_exits_1(
    sync: Callable[[], subprocess.CompletedProcess[str]],
    home: Path,  # noqa: F811
    email: str,
) -> None:
    assert sync().returncode == 0
    proc = keys_cmd(home, email)
    assert proc.returncode == 1
    assert proc.stdout == ""


def test_refuses_on_registry_problem(
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    sync: Callable[[], subprocess.CompletedProcess[str]],
    home: Path,  # noqa: F811
) -> None:
    reg.tier("dave", "maintainer", "alice", keys("alice"))  # alice may not grant it
    assert sync().returncode == 1  # the copy is fetched even though check fails
    proc = keys_cmd(home, "alice@example.org")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "registry check failed" in proc.stderr


def test_refuses_without_configured_registry(reg: Registry) -> None:  # noqa: F811
    """A valid registry in the current directory is never a trust source."""
    proc = keys_cmd(reg.root, "alice@example.org")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "no registry configured" in proc.stderr


def test_status_prints_patatt_selector(
    home: Path,  # noqa: F811
    remote: Path,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    subprocess.run(
        ["git", "config", "--global", "user.signingKey", str(keys("alice").public)],
        check=True,
    )
    proc = run_script("status")
    assert proc.returncode == 0, proc.stderr
    assert f"patatt.selector: {selector(keys('alice'))}\n" in proc.stdout


def test_status_prints_vector_selector(
    home: Path,  # noqa: F811
    remote: Path,  # noqa: F811
) -> None:
    """The signing key need not be registered; the selector comes from the key alone."""
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    subprocess.run(
        ["git", "config", "--global", "user.signingKey", VECTOR_KEY], check=True
    )
    proc = run_script("status")
    assert proc.returncode == 0, proc.stderr
    assert f"patatt.selector: {VECTOR_SELECTOR}\n" in proc.stdout

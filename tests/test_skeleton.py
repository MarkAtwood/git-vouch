"""Tests for the CLI skeleton, subprocess helper, input limits and key fixtures."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Optional

import pytest

from conftest import SCRIPT, Key, run_script

DESIGN_COMMANDS = [
    "setup",
    "sync",
    "status",
    "register",
    "add-key",
    "retire-key",
    "endorse",
    "approve",
    "revoke",
    "check",
    "export",
    "did",
    "keys",
]


def test_script_is_executable_with_python3_shebang() -> None:
    assert os.access(SCRIPT, os.X_OK)
    assert SCRIPT.read_text().splitlines()[0] == "#!/usr/bin/env python3"


def test_help_lists_every_design_command() -> None:
    result = run_script("--help")
    assert result.returncode == 0, result.stderr
    for command in DESIGN_COMMANDS:
        assert re.search(rf"^    {command}\s", result.stdout, re.M), command


@pytest.mark.parametrize("command", DESIGN_COMMANDS)
def test_each_command_has_help(command: str) -> None:
    result = run_script(command, "--help")
    assert result.returncode == 0, result.stderr
    assert f"git vouch {command}" in result.stdout


def test_no_command_is_an_error() -> None:
    assert run_script().returncode != 0


def test_runs_without_site_packages() -> None:
    # -I -S drops site-packages and the script's directory from sys.path, so
    # any third-party import would fail here.
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "name",
    ["a", "0", "torvalds", "gregkh", "alice-1", "a_b", "a" * 39, "9-_"],
)
def test_valid_handles(vouch: ModuleType, name: str) -> None:
    assert vouch.validate_handle(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "a" * 40,
        "Alice",
        "-a",
        "_a",
        "a.json",
        "a/b",
        "..",
        "a\n",
        "a b",
        "é",
        "a\x00",
        5,
        None,
        ["a"],
        b"a",
    ],
)
def test_invalid_handles(vouch: ModuleType, name: str) -> None:
    with pytest.raises(vouch.VouchError):
        vouch.validate_handle(name)


def test_read_capped_accepts_exactly_64_kib(vouch: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "people").mkdir()
    (tmp_path / "people" / "f.json").write_bytes(b"x" * 65536)
    assert vouch.read_capped(tmp_path, "people/f.json") == b"x" * 65536


def test_read_capped_rejects_over_64_kib(vouch: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "f.json").write_bytes(b"x" * 65537)
    with pytest.raises(vouch.VouchError):
        vouch.read_capped(tmp_path, "f.json")


def test_read_capped_rejects_symlink(vouch: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "target").write_bytes(b"{}")
    (tmp_path / "link.json").symlink_to(tmp_path / "target")
    with pytest.raises(vouch.VouchError):
        vouch.read_capped(tmp_path, "link.json")


def test_read_capped_rejects_symlinked_parent(
    vouch: ModuleType, tmp_path: Path
) -> None:
    root = tmp_path / "registry"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "alice.json").write_bytes(b"{}")
    (root / "people").symlink_to(outside)
    with pytest.raises(vouch.VouchError):
        vouch.read_capped(root, "people/alice.json")


def test_read_capped_allows_symlink_above_root(
    vouch: ModuleType, tmp_path: Path
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (real / "f.json").write_bytes(b"{}")
    (tmp_path / "root").symlink_to(real)
    assert vouch.read_capped(tmp_path / "root", "f.json") == b"{}"


@pytest.mark.parametrize(
    "rel", ["../f.json", "a/../f.json", "./f.json", "/f.json", "a//f.json", ""]
)
def test_read_capped_rejects_non_plain_paths(
    vouch: ModuleType, tmp_path: Path, rel: str
) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "f.json").write_bytes(b"{}")
    with pytest.raises(vouch.VouchError):
        vouch.read_capped(tmp_path / "a", rel)


def test_read_capped_rejects_fifo_without_blocking(
    vouch: ModuleType, tmp_path: Path
) -> None:
    os.mkfifo(tmp_path / "f.json")
    with pytest.raises(vouch.VouchError):
        vouch.read_capped(tmp_path, "f.json")


def test_read_capped_rejects_directory(vouch: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "d").mkdir()
    with pytest.raises(vouch.VouchError):
        vouch.read_capped(tmp_path, "d")


def test_run_passes_arguments_literally_without_shell(vouch: ModuleType) -> None:
    hostile = "$(touch pwned); `id` | cat > x"
    out = vouch.run([sys.executable, "-c", "import sys; print(sys.argv[1:])", hostile])
    assert out.decode().strip() == repr([hostile])


def test_run_puts_values_after_double_dash(vouch: ModuleType) -> None:
    out = vouch.run(
        [sys.executable, "-c", "import sys; print(sys.argv[1:])", "-x"],
        values=["--help", "-n"],
    )
    assert out.decode().strip() == repr(["-x", "--", "--help", "-n"])


def test_run_feeds_stdin(vouch: ModuleType) -> None:
    assert vouch.run(["cat"], stdin=b"\x00bytes\xff") == b"\x00bytes\xff"


def test_run_raises_with_stderr_on_failure(vouch: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(vouch.VouchError, match="not a git repository"):
        vouch.run(["git", "rev-parse", "HEAD"], cwd=tmp_path)


def test_run_raises_for_missing_program(vouch: ModuleType) -> None:
    with pytest.raises(vouch.VouchError, match="cannot run"):
        vouch.run(["git-vouch-no-such-program"])


# Typed in from DESIGN.md: the tier table's "Granted by" column (approval
# never grants anchor), and the export ranking anchor > maintainer >
# contributor with automation outside it.
@pytest.mark.parametrize(
    "argv",
    [
        ("approve", "alice", "anchor"),
        ("approve", "alice", "root"),
        ("approve", "alice"),
        ("export", "--min-tier", "automation"),
    ],
)
def test_cli_rejects_tiers_outside_design(argv: tuple[str, ...]) -> None:
    assert run_script(*argv).returncode == 2


@pytest.mark.parametrize("tier", ["maintainer", "contributor", "automation"])
def test_approve_accepts_grantable_tiers(vouch: ModuleType, tier: str) -> None:
    assert vouch.build_parser().parse_args(["approve", "alice", tier]).tier == tier


@pytest.mark.parametrize("tier", ["anchor", "maintainer", "contributor"])
def test_export_accepts_ranked_tiers(vouch: ModuleType, tier: str) -> None:
    args = vouch.build_parser().parse_args(
        ["export", "--min-tier", tier, "--include-automation"]
    )
    assert (args.min_tier, args.include_automation) == (tier, True)


def test_unimplemented_command_fails_cleanly() -> None:
    result = run_script("check")
    assert result.returncode == 1
    assert result.stderr.startswith("git-vouch: error:")


@pytest.mark.parametrize(
    ("fixture", "fingerprint_type", "openssl_marker"),
    [("ed25519_key", "(ED25519)", None), ("ecdsa_key", "(ECDSA)", "prime256v1")],
)
def test_key_fixtures_make_real_keys(
    request: pytest.FixtureRequest,
    fixture: str,
    fingerprint_type: str,
    openssl_marker: Optional[str],
) -> None:
    key: Key = request.getfixturevalue(fixture)
    fp = subprocess.run(
        ["ssh-keygen", "-l", "-f", str(key.public)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert fp.stdout.rstrip().endswith(fingerprint_type)
    if fixture != "ecdsa_key":
        return  # OpenSSH cannot export ed25519 as PKCS8, so openssl cannot cross-check it.
    assert fp.stdout.startswith("256 ")
    pkcs8 = subprocess.run(
        ["ssh-keygen", "-e", "-m", "PKCS8", "-f", str(key.public)],
        capture_output=True,
        check=True,
    )
    text = subprocess.run(
        ["openssl", "pkey", "-pubin", "-noout", "-text"],
        input=pkcs8.stdout,
        capture_output=True,
        check=True,
    )
    assert openssl_marker is not None
    assert openssl_marker in text.stdout.decode()


def test_key_fixture_signs_and_verifies(any_key: Key, tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.write_bytes(b"hello\n")
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-Y",
            "sign",
            "-f",
            str(any_key.private),
            "-n",
            "file",
            str(data),
        ],
        check=True,
    )
    signers = tmp_path / "allowed_signers"
    signers.write_text(f"test@example.org {any_key.pubkey}\n")
    with data.open("rb") as f:
        subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(signers),
                "-I",
                "test@example.org",
                "-n",
                "file",
                "-s",
                f"{data}.sig",
            ],
            stdin=f,
            capture_output=True,
            check=True,
        )

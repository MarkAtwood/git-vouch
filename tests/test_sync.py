"""'git vouch setup', 'sync' and 'status' against a local bare registry repository.

The oracles are real git (config values, commit ids, the refused fetch)
and ssh-keygen (file signatures verified against the exported files).
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import Key, run_script
from test_check import Registry, keys  # noqa: F401 (keys is a fixture)
from test_export import git, reg  # noqa: F401 (reg is a fixture)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Return the temp HOME from conftest, with git-vouch's data under ~/.local/share."""
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    return tmp_path / "home"


def data_dir(home: Path) -> Path:
    return home / ".local" / "share" / "git-vouch"


def copy_head(home: Path) -> str:
    return git(data_dir(home) / "registry", "rev-parse", "HEAD").stdout.strip()


@pytest.fixture
def remote(reg: Registry, tmp_path: Path) -> Path:  # noqa: F811
    """Commit the registry from test_export and serve it from a bare repository."""
    for args in (
        ["init", "-q", "-b", "main"],
        ["add", "-A"],
        ["commit", "-q", "-m", "r"],
    ):
        assert git(reg.root, *args).returncode == 0
    bare = tmp_path / "registry.git"
    proc = subprocess.run(
        ["git", "clone", "-q", "--bare", str(reg.root), str(bare)], capture_output=True
    )
    assert proc.returncode == 0, proc.stderr
    return bare


def push(reg: Registry, remote: Path, *options: str) -> None:  # noqa: F811
    proc = git(reg.root, "push", "-q", *options, str(remote), "main")
    assert proc.returncode == 0, proc.stderr


def commit_change(reg: Registry, *options: str) -> str:  # noqa: F811
    (reg.root / "README").write_text(f"{options}\n")
    assert git(reg.root, "add", "README").returncode == 0
    assert git(reg.root, "commit", "-q", *options, "-m", "change").returncode == 0
    return git(reg.root, "rev-parse", "HEAD").stdout.strip()


def config(name: str) -> str:
    proc = subprocess.run(
        ["git", "config", "--global", "--get", name], capture_output=True, text=True
    )
    assert proc.returncode == 0, name
    return proc.stdout.strip()


def verifies(home: Path, key: Key, tmp_path: Path) -> bool:
    """Return whether ssh-keygen accepts a file signature by ``key`` per the exported files."""
    msg = tmp_path / "release.tar"
    msg.write_bytes(b"release\n")
    sig = Path(str(msg) + ".sig")
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
            "file",
            str(msg),
        ],
        check=True,
        capture_output=True,
    )
    principal = key.private.name.split("-")[0]
    proc = subprocess.run(
        [
            "ssh-keygen",
            "-Y",
            "verify",
            "-f",
            str(data_dir(home) / "allowed_signers"),
            "-r",
            str(data_dir(home) / "revoked_keys"),
            "-I",
            principal,
            "-n",
            "file",
            "-s",
            str(sig),
        ],
        input=msg.read_bytes(),
        capture_output=True,
    )
    return proc.returncode == 0


def test_setup_writes_git_config_in_home(
    home: Path,
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    proc = run_script("setup", "--registry", str(remote), "--min-tier", "maintainer")
    assert proc.returncode == 0, proc.stderr
    data = data_dir(home)
    assert config("vouch.registry") == str(remote)
    assert config("vouch.minTier") == "maintainer"
    assert config("gpg.format") == "ssh"
    assert config("gpg.ssh.allowedSignersFile") == str(data / "allowed_signers")
    assert config("gpg.ssh.revocationFile") == str(data / "revoked_keys")
    assert (home / ".gitconfig").is_file()
    head = git(remote, "rev-parse", "HEAD").stdout.strip()
    assert copy_head(home) == head
    # The first sync exported with the saved --min-tier.
    assert verifies(home, keys("torvalds"), tmp_path)
    assert verifies(home, keys("gregkh"), tmp_path)
    assert not verifies(home, keys("alice"), tmp_path)


def test_setup_without_registry_keeps_the_configured_one(
    home: Path, remote: Path
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    proc = run_script("setup")
    assert proc.returncode == 0, proc.stderr
    assert config("vouch.registry") == str(remote)


SETUP_CONFIG = (
    "vouch.registry",
    "vouch.minTier",
    "gpg.format",
    "gpg.ssh.allowedSignersFile",
    "gpg.ssh.revocationFile",
)


def unset(name: str) -> bool:
    proc = subprocess.run(["git", "config", "--global", "--get", name])
    return proc.returncode == 1


def test_failed_setup_leaves_git_config_unchanged(home: Path, tmp_path: Path) -> None:
    missing = tmp_path / "missing.git"
    proc = run_script("setup", "--registry", str(missing), "--min-tier", "maintainer")
    assert proc.returncode == 1
    assert "cannot fetch the registry" in proc.stderr
    for name in SETUP_CONFIG:
        assert unset(name), name


def test_failed_setup_keeps_the_working_config(
    home: Path,
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    missing = tmp_path / "missing.git"
    proc = run_script("setup", "--registry", str(missing), "--min-tier", "anchor")
    assert proc.returncode == 1
    assert config("vouch.registry") == str(remote)
    assert unset("vouch.minTier")
    assert verifies(home, keys("alice"), tmp_path)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("user.signingKey", "6E7B5903A44C4D50621A2227571AC519C6F05818"),
        ("commit.gpgSign", "true"),
        ("tag.gpgSign", "true"),
        ("gpg.format", "x509"),
        ("gpg.ssh.allowedSignersFile", "/etc/ssh/allowed_signers"),
        ("gpg.ssh.revocationFile", "/etc/ssh/revoked_keys"),
    ],
)
def test_setup_refuses_to_change_how_git_signs(
    home: Path, remote: Path, name: str, value: str
) -> None:
    subprocess.run(["git", "config", "--global", name, value], check=True)
    proc = run_script("setup", "--registry", str(remote))
    assert proc.returncode == 1
    assert name in proc.stderr
    assert config(name) == value
    for other in SETUP_CONFIG:
        if other != name:
            assert unset(other), other
    assert not (data_dir(home) / "registry").exists()


@pytest.mark.parametrize("fmt", [None, "ssh"])
@pytest.mark.parametrize("literal", [False, True])
def test_setup_keeps_ssh_signing(
    home: Path,
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
    fmt: str | None,
    literal: bool,
) -> None:
    public = keys("alice").public
    signing_key = "key::" + public.read_text().strip() if literal else str(public)
    settings = [("user.signingKey", signing_key), ("commit.gpgSign", "true")]
    if fmt is not None:
        settings.append(("gpg.format", fmt))
    for name, value in settings:
        subprocess.run(["git", "config", "--global", name, value], check=True)
    proc = run_script("setup", "--registry", str(remote))
    assert proc.returncode == 0, proc.stderr
    assert config("user.signingKey") == signing_key
    assert config("gpg.format") == "ssh"


def test_sync_without_setup_fails(home: Path) -> None:
    proc = run_script("sync")
    assert proc.returncode == 1
    assert "git vouch setup" in proc.stderr


def test_sync_takes_a_fast_forward(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    new = commit_change(reg)
    push(reg, remote)
    proc = run_script("sync")
    assert proc.returncode == 0, proc.stderr
    assert copy_head(home) == new


def test_sync_refuses_a_force_pushed_rewind(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    before = copy_head(home)
    rewritten = commit_change(reg, "--amend")
    push(reg, remote, "--force")
    assert git(remote, "rev-parse", "HEAD").stdout.strip() == rewritten
    proc = run_script("sync")
    assert proc.returncode == 1
    assert "non-fast-forward" in proc.stderr
    assert copy_head(home) == before


def test_refused_rewind_keeps_the_fetch_time(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    eight_days_ago = time.time() - 8 * 24 * 3600
    stamp = data_dir(home) / "registry" / ".git" / "vouch-fetched"
    os.utime(stamp, (eight_days_ago, eight_days_ago))
    commit_change(reg, "--amend")
    push(reg, remote, "--force")
    assert run_script("sync").returncode == 1
    proc = run_script("status")
    assert proc.returncode == 0, proc.stderr
    assert "(8 days ago)" in proc.stdout
    assert "last fetched 8 days ago" in proc.stderr


def test_sync_checks_out_the_committed_bytes(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    (reg.root / ".gitattributes").write_text("* text eol=crlf\nREADME ident\n")
    (reg.root / "README").write_text("$Id$\n")
    assert git(reg.root, "add", "-A").returncode == 0
    assert git(reg.root, "commit", "-q", "-m", "attributes").returncode == 0
    push(reg, remote)
    assert run_script("sync").returncode == 0
    copy = data_dir(home) / "registry"
    files = git(copy, "ls-files").stdout.split()
    assert "README" in files and "anchors.json" in files
    for name in files:
        blob = subprocess.run(
            ["git", "cat-file", "blob", f"HEAD:{name}"],
            cwd=copy,
            capture_output=True,
            check=True,
        ).stdout
        assert (copy / name).read_bytes() == blob, name


def test_setup_with_a_new_registry_starts_a_fresh_history(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
    tmp_path: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    other = tmp_path / "other.git"
    assert (
        git(tmp_path, "clone", "-q", "--bare", str(remote), str(other)).returncode == 0
    )
    new = commit_change(reg, "--amend")
    assert git(reg.root, "push", "-q", "--force", str(other), "main").returncode == 0
    proc = run_script("setup", "--registry", str(other))
    assert proc.returncode == 0, proc.stderr
    assert copy_head(home) == new
    # The new registry's history is now the one a rewind is judged against.
    commit_change(reg, "--amend", "--allow-empty")
    assert git(reg.root, "push", "-q", "--force", str(other), "main").returncode == 0
    proc = run_script("sync")
    assert proc.returncode == 1
    assert "non-fast-forward" in proc.stderr
    assert copy_head(home) == new


def test_setup_uses_xdg_data_home(
    home: Path, remote: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg))
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    data = xdg / "git-vouch"
    assert config("gpg.ssh.allowedSignersFile") == str(data / "allowed_signers")
    assert config("gpg.ssh.revocationFile") == str(data / "revoked_keys")
    head = git(remote, "rev-parse", "HEAD").stdout.strip()
    assert git(data / "registry", "rev-parse", "HEAD").stdout.strip() == head
    assert not data_dir(home).exists()


def test_sync_saves_and_reuses_export_choices(
    home: Path,
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    assert verifies(home, keys("alice"), tmp_path)
    assert not verifies(home, keys("bot"), tmp_path)
    proc = run_script("sync", "--min-tier", "anchor", "--include-automation")
    assert proc.returncode == 0, proc.stderr
    assert config("vouch.minTier") == "anchor"
    assert config("vouch.includeAutomation") == "true"
    assert run_script("sync").returncode == 0
    assert verifies(home, keys("torvalds"), tmp_path)
    assert not verifies(home, keys("gregkh"), tmp_path)
    assert verifies(home, keys("bot"), tmp_path)
    assert run_script("sync", "--no-include-automation").returncode == 0
    assert config("vouch.includeAutomation") == "false"
    assert not verifies(home, keys("bot"), tmp_path)


def test_sync_writes_revocations_when_check_fails(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    signers = data_dir(home) / "allowed_signers"
    revocations = data_dir(home) / "revoked_keys"
    signers_before = signers.read_text()
    # A second key of gregkh's, revoked by an anchor, and an unrelated problem.
    reg.person("gregkh", keys("gregkh"), keys("gregkh2"), retired=(keys("gregkh-old"),))
    reg.revoke("gregkh", keys("gregkh2"), keys("torvalds"))
    (reg.root / "people" / "stray.txt").write_text("x\n")
    assert git(reg.root, "add", "-A").returncode == 0
    assert git(reg.root, "commit", "-q", "-m", "revoke").returncode == 0
    push(reg, remote)
    proc = run_script("sync")
    assert proc.returncode == 1
    assert "people/stray.txt: unexpected file" in proc.stderr
    revoked = revocations.read_text().split("\n")
    assert " ".join(keys("gregkh2").pubkey.split()[:2]) in revoked
    assert signers.read_text() == signers_before


def test_sync_goes_on_past_an_oversized_version(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    """One past version too large to read is ignored with a warning naming its
    commit; it never stops a revocation or the export (vouch-xlha.24)."""
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    assert verifies(home, keys("gregkh"), tmp_path)
    big = reg.root / "revocations" / "zz-1.json"
    big.write_bytes(b"x" * 70000)
    assert git(reg.root, "add", "-A").returncode == 0
    assert git(reg.root, "commit", "-q", "-m", "oops").returncode == 0
    bad = git(reg.root, "rev-parse", "HEAD").stdout.strip()
    big.unlink()
    reg.person("gregkh", keys("gregkh"), keys("gregkh2"), retired=(keys("gregkh-old"),))
    reg.revoke("gregkh", keys("gregkh2"), keys("torvalds"))
    # A tier removal, so the export's effect shows.
    for tier in (reg.root / "tiers").glob("gregkh.json*"):
        tier.unlink()
    assert git(reg.root, "add", "-A").returncode == 0
    assert git(reg.root, "commit", "-q", "-m", "revoke").returncode == 0
    push(reg, remote)
    proc = run_script("sync")
    assert proc.returncode == 0, proc.stderr
    assert (
        f"revocations/zz-1.json: not a regular file of at most 65536 bytes (ignored, at {bad})"
        in proc.stderr
    )
    assert "Traceback" not in proc.stderr
    revoked = (data_dir(home) / "revoked_keys").read_text().split("\n")
    assert " ".join(keys("gregkh2").pubkey.split()[:2]) in revoked
    assert not verifies(home, keys("gregkh"), tmp_path)


def test_sync_writes_revocations_past_a_commit_beyond_year_9999(
    home: Path,
    reg: Registry,  # noqa: F811
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """A commit dated past what datetime holds is a problem, not an abort, so
    a later revocation still reaches every user (vouch-xlha.24)."""
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    signers = data_dir(home) / "allowed_signers"
    signers_before = signers.read_text()
    # One commit whose date both file_history (a new file) and the tier's
    # end (a deletion) read; git takes the date, datetime cannot hold it.
    stray = reg.root / "revocations" / "zz-1.json"
    stray.write_text("{}\n")
    for tier in (reg.root / "tiers").glob("gregkh.json*"):
        tier.unlink()
    assert git(reg.root, "add", "-A").returncode == 0
    far = "@253402300800 +0000"  # 10000-01-01T00:00:00Z
    assert git(reg.root, "commit", "-q", "-m", "far", date=far).returncode == 0
    bad = git(reg.root, "rev-parse", "HEAD").stdout.strip()
    stray.unlink()
    reg.person("gregkh", keys("gregkh"), keys("gregkh2"), retired=(keys("gregkh-old"),))
    reg.revoke("gregkh", keys("gregkh2"), keys("torvalds"))
    assert git(reg.root, "add", "-A").returncode == 0
    assert git(reg.root, "commit", "-q", "-m", "revoke").returncode == 0
    push(reg, remote)
    proc = run_script("sync")
    assert proc.returncode == 1
    assert f"commit {bad}: committer date out of range" in proc.stderr
    assert "Traceback" not in proc.stderr
    revoked = (data_dir(home) / "revoked_keys").read_text().split("\n")
    assert " ".join(keys("gregkh2").pubkey.split()[:2]) in revoked
    assert signers.read_text() == signers_before


def test_status_shows_commit_fetch_age_and_own_tier(
    home: Path,
    remote: Path,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    subprocess.run(
        ["git", "config", "--global", "user.signingKey", str(keys("alice").public)],
        check=True,
    )
    proc = run_script("status")
    assert proc.returncode == 0, proc.stderr
    head = git(remote, "log", "-1", "--format=%H %cI").stdout.strip()
    assert f"registry: {remote}\n" in proc.stdout
    assert f"commit: {head}\n" in proc.stdout
    assert "(0 days ago)" in proc.stdout
    assert "check: ok\n" in proc.stdout
    assert "you: alice contributor\n" in proc.stdout
    assert "warning" not in proc.stderr


def test_stale_fetch_warns_and_still_succeeds(home: Path, remote: Path) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    copy = data_dir(home) / "registry"
    eight_days_ago = time.time() - 8 * 24 * 3600
    os.utime(copy / ".git" / "vouch-fetched", (eight_days_ago, eight_days_ago))
    warning = "last fetched 8 days ago; run git vouch sync"
    proc = run_script("status")
    assert proc.returncode == 0, proc.stderr
    assert warning in proc.stderr
    assert "(8 days ago)" in proc.stdout
    assert "you: unknown: no signing key" in proc.stdout
    proc = run_script("check", str(copy))
    assert proc.returncode == 0, proc.stderr
    assert warning in proc.stderr
    # A sync is a fresh fetch, so the warning goes away.
    assert run_script("sync").returncode == 0
    assert warning not in run_script("status").stderr


def test_worktree_of_the_copy_shares_its_fetch_time(
    home: Path, remote: Path, tmp_path: Path
) -> None:
    """A worktree's .git is a file; the stamp is in the common git dir (vouch-88xy)."""
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    copy = data_dir(home) / "registry"
    eight_days_ago = time.time() - 8 * 24 * 3600
    os.utime(copy / ".git" / "vouch-fetched", (eight_days_ago, eight_days_ago))
    side = tmp_path / "side"
    assert git(copy, "worktree", "add", "-q", "--detach", str(side)).returncode == 0
    assert (side / ".git").is_file()
    proc = run_script("check", str(side))
    assert proc.returncode == 0, proc.stderr
    assert "last fetched 8 days ago; run git vouch sync" in proc.stderr


def test_status_before_setup_fails(home: Path) -> None:
    proc = run_script("status")
    assert proc.returncode == 1
    assert "git vouch setup" in proc.stderr


def test_unwritable_data_dir_is_a_clean_error(home: Path, remote: Path) -> None:
    data = data_dir(home)
    data.mkdir(parents=True)
    data.chmod(0o555)
    try:
        proc = run_script("setup", "--registry", str(remote))
    finally:
        data.chmod(0o755)
    assert proc.returncode == 1
    assert "git-vouch: error: cannot update the registry copy at" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_unreadable_fetch_time_is_a_clean_error(home: Path, remote: Path) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    copy = data_dir(home) / "registry"
    stamp = copy / ".git" / "vouch-fetched"
    stamp.unlink()
    stamp.symlink_to("vouch-fetched")  # stat fails with ELOOP, not ENOENT
    proc = run_script("check", str(copy))
    assert proc.returncode == 1
    assert "git-vouch: error: cannot read the fetch time" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_registry_url_not_utf8_is_a_clean_error(home: Path) -> None:
    cmd = [b"git", b"config", b"--global", b"vouch.registry", b"/srv/reg-\xff"]
    assert subprocess.run(cmd).returncode == 0
    proc = run_script("sync")
    assert proc.returncode == 1
    assert "git-vouch: error: git config vouch.registry: not UTF-8" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_sync_output_paths_need_not_be_utf8(
    home: Path, remote: Path, tmp_path: Path
) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    signers = os.fsencode(tmp_path) + b"/signers-\xff"
    revocations = os.fsencode(tmp_path) + b"/revoked-\xfe"
    for name, value in (
        (b"gpg.ssh.allowedSignersFile", signers),
        (b"gpg.ssh.revocationFile", revocations),
    ):
        cmd = [b"git", b"config", b"--global", name, value]
        assert subprocess.run(cmd).returncode == 0
    proc = run_script("sync")
    assert proc.returncode == 0, proc.stderr
    with open(signers, "rb") as f:
        assert b"torvalds@example.org" in f.read()
    assert os.path.exists(revocations)


def test_saved_registry_url_not_utf8_is_a_clean_error(home: Path, remote: Path) -> None:
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    (data_dir(home) / "registry" / ".git" / "vouch-url").write_bytes(b"\xff")
    proc = run_script("sync")
    assert proc.returncode == 1
    assert "git-vouch: error: cannot update the registry copy at" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_check_a_worktree_under_a_non_utf8_directory(
    remote: Path, tmp_path: Path
) -> None:
    """A linked worktree's git-common-dir is an absolute path, here not UTF-8."""
    clone = os.fsencode(tmp_path) + b"/r-\xff"
    worktree = os.fsencode(tmp_path) + b"/worktree"
    for cmd in (
        [b"git", b"clone", b"-q", os.fsencode(remote), clone],
        [b"git", b"-C", clone, b"worktree", b"add", b"-q", worktree],
    ):
        proc = subprocess.run(cmd, capture_output=True)
        assert proc.returncode == 0, proc.stderr
    proc = run_script("check", os.fsdecode(worktree))
    assert proc.returncode == 0, proc.stderr
    assert "torvalds" in proc.stdout

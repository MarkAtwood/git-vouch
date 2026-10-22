"""docs/guide-anchors.md, run block by block in a throwaway registry.

Every ``sh`` block on the page follows a ``<!-- as <who> -->`` marker and
runs as that person: in their own home, with their SSH keys in an agent.
A ``<!-- merge <branch> -->`` marker runs the page's merge block, and the
push block after it, again for that branch. A line ending in ``# fails`` must fail. The page is the
script, so the two cannot drift apart. Each step starts in a later second
than the one before: registry times have one-second resolution, and the
page's steps are days apart in real life.

The oracles are real ``git verify-tag``, which judges every tag against
the exported files, and the signatures ``ssh-keygen`` makes on throwaway
keys. ``check`` output is used only to see that the tiers and warnings
the page promises are the ones printed.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import NamedTuple

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "guide-anchors.md"
TOKEN = re.compile(
    r"^<!-- (as|merge) ([a-z0-9-]+) -->$|^```(sh|text)\n(.*?)^```$", re.M | re.S
)
KEYS = {"korg": [], "lena": ["id_ed25519", "backup", "id_new", "id_next"],
        "alice": ["id_ed25519", "id_new"]}  # fmt: skip
TIER = re.compile(r"[a-z0-9_-]+ (anchor|maintainer|contributor|automation|none)")
PROLOGUE = """set -euo pipefail
shopt -s nullglob
eval "$(ssh-agent -s)" >/dev/null
trap 'ssh-agent -k >/dev/null' EXIT
for k in ~/.ssh/*.pub; do ssh-add -q "${k%.pub}"; done
"""


class Step(NamedTuple):
    """One block of the page: who runs it and its commands."""

    who: str
    body: str


class Ran(NamedTuple):
    """A step and what it printed."""

    step: Step
    proc: subprocess.CompletedProcess[str]


def _steps() -> list[Step]:
    """Return the page's runnable steps in order, with merges expanded."""
    steps: list[Step] = []
    who = None
    merge: list[str] = []
    for m in TOKEN.finditer(DOC.read_text()):
        kind, arg, lang, body = m.groups()
        if kind == "as":
            assert who is None, f"two markers before one block: {arg}"
            who = arg
        elif kind == "merge":
            assert len(merge) == 2, "a merge marker before the merge and push blocks"
            first = re.sub(r"^branch=\S+", f"branch={arg}", merge[0])
            steps += [Step("korg", first), Step("korg", merge[1])]
        elif lang == "sh":
            assert who in KEYS, f"sh block without an 'as' marker:\n{body}"
            steps.append(Step(who, body))
            if body.startswith("branch="):
                merge = [body]
            elif len(merge) == 1:
                assert "git push -q origin main" in body, "no push after the merge"
                merge.append(body)
            who = None
        else:
            assert who is None, f"marker before a text block:\n{body}"
    return steps


def _script(body: str) -> str:
    """Return ``body`` as a bash script in which every ``# fails`` line must fail."""
    lines = []
    for line in body.replace("\\\n", " ").splitlines():
        m = re.fullmatch(r"(.*?)\s+# fails\b.*", line)
        lines.append(f"if {m.group(1)}; then exit 1; fi" if m else line)
    return PROLOGUE + "\n".join(lines) + "\n"


def _git(cwd: Path, *args: str, env: dict[str, str]) -> None:
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True)


def _build(world: Path, env: dict[str, str]) -> None:
    """Make each person's home, an empty bare registry and a kernel tree."""
    for who, keys in KEYS.items():
        ssh = world / who / ".ssh"
        ssh.mkdir(parents=True)
        (world / who / ".gitconfig").write_text(
            f"[user]\n\tname = {who}\n\temail = {who}@example.org\n"
            "[init]\n\tdefaultBranch = main\n"
        )
        for key in keys:
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{who} {key}",
                 "-f", str(ssh / key)],
                check=True,
            )  # fmt: skip
    src = world / "linux-src"
    src.mkdir()
    (src / "README").write_text("Linux kernel\n")
    ident = ["-c", "user.name=korg", "-c", "user.email=korg@example.org"]
    _git(src, "init", "-q", "-b", "main", env=env)
    _git(src, "add", "README", env=env)
    _git(src, *ident, "commit", "-q", "-m", "Linux 6.98", env=env)
    _git(world, "clone", "-q", "--bare", str(src), "linux.git", env=env)
    _git(world, "init", "-q", "--bare", "-b", "main", "registry.git", env=env)


@pytest.fixture(scope="module")
def guide(tmp_path_factory: pytest.TempPathFactory) -> list[Ran]:
    """Run every step of the page in order, stopping at the first that fails."""
    world = tmp_path_factory.mktemp("anchors")
    drop = ("GIT_CONFIG_GLOBAL", "GIT_DIR", "SSH_AUTH_SOCK", "SSH_AGENT_PID",
            "XDG_DATA_HOME", "XDG_CONFIG_HOME")  # fmt: skip
    env = {k: v for k, v in os.environ.items() if k not in drop}
    env.update(
        # The tools on PATH as installed, run by this interpreter's python3.
        PATH=os.pathsep.join(
            (str(ROOT), str(Path(sys.executable).parent), env["PATH"])
        ),
        GIT_CONFIG_NOSYSTEM="1",
        # git passes verify-time as local time without a zone, and OpenSSH 9.6
        # reads it as standard time, an hour late under DST: a signature made
        # within the hour before its key's retirement then fails to verify.
        TZ="UTC",
        HOME=str(world),
        REGISTRY=str(world / "registry.git"),
        LINUX=str(world / "linux.git"),
    )
    _build(world, env)
    env["STOLEN"] = (world / "alice" / ".ssh" / "id_ed25519.pub").read_text().strip()
    version = subprocess.run(
        ["python3", "-c", "import sys; print(sys.version_info[:2])"],
        env=env, capture_output=True, text=True, check=True,
    ).stdout.strip()  # fmt: skip
    assert version == str(sys.version_info[:2]), "python3 on PATH is not this one"
    ran = []
    for step in _steps():
        time.sleep(1 - time.time() % 1)
        home = world / step.who
        proc = subprocess.run(
            ["bash", "-c", _script(step.body)], cwd=home,
            env=dict(env, HOME=str(home)), capture_output=True, text=True,
        )  # fmt: skip
        ran.append(Ran(step, proc))
        if proc.returncode != 0:
            break
    return ran


def _out(
    guide: list[Ran], command: str, nth: int = 0
) -> subprocess.CompletedProcess[str]:
    """Return what the ``nth`` step whose commands include ``command`` printed."""
    return [r.proc for r in guide if command in r.step.body][nth]


def _merged(guide: list[Ran], branch: str) -> subprocess.CompletedProcess[str]:
    return _out(guide, f"branch={branch}\n")


def test_every_step_succeeds(guide: list[Ran]) -> None:
    for r in guide:
        assert r.proc.returncode == 0, (
            f"as {r.step.who}:\n{r.step.body}\n{r.proc.stdout}{r.proc.stderr}"
        )
    assert len(guide) == len(_steps())


def test_every_pushed_branch_is_merged() -> None:
    bodies = [s.body for s in _steps()]
    pushed = re.findall(r"origin HEAD:(\S+)", "\n".join(bodies))
    merged = re.findall(
        r"(?:^branch=|fetch -q origin )([a-z0-9-]+)$", "\n".join(bodies), re.M
    )
    assert pushed and sorted(pushed) == sorted(merged)


def test_tags_verify_by_tier(guide: list[Ran]) -> None:
    pull = _out(guide, "git verify-tag alice-6.99").stderr
    assert 'Good "git" signature for alice with ED25519 key' in pull
    release = _out(guide, 'git tag -s -m "Linux 6.99"').stderr
    assert 'Good "git" signature for lena with ED25519 key' in release
    assert release.count("No principal matched") == 1  # alice is not an anchor


def test_retired_key_keeps_its_release_tag(guide: list[Ran]) -> None:
    after = _out(guide, "verify-tag v6.99", nth=1).stderr
    assert 'Good "git" signature for lena with ED25519 key' in after


def test_demotion_ends_maintainer_signing(guide: list[Ran]) -> None:
    assert "alice contributor" in _merged(guide, "demote-alice").stdout.splitlines()
    err = _out(guide, "git verify-tag alice-7.0").stderr
    assert err.count('Good "git" signature for alice') == 1  # alice-6.99 only
    assert err.count("No principal matched") == 1  # alice-7.0


def test_revocation_rejects_old_signatures(guide: list[Ran]) -> None:
    err = _out(guide, "git verify-tag alice-6.99", nth=2).stderr
    assert "No principal matched" in err
    assert "signature for alice" not in err


def test_unsigned_recovery_warns_and_keeps_the_tier(guide: list[Ran]) -> None:
    merge = _merged(guide, "recover-alice")
    assert re.search(r"people/alice\.json: WARNING: changed at \S+ without a signature",
                     merge.stderr)  # fmt: skip
    assert "alice contributor" in merge.stdout.splitlines()


def test_lost_key_voids_what_it_signed_until_resigned(guide: list[Ran]) -> None:
    err = _out(guide, "--reason lost").stderr
    assert re.search(
        r"tiers/alice\.json: void: did:key:z6Mk\w+ of lena is revoked", err
    )
    final = _merged(guide, "lost-lena")
    tiers = [ln for ln in final.stdout.splitlines() if TIER.fullmatch(ln)]
    assert tiers == ["alice contributor", "lena anchor"]
    for gone in ("error", "alice@example.org is not endorsed", "revoked but not retired",
                 "tiers/alice.json: void"):  # fmt: skip
        assert gone not in final.stderr


def test_sample_output_on_the_page_was_printed(guide: list[Ran]) -> None:
    printed = "".join(r.proc.stderr for r in guide)
    samples = [
        m.group(4) for m in TOKEN.finditer(DOC.read_text()) if m.group(3) == "text"
    ]
    assert samples
    for line in "".join(samples).splitlines():
        pattern = re.escape(line).replace("<commit>", r"\S+")
        pattern = pattern.replace(re.escape("did:key:z6Mk..."), r"did:key:z6Mk\w+")
        assert re.search(pattern, printed), line

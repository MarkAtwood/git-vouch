"""docs/guide-captains.md, run block by block in a throwaway registry.

The world is built as a captain finds it during the flag-day window: a
pgpkeys.git of throwaway GPG keys frozen at a commit C that korg signed,
in which alice certified bob's key; a registry where lena is already the
anchor and bob has registered with a continuity proof (the PRELUDE, steps
other guides cover); and a kernel tree. Then every ``sh`` block on the
page runs, in order, as the person its ``<!-- as <who> -->`` marker
names: in their own home, with their SSH keys in an agent and their own
GNUPGHOME. A ``<!-- merge <branch> -->`` marker runs the page's merge
block, and the push block after it, again for that branch. A line ending
in ``# fails`` must fail. Each step starts in a later second than the
one before: registry times have one-second resolution.

The oracles are real ``git verify-tag``, which judges every tag against
the exported files, gpg's own certification, and the signatures
``ssh-keygen`` makes on throwaway keys. ``check`` output is used only to
see that the tiers and warnings the page promises are the ones printed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

from .conftest import C_DATE, Gpg, _git

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "guide-captains.md"
TOKEN = re.compile(
    r"^<!-- (as|merge) ([a-z0-9-]+) -->$|^```(sh|text)\n(.*?)^```$", re.M | re.S
)
KEYS = {"korg": [], "lena": ["id_ed25519"], "bob": ["id_ed25519"],
        "carol": ["id_ed25519"], "alice": ["id_ed25519", "backup", "id_new", "id_next"]}  # fmt: skip
CERTIFIED = "20200102T000000"  # when alice certifies bob, after both keys exist
TIER = re.compile(r"[a-z0-9_-]+ (anchor|maintainer|contributor|automation|none)")
PROLOGUE = """set -euo pipefail
shopt -s nullglob
eval "$(ssh-agent -s)" >/dev/null
trap 'ssh-agent -k >/dev/null' EXIT
for k in ~/.ssh/*.pub; do ssh-add -q "${k%.pub}"; done
"""
MERGE = """cd registry
git fetch -q origin {0}
git merge -q --no-edit FETCH_HEAD
git vouch check .
git push -q origin main
"""


class Step(NamedTuple):
    """One block: who runs it and its commands."""

    who: str
    body: str


class Ran(NamedTuple):
    """A step and what it printed."""

    step: Step
    proc: subprocess.CompletedProcess[str]


class Guide(NamedTuple):
    """The world after the page ran, and what each step printed."""

    world: Path
    fprs: dict[str, str]
    ran: list[Ran]
    env: dict[str, str]


# The window as the page starts: lena is the anchor, bob has registered
# from his pgpkeys draft with a continuity proof.
PRELUDE = [
    Step("korg", 'git clone -q "$REGISTRY" registry\n'),
    Step("lena", """git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$REGISTRY" registry
cd registry
git vouch register --handle lena --name "Lena Anchor" --email lena@example.org \
    ~/.ssh/id_ed25519.pub
git add people
git commit -q -m "people: register lena"
git push -q origin HEAD:register-lena
"""),
    Step("korg", """cd registry
git fetch -q origin register-lena
git merge -q --ff-only FETCH_HEAD
echo '["lena"]' >anchors.json
git add anchors.json
git commit -q -m "anchors: lena"
git vouch check .
git push -q origin main
"""),
    Step("bob", """git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$C" --signer "$SIGNER" --out drafts
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/bob.json ~/.ssh/id_ed25519.pub
gpg --armor --detach-sign people/bob.json
git add people
git commit -q -m "people: register bob"
git push -q origin HEAD:register-bob
"""),
    Step("korg", MERGE.format("register-bob")),
]  # fmt: skip


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


def _home(world: Path, who: str) -> Gpg:
    """Make ``who``'s home with a git identity and SSH keys; return their gpg."""
    home = world / who
    (home / ".ssh").mkdir(parents=True)
    (home / "gnupg").mkdir(mode=0o700)
    (home / ".gitconfig").write_text(
        f"[user]\n\tname = {who}\n\temail = {who}@example.org\n"
        "[init]\n\tdefaultBranch = main\n"
    )
    for key in KEYS[who]:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{who} {key}",
             "-f", str(home / ".ssh" / key)],
            check=True,
        )  # fmt: skip
    return Gpg(home / "gnupg")


def _build(world: Path) -> tuple[dict[str, str], str]:
    """Build the homes, the frozen pgpkeys.git, the registry and the kernel tree.

    Return (fprs, C).
    """
    gpgs = {who: _home(world, who) for who in KEYS}
    fprs = {
        "korg": gpgs["korg"].new_key("Kay Org <korg@kernel.org>"),
        "alice": gpgs["alice"].new_key("Alice Example <alice@example.org>"),
        "bob": gpgs["bob"].new_key("Bob Builder <bob@example.net>"),
    }
    exported = world / "bob.gpg"
    exported.write_bytes(gpgs["bob"]("--export", fprs["bob"]))
    gpgs["alice"]("--import", str(exported))
    gpgs["alice"]("-u", fprs["alice"] + "!", "--quick-sign-key", fprs["bob"],
                  at=CERTIFIED)  # fmt: skip

    repo = world / "pgpkeys.git"
    (repo / "keys").mkdir(parents=True)
    # alice's home holds the copy of bob's key with her certification on it.
    holders = {"korg": "korg", "alice": "alice", "bob": "alice"}
    for who, fpr in fprs.items():
        armored = gpgs[holders[who]]("--armor", "--export", fpr)
        (repo / "keys" / f"{fpr[-16:]}.asc").write_bytes(armored)
    korg = gpgs["korg"].home
    env = dict(
        os.environ,
        GNUPGHOME=str(korg),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_AUTHOR_DATE=C_DATE,
        GIT_COMMITTER_DATE=C_DATE,
    )
    (korg / "gpg.conf").write_text("faked-system-time 20200601T000000!\n")
    ident = ["-c", "user.name=Kay Org", "-c", "user.email=korg@kernel.org"]
    sign = ["-c", "gpg.format=openpgp", "-c", "gpg.program=gpg"]
    sign += ["-c", f"user.signingkey={fprs['korg']}!"]
    _git(repo, "init", "-q", env=env)
    _git(repo, "add", "keys", env=env)
    _git(repo, *ident, *sign, "commit", "-q", "-S", "-m", "freeze", env=env)
    commit = _git(repo, "rev-parse", "HEAD", env=env)
    (korg / "gpg.conf").unlink()

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
def guide(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Guide]:
    """Run the prelude, then every step of the page, stopping at the first failure."""
    world = tmp_path_factory.mktemp("captains")
    drop = ("GIT_CONFIG_GLOBAL", "GIT_DIR", "GNUPGHOME", "GPG_AGENT_INFO",
            "SSH_AUTH_SOCK", "SSH_AGENT_PID", "XDG_DATA_HOME", "XDG_CONFIG_HOME")  # fmt: skip
    env = {k: v for k, v in os.environ.items() if k not in drop}
    try:
        fprs, commit = _build(world)
        env.update(
            # The tools on PATH as installed, run by this interpreter's python3.
            PATH=os.pathsep.join(
                (str(ROOT), str(Path(sys.executable).parent), env["PATH"])
            ),
            GIT_CONFIG_NOSYSTEM="1",
            # git passes verify-time as local time without a zone, and OpenSSH
            # 9.6 reads it as standard time, an hour late under DST.
            TZ="UTC",
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
        ran = []
        for step in PRELUDE + _steps():
            time.sleep(1 - time.time() % 1)
            home = world / step.who
            proc = subprocess.run(
                ["bash", "-c", _script(step.body)], cwd=home,
                env=dict(env, HOME=str(home), GNUPGHOME=str(home / "gnupg")),
                capture_output=True, text=True,
            )  # fmt: skip
            ran.append(Ran(step, proc))
            if proc.returncode != 0:
                break
        yield Guide(world, fprs, ran, env)
    finally:
        for home in world.glob("*/gnupg"):
            subprocess.run(
                ["gpgconf", "--homedir", str(home), "--kill", "all"], check=False
            )


def _out(guide: Guide, command: str, nth: int = 0) -> subprocess.CompletedProcess[str]:
    """Return what the ``nth`` step whose commands include ``command`` printed."""
    return [r.proc for r in guide.ran if command in r.step.body][nth]


def _merged(guide: Guide, branch: str) -> subprocess.CompletedProcess[str]:
    return _out(guide, f"branch={branch}\n")


def test_every_step_succeeds(guide: Guide) -> None:
    for r in guide.ran:
        assert r.proc.returncode == 0, (
            f"as {r.step.who}:\n{r.step.body}\n{r.proc.stdout}{r.proc.stderr}"
        )
    assert len(guide.ran) == len(PRELUDE) + len(_steps())


def test_every_pushed_branch_is_merged() -> None:
    bodies = "\n".join(s.body for s in PRELUDE + _steps())
    pushed = re.findall(r"origin HEAD:(\S+)", bodies)
    merged = re.findall(r"(?:^branch=|fetch -q origin )([a-z0-9-]+)$", bodies, re.M)
    assert pushed and sorted(pushed) == sorted(merged)


def test_the_page_links_to_vouching() -> None:
    assert "](vouching.md)" in DOC.read_text()


def test_continuity_proof_is_alices_gpg_signature(guide: Guide) -> None:
    registry = guide.world / "korg" / "registry"
    asc = registry / "people" / "alice.json.asc"
    first = _git(
        registry, "log", "--format=%H", "--diff-filter=A", "--", "people/alice.json.asc",
        env=dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull),
    )  # fmt: skip
    signed = guide.world / "alice-registered.json"
    signed.write_bytes(
        subprocess.run(
            ["git", "show", f"{first}:people/alice.json"], cwd=registry,
            check=True, capture_output=True,
        ).stdout
    )  # fmt: skip
    alice = guide.fprs["alice"]
    gpg = Gpg(guide.world / "verifier")
    gpg.home.mkdir(mode=0o700)
    gpg("--import", str(guide.world / "pgpkeys.git" / "keys" / f"{alice[-16:]}.asc"))
    status = gpg("--status-fd", "1", "--verify", str(asc), str(signed)).decode()
    assert f"VALIDSIG {alice}" in status


def test_drafts_come_from_alices_certification(guide: Guide) -> None:
    draft = guide.world / "alice" / "endorsement-drafts" / "endorsements" / "bob"
    (only,) = draft.glob("*.json")
    record = json.loads(only.read_text())
    assert record["endorser"] == "alice"
    assert record["subjectEmails"] == ["bob@example.net"]
    assert record["note"] == (
        f'Certified GPG key {guide.fprs["bob"]} user ID "Bob Builder <bob@example.net>"'
        " on 2020-01-02."
    )


def test_tiers_after_approvals(guide: Guide) -> None:
    lines = _merged(guide, "endorse-alice").stdout.splitlines()
    assert "alice maintainer" in lines
    assert "bob contributor" in lines


def test_pull_tags_verify_by_tier(guide: Guide) -> None:
    bob = _out(guide, "git verify-tag bob-6.99").stderr
    assert 'Good "git" signature for bob with ED25519 key' in bob
    carol_before = _out(guide, "git verify-tag carol-6.99").stderr
    assert "No principal matched" in carol_before
    carol_after = _out(guide, "git verify-tag carol-6.99", nth=1).stderr
    assert 'Good "git" signature for carol with ED25519 key' in carol_after


def test_retired_key_keeps_its_tag(guide: Guide) -> None:
    err = _out(guide, "git verify-tag alice-6.99").stderr
    assert 'Good "git" signature for alice with ED25519 key' in err


def test_lost_key_voids_what_it_signed_until_resigned(guide: Guide) -> None:
    err = _out(guide, "--reason lost").stderr
    assert re.search(
        r"tiers/carol\.json: void: did:key:z6Mk\w+ of alice is revoked", err
    )
    assert "tiers/bob.json: void" not in err  # signed by the retired key
    final = _merged(guide, "lost-alice")
    tiers = [ln for ln in final.stdout.splitlines() if TIER.fullmatch(ln)]
    assert tiers == ["alice maintainer", "bob contributor", "carol contributor",
                     "lena anchor"]  # fmt: skip
    for gone in ("error", "carol@example.com is not endorsed", "revoked but not retired",
                 "tiers/carol.json: void"):  # fmt: skip
        assert gone not in final.stderr
    assert "endorsements/carol/alice-1.json: void" in final.stderr  # as the page says


def test_tags_verify_after_lost_key_is_replaced(guide: Guide) -> None:
    err = _out(guide, "git verify-tag bob-6.99", nth=1).stderr
    assert 'Good "git" signature for bob with ED25519 key' in err
    assert 'Good "git" signature for carol with ED25519 key' in err


def _verify(guide: Guide, registry: Path, tag: str, *export: str) -> str:
    """Export ``registry`` with ``export`` options; return git verify-tag's output."""
    out = guide.world / "export"
    out.mkdir(exist_ok=True)
    signers, revoked = out / "allowed_signers", out / "revoked"
    env = dict(guide.env, HOME=str(guide.world / "alice"), GIT_CONFIG_GLOBAL=os.devnull)
    subprocess.run(
        ["git", "vouch", "export", str(registry), *export,
         "--allowed-signers", str(signers), "--revocation-file", str(revoked)],
        env=env, check=True, capture_output=True,
    )  # fmt: skip
    proc = subprocess.run(
        ["git", "-c", "gpg.format=ssh", "-c", f"gpg.ssh.allowedSignersFile={signers}",
         "-c", f"gpg.ssh.revocationFile={revoked}", "verify-tag", tag],
        cwd=guide.world / "alice" / "linux", env=env, capture_output=True, text=True,
    )  # fmt: skip
    return proc.stderr if proc.returncode == 0 else f"FAILED\n{proc.stderr}"


def test_maintainer_export_takes_alice_not_bob(guide: Guide) -> None:
    registry = guide.world / "korg" / "registry"
    alice = _verify(guide, registry, "alice-6.99", "--min-tier", "maintainer")
    assert 'Good "git" signature for alice with ED25519 key' in alice
    bob = _verify(guide, registry, "bob-6.99", "--min-tier", "maintainer")
    assert bob.startswith("FAILED") and "No principal matched" in bob


def test_tier_signed_by_revoked_key_grants_nothing(guide: Guide) -> None:
    clone = guide.world / "void-registry"
    env = dict(guide.env, GIT_CONFIG_GLOBAL=os.devnull)
    _git(guide.world, "clone", "-q", str(guide.world / "registry.git"), str(clone),
         env=env)  # fmt: skip
    # The lost-alice change before alice re-signed: the revocation and her
    # new person file on top of the registry before it, and nothing else.
    _git(clone, "switch", "-q", "-c", "unsigned", "HEAD^1", env=env)
    _git(clone, "checkout", "-q", "main", "--", "people", "revocations", env=env)
    _git(clone, "-c", "user.name=t", "-c", "user.email=t@example.org",
         "commit", "-q", "-m", "revoke only", env=env)  # fmt: skip
    carol = _verify(guide, clone, "carol-6.99")
    assert carol.startswith("FAILED") and "No principal matched" in carol
    assert "Good" in _verify(guide, clone, "bob-6.99")


def test_sample_output_on_the_page_was_printed(guide: Guide) -> None:
    printed = "".join(r.proc.stderr for r in guide.ran)
    samples = [
        m.group(4) for m in TOKEN.finditer(DOC.read_text()) if m.group(3) == "text"
    ]
    assert samples
    for line in "".join(samples).splitlines():
        pattern = re.escape(line).replace(
            re.escape("did:key:z6Mk..."), r"did:key:z6Mk\w+"
        )
        assert re.search(pattern, printed), line

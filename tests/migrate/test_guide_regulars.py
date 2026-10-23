"""docs/guide-regulars.md, run block by block in a throwaway registry.

The world is built as a regular finds it during the flag-day window: a
pgpkeys.git of throwaway GPG keys frozen at a commit that korg signed
(the freeze commit), in which alice certified bob's key; a registry where
lena is the anchor and alice a maintainer registered with a continuity
proof (the PRELUDE, steps other guides cover); and a kernel tree.
Then every ``sh`` block on the page runs, in order, as the person its
``<!-- as <who> -->`` marker names: in their own home, with their SSH
keys in an agent and their own GNUPGHOME. A ``<!-- merge <branch> -->``
marker runs the page's merge block, and the push block after it, again
for that branch. A line ending in ``# fails`` must fail. The one block
marked ``<!-- not-run ... -->`` needs FIDO tokens and is only checked to
hold nothing but ``ssh-keygen`` lines. Each step starts in a later second
than the one before: registry times have one-second resolution.

The oracles are real ``git verify-commit`` and ``git verify-tag``, which
judge every signature against the exported files, gpg's own signature
check, and the signatures ``ssh-keygen`` makes on throwaway keys. After
the page, bob signs with his revoked and his replacement key, and git
judges both.
``check`` output is used only to see that the tiers and warnings the
page promises are the ones printed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import NamedTuple

import pytest

from .conftest import FREEZE_DATE, Gpg, _git

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "guide-regulars.md"
TOKEN = re.compile(
    r"^<!-- (as|merge|not-run) ([a-z0-9-]+) -->$|^```(sh|text)\n(.*?)^```$",
    re.M | re.S,
)
KEYS = {"korg": [], "lena": ["id_ed25519"], "alice": ["id_ed25519"],
        "carol": ["id_ed25519"], "bob": ["id_ed25519", "backup", "id_new", "id_next"]}  # fmt: skip
CERTIFIED = "20200102T000000"  # when alice certifies bob, after both keys exist
# Always on daylight saving time, whatever the date.
DST = "XST0XDT,0/0,365/25"
DROP = ("GIT_CONFIG_GLOBAL", "GIT_DIR", "GNUPGHOME", "GPG_AGENT_INFO",
        "SSH_AUTH_SOCK", "SSH_AGENT_PID", "XDG_DATA_HOME", "XDG_CONFIG_HOME")  # fmt: skip
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


# The window as the page starts: lena is the anchor, alice registered from
# her pgpkeys draft with a continuity proof and lena approved her as a
# maintainer.
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
    Step("alice", """git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$FREEZE_COMMIT" --signer "$SIGNER" --out drafts
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/alice.json ~/.ssh/id_ed25519.pub
gpg --armor --detach-sign people/alice.json
git add people
git commit -q -m "people: register alice"
git push -q origin HEAD:register-alice
"""),
    Step("korg", MERGE.format("register-alice")),
    Step("lena", """cd registry
git fetch -q origin
git switch -q -c approve-alice origin/main
git vouch endorse alice --note "Met at LPC 2026, checked passport."
git vouch approve alice maintainer
git add endorsements tiers
git commit -q -m "lena: endorse and approve alice"
git push -q origin HEAD:approve-alice
"""),
    Step("korg", MERGE.format("approve-alice")),
]  # fmt: skip


def _blocks() -> tuple[list[Step], list[str]]:
    """Return the page's runnable steps in order, with merges expanded, and the
    bodies of its not-run blocks."""
    steps: list[Step] = []
    skipped: list[str] = []
    who = None
    merge: list[str] = []
    for m in TOKEN.finditer(DOC.read_text()):
        kind, arg, lang, body = m.groups()
        if kind in ("as", "not-run"):
            assert who is None, f"two markers before one block: {arg}"
            who = arg if kind == "as" else "not-run"
        elif kind == "merge":
            assert len(merge) == 2, "a merge marker before the merge and push blocks"
            first = re.sub(r"^branch=\S+", f"branch={arg}", merge[0])
            steps += [Step("korg", first), Step("korg", merge[1])]
        elif lang == "sh" and who == "not-run":
            skipped.append(body)
            who = None
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
    return steps, skipped


def _steps() -> list[Step]:
    return _blocks()[0]


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

    Return (fprs, the freeze commit).
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
        GIT_AUTHOR_DATE=FREEZE_DATE,
        GIT_COMMITTER_DATE=FREEZE_DATE,
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
    world = tmp_path_factory.mktemp("regulars")
    env = {k: v for k, v in os.environ.items() if k not in DROP}
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
            FREEZE_COMMIT=commit,
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
        yield Guide(world, fprs, ran)
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
    registry = "\n".join(s.body for s in PRELUDE + _steps() if "registry" in s.body)
    pushed = re.findall(r"origin HEAD:(\S+)", registry)
    merged = re.findall(r"(?:^branch=|fetch -q origin )([a-z0-9-]+)$", bodies, re.M)
    assert pushed and sorted(pushed) == sorted(merged)


def test_only_key_generation_is_not_run() -> None:
    (skipped,) = _blocks()[1]
    lines = skipped.splitlines()
    assert lines and all(ln.startswith("ssh-keygen -t ed25519-sk ") for ln in lines)


def test_the_page_links_to_vouching() -> None:
    assert "](vouching.md)" in DOC.read_text()


def test_continuity_proof_is_bobs_gpg_signature(guide: Guide) -> None:
    registry = guide.world / "korg" / "registry"
    asc = registry / "people" / "bob.json.asc"
    first = _git(
        registry, "log", "--format=%H", "--diff-filter=A", "--", "people/bob.json.asc",
        env=dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull),
    )  # fmt: skip
    signed = guide.world / "bob-registered.json"
    signed.write_bytes(
        subprocess.run(
            ["git", "show", f"{first}:people/bob.json"], cwd=registry,
            check=True, capture_output=True,
        ).stdout
    )  # fmt: skip
    bob = guide.fprs["bob"]
    gpg = Gpg(guide.world / "verifier")
    gpg.home.mkdir(mode=0o700)
    gpg("--import", str(guide.world / "pgpkeys.git" / "keys" / f"{bob[-16:]}.asc"))
    status = gpg("--status-fd", "1", "--verify", str(asc), str(signed)).decode()
    assert f"VALIDSIG {bob}" in status


def test_endorsement_comes_from_alices_certification(guide: Guide) -> None:
    draft = guide.world / "alice" / "endorsement-drafts" / "endorsements" / "bob"
    (only,) = draft.glob("*.json")
    record = json.loads(only.read_text())
    assert record["endorser"] == "alice"
    assert record["subjectEmails"] == ["bob@example.net"]
    assert record["note"] == (
        f'Certified GPG key {guide.fprs["bob"]} user ID "Bob Builder <bob@example.net>"'
        " on 2020-01-02."
    )
    signed = guide.world / "korg" / "registry" / "endorsements" / "bob" / only.name
    assert signed.read_bytes() == only.read_bytes()


def test_bob_is_a_contributor(guide: Guide) -> None:
    merge = _merged(guide, "endorse-alice")
    assert "bob contributor" in merge.stdout.splitlines()
    assert "bob@example.net is not endorsed" not in merge.stderr


def test_signed_commit_and_tag_verify(guide: Guide) -> None:
    err = _out(guide, "git verify-commit origin/bob-fixes").stderr
    assert err.count('Good "git" signature for bob with ED25519 key') == 2


def test_retired_and_revoked_keys(guide: Guide) -> None:
    for nth in (1, 2):  # after the rotation, then after the lost key
        err = _out(guide, "git verify-tag bob-6.99", nth=nth).stderr
        assert 'Good "git" signature for bob with ED25519 key' in err


def _bob(
    guide: Guide, script: str, tz: str = "UTC"
) -> subprocess.CompletedProcess[str]:
    """Run ``script`` as bob in his kernel tree, with no agent, in zone ``tz``."""
    home = guide.world / "bob"
    env = {k: v for k, v in os.environ.items() if k not in DROP}
    env.update(HOME=str(home), GNUPGHOME=str(home / "gnupg"),
               GIT_CONFIG_NOSYSTEM="1", TZ=tz)  # fmt: skip
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + script], cwd=home / "linux",
        env=env, capture_output=True, text=True,
    )  # fmt: skip


def test_revoked_key_fails_and_replacement_verifies(guide: Guide) -> None:
    assert all(r.proc.returncode == 0 for r in guide.ran)
    sign = _bob(
        guide,
        """git -c user.signingKey="$HOME/.ssh/id_new" tag -s -m lost bob-lost
git -c user.signingKey="$HOME/.ssh/id_next" tag -s -m next bob-next
""",
    )
    assert sign.returncode == 0, sign.stderr
    lost = _bob(guide, "git verify-tag bob-lost")
    assert lost.returncode != 0
    assert "signature for bob" not in lost.stderr
    assert "No principal matched" in lost.stderr
    nxt = _bob(guide, "git verify-tag bob-next")
    assert nxt.returncode == 0, nxt.stderr
    assert 'Good "git" signature for bob with ED25519 key' in nxt.stderr


def test_tag_signed_before_retirement_verifies_under_dst(guide: Guide) -> None:
    """The page says the export's extra hour lets a signature made just before
    a key's retirement verify on daylight saving time; bob tagged bob-6.99
    seconds before retiring its key. Without that hour, OpenSSH 9.6 fails it."""
    assert all(r.proc.returncode == 0 for r in guide.ran)
    assert "ending every key an hour after its retirement" in DOC.read_text()
    good = 'Good "git" signature for bob with ED25519 key'
    dst = _bob(guide, "git verify-tag bob-6.99", tz=DST)
    assert dst.returncode == 0, dst.stderr
    assert good in dst.stderr

    version = subprocess.run(["ssh", "-V"], capture_output=True, text=True).stderr
    if not version.startswith("OpenSSH_9.6"):
        pytest.skip(f"the DST bug is in OpenSSH 9.6, not {version.strip()}")
    # The export as it would be without the hour: every valid-before an hour
    # earlier, at the retirement second itself.
    exported = Path(_bob(guide, "git config gpg.ssh.allowedSignersFile").stdout.strip())
    unslacked = guide.world / "allowed_signers.unslacked"
    unslacked.write_text(
        re.sub(
            r'valid-before="(\d{14})Z"',
            lambda m: 'valid-before="{:%Y%m%d%H%M%S}Z"'.format(
                datetime.strptime(m.group(1), "%Y%m%d%H%M%S") - timedelta(hours=1)
            ),
            exported.read_text(),
        )
    )
    assert unslacked.read_text() != exported.read_text()
    verify = f"git -c gpg.ssh.allowedSignersFile={unslacked} verify-tag bob-6.99"
    utc = _bob(guide, verify)
    assert utc.returncode == 0, utc.stderr
    assert good in utc.stderr
    dst = _bob(guide, verify, tz=DST)
    assert dst.returncode != 0
    assert "No principal matched" in dst.stderr


def test_endorsing_carol_exports_her_email(guide: Guide) -> None:
    assert "carol@example.com is not endorsed" in _merged(guide, "endorse-alice").stderr
    assert (
        "carol@example.com is not endorsed"
        not in _merged(guide, "endorse-carol").stderr
    )


def test_lost_key_voids_the_endorsement_until_resigned(guide: Guide) -> None:
    err = _out(guide, "--reason lost").stderr
    assert re.search(
        r"endorsements/carol/bob-1\.json: void: did:key:z6Mk\w+ of bob is revoked", err
    )
    assert "carol@example.com is not endorsed" in err
    final = _merged(guide, "lost-bob")
    tiers = [ln for ln in final.stdout.splitlines() if TIER.fullmatch(ln)]
    assert tiers == ["alice maintainer", "bob contributor", "carol none", "lena anchor"]
    for gone in (
        "error",
        "carol@example.com is not endorsed",
        "revoked but not retired",
    ):
        assert gone not in final.stderr


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

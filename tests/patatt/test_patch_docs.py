"""The Patch signing blocks of the user guides, run with released b4 and the patatt fork.

Each guide marks its patch-signing commands ``<!-- patch as <who> -->``
over a ``shell`` block, which the guides' own tests do not parse. For
each guide, every such block runs in page order, as the person named, in
a world as it stands after the flag day: lena is the anchor, alice a
maintainer, bob a contributor, carol registered but not endorsed; dave
signs patches with GPG and erin with a key ``patatt genkey`` made, both
in a pgpkeys ``.keyring`` frozen at ``$FREEZE_COMMIT``, which also holds
alice's SSH key and which a later commit adds carol's key to. Every home
has git-vouch set up, its SSH keys in an agent, and mail delivered to one
local mbox. Before the page, alice, bob, carol, dave and erin each mail
alice a signed patch.

The tools are real: b4 from a stock source tree (``B4_TREE``, default
``~/GIT/b4``) run by an interpreter with its dependencies (``B4_PYTHON``,
default ``~/PROJECT/b4/.venv/bin/python``), always with
``--offline-mode``; and the fork's committed ``git-vouch`` branch
(conftest ``FORK``) put ahead of b4's own patatt, which is what the
page's ``pip install`` line does. A block's stdin is a terminal holding
a few newlines, so ``b4 send`` gets its Enter.

After the page, carol, whose ``b4.keyringsrc`` points at her pgpkeys
clone as b4's documentation suggests, checks every patch with the page's
keyring lines,
then the page's late-cutoff line, while bob rotates his key and lena
revokes it. The oracles are b4's and patatt's own verdicts on signatures
ssh-keygen and gpg made, the selector computed from ``ssh-keygen -l``
(conftest ``selector``), and the page's sample output, which must be
what b4 printed. The one ``not-run`` block needs the network and is only
checked to be the install line, with ``FORK``'s branch the one on GitHub.
"""

from __future__ import annotations

import mailbox
import os
import pty
import re
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest

from .conftest import FORK, STOCK, selector

ROOT = Path(__file__).resolve().parents[2]
B4_TREE = Path(os.environ.get("B4_TREE", Path.home() / "GIT" / "b4"))
B4_PYTHON = Path(
    os.environ.get(
        "B4_PYTHON", Path.home() / "PROJECT" / "b4" / ".venv" / "bin" / "python"
    )
)
READERS = {"regulars": "bob", "captains": "alice", "anchors": "lena"}
BLOCK = re.compile(
    r"^<!-- patch (as|not-run) ([a-z0-9-]+) -->\n```shell\n(.*?)^```$", re.M | re.S
)
CONSOLE = re.compile(r"^```console\n(.*?)^```$", re.M | re.S)
ANSI = re.compile(r"\x1b\[[0-9;]*m")
INSTALL = "pip install 'patatt @ git+https://github.com/MarkAtwood/patatt@git-vouch'\n"
SSH = {"lena": ["id_ed25519"], "alice": ["id_ed25519"], "bob": ["id_ed25519", "id_new"],
       "carol": ["id_ed25519"], "dave": [], "erin": []}  # fmt: skip
DROP = ("GIT_CONFIG_GLOBAL", "GIT_DIR", "GNUPGHOME", "GPG_AGENT_INFO",
        "SSH_AUTH_SOCK", "SSH_AGENT_PID", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME", "PYTHONPATH")  # fmt: skip
PROLOGUE = """set -euo pipefail
shopt -s nullglob
eval "$(ssh-agent -s)" >/dev/null
trap 'ssh-agent -k >/dev/null' EXIT
for k in ~/.ssh/*.pub; do ssh-add -q "${k%.pub}"; done
"""
# A patch from ``who`` to alice, signed by patatt with the keys in its git config.
SEND = """cd ~/scratch
echo "A line from $(git config user.name)." >>README
git commit -q -a -m "README: line {n} from $(git config user.name)"
git format-patch -q --thread -1 -o ~/out-{n}
patatt sign ~/out-{n}/*.patch
git send-email -q --to alice@example.org ~/out-{n}/*.patch
"""
CONFIG = "git config --global patatt.signingkey\ngit config --global patatt.selector\n"
B4_AM = 'b4 am -m {mbox} -o ~/am "{msgid}"\n'
FORGET = "rm -rf ~/.local/share/b4\n"  # b4's patatt verdict store


class Ran(NamedTuple):
    """A step: its label, who ran it, its commands and what it printed."""

    label: str
    who: str
    body: str
    returncode: int
    out: str


class World(NamedTuple):
    """The world after a page and its checks ran."""

    page: str
    root: Path
    ran: list[Ran]

    def out(self, label: str) -> str:
        """Return what the step ``label`` printed, colours removed."""
        (r,) = [r for r in self.ran if r.label == label]
        return ANSI.sub("", r.out)


def _blocks(page: str) -> list[tuple[str, str, str]]:
    """Return the page's patch blocks as (kind, who, body), in order."""
    text = (ROOT / "docs" / f"guide-{page}.md").read_text()
    return [m.groups() for m in BLOCK.finditer(text)]


def _block(page: str, needle: str) -> str:
    """Return the body of the page's only run block containing ``needle``."""
    (body,) = [b for kind, _, b in _blocks(page) if kind == "as" and needle in b]
    return body


def _git(cwd: Path, *args: str, env: dict[str, str]) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


def _write_bin(world: Path, fork: Path) -> None:
    """Write b4, patatt and the mail sink that every home finds on PATH."""
    bindir = world / "bin"
    bindir.mkdir()
    py, src = B4_PYTHON, B4_TREE / "src"
    scripts = {
        "b4": f'PYTHONPATH="${{PATATT_SRC:-{fork}}}:{src}" exec "{py}" '
        "-c 'import b4.command; b4.command.cmd()' --offline-mode \"$@\"",
        "patatt": f'PYTHONPATH="${{PATATT_SRC:-{fork}}}" exec "{py}" '
        "-c 'import patatt; patatt.command()' \"$@\"",
        # ponytail: one mbox for everyone, mboxrd-quoted; recipients are ignored.
        "mailsink": "{ echo 'From mailsink Thu Jan  1 00:00:00 1970'; "
        f"sed 's/^From />From /'; echo; }} >>\"{world / 'mail.mbox'}\"",
    }
    for name, line in scripts.items():
        (bindir / name).write_text(f"#!/bin/sh\n{line}\n")
        (bindir / name).chmod(0o755)


def _home(world: Path, who: str) -> Path:
    """Make ``who``'s home: git identity, mail settings and SSH keys."""
    home = world / who
    (home / ".ssh").mkdir(parents=True)
    (home / "gnupg").mkdir(mode=0o700)
    config = (
        f"[user]\n\tname = {who.title()}\n\temail = {who}@example.org\n"
        "[init]\n\tdefaultBranch = main\n"
        f"[sendemail]\n\tsmtpServer = {world / 'bin' / 'mailsink'}\n\tconfirm = never\n"
    )
    if SSH[who]:
        config += f"[user]\n\tsigningKey = {home / '.ssh/id_ed25519.pub'}\n"
    (home / ".gitconfig").write_text(config)
    (home / "mail.mbox").symlink_to(world / "mail.mbox")
    for key in SSH[who]:
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{who} {key}",
             "-f", str(home / ".ssh" / key)],
            check=True,
        )  # fmt: skip
    return home


def _build(world: Path, env: dict[str, str]) -> dict[str, str]:
    """Build homes, the fork, pgpkeys.git, registry.git and linux.git; return each sender's patatt config."""
    fork = world / "patatt"
    _git(world, "clone", "-q", "--depth", "1", "--branch", "git-vouch", f"file://{FORK}",
         str(fork), env=env)  # fmt: skip
    _write_bin(world, fork / "src")
    homes = {who: _home(world, who) for who in SSH}

    dave = dict(env, GNUPGHOME=str(homes["dave"] / "gnupg"))
    subprocess.run(
        ["gpg", "--batch", "--passphrase", "", "--quick-gen-key",
         "Dave <dave@example.org>", "ed25519", "sign", "never"],
        env=dave, check=True, capture_output=True,
    )  # fmt: skip
    colons = subprocess.run(
        ["gpg", "--with-colons", "--list-keys", "dave@example.org"],
        env=dave, check=True, capture_output=True, text=True,
    ).stdout  # fmt: skip
    fpr = re.search(r"^fpr:+([0-9A-F]{40}):", colons, re.M).group(1)  # type: ignore[union-attr]
    erin = dict(env, HOME=str(homes["erin"]), PATH=f"{world / 'bin'}:{env['PATH']}")
    subprocess.run(
        ["patatt", "genkey", "-n", "erin"], env=erin, check=True, capture_output=True
    )

    pgpkeys = world / "pgpkeys"
    dave_key = pgpkeys / ".keyring/openpgp/example.org/dave/default"
    dave_key.parent.mkdir(parents=True)
    dave_key.write_bytes(
        subprocess.run(
            ["gpg", "--armor", "--export", fpr],
            env=dave,
            check=True,
            capture_output=True,
        ).stdout  # fmt: skip
    )
    erin_key = pgpkeys / ".keyring/ed25519/example.org/erin/default"
    erin_key.parent.mkdir(parents=True)
    erin_key.write_text(
        (homes["erin"] / ".local/share/patatt/public/erin.pub").read_text()
    )
    # A registered key in both sources: only the order of the page's lines
    # decides whether it verifies through vouch: or with the legacy warning.
    alice_pub = homes["alice"] / ".ssh/id_ed25519.pub"
    alice_key = pgpkeys / ".keyring/openssh/example.org/alice" / selector(alice_pub)
    alice_key.parent.mkdir(parents=True)
    alice_key.write_text(alice_pub.read_text())

    ident = ["-c", "user.name=Kay Org", "-c", "user.email=korg@kernel.org"]
    (world / "linux").mkdir()
    (world / "linux" / "README").write_text("Linux kernel\n")
    reg = world / "registry"
    reg.mkdir()
    (reg / "anchors.json").write_text('["lena"]')

    def vouch(*args: str) -> None:
        subprocess.run(
            ["git", "vouch", *args], cwd=reg, env=env, check=True, capture_output=True
        )

    def key(who: str) -> str:
        return str(homes[who] / ".ssh/id_ed25519")

    for who in ("lena", "alice", "bob", "carol"):
        vouch("register", "--sign-with", key(who), "--handle", who, "--name", who.title(),
              "--email", f"{who}@example.org", f"{key(who)}.pub")  # fmt: skip
    vouch("endorse", "--sign-with", key("lena"), "alice")
    vouch("endorse", "--sign-with", key("alice"), "lena")
    vouch("endorse", "--sign-with", key("alice"), "bob")
    vouch("approve", "--sign-with", key("lena"), "alice", "maintainer")
    vouch("approve", "--sign-with", key("alice"), "bob", "contributor")
    for repo in (pgpkeys, world / "linux", reg):
        _git(repo, "init", "-q", "-b", "main", env=env)
        _git(repo, "add", "-A", env=env)
        _git(repo, *ident, "commit", "-q", "-m", "init", env=env)
        _git(world, "clone", "-q", "--bare", str(repo), f"{repo.name}.git", env=env)
    # A commit after the freeze commit that plants carol's key, as a mirror or a stray clone could.
    carol = Path(f"{key('carol')}.pub")
    late = pgpkeys / ".keyring/openssh/example.org/carol" / selector(carol)
    late.parent.mkdir(parents=True)
    late.write_text(carol.read_text())
    _git(pgpkeys, "add", "-A", env=env)
    _git(pgpkeys, *ident, "commit", "-q", "-m", "after the freeze", env=env)
    _git(pgpkeys, "push", "-q", str(world / "pgpkeys.git"), "main", env=env)

    def ssh(who: str) -> dict[str, str]:
        pub = Path(f"{key(who)}.pub")
        return {"patatt.signingkey": f"openssh:{pub}", "patatt.selector": selector(pub)}

    return {
        "alice": ssh("alice"),
        "bob": ssh("bob"),
        "carol": ssh("carol"),
        "dave": {"patatt.signingkey": f"openpgp:{fpr}"},
        "erin": {"patatt.signingkey": "ed25519:erin"},
    }


def _with_config(config: dict[str, str], body: str) -> str:
    """Return ``body`` run with ``config`` added to git config through the environment."""
    lines = [f"export GIT_CONFIG_COUNT={len(config)}"]
    for i, (k, v) in enumerate(config.items()):
        lines += [
            f"export GIT_CONFIG_KEY_{i}={k}",
            f"export GIT_CONFIG_VALUE_{i}='{v}'",
        ]
    return "\n".join(lines) + "\n" + body


def _msgids(world: Path) -> list[tuple[str, str]]:
    """Return (sender's local part, message-id) for every message mailed so far, in order."""
    box = mailbox.mbox(str(world / "mail.mbox"), create=False)
    try:
        return [(str(m["From"]).split("<")[1].split("@")[0], str(m["Message-ID"]).strip("<>"))
                for m in box]  # fmt: skip
    finally:
        box.close()


@pytest.fixture(scope="module", params=list(READERS))
def world(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[World]:
    """Build the world, mail the prelude patches, run the page, then the checks."""
    page: str = request.param
    root = tmp_path_factory.mktemp(page)
    env = {k: v for k, v in os.environ.items() if k not in DROP}
    (root / "korg").mkdir()  # the home that builds the world
    env.update(
        HOME=str(root / "korg"),
        PATH=os.pathsep.join(
            (
                str(root / "bin"),
                str(ROOT),
                str(Path(sys.executable).parent),
                env["PATH"],
            )
        ),  # fmt: skip
        GIT_CONFIG_NOSYSTEM="1",
        TZ="UTC",
        WORLD=str(root),
        REGISTRY=str(root / "registry.git"),
        PGPKEYS=str(root / "pgpkeys.git"),
        LINUX=str(root / "linux.git"),
    )
    ran: list[Ran] = []

    def run(label: str, who: str, body: str) -> None:
        time.sleep(1 - time.time() % 1)  # registry times have one-second resolution
        home = root / who
        master, slave = pty.openpty()
        os.write(master, b"\n" * 8)
        try:
            proc = subprocess.run(
                ["bash", "-c", PROLOGUE + body], cwd=home, stdin=slave,
                env=dict(env, HOME=str(home), GNUPGHOME=str(home / "gnupg")),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300,
            )  # fmt: skip
        finally:
            os.close(master)
            os.close(slave)
        ran.append(Ran(label, who, body, proc.returncode, proc.stdout))
        assert proc.returncode == 0, f"{label} as {who}:\n{body}\n{proc.stdout}"

    def am(label: str, msgid: str, mbox: str = "~/mail.mbox") -> None:
        run(label, "carol", B4_AM.format(mbox=mbox, msgid=msgid))

    try:
        senders = _build(root, env)
        env["FREEZE_COMMIT"] = _git(
            root / "pgpkeys.git", "rev-parse", "main~1", env=env
        )
        for who in ("lena", "alice", "bob", "carol"):
            run(f"setup {who}", who, 'git vouch setup --registry "$REGISTRY"\n'
                'git clone -q "$LINUX" linux\n')  # fmt: skip
        for who in ("alice", "bob"):  # pgpkeys holders cloned it on the flag day
            run(f"pgpkeys {who}", who, 'git clone -q "$PGPKEYS" pgpkeys\n')
        for who, config in senders.items():
            body = 'git clone -q "$LINUX" scratch\n' + SEND.format(n=1)
            run(f"send {who}", who, _with_config(config, body))
        msgids = dict(_msgids(root))
        env["MSGID"] = msgids["bob"]

        for i, (kind, who, body) in enumerate(_blocks(page)):
            if kind == "as":
                run(f"page {i}", who, body)
        page_sent = [m for _, m in _msgids(root)[len(senders) :]]
        run("config", READERS[page], CONFIG)

        keyring = _block(page, "patatt.keyringsrc vouch:")
        clone = "" if "git clone" in keyring else 'git clone -q "$PGPKEYS" pgpkeys\n'
        b4_docs = "git config --global b4.keyringsrc ~/pgpkeys/.keyring\n"
        run("checker", "carol", clone + b4_docs + keyring)
        for who, msgid in msgids.items():
            am(f"am {who}", msgid)
        for i, msgid in enumerate(page_sent):
            am(f"am page {i}", msgid)
        run("head keyring", "carol", 'git clone -q "$PGPKEYS" head\n'
            'export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=b4.keyringsrc\n'
            'export GIT_CONFIG_VALUE_0="$HOME/head/.keyring"\n'
            + B4_AM.format(mbox="~/mail.mbox", msgid=msgids["carol"]))  # fmt: skip
        am("am dave again", msgids["dave"])
        tampered = (
            (root / "mail.mbox")
            .read_text()
            .replace("A line from Bob.", "A line from Eve.")
        )
        (root / "tampered.mbox").write_text(tampered)
        am("am tampered", msgids["bob"], mbox=str(root / "tampered.mbox"))
        run("stock patatt", "carol", FORGET + f"PATATT_SRC={STOCK / 'src'} "
            + B4_AM.format(mbox="~/mail.mbox", msgid=msgids["bob"]))  # fmt: skip

        run("late cutoff", "carol", _block(page, "--unset patatt.keyringsrc"))
        am("am dave late", msgids["dave"])
        am("am erin late", msgids["erin"])
        run("b4-config", "carol", "git init -q tree && cd tree\n"
            "printf '[b4]\\n\\tkeyringsrc = %s\\n' \"$HOME/pgpkeys/.keyring\" >.b4-config\n"
            + B4_AM.format(mbox="~/mail.mbox", msgid=msgids["dave"]))  # fmt: skip

        run("rotate", "bob", 'git clone -q "$REGISTRY" registry && cd registry\n'
            "git vouch add-key ~/.ssh/id_new.pub\n"
            "git vouch retire-key ~/.ssh/id_ed25519.pub\n"
            'git add people && git commit -q -m "bob: rotate" && git push -q origin HEAD:main\n'
            "git vouch sync\n"
            "git config --global user.signingKey ~/.ssh/id_new.pub\n"
            + _block(page, "patatt.selector") + SEND.format(n=2))  # fmt: skip
        rotated = _msgids(root)[-1][1]
        run("sync", "carol", "git vouch sync\n")
        am("am rotated", rotated)
        run(
            "retired",
            "carol",
            'patatt validate "$WORLD"/bob/out-2/*.patch\n'
            'rc=0\npatatt validate "$WORLD"/bob/out-1/*.patch || rc=$?\ntest $rc -eq 8\n',
        )
        run("revoke", "lena", 'git clone -q "$REGISTRY" registry && cd registry\n'
            'git vouch revoke "$WORLD/bob/.ssh/id_new.pub" --reason lost\n'
            'git add revocations && git commit -q -m "revoke bob" && git push -q origin HEAD:main\n')  # fmt: skip
        run(
            "sync revoked",
            "carol",
            "git vouch sync\nrc=0\n"
            'patatt validate "$WORLD"/bob/out-2/*.patch || rc=$?\ntest $rc -eq 8\n',
        )
        am("am rotated cached", rotated)
        run("send revoked", "bob", SEND.format(n=3))
        am("am revoked", _msgids(root)[-1][1])
        yield World(page, root, ran)
    finally:
        for home in root.glob("*/gnupg"):
            subprocess.run(
                ["gpgconf", "--homedir", str(home), "--kill", "all"], check=False
            )


def test_the_not_run_block_is_the_install_line() -> None:
    for page in READERS:
        skipped = [b for kind, _, b in _blocks(page) if kind == "not-run"]
        assert skipped == [INSTALL], page


def test_the_install_line_installs_the_tested_fork() -> None:
    # The world runs FORK's local git-vouch branch; the install line gets
    # the one on GitHub. Fetch FORK's origin before the run to compare.
    def git(*args: str) -> str:
        return subprocess.run(["git", "-C", str(FORK), *args], check=True,
                              capture_output=True, text=True).stdout.strip()  # fmt: skip

    assert "github.com" in git("remote", "get-url", "origin")
    assert "MarkAtwood/patatt" in git("remote", "get-url", "origin")
    assert git("rev-parse", "refs/heads/git-vouch") == git(
        "rev-parse", "refs/remotes/origin/git-vouch"
    )


def test_every_page_block_ran(world: World) -> None:
    ran = [r.body for r in world.ran if r.label.startswith("page ")]
    runnable = [b for kind, _, b in _blocks(world.page) if kind == "as"]
    assert ran == runnable and len(runnable) >= 3


def test_signing_config_names_the_key_and_its_selector(world: World) -> None:
    pub = world.root / READERS[world.page] / ".ssh/id_ed25519.pub"
    assert world.out("config").split() == [f"openssh:{pub}", selector(pub)]
    # Run again after rotating, the same lines name bob's new key.
    new = world.root / "bob/.ssh/id_new.pub"
    get = ["git", "config", "--file", str(new.parents[1] / ".gitconfig"), "--get"]
    key = subprocess.run([*get, "patatt.signingkey"], capture_output=True, text=True)
    sel = subprocess.run([*get, "patatt.selector"], capture_output=True, text=True)
    assert [key.stdout.strip(), sel.stdout.strip()] == [f"openssh:{new}", selector(new)]


def test_registry_signed_patches_verify(world: World) -> None:
    assert "✓ Signed: openssh/bob@example.org" in world.out("am bob")
    page_sent = [r.label for r in world.ran if r.label.startswith("am page ")]
    # regulars: bob's b4 send and git send-email; the others only check.
    assert len(page_sent) == (2 if world.page == "regulars" else 0)
    for label in page_sent:
        out = world.out(label)
        assert "✓ [PATCH] README: add another line" in out
        assert "✓ Signed: openssh/bob@example.org" in out
    if world.page != "regulars":
        (label,) = [
            r.label
            for r in world.ran
            if r.label.startswith("page ") and "b4 am" in r.body
        ]
        assert "✓ Signed: openssh/bob@example.org" in world.out(label)


def test_legacy_keyring_verifies_with_a_warning_once(world: World) -> None:
    for who, algo in (("dave", "openpgp"), ("erin", "ed25519")):
        out = world.out(f"am {who}")
        assert f"✓ Signed: {algo}/{who}@example.org" in out
        assert re.search(rf"^W: {who}@example.org/default verified via legacy keyring .*/pgpkeys/"
                         rf"\.keyring/{algo}/example\.org/{who}/default", out, re.M)  # fmt: skip
    again = world.out("am dave again")
    assert "✓ Signed: openpgp/dave@example.org" in again and "W:" not in again


def test_bad_and_unknown_signatures(world: World) -> None:
    assert "✗ BADSIG: openssh/bob@example.org" in world.out("am tampered")
    carol = world.out("am carol")
    assert "✗ No key: openssh/carol@example.org" in carol
    assert "Signed:" not in carol
    assert "✗ No key: openssh/bob@example.org" in world.out("stock patatt")


def test_keys_added_after_the_freeze_commit_do_not_verify(world: World) -> None:
    # pgpkeys.git gained carol's key after the freeze: read at its head, it verifies.
    assert "✓ Signed: openssh/carol@example.org" in world.out("head keyring")
    carol = world.out("am carol")
    assert "✗ No key: openssh/carol@example.org" in carol and "Signed:" not in carol


def test_the_registry_comes_before_the_legacy_keyring(world: World) -> None:
    # alice's key is in both: read from vouch: first, no legacy warning.
    alice = world.out("am alice")
    assert "✓ Signed: openssh/alice@example.org" in alice and "W:" not in alice


def test_late_cutoff_ends_the_fallback(world: World) -> None:
    # carol began with b4.keyringsrc at pgpkeys, which b4 reads before
    # patatt.keyringsrc; dave stays verified unless the page removed it.
    dave = world.out("am dave late")
    assert "✗ No key: openpgp/dave@example.org" in dave and "Signed:" not in dave
    assert "? Signed: ed25519/erin@example.org (TOFU: new key)" in world.out(
        "am erin late"
    )
    assert "✗ No key: openpgp/dave@example.org" in world.out("b4-config")


def test_rotation_and_revocation(world: World) -> None:
    assert "✓ Signed: openssh/bob@example.org" in world.out("am rotated")
    assert "NOKEY" in world.out("retired")
    assert "NOKEY" in world.out("sync revoked")
    # b4 remembers the earlier pass for up to 24 hours.
    assert "✓ Signed: openssh/bob@example.org" in world.out("am rotated cached")
    revoked = world.out("am revoked")
    assert "✗ No key: openssh/bob@example.org" in revoked and "Signed:" not in revoked


def test_sample_output_on_the_page_was_printed(world: World) -> None:
    printed = ANSI.sub("", "".join(r.out for r in world.ran))
    text = (ROOT / "docs" / f"guide-{world.page}.md").read_text()
    section = text[text.index("\n## Patch signing\n") :]
    samples = CONSOLE.findall(section)
    if world.page != "anchors":
        assert samples
    for line in "".join(samples).splitlines():
        pattern = re.escape(line.strip()).replace(re.escape("..."), ".*")
        assert re.search(pattern, printed), line

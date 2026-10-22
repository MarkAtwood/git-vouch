"""docs/flag-day.md prints exactly the runbook commands of rehearsal.sh.

rehearsal.sh is the oracle: test_rehearsal.py runs it end to end against
real gpg, ssh-keygen and git. This test only checks that the page and the
script have not drifted apart, in both directions and in order, so every
command the page tells people to run is one that was run, in the order it
was run.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = Path(__file__).with_name("rehearsal.sh")
DOC = ROOT / "docs" / "flag-day.md"
HARNESS = ("home", "agent")  # rehearsal.sh helpers that stand in for a person's machine
# Lines that are no runbook step: comments, subshells, the test's own assertions,
# its loop over developers, and calls to the helpers.
SKIP = re.compile(
    r"#.*|[()]|done|fi|exit 1|set -euo pipefail|for who .*|(home|merge) \S+|agent"
)
# The page names a branch or a developer where the script has "$1" or a loop variable.
ASSIGNMENT = re.compile(r"(branch|who)=[a-z0-9-]+")
SH_BLOCK = re.compile(r"^```sh\n(.*?)^```$", re.M | re.S)


def _commands(lines: Iterable[str]) -> Iterator[str]:
    """Yield each shell command in ``lines``, joining continued lines, whitespace collapsed."""
    buf = ""
    for raw in lines:
        line = raw.strip()
        if not buf and (not line or SKIP.fullmatch(line)):
            continue
        buf = f"{buf} {line}" if buf else line
        if buf.endswith("\\"):
            buf = buf[:-1]
        elif not buf.endswith("|") and buf.count("'") % 2 == 0:
            yield " ".join(buf.split())
            buf = ""
    assert not buf, f"unterminated command: {buf}"


def _rehearsal_units() -> list[list[str]]:
    """Return rehearsal.sh's runbook commands in order, with merge's ``"$1"`` named ``"$branch"``.

    The script is cut into runs at every skipped line (a subshell, comment,
    loop or helper call) and at function boundaries.
    """
    units: list[list[str]] = []
    run: list[str] = []

    def cut() -> None:
        cmds = [re.sub(r"^if (.*); then$", r"\1", c) for c in _commands(run)]
        if cmds:
            units.append(cmds)
        run.clear()

    in_harness = False
    for line in RUNBOOK.read_text().splitlines():
        if re.match(r"\w+\(\) \{", line):
            cut()
            in_harness = line.split("(")[0] in HARNESS
        elif line == "}":
            cut()
            in_harness = False
        elif in_harness:
            continue
        elif SKIP.fullmatch(line.strip()):
            cut()
        else:
            run.append(line.replace('"$1"', '"$branch"'))
    cut()
    return units


def _doc_blocks() -> list[list[str]]:
    """Return the commands of each of the page's sh blocks, without trailing comments."""
    blocks = []
    for block in SH_BLOCK.findall(DOC.read_text()):
        lines = [re.sub(r"\s+#.*$", "", ln) for ln in block.splitlines()]
        blocks.append([c for c in _commands(lines) if not ASSIGNMENT.fullmatch(c)])
    return blocks


def _rehearsal_commands() -> set[str]:
    return {c for unit in _rehearsal_units() for c in unit}


def _doc_commands() -> set[str]:
    return {c for block in _doc_blocks() for c in block}


def _is_rehearsed_run(block: list[str], units: list[list[str]]) -> bool:
    """Return whether ``block`` is one or more consecutive rehearsal runs, in order."""
    for i in range(len(units)):
        joined: list[str] = []
        for unit in units[i:]:
            joined += unit
            if joined == block:
                return True
            if joined != block[: len(joined)]:
                break
    return False


def test_every_runbook_command_is_on_the_page() -> None:
    missing = sorted(_rehearsal_commands() - _doc_commands())
    assert not missing, "\n".join(missing)


def test_every_command_on_the_page_was_rehearsed() -> None:
    unrehearsed = sorted(_doc_commands() - _rehearsal_commands())
    assert not unrehearsed, "\n".join(unrehearsed)


def test_every_block_on_the_page_runs_as_rehearsed() -> None:
    units = _rehearsal_units()
    wrong = [b for b in _doc_blocks() if not _is_rehearsed_run(b, units)]
    assert not wrong, "\n\n".join("\n".join(b) for b in wrong)


def test_the_parse_finds_the_runbook() -> None:
    cmds = _rehearsal_commands()
    # Spot checks against the script's text, so a parser that drops lines fails here.
    assert 'git fetch -q origin "$branch"' in cmds
    assert "git verify-tag bob-6.99" in cmds
    awk = "gpg --list-secret-keys --with-colons --with-keygrip | awk"
    assert any(c.startswith(awk) for c in cmds)
    assert any(c.startswith("for f in ~/endorsement-drafts/") for c in cmds)
    assert not any(
        c.startswith(("home", "agent", "eval", "trap", "ssh-add")) for c in cmds
    )

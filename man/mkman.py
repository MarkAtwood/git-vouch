#!/usr/bin/env python3
"""Write man/git-vouch.1 and man/git-vouch-migrate.1 from the tools' own argument parsers.

The command-line help is the documentation (DESIGN.md, Commands); the man
pages exist so that ``git help vouch`` and ``git vouch --help``, which git
turns into ``man git-vouch``, find it. Each page is generated from the
tool's ``build_parser()``, so the two cannot drift apart:
tests/test_man.py fails if a checked-in page is not what this script
writes. Run it after changing any command, option or help text:

    python3 man/mkman.py

The output depends only on the parsers and the text below, never on the
date, the terminal width or the Python version.
"""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "man"

# Sections the parser cannot give: what the tool is, what it touches, and
# where to read more. Facts come from README.md and DESIGN.md.
EXTRA = {
    "git-vouch": {
        "DESCRIPTION": [
            (
                "git-vouch answers whether a signer is a real person whom real people"
                " vouch for, and whether their key may sign here. People, endorsements"
                " and tier grants are signed files in a registry git repository;"
                " git vouch checks the registry's rules and writes the allowed_signers"
                " and revocation files that git's SSH signing reads. After"
                " \\fBgit vouch setup\\fR, plain \\fBgit verify-tag\\fR and"
                " \\fBgit log --show-signature\\fR verify against the registry."
            ),
            (
                "All signing and verification is done by \\fBssh-keygen\\fR(1) and"
                " \\fBgit\\fR(1); git-vouch contains no cryptography and uses only the"
                " Python standard library."
            ),
            (
                "Commands that write records (\\fBregister\\fR, \\fBadd-key\\fR,"
                " \\fBretire-key\\fR, \\fBendorse\\fR, \\fBapprove\\fR, \\fBrevoke\\fR,"
                " \\fBcosign\\fR) work in the registry checkout in the current directory"
                " and never push: commit the files and send a branch for the registry"
                " maintainer to merge."
            ),
        ],
        "CONFIGURATION": [
            ("vouch.registry", "The registry URL; set by \\fBsetup\\fR."),
            (
                "vouch.minTier, vouch.includeAutomation",
                "Export choices saved by \\fBsetup\\fR and \\fBsync\\fR.",
            ),
            (
                "gpg.ssh.allowedSignersFile, gpg.ssh.revocationFile, gpg.format",
                (
                    "Set globally by \\fBsetup\\fR, only after its first sync succeeds,"
                    " and never over a different existing value."
                ),
            ),
            (
                "user.signingKey",
                (
                    "The default key for the signing commands; \\fB--sign-with\\fR"
                    " overrides it."
                ),
            ),
        ],
        "FILES": [
            (
                "$XDG_DATA_HOME/git-vouch/, else ~/.local/share/git-vouch/",
                (
                    "The synced registry copy in \\fIregistry/\\fR, and the"
                    " \\fIallowed_signers\\fR and \\fIrevoked_keys\\fR files git"
                    " verifies against."
                ),
            ),
        ],
        "EXIT STATUS": [
            (
                "0 on success. 1 on any error: for \\fBcheck\\fR, any problem in the"
                " registry (warnings and void records alone exit 0); for \\fBquery\\fR"
                " and \\fBkeys\\fR, an unknown key or email."
            ),
        ],
        "SEE ALSO": [
            (
                "\\fBgit-verify-tag\\fR(1), \\fBgit-config\\fR(1), \\fBssh-keygen\\fR(1),"
                " \\fBgit-vouch-migrate\\fR(1)."
            ),
            (
                "README.md, DESIGN.md and docs/ in the git-vouch repository:"
                " https://github.com/MarkAtwood/git-vouch"
            ),
        ],
    },
    "git-vouch-migrate": {
        "DESCRIPTION": [
            (
                "Used on the flag day only, and the only git-vouch tool that runs"
                " \\fBgpg\\fR(1). It reads the kernel's pgpkeys.git at one signed"
                " commit, the freeze commit, after checking its signature. Every"
                " draft it writes is unsigned; holders and certifiers read and sign"
                " their own with \\fBgit vouch\\fR."
            ),
        ],
        "EXIT STATUS": [
            (
                "0 on success. 1 on any error, and for \\fBverify-continuity\\fR if"
                " any claim is not proven."
            ),
        ],
        "SEE ALSO": [
            "\\fBgit-vouch\\fR(1), \\fBgpg\\fR(1).",
            (
                "docs/flag-day.md in the git-vouch repository:"
                " https://github.com/MarkAtwood/git-vouch"
            ),
        ],
    },
}


def load(tool: str) -> ModuleType:
    """Return the tool script ``tool`` at the repository root, loaded as a module."""
    name = tool.replace("-", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(ROOT / tool))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    sys.modules[name] = module  # git-vouch-migrate loads git-vouch by this name too
    loader.exec_module(module)
    return module


def text(s: str) -> str:
    """Return ``s`` as roff text: backslashes escaped, no line read as a request."""
    s = s.replace("\\", "\\e")
    lines = s.split("\n")
    return "\n".join("\\&" + ln if ln.startswith((".", "'")) else ln for ln in lines)


def code(s: str) -> str:
    """Return a command-line token as roff: hyphens as minus signs, so they copy as typed."""
    return text(s).replace("-", "\\-")


def prose(s: str) -> str:
    """Return roff for EXTRA text, which is written with roff fonts already."""
    return s.replace("--", "\\-\\-")


def metavar(action: argparse.Action) -> str:
    if action.metavar is not None:
        return str(action.metavar)
    if action.choices is not None:
        return "{" + ",".join(str(c) for c in action.choices) + "}"
    return action.dest.upper() if action.option_strings else action.dest


def item(action: argparse.Action) -> str:
    """Return how ``action`` is written in a synopsis, without brackets."""
    if not action.option_strings:
        name = f"\\fI{code(metavar(action))}\\fR"
        if action.nargs == "*":
            return f"[{name} ...]"
        if action.nargs == "+":
            return f"{name} [{name} ...]"
        return name
    if isinstance(action, argparse.BooleanOptionalAction):
        return " | ".join(f"\\fB{code(o)}\\fR" for o in action.option_strings)
    option = f"\\fB{code(action.option_strings[0])}\\fR"
    if action.nargs == 0:
        return option
    return f"{option} \\fI{code(metavar(action))}\\fR"


def optional(action: argparse.Action) -> bool:
    if action.option_strings:
        return not action.required
    return action.nargs in ("?", "*")


def synopsis(prog: str, parser: argparse.ArgumentParser) -> str:
    groups = {
        id(a): g
        for g in parser._mutually_exclusive_groups  # argparse has no public accessor
        for a in g._group_actions
    }
    parts, done = [f"\\fB{code(prog)}\\fR"], set()
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction) or id(action) in done:
            continue
        group = groups.get(id(action))
        if group is not None:
            members = group._group_actions
            done.update(id(a) for a in members)
            inner = " | ".join(item(a) for a in members)
            parts.append(f"({inner})" if group.required else f"[{inner}]")
        elif optional(action) and action.nargs != "*":
            parts.append(f"[{item(action)}]")
        else:
            parts.append(item(action))
    return " ".join(parts)


def options(parser: argparse.ArgumentParser) -> list[str]:
    out = []
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction) or not action.help:
            continue
        out += [".TP", item(action), text(action.help)]
        if action.choices is not None and action.metavar is not None:
            out.append(
                "One of: " + ", ".join(code(str(c)) for c in action.choices) + "."
            )
    return out


def subcommands(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def page(tool: str) -> str:
    """Return the man page for ``tool`` (``git-vouch`` or ``git-vouch-migrate``)."""
    parser = load(tool).build_parser()
    prog = parser.prog
    extra = EXTRA[tool]
    summary = (parser.description or "").split("\n\n")[0].split(": ", 1)[-1]
    summary = " ".join(summary.split()).rstrip(".")
    commands = subcommands(parser)
    lines = [
        f'.TH {tool.upper()} 1 "" "{tool}" "git-vouch Manual"',
        ".nh",  # no hyphenation, so options and values copy as typed
        ".ad l",
        ".SH NAME",
        f"{tool} \\- {text(summary)}",
        ".SH SYNOPSIS",
        f"\\fB{code(prog)}\\fR \\fIcommand\\fR [\\fIoptions\\fR]",
        ".br",
        f"\\fB{code(prog)}\\fR \\fIcommand\\fR \\fB\\-h\\fR",
        ".SH DESCRIPTION",
    ]
    for para in extra["DESCRIPTION"]:
        lines += [prose(para), ".PP"]
    lines += [
        (
            f"\\fB{code(prog)} \\-h\\fR lists the commands, and"
            f" \\fB{code(prog)}\\fR \\fIcommand\\fR \\fB\\-h\\fR prints one command's"
            " help, which is what this page is made from."
        ),
        ".SH COMMANDS",
    ]
    for name, sub in commands.items():
        lines += [f".SS {code(name)}", synopsis(sub.prog, sub), ".PP"]
        lines.append(text(" ".join((sub.description or "").split())))
        lines += options(sub)
    if "CONFIGURATION" in extra:
        lines.append(".SH CONFIGURATION")
        for key, what in extra["CONFIGURATION"]:
            lines += [".TP", f"\\fB{code(key)}\\fR", prose(what)]
    if "FILES" in extra:
        lines.append(".SH FILES")
        for path, what in extra["FILES"]:
            lines += [".TP", f"\\fI{code(path)}\\fR", prose(what)]
    for section in ("EXIT STATUS", "SEE ALSO"):
        lines.append(f".SH {section}")
        for i, para in enumerate(extra[section]):
            lines += ([".PP"] if i else []) + [prose(para)]
    return "\n".join(lines) + "\n"


TOOLS = ("git-vouch", "git-vouch-migrate")


def main() -> int:
    for tool in TOOLS:
        (OUT / f"{tool}.1").write_text(page(tool))
    return 0


if __name__ == "__main__":
    sys.exit(main())

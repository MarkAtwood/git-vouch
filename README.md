# git-vouch

This is OpenVTC for people who live at the shell, sign with git, and send
patches by email, not through a forge like GitHub or GitLab.

It answers one question: is this signer a real person whom real people
vouch for, and may their key sign here? It does that with tools you
already have:

- **git's SSH signing** signs and verifies tags and commits.
- **`ssh-keygen -Y`** signs patch emails and the registry's records.
  Release files stay with kernel.org.
- **A registry git repository** holds one signed file per person, per
  endorsement and per tier grant. Changes arrive as reviewed merges, and
  `git fetch` distributes them.
- **`git vouch`** checks the registry's rules and writes the
  `allowed_signers` and revocation files that git reads.

Using it needs no service, no agent, and no new place to keep keys. Your
SSH key, YubiKey or gpg-agent works as it is: ed25519, P-256 and RSA of
2048 bits or more are accepted.

**If your key is RSA, now is a good time to upgrade.** 93% of the keys
in `pgpkeys.git` are RSA. RSA keeps working, but FIDO tokens, which
kernel.org issues, hold only ed25519 and P-256 SSH keys, and you are
registering a key anyway. Make it `ed25519-sk` on a token (`ecdsa-sk`
if the token has no ed25519), not a bigger RSA key.

An optional daemon, `git-vouch-trqp`, bridges this to OpenVTC, so
OpenVTC's verifiers can check signers in the registry. Nobody using
git-vouch at the shell depends on it.

## Tools

Each tool is one Python file that uses only the standard library and does
one job. Patch email adds a patatt fork.

| Tool | Job |
|---|---|
| `git-vouch` | The core: registry rules, signing commands, export |
| `git-vouch-migrate` | One-time move from a GPG keyring to the registry |
| `git-vouch-attest` | Verifies a FIDO key's hardware attestation |
| `git-vouch-trqp` | Optional bridge that answers OpenVTC's `verify-trust` from the registry |
| [patatt fork](https://github.com/MarkAtwood/patatt) | Lets b4 check patch-email signatures against the registry |

## Install

You need Python 3.9 or later, git 2.35 or later, and OpenSSH 9.1 or
later. There is nothing to build and no Python package to install. When
you type `git vouch`, git runs the executable `git-vouch` it finds on
your `PATH`, so cloning the repository and linking the tools into a
directory on `PATH` is the whole install:

```sh
git clone https://github.com/MarkAtwood/git-vouch.git ~/src/git-vouch
mkdir -p ~/.local/bin   # or any directory on your PATH
ln -s ~/src/git-vouch/git-vouch ~/.local/bin/
git vouch -h
```

Link the other tools the same way if you need them: anchors and
pgpkeys holders need `git-vouch-migrate` for the flag day, and it finds
`git-vouch` next to its own file. To update, run
`git -C ~/src/git-vouch pull`.

`git vouch -h` and `git vouch <command> -h` print the help. Plain
`git vouch --help` does not: git takes it as `git help vouch` and looks
for a man page, which git-vouch does not have.

Patch signing also needs the b4 and patatt forks; the guides' Patch
signing sections install them. Next, run `git vouch setup` (below). The
kernel's registry does not exist yet (see Status), so pass `--registry`.

## What `git vouch setup` changes

`setup` changes git's config and its own directory, nothing else. It
never touches `~/.ssh`, your SSH config or agent, `~/.gnupg`, or your
GPG keyring.

- **Its directory**, `~/.local/share/git-vouch/` (or
  `$XDG_DATA_HOME/git-vouch/`): the registry copy in `registry/`, and the
  `allowed_signers` and `revoked_keys` files git verifies against.
- **Global git config**: `vouch.registry`, `gpg.ssh.allowedSignersFile`,
  `gpg.ssh.revocationFile`, and `gpg.format=ssh`. With `--min-tier` or
  `--include-automation`, also `vouch.minTier` or
  `vouch.includeAutomation`.

`gpg.format=ssh` makes git sign with your SSH key in every repository.
Signatures already made with GPG still verify. `setup` writes config
only after its first sync succeeds, and changes nothing if git already
signs with GPG or X.509, or already points at other allowed-signers or
revocation files.

To do it yourself, for example to sign with SSH in some repositories
only, set the same config and sync. Verifying needs no `gpg.format`;
only signing does:

```sh
D=~/.local/share/git-vouch
git config --global vouch.registry "$REGISTRY"   # a registry URL; see Status
git config --global gpg.ssh.allowedSignersFile "$D/allowed_signers"
git config --global gpg.ssh.revocationFile "$D/revoked_keys"
git vouch sync
git config gpg.format ssh   # in each repository that signs with SSH
```

## Status

Under active development. The core commands, the migration tool, the
attestation verifier, the TRQP bridge and the patatt fork are implemented
and tested. Nothing is tagged as a release. Formats may still change.

**The kernel's registry does not exist yet.** The default URL,
`https://git.kernel.org/pub/scm/linux/kernel/git/vouch/registry.git`, is
a placeholder until the kernel.org administrators create it, so
`git vouch setup` without `--registry` fails. To try git-vouch now, make
your own registry, a bare git repository, and pass its URL with
`--registry`. [The flag-day runbook](docs/flag-day.md) builds one from
nothing, and its test suite runs every step.

## Read more

- [DESIGN.md](DESIGN.md): the design and every decision behind it
- [docs/guide-regulars.md](docs/guide-regulars.md),
  [docs/guide-captains.md](docs/guide-captains.md),
  [docs/guide-anchors.md](docs/guide-anchors.md): how to use it
- [docs/vouching.md](docs/vouching.md): what vouching for someone means
- [docs/rationale.md](docs/rationale.md): why each choice the guides make was made
- [docs/vs-openvtc.md](docs/vs-openvtc.md): how it compares with OpenVTC

## License

MIT-0. See [LICENSE](LICENSE).

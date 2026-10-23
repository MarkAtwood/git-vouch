# git-vouch

This is OpenVTC for people who live at the shell, sign with git, and send
patches by email, not through a forge like GitHub or GitLab.

It answers one question: is this signer a real person whom real people
vouch for, and may their key sign here? It does that with tools you
already have:

- **git's SSH signing** signs and verifies tags and commits.
- **`ssh-keygen -Y`** signs everything else.
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

There will also be an agent daemon that bridges this to an OpenVTC
instance, so OpenVTC's verifiers can check signers in the registry. It is
optional: nobody using git-vouch at the shell depends on it.

## Tools

Each tool is one Python file that uses only the standard library and does
one job.

| Tool | Job |
|---|---|
| `git-vouch` | The core: registry rules, signing commands, export |
| `git-vouch-migrate` | One-time move from a GPG keyring to the registry |
| `git-vouch-attest` | Verifies a FIDO key's hardware attestation |

Planned: patch-email signing through a [patatt fork](https://github.com/MarkAtwood/patatt)
that reads the registry, and `git-vouch-trqp`, the OpenVTC bridge daemon.

## Status

Under active development. The core commands, the migration tool and the
attestation verifier are implemented and tested. Formats may still change.

## Read more

- [DESIGN.md](DESIGN.md): the design and every decision behind it
- [docs/guide-regulars.md](docs/guide-regulars.md),
  [docs/guide-captains.md](docs/guide-captains.md),
  [docs/guide-anchors.md](docs/guide-anchors.md): how to use it
- [docs/vouching.md](docs/vouching.md): what vouching for someone means
- [docs/vs-openvtc.md](docs/vs-openvtc.md): how it compares with OpenVTC

## License

MIT-0. See [LICENSE](LICENSE).

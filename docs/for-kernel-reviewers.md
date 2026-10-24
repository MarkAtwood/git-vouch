# git-vouch: notes for kernel reviewers

Please red-pen this before anyone writes more guides: is the threat model
right, and would you run it for the kernel? Each claim cites DESIGN.md.

## What it replaces

The `gpg` binary and `pgpkeys.git` for signing kernel tags and pulls
(DESIGN: Summary). Old GPG-signed tags still verify with `gpg` (DESIGN:
Flag day).

Release files are out of scope: tarball signatures (`.tar.sign`,
`sha256sums.asc`) and kup upload authentication stay with kernel.org,
as they are today. A release tarball is `git archive` of a signed tag,
so the tag signature already covers its content. If you ever want
`ssh-keygen -Y` signatures on release files too, that is your call.

## What it is

Signing uses git's SSH signing (`gpg.format=ssh`) and `ssh-keygen -Y`,
with keys people already hold: ed25519, FIDO `sk-` keys, P-256, and RSA from 2048
to 4096 bits (DESIGN: Summary, did:key). Who may sign lives in a
registry: a git repository of signed files, one per person, endorsement
and tier record, changed by reviewed merges (DESIGN: The registry).
Tiers are anchor, maintainer, contributor and automation; an approver
above the tier signs each grant, and endorsements are evidence, not a
count (DESIGN: How trust maps).
`git vouch export` writes the `allowed_signers` and revocation files git
already reads. With `--min-tier maintainer`, plain `git verify-tag`
rejects anyone below maintainer (DESIGN: What git and OpenSSH already
do).

Tools, each one standard-library Python file: `git-vouch`;
`git-vouch-migrate`, flag day only; `git-vouch-attest`, FIDO
attestation (DESIGN: Tools). Patch mail uses published forks,
github.com/MarkAtwood/patatt and github.com/MarkAtwood/b4 (branch
`git-vouch`), not yet upstream (DESIGN: Patch signing). Needs Python
3.9; no git or OpenSSH floor beyond git's SSH signing is set (DESIGN:
Constraints, Upstream path).

## What it costs

Linus runs `git vouch setup --min-tier maintainer` once; `git vouch
sync` refreshes the files (DESIGN: Commands). After the flag day, a tag
from anyone below maintainer tier fails `git verify-tag` (DESIGN: What
git and OpenSSH already do).

A maintainer runs `git vouch register`, collects endorsements made with
`git vouch endorse`, and an anchor runs
`git vouch approve <handle> maintainer`. Each command writes files for a
registry merge (DESIGN: Commands). pgpkeys holds 645 live keys for
about 606 people; 188 can reuse an authentication subkey as their SSH
key; about 1,784 certifications become endorsement drafts; about 80% of
maintainers have no GPG key (DESIGN: Flag day). DESIGN has no merge-load
estimate beyond that.

If `git vouch check` fails, `export` writes nothing and `sync` writes
only the revocation file, so git keeps the last good allowed-signers
file (DESIGN: Commands; `cmd_export`, `cmd_sync`).

## Threat model

It stops:

- Self-promotion: only an approver's signed record grants a tier,
  except through an unsigned key swap (below) (DESIGN: How trust maps).
- A registry merger forging an endorsement, tier record or revocation
  for a key they do not hold, or passing one kind of record off as
  another (DESIGN: The registry).
- A history rewrite: `git vouch sync` refuses it (DESIGN: The
  registry).
- A compromised key: once revoked and synced, every signature by it,
  past and future, is void (DESIGN: Retiring a key versus revoking it).
- A bot key signing tags or commits: automation keys export only with
  `namespaces="file"` (DESIGN: What git and OpenSSH already do).

It does not stop:

- Whoever controls the registry repository adding an anchor, who can
  then approve anyone; history shows it (DESIGN: Anchors).
- A merger letting through an unsigned person-file change that swaps
  the key (`git vouch check` only warns), or deleting a tier record
  (DESIGN: The registry).
- A host withholding updates. `git-vouch` warns once the local copy is
  over 7 days old (DESIGN: The registry).
- A retired key's holder backdating a signature (DESIGN: Retiring a
  key versus revoking it).
- Proof of a touch: `ssh-keygen -Y verify` does not enforce FIDO user
  presence (DESIGN: Keys).
- A stolen GPG key, not revoked by the freeze commit, claiming its
  owner's identity, as it can sign tags today (DESIGN: Flag day).
- Prompt revocation in released b4, which caches verdicts for up to 24
  hours. The b4 fork's `b4.attestation-recheck-hours`, set to 0 in the
  guides, rechecks every signature (DESIGN: Patch signing).

## What it does not do

- No new cryptography: every signature check `git-vouch` relies on is
  done by `ssh-keygen`, directly or through git (DESIGN: Summary).
- No OpenPGP in `git-vouch`, which never runs `gpg`. After the late
  cutoff, `gpg` is needed only to verify old tags and for kernel.org's
  encryption keyring (DESIGN: Tools, Flag day).
- No network trust roots: the registry is the root of trust, and
  `git-vouch` never resolves a DID or fetches a JSON-LD context (DESIGN:
  Anchors, Constraints).
- No service beyond a git repository. Answers come from the local copy,
  offline (DESIGN: Constraints, The registry).

## Flag day

1. The freeze commit: `pgpkeys.git` gets one last signed commit and goes
   read-only. Its hash, the flag day and the late cutoff are published
   together.
2. Window: anchors register first, then everyone else.
3. Flag day: Linus and the release tooling switch to `git vouch export`
   files; GPG-signed tags and pulls stop. No dual period.
4. Patch mail: b4 with the patatt fork checks `vouch:` first and the
   frozen GPG keyring second, with a warning, until the late cutoff
   (DESIGN: Patch signing).
5. Late cutoff, six months after the flag day: continuity claims against the freeze commit end. Merge
   policy, not code.
6. Continuity proof (a GPG signature over the new person file, or the
   GPG authentication subkey reused as the SSH key) only unlocks ported
   endorsement drafts. It grants no tier.

Items 1-3, 5 and 6: DESIGN: Flag day. The freeze date, window length and
anchors are yours to set (DESIGN: Open questions).

## What kernel.org would operate

- The registry repository on git.kernel.org, at a path you choose
  (DESIGN: The registry).
- Registry maintainers who merge branches once `git vouch check` passes.
  A merger can swap any person's key or add an anchor, so this choice
  matters as much as the anchors (DESIGN: The registry, Anchors, Open
  questions).
- The freeze commit, and a small encryption-only GPG keyring for the
  remail and security lists (DESIGN: Flag day).
- Optionally, `git-vouch-trqp`, a bridge that lets outside verifiers
  query the registry. Nothing depends on it, and it is not yet
  released (DESIGN: Constraints, TRQP bridge).

## Where to look next

- [DESIGN.md](../DESIGN.md), first
  [The registry](../DESIGN.md#the-registry),
  [Anchors](../DESIGN.md#anchors),
  [Flag day](../DESIGN.md#flag-day) and
  [Rejected alternatives](../DESIGN.md#rejected-alternatives).
- Guides: [anchors](guide-anchors.md), [captains](guide-captains.md),
  [regulars](guide-regulars.md); the [flag day runbook](flag-day.md).

# git-vouch: notes for kernel reviewers

Please red-pen this: is the threat model right, and would you run it
for the kernel? Each claim cites DESIGN.md.

## What it replaces

The `gpg` binary and `pgpkeys.git` for signing kernel tags and pulls
(DESIGN: Summary). Old GPG-signed tags still verify with `gpg` (DESIGN:
Flag day).

Release files are out of scope: tarball signatures (`.tar.sign`,
`sha256sums.asc`) and kup upload authentication stay with kernel.org,
as they are today. A release tarball is `git archive` of a signed tag,
so the tag signature already covers its content (DESIGN: Summary). If
you ever want `ssh-keygen -Y` signatures on release files too, that is
your call.

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
attestation; `git-vouch-trqp`, an optional bridge for outside verifiers
(DESIGN: Tools). Patch mail uses published forks,
github.com/MarkAtwood/patatt and github.com/MarkAtwood/b4 (branch
`git-vouch`), not yet upstream (DESIGN: Patch signing). Needs Python
3.9, git 2.35 and OpenSSH 9.1: older git checks key lifetimes against
the current time, and older OpenSSH rejects the UTC times on every
exported line (DESIGN: Constraints).

## What it costs

Linus runs `git vouch setup --registry <url> --min-tier maintainer`
once, and `git vouch sync` keeps the files current. On the flag day he
also runs `git config gpg.openpgp.program false` in his tree, so git
fails every OpenPGP signature there (DESIGN: Commands, Flag day). From
then on, a tag from an unregistered or below-maintainer key fails
`git verify-tag` with "No principal matched.", the same message for
both. `git pull` still merges it and shows that line only in the merge
message (measured, git 2.55.0, OpenSSH 9.6p1; guide-anchors: Switch
Linus's git).

A maintainer runs `git vouch register`, collects endorsements made with
`git vouch endorse`, and an anchor runs
`git vouch approve <handle> maintainer`. Each command writes files for a
registry merge (DESIGN: Commands).

Who has to move by the flag day: since v6.15 Linus merged 4,216 signed
tags, all OpenPGP, from 195 tagger emails; the top 100 sent 90%. 151 of
the 195 have a pgpkeys key, and 67 of those can reuse its
authentication subkey as their SSH key (measured 2026-11-15; DESIGN:
Flag day). Everyone else can move any time before the late cutoff. In
pgpkeys overall, 645 live keys belong to about 606 people, and about
1,784 certifications become endorsement drafts; 1,538 of the 1,935
people on MAINTAINERS `M:` lines (79.5%) have no pgpkeys key under a
MAINTAINERS address (measured 2026-10-23; DESIGN: Flag day).

If `git vouch check` fails, `export` writes nothing and `sync` writes
only the revocation file, so git keeps the last good allowed-signers
file (DESIGN: Commands; `cmd_export`, `cmd_sync`).

## Threat model

It stops:

- Self-promotion: only an approver's signed record grants a tier,
  except through an unsigned key swap of a contributor (below) (DESIGN:
  How trust maps).
- A lone merger adding an anchor, or swapping an anchor's or
  maintainer's key: the edit has no effect, or the tier is suspended,
  until two anchors run `git vouch cosign` on its exact bytes (DESIGN:
  Cosign).
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

- Whoever controls the registry repository choosing the first anchors;
  history shows it (DESIGN: Anchors).
- A merger letting through an unsigned person-file change that swaps a
  contributor's key (`git vouch check` only warns), or deleting a tier
  record (DESIGN: The registry).
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
  cutoff, `gpg` is needed only to verify old tags, for release-file
  signatures, which stay with kernel.org, and for kernel.org's
  encryption keyring (DESIGN: Summary, Tools, Flag day).
- No network trust roots: the registry is the root of trust, and
  `git-vouch` never resolves a DID or fetches a JSON-LD context (DESIGN:
  Anchors, Constraints).
- No service beyond a git repository. Answers come from the local copy,
  offline (DESIGN: Constraints, The registry).

## Flag day

1. The freeze commit: `pgpkeys.git` gets one last signed commit and goes
   read-only. Its hash, the flag day and the late cutoff are published
   together.
2. Window: anchors register first, then the core set: everyone
   `git-vouch-migrate pullers` lists from Linus's merges.
3. Flag day: Linus's tree and the release tooling switch to
   `git vouch export` files and stop accepting GPG. Every other tree
   keeps accepting both until its owner switches, by the late cutoff.
4. Patch mail: b4 with the patatt fork checks `vouch:` first and the
   frozen GPG keyring second, with a warning, until the late cutoff
   (DESIGN: Patch signing).
5. Late cutoff, six months after the flag day: GPG-signed tags and
   patches stop everywhere, and continuity claims against the freeze
   commit end. Policy, not code.
6. Continuity proof (a GPG signature over the new person file, or the
   GPG authentication subkey reused as the SSH key) only unlocks ported
   endorsement drafts. It grants no tier.

Items 1-3, 5 and 6: DESIGN: Flag day. The freeze date, window length and
anchors are yours to set (DESIGN: Open questions).

## What kernel.org would operate

- The registry repository on git.kernel.org, at a path you choose. It
  does not exist yet (DESIGN: The registry).
- Registry maintainers who merge branches once `git vouch check` passes.
  A merger alone can swap a contributor's key, delete a tier record, and
  choose the first anchors, so this choice matters almost as much as the
  anchors (DESIGN: The registry, Anchors, Open questions).
- The freeze commit, and a small encryption-only GPG keyring for the
  remail and security lists (DESIGN: Flag day).
- Optionally, `git-vouch-trqp`, a bridge that lets outside verifiers
  query the registry. Nothing depends on it (DESIGN: Constraints, TRQP
  bridge).

## Where to look next

- [DESIGN.md](../DESIGN.md), first
  [The registry](../DESIGN.md#the-registry),
  [Anchors](../DESIGN.md#anchors),
  [Cosign](../DESIGN.md#cosign),
  [Flag day](../DESIGN.md#flag-day) and
  [Rejected alternatives](../DESIGN.md#rejected-alternatives).
- Guides: [anchors](guide-anchors.md), [captains](guide-captains.md),
  [regulars](guide-regulars.md); the [flag day runbook](flag-day.md).

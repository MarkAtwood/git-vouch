# git-vouch: Kernel Identity Without GPG

**Status:** 2026-10-23. Every tool in Tools is implemented: `git-vouch`
(including `git vouch keys` and `git vouch query`), `git-vouch-migrate`,
`git-vouch-attest`, the patatt fork and `git-vouch-trqp`. Nothing is
tagged as a release, and the patatt and b4 forks are not upstream.

## Summary

`git-vouch` replaces the kernel's GPG keyring and web of trust with three
things that already exist and one small script:

- **git's SSH signing** (`gpg.format=ssh`) signs and verifies tags and
  commits.
- **`ssh-keygen -Y`** signs and verifies the registry's own records
  and, through patatt, patch emails.
- **A registry git repository** holds one signed file per person and one
  per endorsement. Changes arrive as reviewed merges; `git fetch`
  distributes them.
- **`git-vouch`**, a single Python file using only the standard library,
  checks the registry's rules and writes the `allowed_signers` and
  revocation files that git reads.

The switch happens on one flag day: `pgpkeys.git` is frozen and ported
into the registry, everyone re-signs with SSH keys, and GPG-signed tags
and pulls stop being accepted (see Flag day).

**Scope:** tags, commits, patch emails and the registry's own records.
Release files (tarball `.tar.sign`, `sha256sums.asc`, the checksum
autosigner) and kup upload authentication are out of scope; kernel.org
keeps them on GPG. git-vouch replaces the keyring, not every use of
`gpg`. A handful of release signers is not a keyring, and endorsements,
tiers and continuity do not apply to them. A release tarball is
`git archive` of a signed tag, which git-vouch covers, so anyone can
regenerate it and compare. Moving distributions' `gpg --verify` scripts
to `ssh-keygen` would cost them a lot for little gain. Rejected: SSH
signatures on release files alongside GPG during an overlap.

Every person is identified by DIDs, and person files are JSON-LD that
people can extend with more DIDs and any metadata they like.

Every signature check `git-vouch` relies on is done by `ssh-keygen`,
either directly or through git. `git-vouch` contains no cryptography.
Version 1 runs on today's git; the aim is to upstream registry support
into git later (see Upstream path). An auditor needs to trust Python 3,
git and OpenSSH, which every kernel developer already has, plus one file
short enough to read in a sitting.

## Constraints

1. **CLI only.** No service, no web interface, no daemon, and no TUI.
   Every command takes its input from arguments and files and never
   prompts, so it works in scripts, CI and over ssh. Output is plain
   text; non-zero exit means failure. The optional `git-vouch-trqp`
   bridge is the one service, and nothing depends on it.
2. **Nothing git or OpenSSH already does.** Signing, verification,
   expiry, purpose limits, revocation, key storage, distribution and
   history all belong to them. The registry always lives in git, and
   `git-vouch` reads git history (commit order, committer dates,
   deletions) instead of inventing records for what git already
   records. `git-vouch` only does what they cannot: check who approved
   whom and generate their input files.
3. **Python standard library only.** Kernel builds already need Python 3
   (for arm/arm64 and several config options). The floor is the kernel's
   documented minimum, Python 3.9 (`Documentation/process/changes.rst`).
   No third-party packages, not even `cryptography`.
4. **Public by design.** The registry, including who endorsed whom, is
   public. There are no privacy features.
5. **The kernel first.** One registry, one project. Other projects can
   copy the registry later.
6. **DIDs are the identifiers, and they are open-ended.** Every key has a
   did:key. A person may list any other DIDs and add any JSON-LD
   metadata. `git-vouch` checks only its own terms and never resolves a DID
   or fetches a context.
7. **Upstreamable.** Nothing in the formats depends on `git-vouch`: plain
   files, SSH signatures over their exact bytes, and git's own
   allowed-signers format. A future git could read the registry itself.
8. **Small tools, not a bigger `git-vouch`.** A job that needs another
   program (gpg, openssl, an HTTP listener) gets its own single-purpose
   tool. `git-vouch` stays the core and never calls them.

## Tools

| Tool | Job | Runs |
|---|---|---|
| `git-vouch` | The core: registry rules, records, export | `git`, `ssh-keygen` |
| `git-vouch-migrate` | Flag day only: drafts person files and endorsements from the frozen `pgpkeys.git` | `gpg`, `git-vouch` |
| `git-vouch-attest` | Verifies a FIDO key's attestation against a vendor root the user supplies | `openssl` (OpenSSL 3.0 or later; `openssl verify -no-CAstore` needs 3.0) |
| patatt fork | patatt with a `vouch:` keyring source, so b4 checks patch signatures against the registry ([github.com/MarkAtwood/patatt](https://github.com/MarkAtwood/patatt)) | `git vouch keys` |
| `git-vouch-trqp` | Optional TRQP bridge so OpenVTC's `verify-trust` can ask whether a DID may sign for the kernel; a thin shim over `git-vouch` | `git-vouch` |

`git-vouch-migrate` is the only tool that runs `gpg`, and it is retired
after the late cutoff. It ports `pgpkeys.git` and nothing else: its
layout, its signer, and kernel.org's list-address role keys are built
in. Another project's keyring needs its own port. Each tool is one
file, standard library only.

## How trust maps

How trust in the kernel actually works is a tree: Linus trusts a few
people, they trust subsystem maintainers, and maintainers vouch for
contributors. The registry records that tree directly.

| Tier | Who | Granted by | May sign |
|---|---|---|---|
| `anchor` | Linus and a few designated people | Listed in the registry (see Anchors) | Tags, commits, files |
| `maintainer` | Subsystem maintainers | An anchor | Tags, commits, files |
| `contributor` | Contributors who sign | A maintainer or an anchor | Tags, commits, files |
| `automation` | CI and build robots | A maintainer or an anchor | Files only |

**The approver sets the tier.** A tier is granted by a tier record that
the approver signs (see The registry), never by the person's own file, so
nobody can promote themselves. The one way round this is an unsigned key
change that review lets through (see Merging needs one person). The approver must sit above the tier they
grant, as in the table, at the commit that adds the tier record. To
lower someone, they must also sit above the tier that person held just
before that commit, judged from history and not from the record's own
date: only an anchor can demote a maintainer, and a record by a peer is
void (vouch-xlha.21).

**Endorsements are evidence, not a count.** There is no minimum number.
The approver reads the endorsements and decides. `git vouch check` verifies
that every endorsement and tier record is validly signed by someone with
the authority to make it; it does not second-guess the approver's
judgement.

**Any registered human may endorse**, with or without a tier. An
endorsement is evidence about identity, not a grant of authority, so
widening who may make one costs nothing; only the approver needs
authority. This is how vouching across projects works: someone from
another community (Apache, another LF project) registers a person file
with no tier, lists their other identities in `alsoKnownAs`, and
endorses. A key used in both registries has the same did:key in both, so
anyone can cross-check without `git-vouch` resolving anything. An
endorsement from an independent community is valuable precisely because
an attacker would have to infiltrate two social graphs, not one.
Nobody can endorse themselves: a self-endorsement is reported as void
and counts for nothing, but never fails `check`.

**Automation identities** can sign files (the `file` namespace)
and patches (see Patch signing), never git tags or
commits. They cannot endorse or
approve anyone. Their person file must name the accountable maintainer,
who must hold the maintainer or anchor tier at the commit that adds the
bot's tier record. Like any approval, that is judged once: if the
accountable maintainer later steps down, the bot keeps its tier.

## What git and OpenSSH already do

| Need | Mechanism | git-vouch's part |
|---|---|---|
| Sign tags and commits | `git tag -s`, `git commit -S` with `gpg.format=ssh` | Sets the git config once (`git vouch setup`) |
| Verify | `git verify-tag`, `git verify-commit`, `git log --show-signature` | None |
| Who may sign | `gpg.ssh.allowedSignersFile` | Generates the file |
| Require a tier | One allowed-signers file per minimum tier | `git vouch export --min-tier maintainer` |
| Key expiry and retirement | `valid-after=` / `valid-before=` on each allowed-signers line | Writes them from the registry and its history |
| Compromised keys | `gpg.ssh.revocationFile` | Generates the file |
| Limit a key's purpose | `namespaces=` on each allowed-signers line | Writes `namespaces="git,file"`, or `namespaces="file"` for automation |
| Sign other files | `ssh-keygen -Y sign -n file` / `-Y verify` | None; kernel release files stay on GPG (see Summary) |
| Hardware keys | The SSH agent; FIDO `sk-` keys; `gpg.ssh.defaultKeyCommand` | None |
| Distribution | `git fetch` | `git vouch sync` = fetch, refuse a rewind, re-export |
| Audit trail, ordering, removal dates | Registry history: commit order, committer dates, deletions | Reads it |
| Review of changes | Merges to the registry; one registry maintainer merges once `git vouch check` passes | `git vouch check` |

**Requiring a tier needs no wrapper.** Linus points `allowedSignersFile`
at the file exported with `--min-tier maintainer`, and plain
`git verify-tag` then rejects anyone below that tier. Release tooling
uses `--min-tier anchor`. The ranking is anchor, then maintainer, then
contributor. Automation sits outside it: its keys are exported only with
`--include-automation`, and always with `namespaces="file"`, so they can
never verify as a git signature.

### Retiring a key versus revoking it

git checks a signature against the key's validity *at the time the
signature says it was made*. The two git mechanisms therefore mean
different things, and `git-vouch` uses each for one job:

- **Retire** (rotation, stepping down, removal): set `valid-before` to
  the retirement time. Earlier signatures stay valid.
- **Revoke** (compromise or suspected compromise): list the key in the
  revocation file. Every signature by it, past or future, is invalid.

The signing time comes from the signer, so a retired key's holder can
backdate a signature. When there is any doubt about who holds a key,
revoke it rather than retiring it.

The export writes every `valid-before` (retirement, removal, demotion)
one hour after the end it records. git passes the verify time to
OpenSSH as local time without a zone, and OpenSSH 9.6 reads it an hour
off under daylight saving time, which would reject signatures made in
the last hour before an end. The hour adds no risk: the signer sets the
signing time and could backdate by any amount anyway. It also means a
signature in the same second as a retirement is not a special case.
Each `valid-before` is the earlier of the key's `retired` and its tier's
end, plus the hour, capped at 9999-12-31T23:59:59Z, so a commit dated
near the end of time that ends a tier still exports.

`git vouch check` judges a record's date the same way, without the hour:
it accepts a record dated from its key's `added` second through its
`retired` second, both included, as OpenSSH treats `valid-after` and
`valid-before`. A record dated in its key's retirement second passes;
one dated a second later does not. `git vouch query --at` and `git vouch
keys` judge validity the same way, in whole seconds: a key is valid from
its `added` second through its `retired` second, both included. So
`keys` run in a key's retirement second still lists that key, and so
does the TRQP bridge for a time in that second.

## The registry

A git repository at a configurable URL: `git vouch setup --registry <url>`
stores it in git config (`vouch.registry`), and every other command
uses that copy. For the kernel, the registry is hosted on git.kernel.org,
which is also the default when `--registry` is omitted; the exact repository
path is for the kernel.org administrators to choose. Other projects run
their own registry anywhere git can be fetched from.

```
README
anchors.json                          list of anchor handles (unsigned; see Anchors)
people/<handle>.json                  identity record
people/<handle>.json.sig              signed by one key current in the previous version   (namespace git-vouch-register)
people/<handle>.json.asc              flag day only: optional GPG continuity proof (see Flag day)
tiers/<handle>.json
tiers/<handle>.json.sig               signed by the approver      (namespace git-vouch-tier)
endorsements/<subject>/<endorser>-<n>.json
endorsements/<subject>/<endorser>-<n>.json.sig                    (namespace git-vouch-endorse)
revocations/<handle>-<n>.json
revocations/<handle>-<n>.json.sig                                 (namespace git-vouch-revoke)
```

Every record is a JSON-LD file signed with `ssh-keygen -Y sign` under a
namespace specific to its kind. **The signature covers the file's exact
bytes; there is no canonicalisation.** Records carry arbitrary
user metadata, and canonicalising that would need exact number
formatting (JCS) or context fetching (RDF canonicalisation). Signing the
bytes on disk needs neither. Editing a record means re-signing it, which
every change needs anyway. Using a separate namespace per kind stops a
signature made for one kind of record from being accepted as another.

**Record dates** (a key's `added` and `retired`, and every record's
`date`) are UTC times like `2026-11-05T00:00:00Z` in the years 1970 to
9998. `check` reports any other year as a problem in that record. That
keeps the export from computing a `valid-before` past the range of a
datetime, and gives OpenSSH four-digit years.

**Git history is part of the registry.** Order and removal come from the
commits rather than from a field anyone could write: which commit first
listed a key, which commit deleted a tier record and its effective date,
which revocations were ever committed, and what a person file said in
the previous version. Two times come from signed fields instead: a key's
`retired`, written by its holder, and a demotion's `date`, written by the
approver. Either signer could backdate them; review is the check.

**Effective dates.** Every commit on HEAD's first-parent line has an
effective date: the later of its committer date and its first parent's
effective date, so the dates on that line never go backwards. A commit
off that line (a side-branch commit) takes the effective date of the
first commit on HEAD's first-parent line that has it as an ancestor, so
a branch merged with `--no-ff` counts from its merge, and so does a
deletion merged from a branch. `check` refuses (an error, not a warning)
any commit in HEAD's history whose committer date is more than 5
minutes after the time `check` runs: `commit <id>: committer date is in
the future`. Such a commit would move every later effective date, so it
fails `check`, and so `export`, even when it touches no registry file;
`sync` then writes only the revocation file.

**Merging needs one person.** A registry maintainer merges a change once
`git vouch check` passes. Endorsements, tier records and revocations are
signed by the key that makes them, so the merger cannot forge one for a
key they do not control. A replayed or merged-back tier record that
undoes a demotion is caught by `check` (see Tier record), so it is not a
review-gated risk. Registry maintainers merge with `git merge --no-ff`,
never a fast-forward, so every commit on the main line's first-parent
chain carries the maintainer's committer date, not the submitter's.
That includes never fast-forwarding a contributor's merge of main:
`--no-ff` is the only protection against such a "foxtrot" merge, whose
first parent is the contributor's own backdated branch. No date clamp
can catch it, because the contributor's commits would then form the
first-parent line. Three things rest on
review instead, as accepted risks:

- **`anchors.json`** (see Anchors).
- **A person file change not signed by any key from the previous
  version** (see Person file). A merger who lets one through can swap in
  their own key and then sign tier records and endorsements as that
  person, and `check` accepts them. The only trace is `check`'s WARNING
  on that version, and git history.
- **Deleting a tier record**, which is an unsigned git change, so any
  merger can remove anyone's tier (see Tier record). Restoring an older
  lower-tier record over a promotion is void unless its approver sits
  above the promoted tier, so it too only ends the tier, like a deletion.

The remaining host attack is to withhold updates, such as a revocation.
Two git behaviours address that:

- `git vouch sync` fetches with a refspec that has no `+`, so git refuses a
  history rewrite.
- `git-vouch` warns whenever the local registry copy was last fetched more
  than 7 days ago. It warns and keeps working, so offline use still
  works.

### Tier record

```json
{
  "@context": ["https://w3id.org/git-vouch/v1"],
  "subject": "alice",
  "tier": "maintainer",
  "approver": "torvalds",
  "approverKey": "did:key:z6Mk...",
  "date": "2026-11-05T00:00:00Z"
}
```

- **One current tier record per person.** Changing a tier replaces the
  record. A tier record committed before its subject's person file
  exists is ignored.
- **Authority is judged at the commit that added the record.** If the
  approver later steps down (their own tier deleted or lowered, or they
  leave `anchors.json`) without a compromise, the tiers they granted
  stay valid. Only a revoked approver key voids the tier records it
  signed; those people have no tier until someone re-approves them.
  "At the commit" means by ancestry: a tier record added on a branch
  that runs concurrently with a commit lowering its approver's authority
  is void, with a warning, until someone re-approves it. When two keys
  revoke each other on concurrent branches, both revocations count.
- **Removal:** when `tiers/<handle>.json` is deleted, the export uses
  the effective date of the deleting commit as `valid-before` for that
  person's keys, provided the record verified at the parent commit; a
  deletion merged from a branch counts from its merge. Replacing the
  record with one that has no effect ends the tier the same way.
  Earlier signatures stay valid. The deletion is unsigned; review is the
  gate. Dropping a handle from `anchors.json` likewise ends the anchor
  tier at the effective date of the commit that dropped it.
- **Demotion:** when a record is replaced by a lower tier, or by one
  across the automation line, the old tier ends at the new record's own
  `date`. An export with `--min-tier` above the new tier keeps the key
  with that `valid-before`. A replacement record that does not verify
  ends nothing: the tier before it stands until a valid record replaces
  it or the file is deleted. A lowering record whose approver does not
  sit above the tier it replaces is void; putting it in the old record's
  place ends that tier at the commit's effective date, like a deletion,
  so a peer cannot choose the date.
- **Restoring:** a tier record cannot come back, by a commit or by a
  merge (including `--no-ff` resolved to the old side, or `-s ours`),
  over a demotion committed after it. If a version that demotes it
  (lower tier, or across the automation line) and did not fail
  verification lies between an earlier copy of the same bytes and the
  commit being judged, `check` fails ("restores an earlier record ...
  needs a new approval"). Deleting the demotion first changes nothing.
  The signature covers the exact bytes, so only the approver can make a
  newer record. Bringing back a same-tier record, or one over a
  record that did not verify, is not flagged. A lower-tier one is void
  unless its approver sits above the tier it replaces (see Demotion);
  like a deletion it only takes authority away, and review is the gate.

### Person file

```json
{
  "@context": [
    "https://w3id.org/git-vouch/v1",
    { "foaf": "http://xmlns.com/foaf/0.1/" }
  ],
  "handle": "gregkh",
  "name": "Greg Kroah-Hartman",
  "emails": ["gregkh@linuxfoundation.org"],
  "keys": [
    {
      "ssh": "sk-ssh-ed25519@openssh.com AAAA... ",
      "added": "2026-11-01T00:00:00Z",
      "retired": null,
      "attestation": {
        "blob": "AAAAEXNzaC1zay1hdHRlc3QtdjAx...",
        "challenge": "q2k4..."
      }
    }
  ],
  "accountable": null,
  "migratedFrom": "openpgp4fpr:647F2865...",
  "alsoKnownAs": [
    "did:web:kroah.com",
    "did:plc:abc123..."
  ],
  "foaf:homepage": "http://www.kroah.com/"
}
```

- **`@context`** must list the git-vouch context first. That context marks
  its terms `@protected` (JSON-LD 1.1), so a later context cannot
  redefine them for JSON-LD processors. `git-vouch` itself reads its terms
  as plain JSON keys and never fetches a context.
- **`handle`** is the lasting identity. It matches the file name and
  never changes.
- **`emails`** are candidate allowed-signers principals, so git's output
  shows a familiar address. Every exported line's principals are the
  handle, which every key gets, then the endorsed emails, so anchors,
  automation and anyone approved without endorsements still verify. An
  email (compared case-insensitively) may
  appear in only one person file; `git vouch check` fails otherwise. Only
  an email covered by at least one valid endorsement (see Endorsement)
  is exported. An unendorsed email stays in the file, is not exported,
  and `check` warns about it.
- **`keys`** holds every key the person has used, oldest first. At most
  16 of them may be current (no `retired`); retired keys do not count
  toward the limit. A key
  with `retired` set becomes `valid-before` in the export. Its did:key
  is not stored; `git-vouch` derives it. If a key appears in two files,
  a listing as a current key (proven by the file's signature) beats any
  listing of it as retired (unproven), and the unproven claimant is
  flagged. Between equally proven listings, the file whose commit listed
  it first wins.
- **`attestation`** is optional and only meaningful for FIDO (`sk-`)
  keys: an object with `blob` and `challenge`, both base64, from
  `ssh-keygen -O challenge=<file> -O write-attestation=<file>` at key
  generation. Verifying it needs SHA-256 of the challenge, so both are
  kept. It is covered by the person file's signature. `git-vouch` checks
  only the shape and never verifies it (see Keys).
- **`accountable`** is used only by automation identities and names the
  responsible maintainer's handle.
- **`migratedFrom`** appears only on files ported on the flag day:
  `openpgp4fpr:` plus the 40-hex v4 fingerprint of the person's key in
  `pgpkeys.git`. `check` validates its format and flags any fingerprint
  claimed by more than one handle (see Flag day).
- **`alsoKnownAs`** (the W3C DID Core term) lists any other DIDs the
  person uses: did:web, did:webvh, did:plc, did:webs, anything.
- **Any other terms** are the person's own metadata. `git-vouch` ignores
  them.
- **Only the name, keys and endorsed emails are vouched for.** Extra
  DIDs and metadata are signed by the person, so nobody else can alter
  them, but nobody has vouched for them. `git-vouch` never resolves an
  extra DID or checks that it links back. A DID that also lists the
  person's did:key in its own `alsoKnownAs` is a stronger claim, but
  checking that is left to tools that resolve DIDs.
- **The `.sig` file** (at most 4 signature blocks) needs a signature
  from any one key current in the
  previous version, so backup tokens can stay in a drawer. The first
  version must be signed by at least one of its own keys. Adding a key
  is therefore signed by an existing key, which is how rotation works.
  For a merge, a key current in any parent will do. A merge that keeps
  one parent's version over a concurrent change on another is judged
  against that change, so keeping a version signed by a key the other
  side retired gets the WARNING below.
- **A signature by a revoked key counts as none.** A change whose only
  signature by a previous key is by a key revoked before it (by
  ancestry) gets the WARNING below. Pending decision: `check` also
  warns when the signing key is revoked concurrently or later. A
  revocation signed by a later-revoked key still counts (see
  Revocation), so this case may yet be treated the same way.
- **A change not signed by a previous key** (a lost key, or a swapped
  one) is not refused. Registry review is the gate, as for
  `anchors.json`. `git vouch check` walks the history of `people/` and
  prints a prominent WARNING for each such version, without failing.
  Recovering from a lost key is a reviewed merge of that kind, and the
  person's tier carries over. A file whose keys are all retired is
  frozen: any later change gets the same warning.

### Endorsement

```json
{
  "@context": ["https://w3id.org/git-vouch/v1"],
  "endorser": "gregkh",
  "endorserKey": "did:key:z6Mk...",
  "subject": "alice",
  "subjectKey": "did:key:z6Mk...",
  "subjectName": "Alice Example",
  "subjectEmails": ["alice@example.org"],
  "note": "Met at LPC 2026, checked passport; reviewed her patches since 2019.",
  "date": "2026-11-03T00:00:00Z"
}
```

- **`note`** is optional free text: whatever the endorser wants to say
  about how they know the person. `git-vouch` does not interpret it.
- **The endorsement binds the subject's name, key and emails.** A later
  rename, or an email the endorser did not vouch for, is not endorsed.
  Only endorsed emails become principals.
- **When the subject rotates keys**, their endorsements carry over to
  every key added in later versions of the person file. That is sound
  along a chain of signed versions. It also carries over across an
  unsigned, warned change, as the tier does, and there it rests on
  registry review (see Person file).
- **When the subject's key is revoked**, endorsements that named it are
  not void: they carry over to the person's later keys, as on rotation.
  Endorsers are encouraged, not required, to re-confirm after a
  compromise.
- **When the endorser retires a key**, endorsements made with it stay
  valid.
- **When the endorser's key is revoked**, every endorsement made with it
  is void.

### Revocation

```json
{ "@context": ["https://w3id.org/git-vouch/v1"],
  "subject": "alice", "key": "did:key:z6Mk...", "reason": "compromise", "date": "..." }
```

Signed by the key itself, by another of the subject's current keys, or by
any anchor. A revocation signed by a key that is later revoked still
counts if it was committed before that key's own revocation. Revocations
are read from history, so a revocation holds once its commit is
reachable from HEAD, even if its file is later deleted or a merge
dropped it (`merge -s ours`, or a conflict resolution that deletes the
file). A revocation never fails `check`: records it voids are
reported, not fatal. `sync` writes the revocation file even when `check`
fails on something else, so a revocation always spreads.

**History git-vouch cannot read.** A past version of a record path that
`git-vouch` cannot read (a directory, symlink or submodule, or over
64 KiB) is treated like a version that does not parse. For each such
commit, including a merge that left it, `check` warns `<path>: not a
regular file of at most 65536 bytes (ignored, at <commit>)` and carries
on. This never blocks `check`, `export` or `sync`, so revocations and
tier removals keep spreading. Files in the working tree are still
reported as problems. A commit whose committer date is beyond what
`git-vouch` can represent (year 10000 or later) is read as
9999-12-31T23:59:59Z. `check` reports it as in the future (see
Effective dates) and, where it uses that date, also as `commit <id>:
committer date out of range`; the commits after it, which inherit that
effective date, are not reported as out of range. Either way
`allowed_signers` is not exported, but the history is still read and
`sync` still writes the revocation file. A commit dated 9999-12-31 is
refused as in the future too, so no such date reaches the export.

Nothing has to be repaired for an unreadable version. It stays in
history, `check` warns about it on every run naming the commit, and
history is not rewritten (`sync` refuses rewinds). Registry maintainers
refuse such commits in review, and the warning on the branch is the
signal. If a registry ever wants the warning gone, the only route is a
coordinated history rewrite after which every user reruns `git vouch
setup`; that is not recommended. A commit dated in the future is
different: it blocks `allowed_signers` until that time passes, which for
a far date (past year 9999, say) is in practice forever, so repairing it
needs that same rewrite, and maintainers must refuse such commits.

Removing someone without suspecting their key is different: their tier
record is deleted in a reviewed merge, and the export gives
their keys `valid-before` set to the deleting commit's effective date (a
deletion merged from a branch counts from its merge), so their earlier
signatures stay valid.

## Anchors

Anchors are whoever `anchors.json` in the registry lists. There is no
local pinning and no extra signature: the registry is the root of trust.

**Accepted risk:** whoever controls the registry repository can add an
anchor, and that anchor can then approve anyone. The change is visible in
the registry's git history, which anyone can audit, and `git vouch sync`
refuses a rewritten history, but nothing in `git-vouch` prevents it. Control
of the registry repository is therefore as sensitive as an anchor key.

## Commands

| Command | Does |
|---|---|
| `git vouch setup [--registry URL] [--min-tier T] [--include-automation]` | Records the registry URL (default: the kernel's on git.kernel.org) and the export choices in git config; sets `gpg.format=ssh`, `gpg.ssh.allowedSignersFile`, `gpg.ssh.revocationFile`; runs a first `sync` |
| `git vouch sync [--min-tier T] [--include-automation]` | Fetches the registry without allowing a rewind and runs `check`. Saves any `--min-tier` / `--include-automation` given to git config, then re-exports with the saved choices; the revocation file is written even if `check` fails |
| `git vouch status` | Shows registry commit, fetch age (warns past 7 days), and your own tier |
| `git vouch register [--from FILE]` | Writes your person file from an SSH public key, or completes a draft such as one from `git-vouch-migrate`, and signs it through the agent |
| `git vouch add-key` / `retire-key` | Rotation: edits your person file and re-signs it |
| `git vouch endorse <handle>` / `--from FILE` | Writes and signs an endorsement, or signs a draft such as one from `git-vouch-migrate drafts` once its `endorser` and `endorserKey` are the signer's. Before signing, prints to stderr the subject, the key (the SHA256 fingerprint `ssh-keygen -l` shows for the person file's ssh line, and its did:key), the name and the emails it signs; if the person file does not list the key, it says so. Run it on the merged registry, not a pull-request checkout |
| `git vouch approve <handle> <tier>` | Writes and signs a tier record |
| `git vouch revoke` | Writes and signs a revocation |
| `git vouch check [DIR]` | Validates every signature and computes every tier; non-zero exit on any error. Warnings (unsigned key change, unendorsed email, records a revocation voids, fetch age) do not fail. Run before every registry merge |
| `git vouch export [DIR] [--min-tier T] [--include-automation]` | Writes the allowed-signers file and the revocation file |
| `git vouch query <did> [--at TIME]` | Prints a did:key's handle, tier and key validity, now or at TIME, as JSON; exit 1 if unknown. `git vouch query --all [--at TIME]` prints one JSON object mapping every did:key listed in a person file to that answer, from one registry check (used by `git-vouch-trqp`). At TIME it reads the newest commit on HEAD's first-parent line whose effective date is at or before TIME |
| `git vouch keys <email>` | For an endorsed email, prints the person's current keys with their patatt selectors; exit 1 otherwise (see Patch signing) |
| `git vouch did <key>` | Prints the did:key for an SSH public key (a `.pub` path or the key text), and the reverse (see did:key) |

`DIR` defaults to the synced registry copy once `setup` has run; pass
`.` to check or export a checkout.
`check`, `query`, `keys` and `status` also work from a git worktree: the
fetch stamp `vouch-fetched` lives in the repository's common git dir
(`git rev-parse --git-common-dir`), which all its worktrees share.
`register`, `endorse`, `approve` and `revoke` write files for a registry
merge request; they never push. `export` and `sync` replace the
allowed-signers and revocation files atomically, keeping an existing
file's mode, and create a new one with mode 0666 minus the umask: the
files are public, and git reads them. `--help` is the documentation; there is
no man page.

## did:key

Each key's did:key is its SSH public key in another encoding: multibase
base58btc of the multicodec prefix plus the raw key. did:keys are how
records name keys (in endorsements and revocations), and with
`alsoKnownAs` they tie a kernel identity to the person's other DIDs. That
makes the registry usable by any DID or verifiable-credential tool, with
no git-vouch code, and is what an upstream git would display. did:key is
the only method `git-vouch` interprets, because it is the only one that
needs no resolution.

Supported key types:

| SSH type | did:key multicodec |
|---|---|
| `ssh-ed25519` | `ed25519-pub` (0xed) |
| `sk-ssh-ed25519@openssh.com` | `ed25519-pub` (0xed); the FIDO wrapping is a signing detail that `ssh-keygen` handles |
| `ecdsa-sha2-nistp256` | `p256-pub` (0x1200), compressed point |
| `sk-ecdsa-sha2-nistp256@openssh.com` | `p256-pub` (0x1200) |
| `ssh-rsa`, 2048 to 4096 bits, odd e with 3 ≤ e < n, n not prime, not a prime power and with no factor below 2^16 | `rsa-pub` (0x1205), PKCS#1 RSAPublicKey DER |

A did:key does not record whether the key is an `sk-` key, and drops
its FIDO application string, so one did:key can match two SSH keys.
`git vouch did` prints the plain form for the reverse; `git-vouch`
itself resolves a did:key only by looking it up in the registry.

DSA, P-384, P-521 and RSA below 2048 bits are not accepted. The RSA
floor is the kernel's (`maintainer-pgp-guide.rst`) and the exponent
range PKCS#1's. The ceiling, 4096 bits, is below OpenSSH's 16384 to
bound what a hostile person file costs: every RSA modulus is tested for
being a prime or prime power while parsing, before any signature check,
which takes about 0.15 s at 4096 bits but 7 s at 16384, so 16 such keys
in one file would cost every `check` about 2 minutes. No live RSA
authentication key in pgpkeys is above 4096 bits (119 in all: 43 of
2048, 2 of 3072, 74 of 4096). RSA is accepted so nobody
is forced off a working key, but the guides recommend upgrading. SSH
base64, mpints and DER must be canonical and minimal, so each key has
exactly one did:key and a revocation cannot be dodged by re-encoding.
Keys anyone can sign with are refused: ed25519 keys (plain and `sk-`)
with y ≥ p or at one of the 8 small-order points (libsodium's list; for
the identity point, R = identity and S = 0 verify every message), and
RSA keys whose modulus is prime, a prime power or has a factor below
2^16. Newer OpenSSH also refuses those ed25519 keys, so accepting them
would make `check` depend on the OpenSSH version. The RSA check catches
only accidental or naive weak moduli: a registrant who deliberately
picks a moderate factor is not detected. The key's base64 must be
canonical, as OpenSSH requires, so no line is exported that
`ssh-keygen` would skip. The ed25519, P-256 and RSA
forms are tested against the W3C CCG did:key test vectors, an oracle
independent of this code.

## Keys

`git-vouch` never touches a private key. Signing goes through `ssh-keygen
-Y sign`, which uses the SSH agent or a key file, so any agent-backed
store works: YubiKey (FIDO or PIV), Secure Enclave, 1Password, TPM, a
cloud KMS, or gpg-agent with `enable-ssh-support` for people keeping an
existing GPG key whose authentication subkey is an accepted type.

**Hardware is recommended, not required.** Maintainers and anchors
should keep their keys on a hardware token, but any supported key type is
accepted for every tier. The tool cannot prove what holds a key, so this
is advice for endorsers and approvers to ask about, not a rule.
kernel.org already issues FIDO keys as `ed25519-sk`, with `ecdsa-sk` as
the fallback, and backup tokens as second keys
(korg.docs.kernel.org/fido2.html), which fits the one-signature rule for
person files.

**Attestation is verified by a separate tool.** A FIDO key generated
with `ssh-keygen -O challenge=<file> -O write-attestation=<file>` comes
with the authenticator manufacturer's certificate chain saying the key
was created inside a device of a given model. `git-vouch-attest` checks
it, doing the X.509 work through the `openssl` CLI against a vendor root
the user supplies; no roots are bundled. A `--ca` file whose
certificates do not all parse is refused. The attestation certificate
must meet the WebAuthn 8.2.1 packed profile: X.509 v3, subject OU
"Authenticator Attestation", basicConstraints CA:FALSE, and, if present,
a non-critical id-fido-gen-ce-aaguid extension (1.3.6.1.4.1.45724.1.1.4)
matching the authData AAGUID. `git-vouch-attest` is stricter than
WebAuthn and requires the extension always, because without it the
printed AAGUID would rest only on authData, which whoever holds the
certificate's key wrote. It is to be cross-validated against OpenSSH's
`regress/misc/ssh-verify-attestation` (expected verdicts are predicted
from source and not yet run; see vouch-ey47.15). `git-vouch` itself
checks only the shape. The attestation exists only if it was captured
at generation, and PIV, Secure Enclave, TPM and software keys have
nothing equivalent that SSH exposes. Note also that `ssh-keygen -Y
verify` does not enforce the FIDO user-presence or user-verification
flags, and `allowed_signers` has no option to require them, so a
verified signature does not prove anyone touched the token.

## Patch signing

Kernel patch emails are signed with patatt, which is built into b4: an
`X-Developer-Signature` header that `b4 am` checks. patatt already
signs and verifies with `ssh-keygen -Y` in the `patatt` namespace and
looks keys up by email at `openssh/<domain>/<local>/<selector>`, from a
directory or straight from a git ref. It has no notion of tiers,
revocation or validity dates: a key in its keyring is trusted. Today
the kernel's b4 keyring is `pgpkeys.git`'s `.keyring/`, which the flag
day freezes.

A fork of patatt adds one keyring source, `keyringsrc = vouch:`, which
asks `git vouch keys <email>` for the signer's current keys instead of
reading a keyring tree. The registry is the keyring; nothing is
generated, published or trusted in between. The fork's change is kept
small and in upstream style so it could be offered upstream. The rules
`git vouch keys` applies:

- **Who:** any registered person with at least one endorsed email,
  whatever their tier, including automation identities whose email is
  endorsed (normally by their accountable maintainer). Only endorsed
  emails become identities.
- **Which keys:** current keys only. patatt cannot say "valid until", so
  a retired key would verify new forgeries; it drops out at the next
  run, and patch emails it signed stop verifying, which matters little
  once a patch is merged. Revoked keys are never written.
- **Selector:** derived from the key itself (`k-` plus a short
  lowercase hex fingerprint; patatt lowercases selectors in file
  keyrings, so base64 would collide), one rule for every key, so a person's main and backup
  tokens never collide. `git vouch status` prints the selector to set as
  `patatt.selector`.
- **Where:** nowhere new. The fork reads the local registry copy that
  `git vouch sync` keeps current, through `git vouch keys`. b4 uses the
  fork when it is installed in place of patatt. Stock patatt still works
  with its existing keyrings, but does not see the registry.
- **GPG fallback for the flag day:** the fork's recommended config lists
  `vouch:` first and the legacy GPG keyring, a clone checked out at
  the freeze commit, second, and patatt tries sources in order. A patch that verifies
  through anything other than `vouch:` gets a warning that the legacy
  keyring stops six months after the flag day, at the late cutoff. The fallback applies to
  everyone, registered or not. After the late cutoff people delete the
  legacy line; no code changes.
- **Limits** (`docs/patatt-interop.md`): patatt cannot enforce FIDO
  touch or PIN, nor key validity dates beyond what `git vouch keys`
  returns. Upstream b4 newer than 0.16 caches verdicts for up to 24
  hours, so a revoked key can still show a pass for up to a day, and the legacy-keyring
  warning appears only on checks b4 has not cached. A b4 fork
  (github.com/MarkAtwood/b4, branch `git-vouch`; upstream submission
  held) makes the window `b4.attestation-recheck-hours`, and the guides
  set it to 0, so b4 checks every signature again. It also names the
  keyring that verified a pass, `(key: vouch:<email>/<selector>)`, and
  carries `misc/vouch-check.sh`.

## TRQP bridge

`git-vouch-trqp` is an optional daemon that lets OpenVTC's
`verify-trust` ask whether a signer may sign. It is a thin shim over
`git vouch query`; kernel developers never depend on it, and `git-vouch`
itself stays a CLI. Facts about `verify-trust` come from
`docs/trqp-interop.md`.

- **Wire format:** a Trust Task envelope (`registry/authorization/0.1`)
  at `POST <base>/trust-tasks`, not plain TRQP `/authorization`. The
  response echoes the tuple and sets `authorized` and `time_evaluated`;
  errors use a `trust-task-error` body. It serves the path directly,
  never by redirect.
- **Authority DID:** configured by the operator: `did:web` on a domain
  of their choosing, or `did:webvh`. `git-vouch-trqp did-document`
  prints the document with one `TRQPRest` service entry whose endpoint
  must be `https://`. For `did:webvh` the operator signs the log with an
  existing webvh tool; our tools add no cryptography. Queries naming any
  other `authority_id` get `authorized: false`.
- **Who is authorized:** for `git.commit.sign`, a did:key that is a
  current key of a registered person with at least one endorsed email,
  any tier; automation identities never, since they do not sign commits.
  Retired and revoked keys get `false`. Any other action gets `false`.
  This is looser than the default `allowed_signers` export (contributor
  and above), so the bridge can say yes where `git verify-commit` would
  not.
- **Repositories:** not scoped. A yes means "a registry-vouched person"
  for any repository; each project decides whether that suffices. The
  resource is validated against `verify-trust`'s grammar and echoed.
- **Time:** answers are for now. If a request carries `context.time`,
  the bridge answers as of that time (`git vouch query --at`), with the
  tier, automation status and emails held then, read from the registry's
  git history, less any tier the current history ends at or before then;
  export answers for now, so the two can differ for past times. The
  registry then is the newest commit on HEAD's first-parent line whose
  effective date (see Effective dates) is at or before that time. A tier
  record deleted, or replaced with one that has no effect, and an anchor
  dropped from `anchors.json` end at the effective date of that commit,
  which is also the export's `valid-before`.
- **Freshness:** it syncs on a timer and refuses to answer, with an
  error that makes `verify-trust` fail closed, once 24 hours pass
  without a successful sync.
- **Caching:** answers for now come from one `git vouch query --all`
  run shared by every DID and every concurrent request, rerun when the
  served copy's commit changes and after 60 seconds, since validity at
  now changes when a retirement or tier end passes with no commit. The
  first request after a sync or a minute waits for a whole check (about
  12 s for 600 people); the rest answer in milliseconds, and an answer
  can be up to 60 s old. A served copy with local changes, and a request
  with `context.time`, run a check each time.
- **Serving:** `--bind` takes an IPv4 address, a host name, `''` (all
  IPv4 interfaces) or an IPv6 literal. Only an address containing `:`
  listens on IPv6; a host name always binds IPv4, so `localhost` is
  127.0.0.1. A failure to listen prints `git-vouch-trqp: cannot listen
  on HOST:PORT: reason` and exits 1; a `--port` outside 0..65535 is a
  usage error (exit 2). Each 503 `unavailable` for a failed or timed-out
  query writes one line to the bridge's stderr (`git-vouch-trqp: git
  vouch query exited N: <last stderr line, escaped, at most 300 chars>`
  or `git-vouch-trqp: git vouch timed out after 30s`); the reply to the
  client stays generic.
- **Trust:** answers over HTTPS are unsigned, so they rest on the
  `https://` endpoint named in the DID document. Anyone can check an
  answer against the public registry.
- **Key types:** `verify-trust` must accept all five types `git-vouch`
  does. Today it accepts only `ssh-ed25519`
  (https://github.com/OpenVTC/verifiable-git-infrastructure/issues/169);
  the bridge is built assuming that is fixed.

## Flag day

GPG and `pgpkeys.git` are retired for the kernel on one date, the flag
day. No period accepts both GPG and SSH signatures on new tags or pulls.
Before the flag day every pgpkeys holder who still signs registers an
SSH key. After it, nothing new needs `gpg`.

1. **Freeze.** `pgpkeys.git` gets one last signed commit, the freeze
   commit, and becomes read-only. Its hash, the flag-day date and the
   late cutoff are published together.
2. **Window.** The first registry merge holds `anchors.json` and the
   anchors' person files. Everyone else then registers.
3. **Flag day.** Linus and the release tooling switch to files from
   `git vouch export`, and GPG-signed tags and pulls stop being accepted.
4. **Late cutoff.** Six months after the flag day; the anchors may
   extend it by announcement. Continuity claims against the freeze
   commit are accepted until this date. After it, people register as newcomers. No
   tool enforces it: after the cutoff, registry maintainers do not merge
   any change that adds or alters a `migratedFrom` field or adds a
   `people/*.json.asc`. That covers both proof routes, since reusing an
   auth subkey also needs `migratedFrom`. The merge date counts, not the
   commit date.

**Porting pgpkeys.** `git-vouch-migrate` reads pgpkeys only at the
freeze commit, after verifying the freeze commit's signature. It reads
with `--no-replace-objects`, so `refs/replace` in the pgpkeys clone
cannot change `keys/` or the freeze commit it checks, and reads `keys/`
as the blobs in the freeze commit's tree, so no git attributes can drop
or change a file. For each
unrevoked person key it writes an unsigned draft person file: a proposed
handle, the name, emails from unrevoked UIDs, and `migratedFrom`. The
holder adds an SSH key, signs the draft with `git vouch register --from`
and submits it. The tool never writes a signed record, and it calls
`git-vouch` for person-file checks rather than re-implementing them.

**Continuity proof** is needed only to receive ported endorsement
drafts. It grants no tier, and registering without it works; the person
then collects fresh endorsements. The proof is either
`people/<handle>.json.asc`, a detached signature by the GPG key over the
new person file's exact bytes, or reuse of that key's authentication
subkey as the SSH key. It is judged against the person-file version it
was made for, found in the registry's history, so later signed edits do
not undo it. A change that only review let through (lost-key recovery,
or a handle registered again after deletion) ends that: the current
version must then carry its own proof. `git-vouch-migrate` accepts it
only if the GPG key is not revoked in the freeze commit (an expired key
is accepted), every email in that version is on an unrevoked UID of that
key, and no other person file claims the same fingerprint. If two do,
`check` flags both and neither gets drafts until an anchor resolves it,
whichever merged first. `git-vouch` itself never runs GPG and never
checks the `.asc`.

**Endorsements.** GPG certifications are not ported as records. Each
certifier runs `git-vouch-migrate drafts --as <handle>` on their own
machine, from the public pgpkeys at the freeze commit and the registry,
and gets one draft per subject with a continuity proof: the latest
unrevoked certification by the key in the certifier's `migratedFrom`
(the certifier needs no proof), including SHA-1 ones that GnuPG 2.4
rejects and ones expired by the freeze commit, because the draft is only
a reminder and the certifier's new SSH signature is what counts. A draft
takes `subjectName` from the person file, fills `subjectEmails` from the
certified UIDs, and puts the certified fingerprint, UID and date in
`note`. The certifier reads and signs them. Drafts are never generated
centrally, and unsigned drafts never enter the registry.

**Tiers.** GPG supplies none. Linus certifies 2 keys, so the web of
trust says nothing about who is a maintainer. Anchors approve
maintainers on their own judgement, using MAINTAINERS and endorsements.

**What continuity cannot catch.** Someone holding a GPG key that was
stolen and not revoked by the freeze commit can claim that person's
identity, just as they can sign tags with it today. The duplicate-claim
rule exposes this if the real holder also migrates, and the late cutoff
ends it.

**Scale** (pgpkeys at research time): 645 live keys for about 606
people; 188 can reuse an authentication key as an accepted SSH key;
about 1,784 verified certification pairs become drafts; about 80% of
maintainers have no GPG key and register fresh.

**Old signatures.** GPG-signed tags stay valid in history. Verifying
them uses `gpg` with the archived pgpkeys at the freeze commit. There is
no manifest.

**Out of scope.** Release files and kup (see Summary), and encryption
keys (the remail and security lists). kernel.org keeps a small
encryption-only GPG keyring. Patch signing is
covered separately (see Patch signing): the patatt fork reads the
registry, with the frozen GPG keyring as a warned fallback until the late
cutoff.

**Kernel-team calls, not design:** the anchor list, the freeze date and
the window length. The late cutoff is six months after the flag day.

## Implementation

- **One file**, `git-vouch`, executable, 3,906 lines (`wc -l`,
  2026-10-23). Standard-library modules used: `argparse`, `base64`,
  `collections.abc`, `datetime`, `functools`, `hashlib`, `json`, `math`,
  `os`, `pathlib`, `re`, `stat`, `subprocess`, `sys`, `tempfile`,
  `typing`. The other tools are separate files.
- **External programs**, called with argument lists and never through a
  shell: `git`, `ssh-keygen`.
- **Input is untrusted:** registry files come from other people. Handles
  and file names match `^[a-z0-9][a-z0-9_-]{0,38}$`; each file has a
  size cap (64 KiB); a person file lists at most 16 current keys
  (retired keys are not counted) and a `.sig` file holds at most 4
  signature blocks, so each costs `check` a bounded number of
  `ssh-keygen` runs; a file over either cap is a problem like any other
  that does not parse; git-vouch's own terms are checked strictly for type and
  format, and all other terms are ignored; no registry value is ever put
  on a command line except as a single argument after `--`. Record dates
  must fall in the years 1970 to 9998.
- **Tests** use only development dependencies: pytest, and as oracles
  for the bridge and patatt tests jsonschema, referencing,
  rfc3339-validator, rfc3986-validator and pynacl. Signatures are
  made and checked by real `ssh-keygen` on throwaway keys. did:key
  encoding is checked against the CCG test vectors, never against
  `git-vouch`'s own output.

## Upstream path

Version 1 needs nothing from git beyond SSH signing. The formats are
chosen so that git could later take over what `git-vouch` does, one piece at
a time, with no change to the registry:

1. **DIDs in git's output.** `git verify-tag` and `log --show-signature`
   print the signer's did:key next to the principal. That is a small,
   self-contained patch.
2. **Allowed signers from a registry.** git reads the registry directly,
   instead of an `allowed_signers` file that `git vouch export` generated.
   This needs git to apply the tier rules, so it lands only after the
   rules have proven stable in `git-vouch`.
3. **Native DID signing** (`gpg.format=did`), if the community wants
   signatures that name a DID rather than an SSH key.

Each step is proposed only after the previous one has users. Until then
`git-vouch` is the reference implementation, and its Python is the
specification for anyone reviewing an upstream patch.

## Rejected alternatives

- **An SSH certificate authority** (`cert-authority` in allowed signers).
  It is native to OpenSSH, but it puts the whole tree behind one CA key,
  makes the CA holder a bottleneck for every contributor, and hides the
  endorsement record that the registry exists to show.
- **OpenVTC / VTI.** Solves the same problem with an always-on agent,
  three transports and seven credential types, in over 900k lines of code. See
  `docs/vs-openvtc.md`. OpenVTC tools can still query the registry
  through the optional `git-vouch-trqp` bridge.
- **Sigstore / gitsign.** Ties identity to an OIDC provider and depends
  on online services; the kernel wants keys people hold.
- **A custom signature payload on git objects.** git's SSH signatures
  already bind the object.
- **`refs/signatures/` or a native DID signing method in git, as a
  prerequisite.** Version 1 must work on today's git; see Upstream path.
- **JCS canonicalisation.** Signatures cover the file's exact bytes,
  which allows arbitrary JSON-LD metadata without canonicalising it.
- **minisign for the registry's records.** `ssh-keygen -Y sign` signs
  them, and everyone who verifies already has `ssh-keygen`.
- **A `tier` field in the person's own file.** The person signs their
  own file, so they could promote themselves. The tier is a separate
  record signed by the approver.
- **Minimum endorsement counts per tier.** The approver decides;
  endorsements are evidence.
- **Delegated signing scopes.** Tier files give the kernel's real
  policy: Linus pulls from maintainers, releases come from anchors.
- **LF-wide registry federation and cross-project lookups.** Kernel
  first.
- **`cryptography` or other dependencies.** `ssh-keygen` does all
  crypto.
- **A dual GPG/SSH transition.** One flag day; see Flag day.

## Open questions

1. **Registry maintainers:** who may merge into the kernel registry on
   git.kernel.org. Given the accepted risks (anchors, unsigned key
   changes, tier-record deletions), this choice matters as much as choosing the anchors. It is
   a kernel-team decision, not a design one.
2. **Flag-day dates and anchors:** the anchor list, freeze date and
   window length. Kernel-team decisions.
3. **Person-file change signed by a key revoked later:** `check` warns,
   as it does for a key revoked before the change. A revocation signed
   by a later-revoked key still counts if committed first, so the
   person-file case might too.

Decided 2026-10-22:

- **Rules of construction:** never replace what git does, keep the
  registry in git and read its history; small single-purpose tools
  (`git-vouch`, `git-vouch-migrate`, `git-vouch-attest`,
  `git-vouch-trqp`).
- **Registry:** URL configurable, the kernel's on git.kernel.org; one
  registry maintainer merges after `git vouch check`; warn when the copy
  is over 7 days old; anchors are whoever the registry lists; anchors,
  unsigned key changes and tier-record deletions rest on review.
- **Tiers:** set by a signed approver record; automation is its own tier,
  files only; authority judged at the commit adding the record, so an
  approver stepping down voids nothing and only a revoked key does (the
  same for a bot's accountable maintainer); a grant concurrent with its
  approver's demotion is void with a warning; mutual concurrent
  revocations both count; a tier record before its person file is
  ignored; removal ends at the
  deleting commit's effective date, a merged branch's at its merge
  (leaving `anchors.json` too),
  demotion at the new record's date; the export adds an hour to every
  end for an OpenSSH 9.6 DST bug.
- **Person files:** a change needs one signature from any key current in
  the previous version; a change without one is allowed by review and
  warned about loudly, and lost-key recovery keeps the tier; an
  all-retired file is frozen; a key in two files belongs to the proven
  (current) listing over an unproven retired one, then the first listed; an email may be in only one file; every exported key
  has its handle as a principal.
- **Endorsements:** any registered human may endorse, tier or not, which
  is how cross-project vouching works (no foreign-registry lookups, no
  federation); nobody can endorse themselves (void, not an error);
  optional free-text note, no minimum count; they bind
  name, key and `subjectEmails`, carry over to later keys (also when
  the subject's key is revoked; only a revoked endorser key voids one),
  and only endorsed emails are exported.
- **Patch signing:** a patatt fork with a `vouch:` keyring source asks
  `git vouch keys <email>`; endorsed emails and current keys, any tier,
  bots included; selectors derived from the key; no generated keyring;
  the legacy GPG keyring stays as a warned fallback for everyone until
  the late cutoff, six months after the flag day.
- **TRQP bridge:** optional `git-vouch-trqp` daemon speaking Trust
  Task envelopes; authority DID configured (`did:web` or `did:webvh`);
  `git.commit.sign` authorized for current keys of anyone with an
  endorsed email, no bots; any repository; refuses after 24 hours
  without a sync; assumes OpenVTC accepts all five key types.
- **Revocations:** never fail `check`; `sync` always writes them; one
  signed by a key revoked later counts if committed first; deleting one
  has no effect.
- **Keys:** hardware recommended, not required; Python floor 3.9;
  delegated signing scopes out of v1; FIDO attestation is `{blob,
  challenge}`, shape-checked by `git-vouch` and verified only by
  `git-vouch-attest` against a user-supplied root.
- **Flag day:** GPG and `pgpkeys.git` replaced on one date, frozen at
  signed commit (the freeze commit), no dual tags; ported files carry
  `migratedFrom` and duplicate fingerprints block drafts for both;
  continuity proof (`.asc` or reused auth subkey, expired keys accepted)
  only unlocks drafts and grants no tier; drafts generated locally by
  each certifier; old tags verified with `gpg` and pgpkeys at the freeze
  commit, no manifest; encryption keys out of scope; patch signing via
  the patatt fork.
- **CLI details:** `git vouch did` takes a `.pub` path or key text;
  `register --from` completes a draft; no
  man page; `setup`/`sync` remember `--min-tier` and
  `--include-automation`; `check`/`export` take an optional registry
  directory.

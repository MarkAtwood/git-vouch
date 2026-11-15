# Why git-vouch works the way it does

**Status:** reference, 2026-11-15. One entry per design choice the
guides make you follow. Every reason comes from `DESIGN.md`, and each
entry links its section; where DESIGN gives no reason, the entry says
so.

<a id="ssh-not-gpg"></a>
## SSH keys, not GPG

**What:** git signs tags and commits with SSH keys (`gpg.format=ssh`),
and `ssh-keygen -Y` signs the registry's records and, through patatt,
patch emails. Release files (`.tar.sign`, `sha256sums.asc`, the checksum
autosigner) and kup upload authentication stay with kernel.org on GPG.

**Why:** git and OpenSSH already do signing, verification, expiry,
purpose limits, revocation and key storage. `git-vouch` adds only the
approval rules and contains no cryptography. An auditor trusts Python 3,
git and OpenSSH, which every kernel developer already has, plus one file
short enough to read in a sitting. git-vouch replaces the keyring and
web of trust, not every use of `gpg`.

Release files stay on GPG because:

- a handful of release signers is not a keyring;
- a release tarball is `git archive` of a signed tag, which git-vouch
  covers;
- moving distributions' `gpg --verify` scripts would cost them a lot
  for little gain.

Measured on 2026-10-23: 1,538 of the 1,935 people on MAINTAINERS `M:`
lines (79.5%, an upper bound) have no unrevoked, unexpired pgpkeys user
ID matching their `M:` emails.

**Rejected:**

- Sigstore and gitsign: they tie identity to an OIDC provider and depend
  on online services, where the kernel wants keys people hold.
- An SSH certificate authority: it puts the whole tree behind one CA
  key, makes its holder a bottleneck for every contributor, and hides
  the endorsement record.
- minisign for records: everyone who verifies already has `ssh-keygen`.
- SSH signatures on release files alongside GPG during an overlap, for
  the reasons above.

DESIGN: [Summary](../DESIGN.md#summary),
[Constraints](../DESIGN.md#constraints),
[Rejected alternatives](../DESIGN.md#rejected-alternatives).

<a id="registry-in-git"></a>
## The registry lives in git

**What:** the registry is a git repository holding one signed file per
person, per endorsement, per tier grant, per revocation and per cosign.
`git fetch` distributes it, and `git-vouch` reads commit order,
committer dates and deletions as part of the registry. `anchors.json` in
it names the anchors; nothing is pinned locally.

**Why:** distribution and history belong to git, so `git-vouch` reads
history instead of inventing records for what git already records.
Order and removal come from commits, not from a field anyone could
write. The formats are plain files and git's own allowed-signers format,
so a future git could read the registry itself.

The cost is an accepted risk: whoever controls the repository chooses
the first anchors. Every later change to them needs two anchors' cosigns
([cosign](#cosign)), shows in public history, and `git vouch sync`
refuses a rewrite.

**Rejected:**

- OpenVTC / VTI, which solves the same problem with an always-on agent,
  three transports and seven credential types in over 1.5 million lines.
- LF-wide federation and cross-project lookups: the kernel comes first.
- Local anchor pinning: no reason given in DESIGN beyond making the
  registry the root of trust.

DESIGN: [Constraints](../DESIGN.md#constraints),
[The registry](../DESIGN.md#the-registry),
[Anchors](../DESIGN.md#anchors).

<a id="nothing-pushes"></a>
## Nothing pushes for you

**What:** `register`, `endorse`, `approve`, `revoke` and `cosign` write
and sign files in your checkout. You commit and push a branch; a registry
maintainer merges it once `git vouch check` passes.

**Why:** changes arrive as reviewed merges. Review is the only gate for
three accepted risks:

- the first `anchors.json`;
- person-file changes no previous key signed, for anyone below
  maintainer;
- deleted tier records.

Two anchors' cosigns guard the rest of what review used to carry alone
([cosign](#cosign)). Every command takes its input from arguments and
files and never prompts, so it works in scripts, CI and over ssh. No
reason given in DESIGN for the commands stopping short of a push.

**Rejected:** DESIGN names no alternative.

DESIGN: [Summary](../DESIGN.md#summary),
[Constraints](../DESIGN.md#constraints),
[The registry](../DESIGN.md#the-registry) (Merging needs one person),
[Commands](../DESIGN.md#commands).

<a id="cosign"></a>
## Two anchors cosign what one merger cannot check

**What:** two changes need cosigns (`git vouch cosign <path>`) by two
anchors in effect before the change, never the person whose file it is:

- a change to `anchors.json` after its first version;
- an anchor's or maintainer's person-file change that no previous key
  signed.

A cosign is a signed record naming the SHA-256 of the exact bytes it
approves. Without two cosigns, the `anchors.json` edit has no effect and
the person's tier is suspended from that commit; `check` reports both as
void and still passes. With fewer than two eligible anchors, every
eligible one must cosign.

**Why:** `check` could not verify these changes by a signature, so one
registry maintainer's merge decided them: adding an anchor, or swapping
in a key that keeps an anchor's or maintainer's tier. Two cosigners are
two people `check` can count, whoever merged. Voiding instead of failing
means one bad merge cannot stop the export for everyone. Cosign
authority is judged before the commit that added the cosign, as tier
records are judged where they were added, so no cosign lends authority
to itself.

**Rejected:**

- One anchor's cosign with the merger as the second person: `check`
  cannot see who merged.
- Failing `check`, which would stop every export.
- Signed merge commits, which carry one signature each.
- Covering tier-record deletions, which only take authority away; an
  anchor can already revoke a key at once.

DESIGN: [Cosign](../DESIGN.md#cosign),
[Anchors](../DESIGN.md#anchors).

<a id="endorse-vs-approve"></a>
## Endorse versus approve

**What:** an endorsement is your signed statement that a key and some
emails belong to a named person. It grants nothing, and any registered
human may make one, with or without a tier. An approval is a tier record
the approver signs, and only someone above that tier may make it.

**Why:** an endorsement is evidence about identity, not a grant of
authority. Only the approver needs authority, so widening who may
endorse costs nothing. Someone from another community can then register
with no tier and endorse, and an attacker would have to infiltrate two
social graphs, not one.

Endorsements are evidence, not a count. The approver reads them and
decides; `check` verifies signatures and authority, never the approver's
judgement. A self-endorsement is void.

`git vouch show` marks an endorsement as from outside the kernel graph
when its endorser holds no tier and lists `alsoKnownAs`, and prints
those identities. The cross-community argument helps only if the
approver can see which endorsements it applies to. Both facts are
self-service, so the mark says where to check, not that anyone outside
did.

**Rejected:**

- Minimum endorsement counts per tier: the approver decides.
- Calling every untiered endorser outside, which would include kernel
  newcomers.
- Judging by the endorsement graph, which a sock puppet nobody endorsed
  passes anyway.
- Tiers from the GPG web of trust: Linus certifies 2 keys, so it says
  nothing about who is a maintainer.

DESIGN: [How trust maps](../DESIGN.md#how-trust-maps),
[Endorsement](../DESIGN.md#endorsement),
[Flag day](../DESIGN.md#flag-day) (Tiers).

<a id="tiers"></a>
## Tiers and who may grant or lower them

**What:**

- `anchors.json` makes anchors.
- An anchor grants `maintainer`.
- A maintainer or an anchor grants `contributor` and `automation`.
- To lower someone, the approver must also sit above the tier that
  person held just before, so only an anchor can demote a maintainer.
- Authority is judged once, at the commit that adds the record.
- Automation signs files and patches, never tags or commits, cannot
  endorse or approve, and names an accountable maintainer.

**Why:** the tier is a separate record signed by the approver, so nobody
can promote themselves. The demotion check reads history, not the
record's own date, so a peer's lowering record is void and a peer cannot
choose the date. Because authority is judged at the commit, an approver
who steps down voids nothing; only a revoked approver key voids the
records it signed.

Tier files express the kernel's real policy: Linus pulls from
maintainers, releases come from anchors. Requiring a tier needs no
wrapper: `git verify-tag` against the `--min-tier maintainer` export
rejects anyone below it.

**Rejected:** a `tier` field in the person's own file, which they sign
and could use to promote themselves. Delegated signing scopes, because
tier files already give the policy.

DESIGN: [How trust maps](../DESIGN.md#how-trust-maps),
[Tier record](../DESIGN.md#tier-record),
[What git and OpenSSH already do](../DESIGN.md#what-git-and-openssh-already-do).

<a id="endorsed-emails"></a>
## Only endorsed emails are exported

**What:** an email becomes an allowed-signers principal, and a patatt
identity, only once a valid endorsement covers it. Every exported key
also carries its handle as a principal. An unendorsed email stays in
your file, is not exported, and `check` warns about it. An email may
appear in only one person file.

**Why:** the endorsement binds the subject's name, key and emails, so an
address the endorser did not vouch for is not endorsed. Emails are
principals so git's output shows a familiar address. The handle
principal lets anchors, automation and anyone approved without
endorsements still verify.

**Rejected:** DESIGN names no alternative.

DESIGN: [Person file](../DESIGN.md#person-file),
[Endorsement](../DESIGN.md#endorsement).

<a id="hardware-keys"></a>
## Hardware keys are advice, not a rule

**What:** every supported key type is accepted for every tier.
Maintainers and anchors should keep keys on a hardware token; kernel.org
issues FIDO keys as `ed25519-sk`, with `ecdsa-sk` as the fallback, plus
backup tokens. A FIDO attestation is optional. `git-vouch` checks only
its shape; `git-vouch-attest` verifies it against a vendor root you
supply.

**Why:** the tool cannot prove what holds a key, so hardware is
something endorsers and approvers ask about.

- An attestation exists only if it was captured at generation, and PIV,
  Secure Enclave, TPM and software keys have nothing equivalent that SSH
  exposes.
- Verifying one needs `openssl`, and a job that needs another program
  gets its own tool.
- `ssh-keygen -Y verify` does not enforce FIDO user presence, so a
  verified signature does not prove anyone touched the token.

**Rejected:** a hardware requirement, which the tool could not check.
Bundling vendor roots: no reason given in DESIGN.

DESIGN: [Keys](../DESIGN.md#keys), [Constraints](../DESIGN.md#constraints).

<a id="backup-key"></a>
## A backup key in a drawer

**What:** a new version of your person file needs a signature from any
one key current in the previous version; the first version needs one of
its own keys. Register a backup key while your main key can sign for it.
A file lists at most 16 current keys and its `.sig` holds at most 4
signatures.

**Why:** adding a key is signed by an existing key. That is how rotation
works, and the backup token can stay in a drawer. kernel.org's backup
tokens fit this rule.

Without a backup, recovery is a change no previous key signed, and
`check` prints a WARNING. For an anchor or maintainer the tier is then
suspended until two anchors cosign the change ([cosign](#cosign)). For
anyone else review is the gate, and a merger who lets a swapped key
through hands its holder your tier and endorsements.

The caps bound how many `ssh-keygen` runs a hostile file costs `check`.

**Rejected:** refusing a change no previous key signed. DESIGN keeps it
as the route for lost-key recovery.

DESIGN: [Person file](../DESIGN.md#person-file),
[Keys](../DESIGN.md#keys),
[Implementation](../DESIGN.md#implementation).

<a id="exact-bytes"></a>
## Signatures cover exact bytes

**What:** every record's signature covers the file's exact bytes, under
a namespace for its kind. Any edit means re-signing. A continuity
`.asc` covers the exact bytes it signed; once that version is
committed, later signed edits keep the proof.

**Why:** records carry arbitrary user metadata, and canonicalising it
would need exact number formatting (JCS) or context fetching (RDF
canonicalisation). Signing the bytes on disk needs neither. A namespace
per kind stops a signature made for one kind of record being accepted
as another.

**Rejected:** JCS canonicalisation.

DESIGN: [The registry](../DESIGN.md#the-registry),
[Rejected alternatives](../DESIGN.md#rejected-alternatives).

<a id="revoke-vs-retire"></a>
## Revoking versus retiring

**What:** retiring a key sets `valid-before` to the retirement time, and
its earlier signatures stay valid. Revoking lists it in the revocation
file: every signature it made, past or future, fails, and every
endorsement and tier record it signed is void.

- The key itself, another current key of its owner, or any anchor may
  sign a revocation.
- A revocation never fails `check`.
- `sync` writes the revocation file even when `check` fails.
- A committed revocation holds even if its file is later deleted.

**Why:** git checks a signature against the key's validity at the time
the signature says it was made, and the signer sets that time, so a
retired key's holder can backdate. When there is any doubt about who
holds a key, revoke it. Revocations always spread so that nothing else
wrong in the registry can hold one back.

**Rejected:** retiring a key whose holder is in doubt, for the
backdating reason above.

DESIGN: [Retiring a key versus revoking it](../DESIGN.md#retiring-a-key-versus-revoking-it),
[Revocation](../DESIGN.md#revocation).

<a id="extra-hour"></a>
## The extra hour on every end

**What:** the export writes every `valid-before` (retirement, removal,
demotion) one hour after the end it records.

**Why:** git passes the verify time to OpenSSH as local time without a
zone, and OpenSSH 9.6 reads it an hour off under daylight saving time.
Without the hour, signatures made in the last hour before an end would
fail. The hour adds no risk: the signer sets the signing time and could
backdate by any amount anyway.

**Rejected:** DESIGN names no alternative.

DESIGN: [Retiring a key versus revoking it](../DESIGN.md#retiring-a-key-versus-revoking-it).

<a id="no-ff-merges"></a>
## --no-ff merges and effective dates

**What:** registry maintainers merge with `git merge --no-ff`, never a
fast-forward, not even of a contributor's merge of main. Each commit on
HEAD's first-parent line has an effective date that never goes
backwards, and a branch merged with `--no-ff` counts from its merge.
`check` refuses any commit dated more than 5 minutes in the future.

**Why:** tier removals and `--at` queries take their dates from
commits, so the main line must carry the maintainer's committer dates,
not the submitter's. A fast-forwarded "foxtrot" merge would make the
contributor's own backdated branch the first-parent line. A
future-dated commit would move every later effective date.

**Rejected:** a date clamp, which cannot catch a foxtrot merge because
the contributor's commits would then form the first-parent line.

DESIGN: [The registry](../DESIGN.md#the-registry) (Effective dates,
Merging needs one person).

<a id="sync-refuses-rewinds"></a>
## sync refuses rewinds and warns after 7 days

**What:** `git vouch sync` fetches with a refspec that has no `+`, so
git refuses a rewritten history. Every command warns once your copy was
last fetched more than 7 days ago, and keeps working.

**Why:** the one attack left to whoever hosts the registry is to
withhold updates, such as a revocation. The warning does not stop the
command, so offline use still works.

**Rejected:** DESIGN names no alternative.

DESIGN: [The registry](../DESIGN.md#the-registry).

<a id="rsa-cap"></a>
## Key types and the 4096-bit RSA cap

**What:** ed25519 and P-256 keys, plain or FIDO `sk-`, and RSA of 2048
to 4096 bits are accepted. DSA, P-384, P-521 and RSA below 2048 bits are
refused. The guides recommend upgrading from RSA.

**Why:** the 2048-bit floor is the kernel's
(`maintainer-pgp-guide.rst`). The ceiling bounds what a hostile person
file costs. Every RSA modulus is tested for primality while parsing,
which takes about 0.15 s at 4096 bits but 7 s at 16384, so 16 such keys
would cost every `check` about 2 minutes. No live RSA authentication key
in pgpkeys is above 4096 bits (119 in all: 43 of 2048, 2 of 3072, 74 of
4096). RSA is accepted so nobody is forced off a working key.

No reason given in DESIGN for refusing DSA, P-384 and P-521, or for the
upgrade advice.

**Rejected:** OpenSSH's own 16384-bit ceiling.

DESIGN: [did:key](../DESIGN.md#didkey).

<a id="no-forge-key-refs"></a>
## No forge key references

**What:** your person file holds the key itself. It cannot name
`github:<user>` or a URL to an SSH key or a GPG `.asc`. To use a key a
forge lists, save its `.keys` line as a `.pub` file and register that.

**Why:** the registry must answer from git alone, offline and
reproducibly. The person file's signature must cover the key itself, not
a pointer whose content can change, or the forge becomes a trust root. A
GPG `.asc` URL adds nothing: `git-vouch` never runs `gpg`, continuity is
checked against pgpkeys at the freeze commit, and a newcomer's GPG key
proves nothing.

**Rejected:** key references and forge-sourced keys in person files.

DESIGN: [Rejected alternatives](../DESIGN.md#rejected-alternatives).

<a id="one-flag-day"></a>
## A flag day for Linus's tree only

**What:** `pgpkeys.git` freezes for everyone. On the flag day only
Linus's tree and the release tags stop accepting OpenPGP signatures and
verify against `git vouch export` files.

- The core set that must register first is everyone
  `git-vouch-migrate pullers` lists from Linus's merges, plus the
  release signers.
- Every other tree keeps verifying both kinds, because git picks the
  verifier from the signature, and switches when its owner chooses. A
  tree switches with `git config gpg.openpgp.program false`.
- At the late cutoff GPG ends for tags and patches alike.

**Why:** a kernel-wide flag day gives every GPG holdout a veto over the
date. Linus's pulls are the one place the kernel applies one policy to
everyone; every other tree verifies on its owner's terms.

The freeze still forces the move: no new GPG identity can enter
anywhere, so the GPG population only shrinks. The core set comes from
git history, so nobody picks names and anyone can rerun it. A tree that
has not switched is no weaker than today.

**Rejected:**

- A kernel-wide flag day with no period accepting both.
- Accepting GPG in Linus's tree after the flag day: the core set is
  small and named by `pullers`, so it can register in the window.
- A manifest of old signatures: no reason given in DESIGN.

DESIGN: [Flag day](../DESIGN.md#flag-day),
[Rejected alternatives](../DESIGN.md#rejected-alternatives).

<a id="freeze-commit"></a>
## The freeze commit

**What:** `pgpkeys.git` gets one last signed commit and goes read-only;
its hash, the flag-day date and the late cutoff are published together.
`git-vouch-migrate` verifies the freeze commit's signature, then reads
pgpkeys only there. Continuity proofs, endorsement drafts, the legacy
patatt keyring and old tag verification all use pgpkeys at that commit.

**Why:** DESIGN gives no reason for reading one commit only; it says
what reading that commit safely takes:

- The tool reads with `--no-replace-objects`, so `refs/replace` in a
  clone cannot change `keys/` or the commit it checks.
- It reads `keys/` as the blobs in the freeze commit's tree, so no git
  attributes can drop or change a file.
- Each person runs the tool on their own machine; drafts are never
  generated centrally.

**Rejected:** DESIGN names no alternative.

DESIGN: [Flag day](../DESIGN.md#flag-day) (Freeze, Porting pgpkeys).

<a id="continuity-proof"></a>
## The continuity proof

**What:** an optional proof that you hold your old pgpkeys key: either a
detached GPG signature `people/<handle>.json.asc` over your person
file's exact bytes, or reuse of that key's authentication subkey as your
SSH key. It only lets your old GPG certifiers get endorsement drafts for
you, and it grants no tier. It holds only if:

- the key was unrevoked at the freeze commit (expired is accepted);
- every email is on an unrevoked user ID of it;
- no other person file claims the same fingerprint.

**Why:** GPG certifications are not ported as records; the draft is a
reminder, and the certifier's new SSH signature is what counts. The
proof is judged against the person-file version it was made for, so
later signed edits do not undo it, while a change only review let
through ends it.

The threat it cannot stop is a stolen, unrevoked GPG key. The
duplicate-claim rule exposes it if the real holder also migrates, and
the late cutoff ends it.

**Rejected:**

- Porting certifications as endorsement records.
- Generating drafts centrally; no reason given in DESIGN.
- `git-vouch` checking the `.asc`: it never runs GPG, which only
  `git-vouch-migrate` does.

DESIGN: [Flag day](../DESIGN.md#flag-day) (Continuity proof,
Endorsements, What continuity cannot catch),
[Tools](../DESIGN.md#tools).

<a id="late-cutoff"></a>
## The six-month late cutoff

**What:** six months after the flag day, extendable by the anchors'
announcement. From then:

- no tree accepts a new GPG-signed tag or patch;
- registry maintainers merge no change that adds or alters
  `migratedFrom` or adds a `people/*.json.asc`, judged by merge date;
- everyone deletes the legacy patatt keyring line;
- `git-vouch-migrate` is retired.

Late registrants register as newcomers.

**Why:** it ends the window in which someone holding a stolen, unrevoked
GPG key can claim that person's identity. No reason given in DESIGN for
six months, or for leaving enforcement to registry maintainers instead
of a tool.

**Rejected:** DESIGN names no alternative.

DESIGN: [Flag day](../DESIGN.md#flag-day) (Late cutoff, What continuity
cannot catch), [Patch signing](../DESIGN.md#patch-signing).

<a id="patch-fallback"></a>
## Patch signing and its GPG fallback

**What:** a patatt fork adds the keyring source `vouch:`, which asks
`git vouch keys` for the signer's current keys: any tier, automation
included, endorsed emails only, with a selector derived from the key.
The frozen pgpkeys keyring comes second, with a warning, for everyone
until the late cutoff. The b4 fork's `b4.attestation-recheck-hours = 0`
makes b4 check every signature again.

**Why:** the registry is the keyring, so nothing is generated, published
or trusted in between.

- patatt cannot say "valid until", so a retired key would verify new
  forgeries; `keys` serves current keys only.
- A selector derived from the key keeps main and backup tokens from
  colliding. It is lowercase hex because patatt lowercases selectors
  and base64 would collide.
- Upstream b4 newer than 0.16 caches verdicts for up to 24 hours, so a
  revoked key can show a pass for up to a day.

Tags get the same fallback outside Linus's tree, and both end at the
late cutoff.

**Rejected:** a generated keyring.

DESIGN: [Patch signing](../DESIGN.md#patch-signing).

<a id="bridge"></a>
## The optional TRQP bridge

**What:** `git-vouch-trqp` is a daemon that answers OpenVTC's
`verify-trust`: `git.commit.sign` is authorized for a current key of a
registered person with an endorsed email, any tier, never automation.
It is a thin shim over `git vouch query`, and it refuses to answer once
24 hours pass without a successful sync. For the kernel we propose the
authority DID `did:web:registry.kernel.org`; kernel.org decides.

**Why:** it is the one service, and nothing in the kernel's own use of
git-vouch depends on it. A job that needs an HTTP listener gets its own
tool, so `git-vouch` stays a CLI. Answers over HTTPS are unsigned, and
anyone can check one against the public registry.
`did:web:kernel.org` would spend the domain-wide name, and `did:webvh`
adds machinery an optional bridge does not need.

**Rejected:** OpenVTC / VTI as the system itself: an always-on agent,
three transports and seven credential types in over 1.5 million lines.

DESIGN: [TRQP bridge](../DESIGN.md#trqp-bridge),
[Constraints](../DESIGN.md#constraints),
[Rejected alternatives](../DESIGN.md#rejected-alternatives).

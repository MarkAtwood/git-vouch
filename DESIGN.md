# git-vouch: Kernel Identity Without GPG

**Status:** revised design, 2026-10-21. Replaces the signing format, git
patch series and multi-project federation in the March 2026 documents
(`kernel-did.md`, `git-did-design.md`, `lf-did-architecture.md`), which
are kept for history. Not implemented.

## Summary

`git-vouch` replaces the kernel's GPG web of trust with three things that
already exist and one small script:

- **git's SSH signing** (`gpg.format=ssh`) signs and verifies tags and
  commits.
- **`ssh-keygen -Y`** signs and verifies everything else: release files
  and the registry's own records.
- **A registry git repository** holds one signed file per person and one
  per endorsement. Changes arrive as reviewed merges; `git fetch`
  distributes them.
- **`git-vouch`**, a single Python file using only the standard library,
  checks the registry's rules and writes the `allowed_signers` and
  revocation files that git reads.

Every person is identified by DIDs, and person files are JSON-LD that
people can extend with more DIDs and any metadata they like.

Every signature check is done by `ssh-keygen`, either directly or through
git. `git-vouch` contains no cryptography. Version 1 runs on today's git; the
aim is to upstream registry support into git later (see Upstream path). An auditor needs to trust Python
3, git and OpenSSH, which every kernel developer already has, plus one
file short enough to read in a sitting.

## Constraints

1. **CLI only.** No service, no web interface, no daemon, and no TUI.
   Every command takes its input from arguments and files and never
   prompts, so it works in scripts, CI and over ssh. Output is plain
   text; non-zero exit means failure.
2. **Nothing git or OpenSSH already does.** Signing, verification,
   expiry, purpose limits, revocation, key storage, distribution and
   history all belong to them. `git-vouch` only does what they cannot:
   check who approved whom and generate their input files.
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
nobody can promote themselves. The approver must sit above the tier they
grant, as in the table.

**Endorsements are evidence, not a count.** There is no minimum number.
The approver reads the endorsements and decides. `git vouch check` verifies
that every endorsement and tier record is validly signed by someone with
the authority to make it; it does not second-guess the approver's
judgement.

**Automation identities** can sign only files (the `file` namespace:
tarballs, checksums), never git tags or commits. They cannot endorse or
approve anyone. Their person file must name the accountable maintainer.

## What git and OpenSSH already do

| Need | Mechanism | git-vouch's part |
|---|---|---|
| Sign tags and commits | `git tag -s`, `git commit -S` with `gpg.format=ssh` | Sets the git config once (`git vouch setup`) |
| Verify | `git verify-tag`, `git verify-commit`, `git log --show-signature` | None |
| Who may sign | `gpg.ssh.allowedSignersFile` | Generates the file |
| Require a tier | One allowed-signers file per minimum tier | `git vouch export --min-tier maintainer` |
| Key expiry and retirement | `valid-after=` / `valid-before=` on each allowed-signers line | Writes them from the registry |
| Compromised keys | `gpg.ssh.revocationFile` | Generates the file |
| Limit a key's purpose | `namespaces=` on each allowed-signers line | Writes `namespaces="git,file"`, or `namespaces="file"` for automation |
| Sign release files | `ssh-keygen -Y sign -n file` / `-Y verify` | None |
| Hardware keys | The SSH agent; FIDO `sk-` keys; `gpg.ssh.defaultKeyCommand` | None |
| Distribution | `git fetch` | `git vouch sync` = fetch, refuse a rewind, re-export |
| Audit trail | Registry history | None |
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
people/<handle>.json.sig              signed by every key in it   (namespace git-vouch-register)
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

**Merging needs one person.** A registry maintainer merges a change once
`git vouch check` passes. Each record is signed by the key that makes it, so
the merger can refuse or delay a change but cannot forge one. The
exception is `anchors.json`, which is trusted because it is in the
registry (see Anchors).

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

One current tier record per person. Changing a tier replaces the record.
If the approver's key is later revoked, the tier records it signed are
void, and those people have no tier until someone re-approves them.

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
      "retired": null
    }
  ],
  "accountable": null,
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
- **`emails`** become the allowed-signers principals, so git's output
  shows a familiar address.
- **`keys`** holds every key the person has used, oldest first. A key
  with `retired` set becomes `valid-before` in the export. Its did:key
  is not stored; `git-vouch` derives it.
- **`accountable`** is used only by automation identities and names the
  responsible maintainer's handle.
- **`alsoKnownAs`** (the W3C DID Core term) lists any other DIDs the
  person uses: did:web, did:webvh, did:plc, did:webs, anything.
- **Any other terms** are the person's own metadata. `git-vouch` ignores
  them.
- **Only the name and keys are endorsed.** Extra DIDs and metadata are
  signed by the person, so nobody else can alter them, but nobody has
  vouched for them. `git-vouch` never resolves an extra DID or checks that
  it links back. A DID that also lists the person's did:key in its own
  `alsoKnownAs` is a stronger claim, but checking that is left to tools
  that resolve DIDs.
- **The `.sig` file** holds one signature per current key. Adding a key
  therefore needs a signature from an existing key, which is how
  rotation works. Losing every key means registering again and being
  endorsed again.

### Endorsement

```json
{
  "@context": ["https://w3id.org/git-vouch/v1"],
  "endorser": "gregkh",
  "endorserKey": "did:key:z6Mk...",
  "subject": "alice",
  "subjectKey": "did:key:z6Mk...",
  "subjectName": "Alice Example",
  "note": "Met at LPC 2026, checked passport; reviewed her patches since 2019.",
  "date": "2026-11-03T00:00:00Z"
}
```

- **`note`** is optional free text: whatever the endorser wants to say
  about how they know the person. `git-vouch` does not interpret it.
- **The endorsement binds the subject's name and key**, so a later
  rename or a key the endorser never saw is not endorsed.
- **When the subject rotates keys**, their endorsements carry over to
  the new key, because the rotation itself was signed by the old key.
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
any anchor. Removing someone without suspecting their key is different:
an approver at or above their tier deletes their tier record, and the
export gives their keys `valid-before` set to the removal date, so their
earlier signatures stay valid.

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
| `git vouch setup [--registry URL]` | Records the registry URL (default: the kernel's on git.kernel.org); sets `gpg.format=ssh`, `gpg.ssh.allowedSignersFile`, `gpg.ssh.revocationFile`; runs a first `sync` |
| `git vouch sync` | Fetches the registry without allowing a rewind, runs `check`, re-exports |
| `git vouch status` | Shows registry commit, fetch age (warns past 7 days), and your own tier |
| `git vouch register` | Writes your person file from an SSH public key and signs it through the agent |
| `git vouch add-key` / `retire-key` | Rotation: edits your person file and re-signs it |
| `git vouch endorse <handle>` | Writes and signs an endorsement |
| `git vouch approve <handle> <tier>` | Writes and signs a tier record |
| `git vouch revoke` | Writes and signs a revocation |
| `git vouch check` | Validates every signature and computes every tier; non-zero exit on any problem. Run before every registry merge |
| `git vouch export [--min-tier T]` | Writes the allowed-signers file and the revocation file |
| `git vouch did <ssh-pubkey>` | Prints the did:key for an SSH public key, and the reverse |

`register`, `endorse`, `approve` and `revoke` write files for a registry merge
request; they never push.

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

RSA and DSA are not accepted. The ed25519 and P-256 forms are tested
against the W3C CCG did:key test vectors, an oracle independent of this
code.

## Keys

`git-vouch` never touches a private key. Signing goes through `ssh-keygen
-Y sign`, which uses the SSH agent or a key file, so any agent-backed
store works: YubiKey (FIDO or PIV), Secure Enclave, 1Password, TPM, a
cloud KMS, or gpg-agent with `enable-ssh-support` for people keeping an
existing GPG key.

**Hardware is recommended, not required.** Maintainers and anchors
should keep their keys on a hardware token, but any supported key type is
accepted for every tier. The tool cannot prove what holds a key, so this
is advice for endorsers and approvers to ask about, not a rule.

## Moving from GPG

- **Keep using an existing key:** gpg-agent's SSH support exposes a GPG
  authentication subkey to `ssh-keygen`; `gpg --export-ssh-key` prints
  its public half for `git vouch register`.
- **Bootstrap endorsements:** a new person file may carry an optional
  `person.json.asc`, a detached signature by the person's key in the
  kernel's existing `pgpkeys.git`. It is a cue for human endorsers and
  never counts as an endorsement. `git-vouch` does not run GPG.
- **During the transition**, tags can carry both signatures. git accepts
  one signature per tag, so the GPG-signed and SSH-signed tags have
  different names (for example `v6.20` and `v6.20-ssh`) until the GPG
  side is dropped.

## Implementation

- **One file**, `git-vouch`, executable, about 1,000–1,500 lines. Modules
  used: `argparse`, `json`, `subprocess`, `pathlib`, `datetime`,
  `hashlib`, `base64`, `tempfile`.
- **External programs**, called with argument lists and never through a
  shell: `git`, `ssh-keygen`.
- **Input is untrusted:** registry files come from other people. Handles
  and file names match `^[a-z0-9][a-z0-9_-]{0,38}$`; each file has a
  size cap (64 KiB); git-vouch's own terms are checked strictly for type and
  format, and all other terms are ignored; no registry value is ever put
  on a command line except as a single argument after `--`.
- **Tests** use pytest only as a development dependency. Signatures are
  made and checked by real `ssh-keygen` on throwaway keys. did:key
  encoding is checked against the CCG test vectors, never against
  `git-vouch`'s own output.

## Dropped from the March design

| Dropped | Why |
|---|---|
| Custom signature payload on git objects | git's SSH signatures already bind the object. The payload's "nonce" copied the object id, and it claimed SHA-256 object ids, which kernel git does not use. |
| `refs/signatures/` and a native DID signing method in git, as a prerequisite | Version 1 must work on today's git. Upstreaming stays the goal; see Upstream path. |
| JCS canonicalisation | Signatures cover the file's exact bytes, which allows arbitrary JSON-LD metadata without canonicalising it. |
| minisign output | `ssh-keygen -Y sign -n file` signs files; people who verify with git-vouch's keys already have `ssh-keygen`. |
| `tier` field inside the person's own file | The person signs their own file, so they could promote themselves. The tier now lives in a separate record signed by the approver. |
| Minimum endorsement counts per tier | The approver decides; endorsements are evidence. |
| Delegated signing scopes | Not needed for v1. Tier files give the kernel's real policy: Linus pulls from maintainers, releases come from anchors. |
| LF-wide registry federation and cross-project lookups | Kernel first. |
| `cryptography` and other dependencies | `ssh-keygen` does all crypto. |

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
3. **Native DID signing** (`gpg.format=did`), as in the March
   `git-did-design.md`, if the community wants signatures that name a
   DID rather than an SSH key.

Each step is proposed only after the previous one has users. Until then
`git-vouch` is the reference implementation, and its Python is the
specification for anyone reviewing an upstream patch.

## Rejected alternatives

- **An SSH certificate authority** (`cert-authority` in allowed signers).
  It is native to OpenSSH, but it puts the whole tree behind one CA key,
  makes the CA holder a bottleneck for every contributor, and hides the
  endorsement record that the registry exists to show.
- **OpenVTC / VTI.** Solves the same problem with an always-on agent,
  three transports and seven credential types, in about 900k lines. See
  `~/PROJECT/ToIP/docs/openvtc-explainer.md`.
- **Sigstore / gitsign.** Ties identity to an OIDC provider and depends
  on online services; the kernel wants keys people hold.

## Open questions

1. **Registry maintainers:** who may merge into the kernel registry on
   git.kernel.org. Given the accepted anchor risk, this choice matters as
   much as choosing the anchors. It is a kernel-team decision, not a
   design one.

Decided 2026-10-22: the registry URL is configurable, and the kernel's
registry is on git.kernel.org; hardware keys recommended, not required; automation
is its own tier, files only; warn when the registry copy is over 7 days
old; one registry maintainer merges after `git vouch check`; tiers are set
by a signed approver record; endorsements carry an optional free-text
note and no minimum count; anchors are whoever the registry lists;
delegated signing scopes are out of v1; Python floor is 3.9.

# lf-did: Kernel Identity Without GPG

**Status:** revised design, 2026-10-21. Replaces the signing format, git
patch series and multi-project federation in the March 2026 documents
(`kernel-did.md`, `git-did-design.md`, `lf-did-architecture.md`), which
are kept for history. Not implemented.

## Summary

`lf-did` replaces the kernel's GPG web of trust with three things that
already exist and one small script:

- **git's SSH signing** (`gpg.format=ssh`) signs and verifies tags and
  commits.
- **`ssh-keygen -Y`** signs and verifies everything else: release files
  and the registry's own records.
- **A registry git repository** holds one signed file per person and one
  per endorsement. Changes arrive as reviewed merges; `git fetch`
  distributes them.
- **`lf-did`**, a single Python file using only the standard library,
  checks the registry's rules and writes the `allowed_signers` and
  revocation files that git reads.

Every signature check is done by `ssh-keygen`, either directly or through
git. `lf-did` contains no cryptography. An auditor needs to trust Python
3, git and OpenSSH, which every kernel developer already has, plus one
file short enough to read in a sitting.

## Constraints

1. **CLI only.** No service, no web interface, no daemon.
2. **Nothing git or OpenSSH already does.** Signing, verification,
   expiry, purpose limits, revocation, key storage, distribution and
   history all belong to them. `lf-did` only does what they cannot:
   apply the endorsement rules and generate their input files.
3. **Python standard library only.** Kernel builds already need Python 3.
   The supported floor is the kernel's documented minimum
   (`Documentation/process/changes.rst`). No third-party packages, not
   even `cryptography`.
4. **Public by design.** The registry, including who endorsed whom, is
   public. There are no privacy features.
5. **The kernel first.** One registry, one project. Other projects can
   copy the registry later.

## How trust maps

How trust in the kernel actually works is a tree: Linus trusts a few
people, they trust subsystem maintainers, and maintainers vouch for
contributors. The registry records that tree directly.

| Tier | Who | Reached by |
|---|---|---|
| `anchor` | Linus and a few designated people | Pinned out of band (see Anchors) |
| `maintainer` | Subsystem maintainers | 2 maintainer-or-above endorsements, at least 1 from an anchor |
| `contributor` | Contributors who sign | 1 maintainer-or-above endorsement |

A person's tier is **computed, never stored**. A person file has no tier
field; `lf-did check` derives each tier from the endorsements that are
currently valid. If an endorser is revoked and someone falls below a
rule, their tier drops on the next check.

Automation identities, such as CI builders, are not a tier in this
version. A builder that signs artifacts is registered as a contributor
whose person file names the accountable maintainer. See Open questions.

## What git and OpenSSH already do

| Need | Mechanism | lf-did's part |
|---|---|---|
| Sign tags and commits | `git tag -s`, `git commit -S` with `gpg.format=ssh` | Sets the git config once (`lf-did setup`) |
| Verify | `git verify-tag`, `git verify-commit`, `git log --show-signature` | None |
| Who may sign | `gpg.ssh.allowedSignersFile` | Generates the file |
| Require a tier | One allowed-signers file per minimum tier | `lf-did export --min-tier maintainer` |
| Key expiry and retirement | `valid-after=` / `valid-before=` on each allowed-signers line | Writes them from the registry |
| Compromised keys | `gpg.ssh.revocationFile` | Generates the file |
| Limit a key's purpose | `namespaces=` on each allowed-signers line | Writes `namespaces="git,file"` |
| Sign release files | `ssh-keygen -Y sign -n file` / `-Y verify` | None |
| Hardware keys | The SSH agent; FIDO `sk-` keys; `gpg.ssh.defaultKeyCommand` | None |
| Distribution | `git fetch` | `lf-did sync` = fetch, refuse a rewind, re-export |
| Audit trail | Registry history | None |
| Review of changes | Merges to the registry, by its maintainers | `lf-did check` before merging |

**Requiring a tier needs no wrapper.** Linus points `allowedSignersFile`
at the file exported with `--min-tier maintainer`, and plain
`git verify-tag` then rejects anyone below that tier. Release tooling
uses `--min-tier anchor`.

### Retiring a key versus revoking it

git checks a signature against the key's validity *at the time the
signature says it was made*. The two git mechanisms therefore mean
different things, and `lf-did` uses each for one job:

- **Retire** (rotation, stepping down, removal): set `valid-before` to
  the retirement time. Earlier signatures stay valid.
- **Revoke** (compromise or suspected compromise): list the key in the
  revocation file. Every signature by it, past or future, is invalid.

The signing time comes from the signer, so a retired key's holder can
backdate a signature. When there is any doubt about who holds a key,
revoke it rather than retiring it.

## The registry

A git repository, for example `kernel.org/pub/scm/kernel/did-registry.git`.

```
README
people/<handle>.json                  identity record
people/<handle>.json.sig              signed by every key in it   (namespace lf-did-register)
endorsements/<subject>/<endorser>-<n>.json
endorsements/<subject>/<endorser>-<n>.json.sig                    (namespace lf-did-endorse)
revocations/<handle>-<n>.json
revocations/<handle>-<n>.json.sig                                 (namespace lf-did-revoke)
```

Every record is JSON, canonicalised as RFC 8785 (JCS) before signing, and
signed with `ssh-keygen -Y sign` under a namespace specific to its kind.
Using a separate namespace per kind stops a signature made for one kind
of record from being accepted as another. `lf-did` writes JCS with the
standard library; the records use only strings, arrays and objects, so
it needs no number canonicalisation.

**Merging is not trusted.** Each claim is signed by the key that makes
it, so a registry maintainer can refuse or delay a change but cannot
forge one. The remaining host attack is to withhold updates, such as a
revocation. Two git behaviours address that:

- `lf-did sync` fetches with a refspec that has no `+`, so git refuses a
  history rewrite.
- `lf-did status` reports how long ago the registry was last fetched.

### Person file

```json
{
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
  "accountable": null
}
```

- **`handle`** is the lasting identity. It matches the file name and
  never changes.
- **`emails`** become the allowed-signers principals, so git's output
  shows a familiar address.
- **`keys`** holds every key the person has used, oldest first. A key
  with `retired` set becomes `valid-before` in the export. Its did:key
  is not stored; `lf-did` derives it.
- **`accountable`** is used only by automation identities and names the
  responsible maintainer's handle.
- **The `.sig` file** holds one signature per current key. Adding a key
  therefore needs a signature from an existing key, which is how
  rotation works. Losing every key means registering again and being
  endorsed again.

### Endorsement

```json
{
  "endorser": "gregkh",
  "endorserKey": "did:key:z6Mk...",
  "subject": "alice",
  "subjectKey": "did:key:z6Mk...",
  "subjectName": "Alice Example",
  "tier": "contributor",
  "basis": "in-person",
  "date": "2026-11-03T00:00:00Z"
}
```

- **`basis`** is one of `in-person`, `video-with-id`, or
  `long-collaboration`. Each endorsement states what was checked, which
  the GPG web of trust never did. The README defines each value in one
  sentence.
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
{ "subject": "alice", "key": "did:key:z6Mk...", "reason": "compromise", "date": "..." }
```

Signed by the key itself, by another of the subject's current keys, or by
any anchor. A maintainer who wants a contributor gone removes their
endorsement in a reviewed merge; that is removal, not revocation, and
the person's keys get `valid-before` if they lose all standing.

## Anchors

Anchors cannot be checked against the registry, because they are what
everything else is checked against. Each user pins them locally, the way
people check Linus's GPG fingerprint today:

- `lf-did setup` prints the anchors' did:keys and their SSH fingerprints
  from the registry, asks the user to compare them with an out-of-band
  source (a kernel.org page, a signed mail, a talk slide), and writes
  them to `~/.config/lf-did/anchors`.
- `lf-did check` refuses a registry whose anchors are not all pinned.
- Adding or rotating an anchor is announced out of band, and each user
  updates their pin with `lf-did setup --repin`.

## Commands

| Command | Does |
|---|---|
| `lf-did setup` | Pins anchors; sets `gpg.format=ssh`, `gpg.ssh.allowedSignersFile`, `gpg.ssh.revocationFile`; runs a first `sync` |
| `lf-did sync` | Fetches the registry without allowing a rewind, runs `check`, re-exports |
| `lf-did status` | Shows registry commit, fetch age, and your own tier |
| `lf-did register` | Writes your person file from an SSH public key and signs it through the agent |
| `lf-did add-key` / `retire-key` | Rotation: edits your person file and re-signs it |
| `lf-did endorse <handle>` | Writes and signs an endorsement |
| `lf-did revoke` | Writes and signs a revocation |
| `lf-did check` | Validates every signature and computes every tier; non-zero exit on any problem. Run before every registry merge |
| `lf-did export [--min-tier T]` | Writes the allowed-signers file and the revocation file |
| `lf-did did <ssh-pubkey>` | Prints the did:key for an SSH public key, and the reverse |

`register`, `endorse` and `revoke` write files for a registry merge
request; they never push.

## did:key

A did:key here is the person's SSH public key in another encoding:
multibase base58btc of the multicodec prefix plus the raw key. The
registry uses did:keys in endorsements and revocations, so records are
meaningful outside git and fit the ToIP and W3C tooling. Inside the
kernel workflow they do no work that the SSH key does not already do.

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

`lf-did` never touches a private key. Signing goes through `ssh-keygen
-Y sign`, which uses the SSH agent or a key file, so any agent-backed
store works: YubiKey (FIDO or PIV), Secure Enclave, 1Password, TPM, a
cloud KMS, or gpg-agent with `enable-ssh-support` for people keeping an
existing GPG key.

**Proposed rule:** maintainer and anchor keys must be `sk-` types. That
is stronger than "keep your key on hardware" but not proof of it:
`SSH_SK_PROVIDER` can load a software authenticator. Proof needs the FIDO
attestation from `ssh-keygen -O write-attestation=<path>` at key generation, kept with the person
file and checked by the endorser. See Open questions.

## Moving from GPG

- **Keep using an existing key:** gpg-agent's SSH support exposes a GPG
  authentication subkey to `ssh-keygen`; `gpg --export-ssh-key` prints
  its public half for `lf-did register`.
- **Bootstrap endorsements:** a new person file may carry an optional
  `person.json.asc`, a detached signature by the person's key in the
  kernel's existing `pgpkeys.git`. It is a cue for human endorsers and
  never counts as an endorsement. `lf-did` does not run GPG.
- **During the transition**, tags can carry both signatures. git accepts
  one signature per tag, so the GPG-signed and SSH-signed tags have
  different names (for example `v6.20` and `v6.20-ssh`) until the GPG
  side is dropped.

## Implementation

- **One file**, `lf-did`, executable, about 1,000–1,500 lines. Modules
  used: `argparse`, `json`, `subprocess`, `pathlib`, `datetime`,
  `hashlib`, `base64`, `tempfile`.
- **External programs**, called with argument lists and never through a
  shell: `git`, `ssh-keygen`.
- **Input is untrusted:** registry files come from other people. Handles
  and file names match `^[a-z0-9][a-z0-9_-]{0,38}$`; JSON has a size
  cap; unknown fields are an error; no registry value is ever put on a
  command line except as a single argument after `--`.
- **Tests** use pytest only as a development dependency. Signatures are
  made and checked by real `ssh-keygen` on throwaway keys. did:key
  encoding is checked against the CCG test vectors, never against
  `lf-did`'s own output.

## Dropped from the March design

| Dropped | Why |
|---|---|
| Custom signature payload on git objects | git's SSH signatures already bind the object. The payload's "nonce" copied the object id, and it claimed SHA-256 object ids, which kernel git does not use. |
| `refs/signatures/` and a native DID signing method in git | A git patch series is a multi-year adoption barrier for something git already does. |
| JSON-LD `@context` | Signing uses JCS, so contexts did nothing. |
| minisign output | `ssh-keygen -Y sign -n file` signs files; people who verify with lf-did's keys already have `ssh-keygen`. |
| Stored `tier` field set by the approver | Tiers are computed from endorsements. |
| Delegated signing scopes | Not needed for v1. Tier files give the kernel's real policy: Linus pulls from maintainers, releases come from anchors. |
| LF-wide registry federation and cross-project lookups | Kernel first. |
| `cryptography` and other dependencies | `ssh-keygen` does all crypto. |

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

1. **Require `sk-` keys for maintainers and anchors?** Checkable and
   strong, but it excludes PIV and OpenPGP-applet users until they move
   to FIDO.
2. **Automation identities:** keep them as contributors with an
   `accountable` maintainer, or give them their own tier limited to the
   `file` namespace.
3. **Fetch age limit:** whether `lf-did sync` should fail, not just warn,
   when the registry is more than N days stale; and what N is.
4. **Registry hosting and merge rights:** who maintains the registry
   repo, and whether a merge needs a second registry maintainer.
5. **Python floor:** confirm the kernel's documented minimum and pin it
   in the script.

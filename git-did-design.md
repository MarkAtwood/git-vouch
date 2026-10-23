# Native DID Signing Support for Git

> **Superseded.** Kept for history; [DESIGN.md](DESIGN.md) is the current design. Statements here about key types (P-384, importing GPG secret keys) and status do not describe git-vouch.
## Design Proposal

**Author:** Linux Foundation / Linux Kernel Project  
**Date:** 2025  
**Target:** git-devel discussion, git maintainers  
**Related work:** `gpg.format = ssh` (git 2.34), `refs/notes/` namespace precedent  
**Status:** Proposal, seeking feedback

---

## Abstract

This document proposes two changes to git, submitted as separate but related patch
series:

**Series 1: Parallel signature ref storage.** Move object signatures out of embedded
object headers and into a dedicated `refs/signatures/` namespace. This is an
improvement to the object model that benefits all signing methods (openpgp, ssh, and
any future methods), enables multiple signatures per object, and decouples signature
lifecycle from object identity.

**Series 2: Native DID signing method.** Add `gpg.format = did` as a first-class
signing method alongside the existing `openpgp` and `ssh` methods, using the parallel
ref storage introduced in Series 1. DID signing uses W3C Decentralized Identifiers
(`did:key` method) with a git-native trust registry, providing offline verification,
structured trust tiers, and a chain-of-trust model that accurately reflects how open
source project governance actually works.

Series 1 stands on its own merits and is useful regardless of whether Series 2 is
adopted. Series 2 depends on Series 1.

The motivation for both is a concrete deployment: the Linux Foundation is replacing
GPG-based tag signing across its hosted projects, beginning with the Linux kernel, using
a DID-based identity system. We want that system to be a first-class git feature rather
than a permanent shim.

---

## Background and motivation

### The state of git tag signing

Git has supported signed tags since 2005. The signing model has two problems that have
never been resolved: the signature is embedded in the object, and the trust model is
entirely delegated to an external tool with no structured interface.

**Embedded signatures** mean the tag object's SHA changes depending on whether it is
signed, the signature cannot be added or updated without creating a new object, multiple
signers cannot countersign the same tag object without coordination, and stripping a
signature for inspection requires parsing the object format. The `gpgsig` header is a
workaround that the git object model was not designed for.

**Unstructured trust delegation** means git knows only pass/fail from GPG. It has no
concept of who the signer is, what authority they hold, whether their key is current, or
whether the signature satisfies any project-specific policy. The output of `git tag -v`
is raw GPG text that humans read but tooling cannot parse reliably. There is no way to
express "this repo requires tags signed by a maintainer-tier key" without external
scripting.

### Why SSH signing did not solve this

`gpg.format = ssh` added in git 2.34 solved the GPG-specific UX problem (GPG is
painful to operate) but kept the same embedded header approach and the same unstructured
trust delegation model. SSH `allowed_signers` files are flat and have no hierarchy. The
trust model is still essentially "we have a list of trusted keys" with no concept of
delegation, expiry, tier, or chain of custody.

SSH signing was the right incremental step. This proposal is the next one.

### DIDs seem complicated. Git fixes that.

The DID specification has a reputation for complexity, and in most deployments that
reputation is earned. The full DID stack -- resolution infrastructure, verifiable data
registries, distributed ledgers or DHTs for document storage, protocol negotiation for
method-specific resolution -- exists to solve a single underlying problem: there is no
universal substrate for storing and distributing identity documents, so each deployment
builds one.

The git community already operates the best available substrate for this purpose. Git is
content-addressed, cryptographically integrity-protected, distributed, and spoken by
every developer on the planet. It stores the thing we care most about -- code -- with
full auditable history. Identity documents stored in git get all of that for free:
no blockchain, no DHT, no consensus protocol, no resolution infrastructure, no
availability dependency beyond the git hosting already in operation. Revocation is a
merged PR. Key rotation is a commit. The audit log is the reflog. Verification is
offline against a local clone.

What the DID specification contributes is the identifier format (`did:key`) and the
document schema (W3C DID documents in JSON-LD). These are well-specified,
standards-track, and genuinely useful. The rest of the DID complexity stack simply does
not apply when git is the substrate. The system described in this proposal is, at its
core, a straightforward application of tools developers already understand: public key
cryptography, JSON documents, and git.

The system is entirely self-contained. No operation in the signing or verification
flow makes a network call or depends on any running service beyond git hosting. There
is no DID resolver in the critical path -- not an optional one that happens to be
skipped, but genuinely none. `did:key` resolution is local computation: decode the
multibase string, extract the key bytes. Revocation, endorsement, and trust chain data
are in the local registry clone. An air-gapped build system verifies kernel release
signatures identically to an internet-connected developer workstation.

This is a deliberate design constraint, not an implementation shortcut. DID resolution
infrastructure exists. The W3C DID resolution specification is real. Anyone who wants
to dereference a `did:key` or a `did:plc` against external infrastructure to
cross-check identity claims is free to do so -- nothing in this design prevents it.
But it is optional supplementary verification, never a dependency. If the resolution
infrastructure is down, slow, or censored, signing and verification are unaffected.
The security properties of the system do not degrade when the network is unavailable.

The git-native implementation is also what makes this proposal appropriate for git
itself to support natively. The signing method is not a foreign system bolted on from
outside. It is git objects, git refs, git transport, and a structured identity document
format. The complexity that makes other DID systems hard to integrate with developer
tooling is absent here.

A related point: every artifact in this system is a text file. A signer's identity is
a JSON file. Their endorsements are JSON files. Revocations, delegations, the trust
policy, the registry index -- all text files in a git repo, readable with any editor,
diffable with any diff tool, reviewable in any code review interface. The trust graph
of the entire Linux kernel project is auditable by any developer with a terminal. There
is no app to install for auditing, no GUI to navigate, no opaque binary format to
reverse-engineer. For a community that has consistently preferred `git log` over
enterprise dashboards, this is the right format. It is also the right format for git to
support natively: the signing infrastructure is already expressed in the vocabulary git
uses for everything else.

The system is also entirely self-contained. No DID resolution endpoint is contacted at
any point during any git operation -- not during signing, not during verification, not
during fetch, not during push. The `did:key` method encodes the public key directly in
the identifier; resolution is local arithmetic requiring no network. All identity
documents, endorsements, and revocation records are in the local registry clone.
`git tag -v` with DID signing works offline, in air-gapped build infrastructure, when
every server the project operates is unreachable. This is not an implementation detail;
it is a stated requirement. A verification step that can fail due to network conditions
or third-party availability is a verification step that build engineers will route
around. This one cannot fail that way.

The `alsoKnownAs` fields in identity documents may reference external DID methods
(`did:plc`, `did:web`, EU wallet DIDs). These are informational. Nothing in the git
operation flow resolves them. Tooling that wants to dereference them for out-of-band
identity correlation can do so independently; the security model does not require it
and git never invokes it.

### The Linux Foundation deployment

The Linux Foundation is deploying a DID-based identity and signing system across its
hosted projects under the name LF DID. The Linux kernel is the pilot. The system uses
W3C `did:key` identifiers, git-committed identity registries, structured trust tiers,
and a federated root of trust anchored at the Linux Foundation.

This system works today using `gpg.program` shim and `lf-did` as a drop-in. But
shimming is the wrong long-term answer. The design described here is what we would like
git to natively support.

---

## Series 1: Parallel signature ref storage

### Problem statement

The current signature storage model embeds signatures in object headers:

```
object abc123def...
type commit
tag v6.12
tagger Linus Torvalds <torvalds@linux-foundation.org> 1705756320 +0000

Linux 6.12
-----BEGIN PGP SIGNATURE-----
[...]
-----END PGP SIGNATURE-----
```

This means:

1. The tag object SHA includes the signature bytes. A tag signed by Linus has a
   different SHA than the same tag unsigned. This is counterintuitive and complicates
   tooling.

2. You cannot add a second signature to an existing signed tag without creating a new
   object with a new SHA, which invalidates the first signature if it covered the object
   SHA.

3. Removing the signature for inspection requires parsing the raw object format.

4. There is no standard mechanism for distributing signatures separately from the
   objects they cover, which matters for release tarballs and bundles.

5. Signature metadata (who signed, when, with what key, under what authority) is
   embedded in the signature blob and not queryable without invoking the signing tool.

### Proposed: `refs/signatures/` namespace

Signatures are stored as separate ref objects in a dedicated namespace:

```
refs/signatures/tags/v6.12
refs/signatures/tags/v6.12/gregkh      # countersignature, identified by signer fragment
refs/signatures/commits/abc123def...   # commit signatures (future use)
```

Each ref points to a git blob object containing the signature document. The signature
document is a structured JSON object (format defined in Series 2 for DID signatures;
existing methods would define their own formats or continue using embedded headers
during a transition period).

The signed object is identified by its SHA within the signature document, not by the
ref. This means:

- The tag object SHA is independent of whether it is signed
- Multiple signatures accumulate as additional refs without mutating any object
- Signatures can be fetched, pushed, and inspected independently
- The signature document can carry structured metadata queryable without invoking an
  external tool

### Object model

A signature ref points to a blob. For DID signatures (format defined in Series 2):

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://lf.org/ns/did/v1"
  ],
  "type": "lf:GitSignature",
  "lf:objectType": "tag",
  "lf:objectSha": "abc123def...full SHA-256 of the git object",
  "lf:ref": "refs/tags/v6.12",
  "lf:signer": "did:key:z6Mk...",
  "lf:timestamp": "2025-01-20T14:32:00Z",
  "lf:nonce": "first 32 bytes of objectSha hex-encoded",
  "lf:signature": "base64url-encoded-signature-over-canonicalized-payload"
}
```

For backwards compatibility, openpgp and ssh signatures can continue using embedded
headers. The parallel ref storage is additive: new signing methods use it by default,
existing methods gain it as an option.

### Transport

`refs/signatures/` follows the same transport rules as `refs/notes/`:

**Push:** `git push` with `push.autoSignatureRefs = true` (default when
`gpg.format = did`) automatically includes `refs/signatures/tags/*` when pushing
`refs/tags/*`. Explicit: `git push origin refs/signatures/*:refs/signatures/*`.

**Fetch:** `fetch.autoSignatureRefs = true` fetches `refs/signatures/` alongside tags.
`fetch.verifySignatures = true` verifies fetched signed tags before updating local refs
and fails the fetch if verification fails.

**Clone:** `clone.fetchSignatureRefs = true` fetches `refs/signatures/` during initial
clone.

These are opt-in in the general case and opt-out when `gpg.format = did` is set,
reflecting the expectation that DID deployments treat signature verification as a hard
requirement rather than an optional check.

### Configuration

```ini
[push]
    autoSignatureRefs = true    # push refs/signatures/* with refs/tags/*

[fetch]
    autoSignatureRefs = true    # fetch refs/signatures/* with refs/tags/*
    verifySignatures = true     # verify on receipt, fail fetch if invalid

[signature]
    required = true             # reject unsigned tags in this repo
    minimumTier = maintainer    # minimum tier for valid signatures (DID only)
    project = kernel            # project context for tier verification (DID only)
```

### Compatibility

Repositories that do not use `refs/signatures/` are unaffected. The namespace is
ignored by git versions that do not understand it, the same way `refs/notes/` is
ignored by old clients. Existing signed tags with embedded signatures continue to
verify normally. The two storage models coexist indefinitely.

---

## Series 2: Native DID signing method

### What is a DID

A W3C Decentralized Identifier (DID) is a URI that identifies a subject and resolves
to a DID document containing cryptographic material. The `did:key` method, which this
proposal uses exclusively for security-relevant operations, encodes the public key
directly in the identifier:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

The `z6Mk` prefix is a multicodec identifier for ed25519. The remainder is the
multibase-encoded public key. Resolution is local computation with no network access.
The DID is the key.

This is different from PGP key IDs (which are hashes pointing to keyserver records) and
from SSH key fingerprints (which have no associated identity document). A `did:key` is
self-describing, self-contained, and verifiable offline.

### Configuration

```ini
[gpg]
    format = did

[gpg "did"]
    program = lf-did
    registryPath = /path/to/local/did-registry-clone
    project = kernel            # optional, auto-detected from lf-did.json if present
```

`gpg.did.program` defaults to `lf-did` if installed. `gpg.did.registryPath` specifies
a local clone of the project DID registry. If absent, `lf-did` looks for a registry
clone in a standard location or uses a registry embedded in the tool for the configured
project.

### Signing interface

When `gpg.format = did`, git calls the DID program as:

```
lf-did sign-object --output <sigfile> <payload-file>
```

Where `<payload-file>` contains the raw git object text (same payload currently handed
to GPG). The DID program writes the signature document (JSON, as specified in Series 1)
to `<sigfile>`. Git stores this as a blob under `refs/signatures/`.

The DID program is responsible for:
- Locating the user's private key (filesystem, USB, or hardware token via SSH agent)
- Constructing the signature payload (object SHA, ref, signer DID, timestamp, nonce)
- Signing the canonicalized payload (RFC 8785 / JCS)
- Writing the signature document

### Verification interface

```
lf-did verify-object --signature <sigfile> --payload <payload-file>
```

Returns exit 0 on success, non-zero on failure. On stdout, a structured verification
result:

```
SIGNER:    did:key:z6Mk...
NAME:      Linus Torvalds <torvalds@linux-foundation.org>
TIER:      anchor
PROJECT:   kernel
SIGNED:    2025-01-20T14:32:00Z
EXPIRES:   2026-01-01 (valid)
REVOKED:   no
CHAIN:     did:key:z6Mk... → LF root
RESULT:    GOOD
```

Git parses this structured output for display in `git tag -v` and `git log
--show-signature`, rather than passing raw tool output through to the user as it does
with GPG.

The verification check sequence:

1. Parse signature document, extract signer DID and signature bytes
2. Decode public key from `did:key` (local computation, no network)
3. Verify cryptographic signature over canonicalized payload
4. Check nonce matches first 32 bytes of object SHA (replay prevention)
5. Look up signer in local registry clone
6. Verify identity document self-signature
7. Walk endorsement chain to project anchor
8. Check project anchor chains to LF root (if root registry clone available)
9. Check revocation records
10. Check expiry
11. Check tier satisfies repo signature policy (if configured)

Steps 1-4 are pure cryptography, entirely local. Steps 5-11 are registry lookups,
entirely local against the registry clone. No network calls at any step.

### `git tag -v` output

Current output for a GPG-signed tag:

```
object abc123...
type commit
tag v6.12
tagger Linus Torvalds <torvalds@linux-foundation.org>

Linux 6.12

gpg: Signature made Mon 20 Jan 2025 14:32:00 UTC
gpg:                using RSA key ABCD1234...
gpg: Good signature from "Linus Torvalds <torvalds@linux-foundation.org>" [ultimate]
```

Proposed output for a DID-signed tag:

```
object abc123...
type commit
tag v6.12
tagger Linus Torvalds <torvalds@linux-foundation.org>

Linux 6.12

Signature:  GOOD
Signer:     Linus Torvalds <torvalds@linux-foundation.org>
DID:        did:key:z6Mk...
Tier:       anchor (kernel)
Signed:     2025-01-20T14:32:00Z
Expires:    2026-01-01 (valid)
Chain:      did:key:z6Mk... → LF root anchor
```

For multiple signatures (countersignatures):

```
Signatures: 2 (all GOOD)

[1] Linus Torvalds <torvalds@linux-foundation.org>
    DID:    did:key:z6Mk...
    Tier:   anchor (kernel)
    Signed: 2025-01-20T14:32:00Z

[2] Greg Kroah-Hartman <gregkh@linuxfoundation.org>
    DID:    did:key:z6Mk...
    Tier:   maintainer (kernel)
    Signed: 2025-01-20T15:10:00Z
    Via:    delegation from did:key:z6Mk...(Linus)
```

### `git log --show-signature` output

Same structured format, abbreviated for log context:

```
commit abc123...
Author: Linus Torvalds <torvalds@linux-foundation.org>
Date:   Mon Jan 20 14:32:00 2025 +0000

    Linux 6.12

    Signed: GOOD (anchor/kernel) did:key:z6Mk...
```

### Countersignature support

Multiple parties can sign the same tag by creating additional signature refs:

```bash
# Linus signs
lf-did tag v6.12 -m "Linux 6.12"
# creates refs/signatures/tags/v6.12

# Greg countersigns (adds a second signature ref)
lf-did countersign v6.12
# creates refs/signatures/tags/v6.12/gregkh-fragment
```

`git tag -v v6.12` shows all signatures. `git push` with `push.autoSignatureRefs = true`
pushes all of them. This requires no changes to the tag object itself.

### Signature policy enforcement

A repo can declare a signature policy that git enforces:

```ini
[signature]
    required = true
    minimumTier = maintainer
    project = kernel
    registryPath = /srv/did-registry
```

When `signature.required = true`:
- `git tag` without signing fails with an error
- `git fetch --verify-signatures` (or with `fetch.verifySignatures = true`) rejects
  unsigned or invalid tags
- `git merge` of a signed tag verifies before merging

When `signature.minimumTier = maintainer`:
- Signatures from tiers below `maintainer` in the project tier hierarchy are rejected
- Verification output indicates the tier check result

This lets a distro's build infrastructure express "we will not process any kernel tag
that does not carry a valid maintainer-tier-or-above DID signature" as a git-native
policy rather than a wrapper script.

### Key types

Accepted `did:key` key types:

| Multicodec prefix | Key type | Multibase prefix |
|-------------------|----------|-----------------|
| 0xed              | ed25519  | `z6Mk`          |
| 0x1200            | P-256    | `zDn`           |
| 0x1201            | P-384    | `z82`           |

ed25519 is the recommended default. P-256 and P-384 are accepted for compatibility with
hardware security modules and EU digital identity wallets that do not generate ed25519
keys. secp256k1 is not accepted.

Key material is accessed via the SSH agent protocol, which all hardware tokens (YubiKey,
Nitrokey, and others) support without GPG card emulation. The DID program speaks
directly to `ssh-agent`; no `gpg-agent` involved.

### Relationship to existing signing methods

`gpg.format = did` is additive. It does not deprecate or remove `openpgp` or `ssh`
support. Existing signed tags with embedded GPG or SSH signatures continue to verify
normally using their respective methods.

A repo can specify a preferred format:

```ini
[gpg]
    format = did      # new signatures use DID
```

And accept verification of legacy signatures:

```ini
[gpg "legacy"]
    acceptOpenpgp = true   # still verify embedded GPG sigs
    acceptSsh = true       # still verify embedded SSH sigs
```

During a transition period (as the Linux kernel is currently in), both old and new
signature formats coexist. The cutover is a policy decision, not a technical one.

---

## Implementation notes

### Patch series 1 scope

- Add `refs/signatures/` as a recognized namespace in `refs.c`
- Add `push.autoSignatureRefs` config handling in `push.c`
- Add `fetch.autoSignatureRefs` and `fetch.verifySignatures` config handling in
  `fetch.c`
- Add `signature.required` and related policy config in `tag.c` and `merge.c`
- Update `git tag -v` to look in `refs/signatures/` for signature blobs
- Update `git log --show-signature` to render from `refs/signatures/` blobs
- Add `git tag --countersign` for adding additional signatures to an existing signed tag
- Add `git push --signatures` shorthand for pushing signature refs
- Update transport negotiation to communicate `refs/signatures/` capability

The embedded `gpgsig` header mechanism is unchanged. Refs storage is additive, not
a replacement.

### Patch series 2 scope

- Add `did` as a valid value for `gpg.format` in `gpg-interface.c`
- Add `gpg.did.program` and `gpg.did.registryPath` config handling
- Define the signing and verification subprocess interface (stdin/stdout protocol)
- Add structured verification result parsing in `gpg-interface.c`
- Update `git tag -v` and `git log --show-signature` to render structured DID
  verification output
- Add `signature.minimumTier` and `signature.project` policy enforcement
- Add `--countersign` implementation using `refs/signatures/` sub-refs

### What `lf-did` provides

The `lf-did` tool (reference implementation, Python 3.11+) implements the signing and
verification subprocess interface defined in Series 2. It is not part of the git
codebase. Git ships no DID tooling, same as it ships no GPG binary. The interface is
documented so any conformant DID tool can serve as `gpg.did.program`.

The reference implementation and the subprocess interface spec will be published at
`linuxfoundation.org/pub/scm/lf-did.git` prior to the patch series submission.

---

## Security considerations

### No external dependencies during verification

The system contacts no external service at any point during verification. This is a
security property, not an implementation convenience.

A verification step that makes network calls can be MITMed. It can fail under network
partition, making verification impossible precisely when it matters most. It can be
censored selectively -- certain builds verified, others not. It can be compelled: a
third-party resolver under legal jurisdiction can be ordered to return false results or
withhold them. None of these attack surfaces exist here. The public key is in the
identifier. The identity documents are in the local registry clone. Verification is
deterministic local computation against local data.

This property should be preserved in any implementation of this spec. An implementation
that adds network calls during the verification path -- for any reason, including
optional enrichment -- should be considered non-conformant for the purposes of build
infrastructure deployment.

### Threat model

The signing system is designed to resist:

**Key compromise:** Revocation is a signed document committed to the git registry repo.
Once a revocation is merged, all subsequent verifications of signatures from the revoked
DID fail, regardless of cryptographic validity. Past signatures are not retroactively
invalidated (consistent with GPG behavior and the practical reality that retroactive
invalidation requires a different threat model than this system is designed for).

**Replay attacks:** Every signature document includes a nonce derived from the signed
object's SHA-256. A valid signature for object A cannot be replayed as a valid signature
for object B because the nonce will not match B's SHA-256. An attacker who captures a
valid signature gains nothing they can apply to a different object.

**Registry tampering:** The registry is a git repo. Its integrity is protected by git's
object model (SHA-256 hashing of all content) and by the endorsement chain: every
document in the registry is signed by a key in the registry, and the chain terminates
at project anchor keys whose fingerprints are published out-of-band. An attacker who can
write to the registry repo must also compromise an anchor key to introduce trusted
content.

**Keyserver poisoning:** Not applicable. There are no keyservers. All public key
material is in the local registry clone. The only way to introduce a malicious key is
to compromise the registry repo and an anchor key simultaneously.

**Social engineering of endorsement:** Endorsements are signed, timestamped, and
include a human-readable note from the endorser describing how they verified the
subject. They are permanent in git history. Endorsers are accountable for their
endorsements. This does not prevent social engineering but it does create a clear
attribution trail.

### Timestamp assertion

The `lf:timestamp` field in the signature document is self-asserted by the signer. It
is not independently verified by a third party. This has a concrete implication: a
compromised key could be used to produce a backdated signature -- one with a timestamp
before the key was revoked -- that would appear valid against the revocation record.

This is a known limitation and an accepted tradeoff. The alternative, RFC 3161 trusted
timestamping, requires a third-party timestamp authority and introduces an availability
dependency that breaks offline verification. The design prioritizes offline verification
as a hard requirement.

The practical impact is limited. An attacker with a compromised key can produce a
backdated signature, but they can only do so for objects that exist at the time of
compromise. They cannot retroactively sign a future release. And revocation, once
published, prevents the compromised key from being used for any new legitimate signing
operation visible to a current registry clone. Backdated signatures on past objects are
a minor concern compared to the primary threat of a compromised key signing new
malicious content.

Git consumers that require timestamp non-repudiation stronger than self-assertion should
integrate an RFC 3161 timestamping step in their release pipeline alongside this system.
This is not a git-level concern.

### Nonce construction

The nonce in the signature payload is the first 32 bytes (256 bits) of the object
SHA-256, hex-encoded. This is deterministic and does not require any state or randomness
source. It binds the signature to the specific object being signed without adding
protocol complexity. An alternative of a random nonce would require the signing tool to
store state, which creates operational problems for hardware tokens.

The nonce is not a substitute for the cryptographic signature over the object SHA -- it
is an additional layer that makes the replay attack surface explicit and auditable.

### Key storage requirements

The DID signing system does not mandate key storage beyond what the external signing
tool (`lf-did` or equivalent) enforces. However the LF DID deployment mandates hardware
token storage for maintainer tier and above, with the token accessed via the SSH agent
protocol. This is enforced at registry policy level, not at the git level.

Git's role is to invoke the signing tool and trust its output. Key storage policy is
out of scope for this proposal.

### SHA-256 transition

Git is in the process of transitioning from SHA-1 to SHA-256 for object addressing.
This proposal is designed to be SHA-256 native: the `lf:objectSha` field in the
signature document contains the SHA-256 of the signed object, regardless of what SHA
git uses internally for object addressing. During the SHA-1 to SHA-256 transition,
both hashes may be recorded in the signature document. Verification uses SHA-256
regardless.

The parallel ref storage design (`refs/signatures/`) does not embed object SHAs in ref
names, so it is unaffected by the SHA transition.

---

## Alternatives considered

### Continue using `gpg.program` shim

Viable short-term. The LF DID deployment works today with `lf-did` shimmed in via
`gpg.program`. The problems: the shim must speak enough of the GPG CLI protocol to
satisfy git's expectations, the output of `git tag -v` is raw GPG-format text that
does not render structured DID verification results well, and the embedded header
approach forecloses multi-signature support. The shim approach is technically correct
but permanently second-class.

### Extend SSH signing with a DID layer

SSH signing already supports `allowed_signers` as a trust mechanism. One could imagine
a DID-aware `allowed_signers` replacement that adds tier and chain information. This
does not solve the embedded header problem and ties the implementation to the SSH
signing infrastructure in ways that add complexity without benefit. DID and SSH are
different trust models; conflating them serves neither.

### Store signatures in git notes

`refs/notes/` is an existing parallel namespace for per-object metadata. Signatures
could be stored there. We chose `refs/signatures/` as a dedicated namespace because:
notes have existing semantics and tooling expectations that signatures would interfere
with; the merge strategy for conflicting notes entries is not appropriate for signatures
(you do not merge signatures, you accumulate them); and a dedicated namespace makes the
semantic intent clear and allows dedicated transport configuration.

### Require a resolver for DID methods beyond did:key

Supporting `did:plc`, `did:web`, and other DID methods for security-relevant operations
would require network access during verification and introduce availability dependencies.
We chose to require `did:key` for all security operations and treat other DID methods
as informational metadata only (`alsoKnownAs` fields, unverified by tooling).

This is not a simplification that trades flexibility for reliability -- it is the
correct design. A verification step that sometimes requires a network call is not an
offline verifier with an optional network step; it is a network-dependent verifier with
an offline fallback, which is a different and weaker security posture. The requirement
is: given a git repo clone and a registry clone, verification completes correctly and
completely with zero network access. `did:key` satisfies this requirement by
construction. No other DID method does.

External DID resolution is available for anyone who wants supplementary identity
verification beyond what this system provides. The architecture does not foreclose it.
It simply never depends on it, and git never needs to know it exists.

---

## Open questions for the community

**1. Subprocess interface specification.** The signing and verification interface between
git and `gpg.did.program` needs to be formally specified, similar to how the GPG
interface is documented. We propose a simple stdin/stdout line protocol with a JSON
payload. Feedback on the interface design is welcome before we commit to it.

**2. `refs/signatures/` naming.** We chose `refs/signatures/` by analogy with
`refs/notes/`. Alternative proposals: `refs/attestations/`, `refs/proofs/`. The name
should be generic enough to accommodate future signing methods and use cases (e.g. SLSA
provenance attestations, SBOM signatures) without implying DID-specific semantics.

**3. Transport negotiation.** Fetching `refs/signatures/` alongside `refs/tags/*`
requires the server to advertise this capability and the client to request it. We
propose following the `refs/notes/` precedent where the namespace is fetched on explicit
request or config, not by default. Whether it should be on-by-default for new repos is
a policy question.

**4. Embedded header deprecation timeline.** We are not proposing to deprecate embedded
`gpgsig` headers in this series. Whether and when to do so is a separate discussion.
The parallel ref approach is strictly additive and the two models coexist indefinitely.
Feedback on whether the community wants a deprecation path for embedded headers is
welcome.

**5. `git bundle` signing.** Bundle files are a distribution mechanism for git content
outside the normal push/fetch transport. Extending signature support to bundles
(carrying signature refs inside the bundle) is desirable for the LF use case but is
scoped out of this proposal to keep the patch series manageable. We note it here as
intended future work.

**6. `refs/signatures/` discoverability.** The `refs/notes/` namespace suffered from a
discoverability problem: tooling cannot efficiently determine whether a repo uses notes
for a particular purpose without fetching the entire namespace. We propose that repos
using `refs/signatures/` advertise this via a sentinel ref `refs/signatures/PRESENT`,
a zero-byte blob whose existence signals that the repo has signature refs. This allows
clients to make a single ref existence check before fetching the full namespace and
avoids unnecessary fetch traffic against repos that do not use signatures. The sentinel
ref is created automatically by `git tag` when `gpg.format = did` and
`push.autoSignatureRefs = true`. Whether to also include a capability advertisement in
the protocol negotiation handshake is an open question for the community; the sentinel
ref approach works without any protocol changes.

---

## Relationship to other work

**SLSA (Supply chain Levels for Software Artifacts):** SLSA provenance attestations are
a related but distinct problem -- they attest to how software was built, not who
released it. The `refs/signatures/` namespace could accommodate SLSA attestation
documents alongside signing documents using the same transport and storage mechanisms.
This is future work outside this proposal.

**Sigstore / Cosign:** Sigstore uses ephemeral keys with certificate transparency for
signing OCI artifacts. It is not git-native and has a different threat model
(certificate transparency log rather than explicit trust chain). The two systems are
complementary for different points in the supply chain. LF DID handles git object
signing; Sigstore handles artifact signing downstream of the build. They do not compete.

**in-toto:** in-toto defines a framework for supply chain integrity that can use various
signing mechanisms. The `refs/signatures/` storage format is compatible with being an
in-toto link metadata transport. This is noted as a future integration point.

**W3C DID specification:** This proposal implements a subset of the W3C DID Core
specification (https://www.w3.org/TR/did-core/) using the `did:key` method
(https://w3c-ccg.github.io/did-method-key/). The identity document format uses JSON-LD
(https://www.w3.org/TR/json-ld11/) and JCS canonicalization (RFC 8785).

---

## Appendix A: Signature document format (normative)

A DID signature document stored in `refs/signatures/` is a JSON-LD document conforming
to the following schema. All fields prefixed `lf:` are defined in the LF DID context
at `https://lf.org/ns/did/v1`.

**Required fields:**

| Field | Type | Description |
|-------|------|-------------|
| `@context` | array | Must include W3C DID context and `lf.org/ns/did/v1` |
| `type` | string | Must be `"lf:GitSignature"` |
| `lf:objectType` | string | `"tag"`, `"commit"`, or `"blob"` |
| `lf:objectSha` | string | Full SHA-256 hex of the signed git object |
| `lf:ref` | string | Fully qualified ref name (e.g. `refs/tags/v6.12`) |
| `lf:signer` | string | `did:key` URI of the signer |
| `lf:timestamp` | string | ISO 8601 datetime of signing |
| `lf:nonce` | string | First 32 bytes of `lf:objectSha`, hex-encoded |
| `lf:signature` | string | base64url-encoded signature over JCS-canonicalized payload |

**Signature payload construction (normative):**

1. Construct a JSON object containing all fields listed above except `lf:signature`
2. Canonicalize using RFC 8785 (JCS)
3. Sign the canonicalized bytes using the private key corresponding to the `did:key`
   in `lf:signer`
4. base64url-encode the signature bytes (no padding)
5. Set `lf:signature` to the encoded value

**Verification (normative):**

1. Extract `lf:signature` from the document
2. Construct the payload object (all fields except `lf:signature`)
3. Canonicalize using RFC 8785
4. Decode the public key from `lf:signer` (multibase decode of the `did:key` fragment)
5. Verify the signature over the canonicalized payload bytes
6. Verify `lf:nonce` equals the first 32 bytes of `lf:objectSha`, hex-encoded
7. Fetch the git object at `lf:objectSha` and verify its SHA-256 matches
8. Perform registry chain verification (steps 5-11 from Series 2 verification section)

Steps 5-7 are cryptographic verification, purely local. Step 8 requires a registry
clone.

---

## Appendix B: Subprocess interface (normative)

When `gpg.format = did`, git communicates with `gpg.did.program` via subprocess:

**Signing:**

```
lf-did sign-object [--project <p>] [--registry <path>] --output <sigfile> <payload-file>
```

Exit 0 on success. Writes signature document JSON to `<sigfile>`. Stderr for human-
readable error messages. No stdout expected.

**Verification:**

```
lf-did verify-object [--project <p>] [--registry <path>] \
    --signature <sigfile> --payload <payload-file> \
    [--minimum-tier <tier>]
```

Exit 0 on successful verification, non-zero on any failure. Stdout contains structured
verification result (key-value pairs, one per line, as shown in Series 2 section).
Stderr for human-readable error messages.

**Structured output fields:**

| Field | Values | Description |
|-------|--------|-------------|
| `RESULT` | `GOOD`, `BAD`, `EXPIRED`, `REVOKED`, `UNTRUSTED`, `ERROR` | Overall result |
| `SIGNER` | DID URI | Signer's `did:key` |
| `NAME` | string | Display name from identity document |
| `TIER` | string | Tier name in the project |
| `PROJECT` | string | Project identifier |
| `SIGNED` | ISO 8601 | Signing timestamp |
| `EXPIRES` | ISO 8601 + validity | Identity document expiry |
| `REVOKED` | `yes` / `no` | Whether signer DID is revoked |
| `CHAIN` | string | Trust chain summary |
| `TIER_CHECK` | `pass` / `fail` / `n/a` | Result of minimum tier policy check |

Git parses these fields for display. Unknown fields are ignored, allowing future
extension without breaking older git versions.

---

## Appendix C: Example configuration

**Developer workstation (kernel contributor):**

```ini
[gpg]
    format = did

[gpg "did"]
    program = lf-did
    registryPath = ~/src/kernel-did-registry

[push]
    autoSignatureRefs = true

[fetch]
    autoSignatureRefs = true
    verifySignatures = true
```

**Build/CI system (automated verification only, no signing):**

```ini
[gpg]
    format = did

[gpg "did"]
    program = lf-did
    registryPath = /srv/did-registries/kernel

[fetch]
    autoSignatureRefs = true
    verifySignatures = true

[signature]
    required = true
    minimumTier = maintainer
    project = kernel
```

**Repository policy (committed to repo, applies to all clones):**

```ini
# .gitsignpolicy (proposed new file, read by git alongside .gitattributes)
[signature]
    required = true
    minimumTier = maintainer
    project = kernel
```

The `.gitsignpolicy` file is a proposed new repo-level policy file, analogous to
`.gitattributes`, that declares signing requirements for the repository. It is not a
security boundary (a malicious committer could modify it) but it establishes the
canonical policy that tooling and infrastructure enforce. Whether to implement this as
a separate file or as committed `.git/config` content is an open question for the
community.

---

## Summary

This proposal asks the git community to adopt two patch series:

**Series 1** moves signature storage from embedded object headers to a parallel
`refs/signatures/` namespace. This is an improvement to the object model that benefits
all signing methods and enables multi-signature support. It is independently useful and
not coupled to DID signing.

**Series 2** adds `gpg.format = did` as a first-class signing method using W3C
`did:key` identifiers, offline verification against a git-committed trust registry,
structured verification output that git parses natively, and repo-level signature policy
enforcement.

Together they replace an ad-hoc GPG shim with a designed, extensible, offline-capable
signing infrastructure that accurately models how open source project trust actually
works.

The Linux Foundation is deploying this system across its hosted projects beginning with
the Linux kernel. We would like that deployment to be a first-class git feature, not a
permanent workaround.

Reference implementation and full specification: `linuxfoundation.org/pub/scm/lf-did.git`  
LF DID infrastructure documentation: `linuxfoundation.org/did`  
Contact: `lf-did@lists.linuxfoundation.org`

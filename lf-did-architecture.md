# LF DID Infrastructure: Architecture and Deployment Guide

**Audience:** Linux Foundation staff, CNCF technical staff, project governing boards,
and technical leads responsible for adopting LF DID within their projects  
**Status:** Adopted by the Linux Foundation  
**Tooling:** `lf-did` CLI (Python 3.11+)  
**Root registry:** `linuxfoundation.org/pub/scm/lf-did-root.git`  
**Mailing list:** `lf-did@lists.linuxfoundation.org`

---

## What this is

LF DID is a shared identity and signing infrastructure for Linux Foundation hosted
projects. It replaces ad-hoc GPG webs of trust, per-project keyserver dependencies,
and informal identity verification with a unified system built on W3C Decentralized
Identifiers (DIDs), git-native storage, and a federated trust hierarchy rooted at the
Linux Foundation.

The Linux kernel is the pilot deployment. This document describes the full
infrastructure that the kernel instantiates and that all LF-hosted projects can adopt.

Every project gets its own registry repo, its own tier definitions, and its own
governance policy. The LF layer provides shared tooling, a common identity document
format, a root trust anchor, and cross-project identity correlation. Projects do not
share contributor registries -- they federate through the root.

---

## Design principles

**DIDs are simple when you have git.** The DID ecosystem has a reputation for
complexity -- blockchains, distributed hash tables, resolution infrastructure, consensus
protocols, verifiable data registries. That complexity exists because most DID
deployments lack a substrate for storing and distributing identity documents, so they
build one. The Linux Foundation and every project it hosts already operates a substrate
that is content-addressed, cryptographically integrity-protected, distributed, and
spoken fluently by every developer on the planet: git. Nearly everything that makes
DIDs complicated in other deployments is a problem git already solves. We adopt the
DID identifier format and document schema -- the parts that are genuinely useful -- and
replace the rest of the complexity stack with git primitives that developers already
understand and trust.

**Git is the database.** All identity, endorsement, delegation, revocation, and rotation
records are files in git repos. The full history of who trusted whom, when, and who
approved it is auditable forever via standard git tooling. No external databases, no
custom storage, no availability dependencies beyond git hosting.

**Identity documents are text files.** A contributor's identity is a JSON file. Their
endorsements are JSON files. Revocations, delegations, rotations -- all JSON files in a
git repo. They are readable, diffable, greppable, and reviewable in a pull request
exactly like any other code change. No app required. No GUI required. No wallet
required. No browser extension required. The entire trust infrastructure of a major
open source project is auditable by anyone with `git clone` and a text editor. For an
audience of developers, this is the right default.

**No DID dereferencer, ever.** The system is entirely self-contained. No network call
to a DID resolution endpoint is made at any point during signing, verification,
endorsement, revocation, or any other operation. The `did:key` method encodes the
public key directly in the identifier -- resolution is local arithmetic, not a network
request. All other documents are in the local registry clone. This is a deliberate
security property: a system that phones home during verification can be MITMed, can
fail under network partition, can be censored, can be compelled. This system has none
of those properties. It works in air-gapped environments, in network-restricted build
infrastructure, when LF servers are unreachable, when the internet is having a bad day.
Contributors and projects that want to dereference external DID methods for their own
purposes -- resolving `did:web`, validating EU wallet credentials, checking Bluesky
handles -- are free to do so. That is never in the operation flow and the security
model does not depend on it.

**The system is self-contained and never requires internet connectivity.** No operation
-- signing, verifying, endorsing, revoking, rotating, chain verification -- makes a
network call or depends on a running service beyond git hosting. There is no DID
resolver in the operation flow. `did:key` resolution is local computation: decode the
multibase-encoded key from the identifier string. Done. Revocation, endorsement, and
trust chain data are all in the local registry clone. An air-gapped build system
verifies signatures exactly as well as an internet-connected developer workstation.
External DID resolution infrastructure exists and is accessible to anyone who wants to
cross-check identity claims against it, but it is strictly optional and never a
dependency. Projects that want to integrate external resolution for supplementary
identity verification can do so; the architecture does not foreclose it. It simply
never requires it.

**Verification is offline.** `lf-did verify` never makes network calls. All context
vocabularies are bundled with the tooling. All public key material is in the local clone
of the registry repo. A build system with no external network access can verify
signatures completely.

**did:key is the security primitive.** The `did:key` method encodes the public key
directly in the identifier. No resolver infrastructure. No registry lookups. The DID
is the key. Other DID types (did:plc, did:web, EU wallet DIDs) may appear in
`alsoKnownAs` for identity correlation but carry no security weight.

**Tiers are project-defined, capabilities are LF-defined.** The LF base context defines
the capability model: what it means to be able to endorse, to sign, to revoke. Each
project defines its own tier names and maps them to those capabilities in their policy
config. The kernel's `anchor/maintainer/contributor` and k8s's
`steering/lead/approver/reviewer/member` are both valid instantiations of the same
underlying model.

**Extension is native.** Identity documents are W3C DID documents in JSON-LD. Adding
data to your identity means adding a JSON-LD context and using its terms, then
re-signing. The self-signature covers all fields. No schema changes required, no
maintainer approval needed for self-edits.

---

## Trust hierarchy

```
Linux Foundation Root Anchors
  (HSM-held keys, key ceremony documented in POLICY.md)
  │
  ├── Linux Kernel Project Anchors
  │     (Linus Torvalds, Greg Kroah-Hartman, LF kernel contacts)
  │     └── kernel maintainers → kernel contributors
  │
  ├── CNCF Anchors
  │     (CNCF Governing Board designated keys)
  │     │
  │     ├── containerd Project Anchors
  │     │     └── containerd maintainers → containerd contributors
  │     │
  │     ├── Kubernetes Project Anchors
  │     │     └── k8s SIG leads → approvers → reviewers → members
  │     │
  │     └── [other CNCF projects...]
  │
  └── [other LF projects...]
```

Each level is established by a signed anchor delegation from the level above. Project
anchors are established when a project joins LF or CNCF -- the onboarding PR to the LF
root registry is signed by an LF root anchor. Everything below that chains through
project-internal endorsements.

Cross-project trust does not flow automatically. A k8s approver is not automatically
trusted in containerd. A contributor's DID can appear in multiple project registries
pointing to the same `did:key` -- the `alsoKnownAs` field links them for human
correlation -- but each project endorses independently.

---

## Registry federation

The LF root registry is a git repo containing pointers to project registries, not the
project registries themselves:

```
lf-did-root.git
  policy/
    trust-anchors.json      # LF root anchor DIDs and fingerprints
    registry-admins.json    # LF staff with root merge rights
    POLICY.md               # root governance and key ceremony docs

  projects/
    kernel/
      registry.json         # URL + expected head commit hash of kernel registry
      anchors.json          # kernel anchor DIDs, signed by LF root
    cncf/
      registry.json         # CNCF meta-registry pointer
      anchors.json          # CNCF anchor DIDs, signed by LF root
      projects/
        kubernetes/
          registry.json
          anchors.json
        containerd/
          registry.json
          anchors.json
        [...]
```

`registry.json` contains the canonical URL of the project's registry repo and the
expected HEAD commit hash, updated on each project registry push. This gives the root
registry a tamper-evident audit trail of project registry state without replicating all
content into a monorepo.

A project registry is a self-contained git repo following the standard layout (see
Project Registry Layout below). It does not depend on the root registry for its internal
operations -- maintainers endorse contributors, sign tags, and revoke keys entirely
within the project registry. The root registry is consulted only for cross-project
verification and onboarding.

---

## The LF context vocabulary

### Namespace status

The `lf:` and `kernel:` (and other project) prefixes used throughout this document
are JSON-LD compact IRIs that expand to URLs under domains controlled by the
respective organizations:

| Prefix | Expands to | Domain controller |
|--------|-----------|-------------------|
| `lf:` | `https://lf.org/ns/did/v1#` | Linux Foundation |
| `kernel:` | `https://kernel.org/ns/did/v1#` | kernel.org admins |
| `k8s:` | `https://k8s.io/ns/did/v1#` | CNCF / Kubernetes project |

**These URLs do not currently exist.** The context documents they point to have not
yet been written or published. The URLs are placeholders established in this design
document; the context documents will be authored and published at those URLs before
the system goes live. This is standard practice in JSON-LD and W3C specification work
-- the namespace URL is defined in the spec first, then the document is published at
that URL when the spec is ready to ship.

The domain control is what makes the namespace legitimate, not the current existence
of the document. `lf.org` is controlled by the Linux Foundation; `kernel.org` is
controlled by the kernel.org admins. No one else can publish authoritative context
documents at those URLs. The terms defined under `lf:` (`lf:GitSignature`,
`lf:Endorsement`, etc.) and under `kernel:` (`kernel:gpgFingerprint`,
`kernel:minisignPublicKey`, etc.) mean what this specification says they mean,
because the organizations that control those domains say so.

**Runtime behavior is unaffected by publication status.** The tooling bundles all
context documents offline and never fetches them at runtime. A context document that
does not yet exist at its canonical URL causes no operational problem -- the bundled
copy is what the tool uses. The canonical URL matters for external validators and
interoperability with other JSON-LD tooling, not for `lf-did` itself.

When context documents are published, their content must exactly match the bundled
copies shipped with the tooling at that version. Any change to a context document
is a breaking change requiring a version bump and tooling update.

### Vocabulary

The LF base context at `https://lf.org/ns/did/v1` defines shared terms used by all
projects:

| Term | Type | Description |
|------|------|-------------|
| `lf:project` | string | Project identifier (e.g. `kernel`, `kubernetes`) |
| `lf:tier` | string | Tier name within the project |
| `lf:registered` | datetime | When this identity was registered |
| `lf:expires` | datetime | When this identity expires |
| `lf:selfSignature` | string | base64url signature over canonicalized document |
| `lf:Endorsement` | type | Endorsement document type |
| `lf:Delegation` | type | Delegation document type |
| `lf:Revocation` | type | Revocation document type |
| `lf:GitSignature` | type | Git object signature document type |
| `lf:subject` | DID ref | Subject of an endorsement or revocation |
| `lf:endorser` | DID ref | Endorser DID |
| `lf:tierVouched` | string | Tier the endorser is vouching for |
| `lf:scope` | string | Ref glob for delegation scope |
| `lf:objectSha` | string | Git object SHA being signed |
| `lf:nonce` | string | Replay-prevention nonce |

Projects extend this with project-specific terms in their own context. The kernel uses
`kernel:` prefix and `https://kernel.org/ns/did/v1`. Kubernetes would use `k8s:` and
`https://k8s.io/ns/did/v1`. Project contexts define project-specific tier names,
capability mappings, and any other project-specific vocabulary.

Both the LF base context and all registered project contexts are bundled with the
`lf-did` tooling and resolved offline. Adding a new project context requires a PR to
the `lf-did` tooling repo plus a version bump. Context files are static documents
hosted at stable URLs but never fetched at runtime.

---

## Project identity documents

A contributor's identity document in any LF project registry looks like this:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://www.w3.org/ns/did/v1.1",
    "https://lf.org/ns/did/v1",
    "https://k8s.io/ns/did/v1"
  ],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{
    "id": "did:key:z6Mk...#z6Mk...",
    "type": "Multikey",
    "controller": "did:key:z6Mk...",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": ["did:key:z6Mk...#z6Mk..."],
  "name": "Jane Developer",
  "email": "jane@example.com",
  "alsoKnownAs": [
    "at://jane.bsky.social",
    "did:web:jane.example.com"
  ],
  "lf:project": "kubernetes",
  "lf:tier": "approver",
  "lf:registered": "2025-01-15T00:00:00Z",
  "lf:expires": "2027-01-15T00:00:00Z",
  "k8s:sigs": ["sig-network", "sig-storage"],
  "lf:selfSignature": "base64url-encoded-signature-over-this-document"
}
```

The same person contributing to both Kubernetes and containerd has two separate identity
files in two separate registry repos, both pointing to the same `did:key`. Their
`alsoKnownAs` may cross-reference their other project DIDs. Each project endorses
independently. The shared key is the cryptographic thread connecting the identities.

---

## Tier system

The LF base context defines the capability model. Each project maps its tier names to
these capabilities in `policy/tiers.json` in their registry repo.

Defined capabilities:

| Capability | Description |
|------------|-------------|
| `can_endorse_up_to` | Maximum tier this tier can endorse others to |
| `can_sign_refs` | Ref glob patterns this tier can sign |
| `can_revoke_up_to` | Maximum tier this tier can revoke |
| `can_delegate` | Whether this tier can create delegation documents |
| `can_register_automation` | Whether this tier can register automation identities |
| `requires_hardware_key` | Whether hardware token is required |

Example `policy/tiers.json` for the Linux kernel:

```json
{
  "@context": ["https://lf.org/ns/did/v1"],
  "project": "kernel",
  "tiers": {
    "anchor": {
      "can_endorse_up_to": "maintainer",
      "can_sign_refs": ["refs/tags/*"],
      "can_revoke_up_to": "maintainer",
      "can_delegate": true,
      "can_register_automation": true,
      "requires_hardware_key": true
    },
    "maintainer": {
      "can_endorse_up_to": "contributor",
      "can_sign_refs": ["refs/tags/*"],
      "can_revoke_up_to": "contributor",
      "can_delegate": true,
      "can_register_automation": true,
      "requires_hardware_key": true
    },
    "contributor": {
      "can_endorse_up_to": null,
      "can_sign_refs": ["refs/heads/*"],
      "can_revoke_up_to": null,
      "can_delegate": false,
      "can_register_automation": false,
      "requires_hardware_key": false
    },
    "automation": {
      "can_endorse_up_to": null,
      "can_sign_refs": ["refs/tags/*-build"],
      "can_revoke_up_to": null,
      "can_delegate": false,
      "can_register_automation": false,
      "requires_hardware_key": true
    }
  }
}
```

Example `policy/tiers.json` for Kubernetes:

```json
{
  "@context": ["https://lf.org/ns/did/v1"],
  "project": "kubernetes",
  "tiers": {
    "steering": {
      "can_endorse_up_to": "lead",
      "can_sign_refs": ["refs/tags/*"],
      "can_revoke_up_to": "lead",
      "can_delegate": true,
      "can_register_automation": true,
      "requires_hardware_key": true
    },
    "lead": {
      "can_endorse_up_to": "approver",
      "can_sign_refs": ["refs/tags/*"],
      "can_revoke_up_to": "approver",
      "can_delegate": true,
      "can_register_automation": true,
      "requires_hardware_key": true
    },
    "approver": {
      "can_endorse_up_to": "reviewer",
      "can_sign_refs": ["refs/heads/*", "refs/tags/v*-rc*"],
      "can_revoke_up_to": "reviewer",
      "can_delegate": false,
      "can_register_automation": false,
      "requires_hardware_key": false
    },
    "reviewer": {
      "can_endorse_up_to": "member",
      "can_sign_refs": ["refs/heads/*"],
      "can_revoke_up_to": null,
      "can_delegate": false,
      "can_register_automation": false,
      "requires_hardware_key": false
    },
    "member": {
      "can_endorse_up_to": null,
      "can_sign_refs": ["refs/heads/*"],
      "can_revoke_up_to": null,
      "can_delegate": false,
      "can_register_automation": false,
      "requires_hardware_key": false
    },
    "automation": {
      "can_endorse_up_to": null,
      "can_sign_refs": ["refs/tags/*-build", "refs/tags/*-release"],
      "can_revoke_up_to": null,
      "can_delegate": false,
      "can_register_automation": false,
      "requires_hardware_key": true
    }
  }
}
```

The tooling reads `policy/tiers.json` at runtime and enforces capabilities accordingly.
Adding or modifying tiers requires a PR to the project registry with anchor-tier
approval.

---

## Project registry layout

Every project registry repo follows this standard layout:

```
lf-did.json                 # project config (read by lf-did CLI for auto-detection)
policy/
  trust-anchors.json        # project anchor DIDs and fingerprints
  registry-admins.json      # who has merge rights to this repo
  tiers.json                # tier definitions and capability mappings
  POLICY.md                 # project governance and emergency procedures

identities/
  <tier-name>/              # one directory per tier, named to match tiers.json
    INDEX.md                # generated, human-readable, do not edit
    z6Mk<fragment>.json     # identity files named by DID fragment

endorsements/
  <subject-fragment>/
    <endorser-fragment>.json

delegations/
  <delegator-fragment>/
    <delegate-fragment>.json

revocations/
  <subject-fragment>.json

rotations/
  <old-fragment>-to-<new-fragment>.json

TRANSITION.md               # if migrating from GPG or another system
MAINTAINERS                 # human-readable list, cross-references identity files
```

Project configuration lives in each developer's global config file at
`~/.config/lf-did/projects.json`, not in the project source tree. This file maps project
names to local registry clone paths:

```json
{
  "kernel": {
    "registry": "~/src/kernel-did-registry",
    "context": "https://kernel.org/ns/did/v1"
  },
  "kubernetes": {
    "registry": "~/src/k8s-did-registry",
    "context": "https://k8s.io/ns/did/v1"
  }
}
```

`lf-did init-project <name>` creates the entry and clones the registry. Project
auto-detection works by matching the current repo's git remote URL against known
registry URLs; no config file needs to be committed to the source tree. The
`--project <name>` flag overrides auto-detection for CI environments and bare checkouts.

The registry repo itself contains a machine-readable project metadata file at
`policy/project.json` that the tooling uses for registry operations:

```json
{
  "project": "kubernetes",
  "registry_url": "https://github.com/kubernetes/did-registry.git",
  "lf_root": "https://linuxfoundation.org/pub/scm/lf-did-root.git",
  "context_url": "https://k8s.io/ns/did/v1",
  "context_prefix": "k8s"
}
```

---

## Registry governance

### LF root registry

The root registry is governed by Linux Foundation staff. Merge access is held by a
small group of LF root anchor key holders documented in `policy/registry-admins.json`.

| PR type | Required approvals | Notes |
|---------|--------------------|-------|
| New project onboarding | 1 LF root anchor | After governing board approval |
| Project anchor update | 1 LF root anchor + project confirmation | Key rotation or governance change |
| Project archival | 1 LF root anchor | Anchors marked superseded, not revoked |
| Root anchor rotation | 2 LF root anchors + key ceremony | Documented in POLICY.md |

### Project registries

Each project defines its own merge requirements in `policy/POLICY.md`. The LF mandates
minimum requirements:

| PR type | Minimum required | Projects may require more |
|---------|-----------------|--------------------------|
| New contributor identity | 1 top-minus-one tier endorsement | — |
| New top-minus-one tier identity | 2 top-minus-one + 1 anchor | — |
| Endorsement | Automated CI after 24h no-objection | — |
| Self-edit of own identity | Automated CI on signature pass | — |
| Delegation | 1 anchor review | — |
| Revocation (routine) | 1 top-minus-one tier | — |
| Revocation (emergency) | 1 anchor | 4-hour merge window |
| Key rotation | Same as original tier | — |
| Renewal | Same as original tier | — |
| Automation identity | 1 top-minus-one tier (accountable) | — |

"Top-minus-one" means one tier below anchor in the project's tier hierarchy. For the
kernel that is `maintainer`. For k8s that is `lead`.

---

## Onboarding a new project

### Prerequisites

The project must have an existing governance structure with identified leads who will
become the initial anchor-tier key holders. For CNCF projects, this is typically the
maintainers listed in the CNCF project proposal.

### Process

**1. Project leads generate anchor DIDs**

Each initial anchor generates their identity using `lf-did init --generate-on-token`.
Hardware token is required for anchor tier. They announce fingerprints on the project
mailing list and the LF onboarding ticket.

**2. Project creates registry repo**

Fork the `lf-did-registry-template` repo from the LF git hosting. Update `lf-did.json`,
`policy/tiers.json`, and `policy/POLICY.md` for the project. Submit anchor identity
files as the first PR, approved by LF staff.

**3. LF root registry PR**

LF staff open a PR to the root registry adding the project entry under `projects/`.
The `anchors.json` file is signed by an LF root anchor key, establishing the trust chain.
This PR is the moment the project joins the LF DID federation.

**4. Project context vocabulary**

Project creates their JSON-LD context document at their canonical URL (e.g.
`https://k8s.io/ns/did/v1`). LF DID tooling team opens a PR to the `lf-did` tool repo
to bundle the new context. Released in the next tooling version.

**5. Contributor onboarding begins**

Project anchor-tier holders begin endorsing initial maintainers. Maintainers endorse
contributors. Normal operations proceed as documented in the project-specific operations
guide (see the Linux kernel guide as a reference instantiation).

### For CNCF projects specifically

CNCF projects onboard through the CNCF anchors, not directly to LF root. The CNCF
anchor-tier holders (CNCF Governing Board designated keys) sign the project anchor
establishment. The trust chain is: LF root → CNCF anchors → project anchors →
project maintainers → project contributors.

A CNCF sandbox project gets contributor and maintainer tiers. Incubating and graduated
projects can optionally add an anchor tier with CNCF governing board endorsement. Most
CNCF projects will run fine with two tiers (maintainer, contributor) plus automation.

---

## Tooling architecture

`lf-did` is a single Python CLI tool that handles all projects. Project context is
loaded from `lf-did.json` in the current or any parent directory (same lookup as
`.git/config`). Explicit override: `lf-did --project <name>`.

### Key import policy

Contributors can import existing ed25519, P-256, or P-384 keys from GPG, SSH, SSH
agent, or raw PEM format rather than generating new key material. An imported key is
treated as filesystem-tier regardless of its origin -- the system has no way to verify
a key's custody history after the fact, so it cannot grant hardware-tier status to
imported material. RSA, DSA, and ed448 keys are not supported types and cannot be
imported; holders of those key types must generate new keys.

Tier enforcement for imported keys follows the same model as all other keys: project
policy enforced socially during the endorsement process. An endorser vouching for a
maintainer-tier contributor is responsible for verifying that contributor's key storage
meets the tier requirement. Hardware attestation certificates (available from YubiKeys,
TPMs, and Secure Enclave) are the verification mechanism for hardware-backed claims;
imported keys by definition cannot produce valid attestation.

Projects that want to require fresh key generation (no imports) for specific tiers can
state this in their `policy/POLICY.md`. The tooling does not enforce this automatically
but the endorsement record -- which is signed, public, and permanent -- creates
accountability for endorsers who vouch for storage tier claims they did not verify.

### Minisign interoperability

Minisign is widely used in the Rust and Go ecosystems for signing release artifacts. It
uses ed25519 and is a legitimate target for interoperability. However, minisign has no
SSH agent support and no PKCS#11 support -- it requires the raw private key on disk.
Exporting a DID private key to minisign format to use with the minisign binary defeats
hardware token storage for anyone who needs both.

The correct approach: `lf-did sign-file --format minisign` produces a standard
`.minisig` file using the SSH agent interface. The private key never leaves the token.
The signature bytes come from the agent; `lf-did` wraps them in minisign's wire format.
The resulting `.minisig` file is accepted by `minisign -V` without modification.

The key ID embedded in the `.minisig` header is derived deterministically from the DID
public key rather than being a random 64-bit number. This means `lf-did verify-file`
can resolve the signature back to a DID document and perform full chain verification,
while `minisign -V` performs standard minisign verification against a published public
key -- both work against the same `.minisig` file.

**Private key export to minisign format is not supported** for hardware-backed keys.
For filesystem-tier keys it is technically possible but not exposed as a command --
the key file is already accessible at `~/.config/lf-did/private/key.pem` for
contributors who want to manage that themselves.

**Import from minisign is supported**: `import-key --from-minisign` extracts the
ed25519 key material from a minisign secret key file and registers it as a
filesystem-tier DID key. Useful for contributors who have been signing with minisign
and want continuity of key material into the DID system.

The identity document is the authoritative mapping between key representations. The
`kernel:minisignPublicKey` field (or equivalent project-specific field) records the
minisign public key derived from the DID key, creating a signed, verifiable bridge that
consumers can use to correlate the two identity representations. This pattern extends to
other formats -- age encryption keys, Sigstore signing certificates, WireGuard public
keys -- via the same JSON-LD extension field mechanism.

### Registry location resolution

`lf-did` resolves the registry location using the following precedence, stopping at
the first match. This applies to all operations -- signing, verifying, endorsing,
revoking.

| Priority | Mechanism | Notes |
|----------|-----------|-------|
| 1 | `LF_DID_REGISTRY` env var | Full path. Overrides everything. Use in CI. |
| 2 | `--registry <path>` flag | Per-invocation override. |
| 3 | Config file entry | `~/.config/lf-did/projects.json`, written by `init-project`. |
| 4 | Well-known default | `~/.local/share/lf-did/<project>/registry/` |

`lf-did init-project <project>` clones the registry to the well-known default path and
writes the config file entry. For most users running a single project, this is the only
setup step needed.

The config file maps project names to registry paths and remote URLs:

```json
{
  "kernel": {
    "registry": "~/.local/share/lf-did/kernel/registry",
    "remote": "https://git.kernel.org/pub/scm/lf-did/kernel-did-registry.git",
    "url_patterns": ["kernel.org"]
  },
  "kubernetes": {
    "registry": "~/.local/share/lf-did/kubernetes/registry",
    "remote": "https://github.com/kubernetes/did-registry.git",
    "url_patterns": ["github.com/kubernetes"]
  }
}
```

The `url_patterns` field drives project auto-detection: if `--project` is omitted,
`lf-did` inspects the current git repository's remote URLs and matches against all
configured patterns. Unambiguous match proceeds automatically; ambiguous or no match
exits with an error asking for an explicit `--project` flag.

The registry is a plain git clone. There is nothing special about the well-known default
path -- it is a convenience. Projects can keep the registry anywhere; CI systems can
point `LF_DID_REGISTRY` at a path on a shared filesystem or a freshly cloned tmpdir.
The tool does not care where the clone lives, only that it is a valid git repository
containing the expected directory structure.

### Registry clone freshness

All verification is offline against a local registry clone. Stale clones create a
revocation window: a key revoked after the last sync still appears valid locally.
Freshness thresholds apply to all `lf-did verify-*` operations:

| Clone age | Behavior |
|-----------|----------|
| 0–7 days | Normal verification, age reported in output |
| 7–30 days | Warning printed, verification proceeds |
| 30+ days | Verification fails with `REGISTRY_STALE` |

Override for air-gapped environments: `--allow-stale`. If you use this flag in
production, document it explicitly in your build policy. The flag exists for legitimate
isolated environments, not as a way to skip freshness enforcement casually.

Projects operating CI systems should sync registry clones at the start of each build
pipeline. `lf-did registry sync --project <n>` is a thin wrapper around
`git fetch --prune` against the configured registry clone path.

### Key commands

```bash
# Project management (LF staff / project leads)
lf-did project init        # initialize a new project registry
lf-did project verify      # verify project registry internal consistency
lf-did project onboard     # generate onboarding PR bundle for LF root registry

# Identity operations (all users, auto-detects project)
lf-did init                # create identity
lf-did init --generate-on-token
lf-did whoami              # show DID and fingerprint
lf-did edit                # edit and re-sign identity document
lf-did set --field <f> --value <v>
lf-did renew               # renew before expiry
lf-did rotate              # rotate key

# Trust operations
lf-did endorse <did> --tier <tier> --note <note>
lf-did delegate --to <did> --scope <glob> --expires <date>
lf-did revoke <did> --reason <reason>
lf-did self-revoke --reason <reason>

# Signing and verification
lf-did tag <tagname> -m <message>
lf-did verify-tag <tagname>
lf-did verify-chain HEAD --anchor-commit <sha>
lf-did sign-file <file>
lf-did verify-file <file> <file.sig>

# Cross-project
lf-did cross-verify <did> --in-project <project>
  # verify a DID from another project chains to LF root

# Device management
lf-did device list
lf-did device info

# Registry verification
lf-did verify-registry
lf-did verify-registry --against-root  # also checks root registry chain
```

### CI as enforcement layer

CI is not optional tooling. CI is the mechanism that makes the tier and endorsement
model mandatory rather than advisory. This distinction matters: without correctly
configured CI, the endorsement thresholds and tier requirements are honor-system only.
Any project admin who can merge a registry PR without CI passing can bypass the entire
trust model.

**What CI enforces that the tool alone cannot:**

The `lf-did` tool verifies signatures and checks policy against a local registry clone.
It cannot prevent a registry PR from merging without meeting endorsement thresholds --
only the hosting platform's branch protection can do that. CI is the bridge between
cryptographic verification and merge authorization.

| Enforcement point | Mechanism | What breaks without it |
|-------------------|-----------|----------------------|
| Endorsement thresholds | CI required status check on registry PRs | Anyone can merge under-endorsed identities |
| Tier promotion policy | CI validates endorser tiers before approving | Contributors can self-promote |
| Expired identity detection | CI blocks merges referencing expired DIDs | Stale identities remain active |
| Tag signature verification | CI blocks unsigned or weakly-signed release tags | Release integrity unverified |
| Revocation propagation | CI enforces revoked DIDs cannot sign | Revoked keys remain usable |
| Registry structural integrity | CI verifies full chain on every PR | Corruption goes undetected |

**Required platform configuration:**

The registry repository must have branch protection configured such that:

1. The `lf-did` CI workflow is a **required status check** -- PRs cannot merge if it fails
2. Branch protection applies to **administrators** -- no bypass for repo owners
3. Direct pushes to the default branch are **disabled** -- all changes go through PRs
4. The CI bot's merge authorization is the **only** merge path for policy-gated PRs

Without all four of these, the enforcement model has gaps. Projects running on
platforms that cannot enforce these constraints (some self-hosted Gitea instances,
some corporate GitHub Enterprise configurations with mandatory admin bypass) must
document this explicitly in `policy/POLICY.md` and acknowledge they are running
in honor-system mode for those enforcement points.

**CI automation identity:**

The CI system is itself a participant in the registry and must have a registered
`automation` tier identity. This identity:

- Is registered by a named maintainer who is permanently accountable for it
- Has a hardware-backed key (TPM in the CI runner, or HSM in CI infrastructure)
- Is used to sign automated actions: auto-approved self-edit merges, registry
  integrity attestations, automated revocation propagation
- Is listed in `policy/ci-identity.json` in the registry so its role is explicit
- Has a shorter expiry than human identities (90 days recommended) with automated
  renewal

A CI system that merges PRs without a registered automation identity is performing
unsigned actions -- there is no cryptographic record of what the CI system approved
and why. The automation identity closes this gap: every merge the CI bot performs
is attributable to a specific key, registered to a specific accountable maintainer.

**What CI does on each trigger:**

*Registry PR:*
- Clone registry at PR head
- Verify all identity document self-signatures
- Verify all endorsement signatures and check counts against tier policy
- Verify endorser tiers are sufficient for the vouched tier
- Check for expired identities referenced in the PR
- Check revocation record signatures
- On self-edit PRs: verify signature matches the identity being edited, auto-approve
- Emit structured JSON report as PR comment with pass/fail per check

*Code repo tag push:*
- Fetch registry clone (or use `LF_DID_REGISTRY` pointing to CI-local clone)
- Verify tag signature chains to a project anchor
- Verify signer's DID is not expired or revoked
- Verify signer's tier authorizes tag signing per `policy/tiers.json`
- Block the push or mark the release as unverified if any check fails

*Scheduled (daily):*
- Scan all identities for upcoming expiry (warn at 30 days, flag at 7 days)
- Open automated PRs for identities requiring renewal attention
- Verify full registry chain against LF root
- Post integrity report to project security channel

### CI integration

```yaml
# .github/workflows/lf-did-registry.yml -- drop into the registry repo
name: LF DID Registry Enforcement
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'   # daily integrity check

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write   # to post structured report as PR comment
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # full history needed for chain verification
      - uses: linuxfoundation/lf-did-action@v1
        with:
          project: kernel    # or omit to auto-detect from lf-did.json
          mode: registry     # registry PR enforcement mode
          ci-identity: ${{ secrets.LF_DID_CI_KEY }}

# .github/workflows/lf-did-tags.yml -- drop into the code repo
name: LF DID Tag Verification
on:
  push:
    tags: ['v*']

jobs:
  verify-tag:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: linuxfoundation/lf-did-action@v1
        with:
          project: kernel
          mode: tag          # tag signature verification mode
          registry: ${{ vars.LF_DID_REGISTRY_REMOTE }}
```

The `ci-identity` secret is the CI automation key material stored in the platform's
secret manager. On GitHub Actions this is stored as a repository secret and injected
at runtime -- the key never exists on disk in the runner. The CI action speaks to it
via the SSH agent protocol, same as any other key backend.

---

## Cross-project identity correlation

Someone contributing to both Kubernetes and the Linux kernel has two identity files in
two separate registries, both containing the same `did:key` as their `id`. Their
`alsoKnownAs` fields may cross-reference each other.

Tooling support:

```bash
# Find all LF project registries containing a given DID
lf-did find-did did:key:z6Mk...

# Verify a DID chains to LF root across any registered project
lf-did cross-verify did:key:z6Mk... --in-project kernel

# Show all projects a contributor is registered in
lf-did contributor-profile did:key:z6Mk...
```

This is useful for understanding the full trust footprint of a contributor, for
onboarding across projects (a kernel maintainer joining k8s as a member has prior
credibility visible in the system), and for incident response (a compromised key can be
found and revoked across all project registries it appears in).

---

## LF root key management

The LF root anchors are the most critical keys in the system. Operational requirements:

**Hardware:** Keys must be generated in and held by hardware security modules (HSMs).
Recommended: Thales Luna or equivalent FIPS 140-3 Level 3 certified device. Not
YubiKeys -- root anchors require institutional-grade HSMs with documented custody.

**Key ceremony:** Root anchor key generation must follow a documented key ceremony with
at least three LF staff present, recorded in `policy/POLICY.md` in the root registry.
The ceremony record is itself signed by the generated keys and committed.

**Quorum:** Root anchor operations (signing project onboarding, signing root-level
revocations) require a 2-of-N quorum where N is the number of root anchor key holders
(minimum 3, recommended 5).

**Rotation schedule:** Root anchor keys rotate every two years maximum, coordinated with
a key ceremony. The rotation record is signed by the old keys and committed before the
old keys are decommissioned.

**Geographic distribution:** Root anchor key holders should be in different physical
locations. The HSMs should not all be in the same building.

None of this complexity propagates to project-level keys. Project anchors use hardware
tokens (YubiKey, Nitrokey) with the same requirements as documented in project-level
guides. The institutional-grade HSM requirement applies only to LF root.

### Why the SSH agent protocol

All hardware key operations in `lf-did` go through the SSH agent protocol -- the binary
socket interface that lets a process request "sign these bytes with the key that has
this fingerprint" without the private key material ever leaving the token. This is
distinct from SSH the transport protocol; only the agent socket interface is used.

The SSH agent protocol is the de facto universal ABI for hardware-backed signing at the
developer workstation level. Every token that matters speaks it:

| Device | Interface |
|--------|-----------|
| YubiKey (PIV) | SSH agent via `ssh-agent` + PKCS#11 |
| YubiKey (OpenPGP applet) | SSH agent via `gpg-agent --enable-ssh-support` |
| Nitrokey | SSH agent via `ssh-agent` + PKCS#11 |
| FIDO2 / sk-* tokens | SSH agent natively (`ssh-keygen -t ecdsa-sk`) |
| Apple Secure Enclave | Platform SSH agent on macOS |
| TPM 2.0 | SSH agent via `tpm2-pkcs11` + `ssh-pkcs11-helper` |

The alternative is PKCS#11, which is the formal standard for HSM interfaces. PKCS#11
is a C library API, not a process boundary. Integrating it directly means linking
against vendor-provided shared libraries with varying quality, handling C calling
conventions, and working around the quirks in each token's implementation. The SSH
agent protocol is a simple binary socket protocol that Python speaks in a handful of
lines. It is also already running on every developer's machine.

**For institutional HSMs (LF root anchors):** Thales Luna, nCipher, AWS CloudHSM, and
similar devices present PKCS#11 or proprietary APIs, not SSH agent natively. The
integration path is a PKCS#11-to-SSH-agent bridge: `ssh-pkcs11-helper` (ships with
OpenSSH) connects a PKCS#11 library to the SSH agent socket. This is well-understood,
widely deployed infrastructure -- it is how many organizations already use HSMs with
SSH certificate authorities. The `lf-did` tool sees only the SSH agent socket
regardless of what is behind it. The bridge is an operational concern for whoever
manages the HSM, not a design concern for the signing system.

The practical result: the same `lf-did` codebase works identically against a
developer's YubiKey, a CI system's TPM, and an LF root anchor held in a Thales HSM.
The abstraction holds all the way up.

### Everything behind an SSH agent is a valid key store

Because `lf-did` talks to an SSH agent socket and nothing else, any software that can
present an SSH agent interface is a valid key backend. The list is longer than most
people expect:

| Key store | Notes |
|-----------|-------|
| Hardware tokens (YubiKey, Nitrokey, FIDO2) | Recommended for maintainer tier and above |
| Apple Keychain / Secure Enclave | Via platform SSH agent on macOS; Secure Enclave-backed keys are hardware-equivalent |
| GNOME Keyring | Via `gnome-keyring-daemon` SSH agent support |
| KDE Wallet | Via `ksshaskpass` |
| 1Password | Built-in SSH agent; touch-to-sign UX; keys in 1Password vault |
| Bitwarden | SSH agent support; keys in Bitwarden vault |
| HashiCorp Vault | Via community SSH agent shims |
| AWS Secrets Manager / KMS | Via community shims; approved infrastructure for many corporate contributors |
| Azure Key Vault | Via `azure-keyvault-agent` and similar |
| GCP Cloud KMS | Via `gcpkms-ssh-agent` and similar |
| Secretive (macOS) | Secure Enclave backed, presents as SSH agent |
| TPM 2.0 | Via `tpm2-pkcs11` + `ssh-pkcs11-helper` |
| `ssh-agent` with key on disk | Software only; acceptable for contributor tier |

**The tool has no visibility into what is behind the agent socket.** `lf-did` asks the
agent to sign bytes and receives a signature. It cannot distinguish a YubiKey from a
1Password vault from a cloud KMS. The tier-based key storage requirements (hardware
token required for maintainer and above) are project policy enforced socially during
the endorsement process -- the endorser is responsible for verifying the contributor's
claimed storage tier -- not technical constraints enforced by the tooling. This is the
same trust model as GPG key generation claims, with a cleaner interface.

The honest implication: the security guarantee for higher tiers depends on contributors
being truthful about their key storage and endorsers asking the right questions. Projects
that want stronger assurance can require attestation documents from hardware tokens
(YubiKeys and TPMs can produce attestation certificates proving a key was generated
on-device) as part of the registration PR. The `lf-did` tooling supports optional
attestation verification at registration time; whether to require it is a per-project
policy decision.

The practical upside is significant for enterprise adoption. Corporate contributors
are often prohibited from using personal hardware tokens on work systems but have
approved access to AWS KMS, Azure Key Vault, or HashiCorp Vault. Those contributors
can participate fully using their existing approved infrastructure. The key lives in
the corporate-approved secret manager; the SSH agent protocol is the bridge; the
project gets a cryptographically signed identity document without requiring anyone to
plug in a USB device.

---

## Deployment timeline

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Linux kernel pilot | Active |
| 2 | LF root registry establishment | Following kernel pilot |
| 3 | CNCF anchor establishment | After LF root |
| 4 | CNCF graduated projects | kubernetes, containerd, prometheus, envoy, ... |
| 5 | CNCF incubating projects | Batch onboarding |
| 6 | Remaining LF projects | Per project bandwidth |

The kernel pilot is deliberately first because it has the hardest constraints: 30 years
of GPG history, strong opinions, real adversarial threat model, and the highest
visibility. A system that works for the kernel works for everything else.

---

## Quick reference: what each audience needs to do

**LF staff:** Establish root registry, generate root anchor keys via key ceremony,
sign CNCF anchor establishment, maintain `lf-did` tooling releases.

**CNCF staff:** Generate CNCF anchor keys (hardware token), sign project anchor
establishments for graduating and incubating projects, maintain CNCF-level policy.

**Project governing boards:** Designate initial anchor key holders, approve tier
definitions in `policy/tiers.json`, establish emergency revocation contacts.

**Project anchor key holders:** Generate keys on hardware tokens, sign project
onboarding PRs to LF root, endorse initial maintainers, handle emergency revocations.

**Project maintainers:** Generate keys (hardware token required), get endorsed by
anchors, endorse contributors, sign release tags, manage delegations.

**Contributors:** Generate keys (any storage tier), get endorsed by a maintainer, sign
commits. Read your project's operations guide (e.g. `kernel-did.md` for the kernel).

**Everyone:** Run `lf-did init` in your project tree. The tool figures out the rest.

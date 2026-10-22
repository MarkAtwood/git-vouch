# lf-did: Full Python Implementation — Agentic Build Prompt

## PREAMBLE FOR ORCHESTRATOR AGENT

You are the **Orchestrator Agent** for this build. You will spawn and coordinate a fleet of subagents. Each subagent receives an explicit handoff packet (defined below) and returns an explicit result packet. You must not proceed to the next phase until the current phase's subagent returns `STATUS: COMPLETE` and all acceptance criteria pass. If a subagent returns `STATUS: BLOCKED` or `STATUS: FAILED`, you must resolve the blocker before continuing.

Read this entire prompt before spawning anything. The subagent topology is in the "Parallelism Plan" section. Do not deviate from the topology — the dependency ordering is load-bearing.

**Project:** `lf-did` — a Python 3.11+ CLI implementing the LF DID identity and signing system for git-based open source project governance.

**Language:** Python 3.11+ exclusively. No shell scripts as primary logic. No Go, Rust, or C.

**Output structure:** A single installable Python package named `lf_did` with a `lf-did` entry point. All tests in `tests/`. The project must pass `pytest` with zero failures and zero warnings.

**You will be evaluated by another AI agent.** Every design decision must be defensible. Every normative requirement from the spec must be traceable to a test. No hardcoded tier names or tier orderings anywhere in the codebase — tier ordering is always derived from `policy/tiers.json` at runtime.

---

## WHAT YOU ARE BUILDING

`lf-did` is a Python 3.11+ CLI tool that implements a W3C DID-based identity and signing infrastructure for Linux Foundation hosted projects, beginning with the Linux kernel. It replaces GPG-based tag signing with a system built on `did:key` identifiers, JSON-LD identity documents stored in git, and a hierarchical trust model that accurately reflects how open source project governance actually works.

**Explicitly excluded from scope:** any changes to git itself. You are building the userspace tool. It operates today as a `gpg.program` shim (git calls it as a subprocess). When git gains native `gpg.format = did` support, this tool becomes the backend. The subprocess interface is specified below and must be implemented exactly.

**Core design constraints that must be enforced throughout:**

- No network calls during any operation, ever. Signing, verifying, endorsing, revoking, rotating — all offline. `did:key` resolution is local arithmetic. JSON-LD contexts are bundled with the tool, never fetched.
- No external database. The git registry clone on disk is the database.
- No DID resolver in any code path. Not optional, not skippable, not present.
- No GPG dependency for any operation except the one-time bootstrap attestation import (`import-from-gpg`), which calls `gpg` as a subprocess.
- No hardcoded tier names. Tier names and their capabilities come from `policy/tiers.json` in the registry at runtime. Tier names are opaque strings everywhere in production code.
- No secp256k1 keys. Accepted: ed25519 (`z6Mk` prefix), P-256 (`zDn`), P-384 (`z82`).
- No chained delegations. You cannot delegate authority you received via delegation.
- No automatic endorsement transfer on key rotation.
- No software keys for tiers where `requires_hardware_key` is true in policy.

---

## HANDOFF PROTOCOL SPECIFICATION

Every subagent handoff uses this structure.

**Orchestrator → Subagent (TASK PACKET):**
```
TASK_ID: <unique identifier>
PHASE: <phase name>
DEPENDS_ON: <comma-separated TASK_IDs that must be COMPLETE before this starts>
INPUTS: <list of files/artifacts this agent needs>
DELIVERABLES: <list of files/artifacts this agent must produce>
ACCEPTANCE_CRITERIA: <numbered list of verifiable checks>
INSTRUCTIONS: <full task description>
```

**Subagent → Orchestrator (RESULT PACKET):**
```
TASK_ID: <same as input>
STATUS: COMPLETE | FAILED | BLOCKED
DELIVERABLES_PRODUCED: <list of files actually created or modified>
TEST_RESULTS: <pytest output summary or N/A>
BLOCKER: <if STATUS=BLOCKED, describe what is needed>
NOTES: <any deviations from spec, design decisions made, open issues>
```

Orchestrator must log every packet. Subagent must not make assumptions about prior phases unless explicitly listed in INPUTS.

---

## CRYPTOGRAPHIC SPECIFICATION

### did:key

A `did:key` identifier encodes the public key directly:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
         ^--- multibase-encoded public key (base58btc, 'z' prefix)
```

Resolution: strip `did:key:`, multibase-decode the remainder, extract key bytes. The multicodec prefix in the decoded bytes identifies the key type:

| Multicodec prefix | Key type | did:key prefix |
|-------------------|----------|----------------|
| `0xed01`          | ed25519  | `z6Mk`         |
| `0x1200`          | P-256    | `zDn`          |
| `0x1201`          | P-384    | `z82`          |

The "DID fragment" throughout this spec means the full multibase string including the leading `z`, e.g. `z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`.

### Signing and verification

All signatures use the private key corresponding to the signer's `did:key`.

Signature construction (normative for all document types):
1. Build the document dict with all fields except the signature field
2. JCS-canonicalize (RFC 8785) — this handles key ordering and Unicode normalization
3. Sign the canonical bytes with the private key
4. base64url-encode with no padding (`base64.urlsafe_b64encode(sig).rstrip(b'=')`)
5. Set the signature field to the encoded string

Verification reverses this: extract signature field, reconstruct payload dict, JCS-canonicalize, base64url-decode signature, verify against public key decoded from the signer's `did:key`.

**Never call `json.dumps` with `sort_keys=True` on documents before JCS.** JCS handles ordering. Pre-sorting is not equivalent and corrupts canonicalization.

### JCS (RFC 8785)

Use the `jcs` PyPI package. If implementing from scratch for any reason, test against the RFC 8785 appendix test vectors. The test suite must include these vectors.

---

## DOCUMENT FORMAT SPECIFICATION (NORMATIVE)

All documents are JSON-LD. The `@context` array is always first. Field ordering in the stored file follows JCS ordering after canonicalization, but the human-facing `edit` command may store fields in a more readable order — what matters is that the signature verifies, not the storage ordering.

### Identity document

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://www.w3.org/ns/did/v1.1",
    "https://lf.org/ns/did/v1",
    "<project-context-url>"
  ],
  "id": "did:key:<fragment>",
  "verificationMethod": [{
    "id": "did:key:<fragment>#<fragment>",
    "type": "Multikey",
    "controller": "did:key:<fragment>",
    "publicKeyMultibase": "<fragment>"
  }],
  "authentication": ["did:key:<fragment>#<fragment>"],
  "name": "<display name>",
  "email": "<email>",
  "alsoKnownAs": [],
  "lf:project": "<project-id>",
  "lf:tier": "<tier-name>",
  "lf:registered": "<ISO8601-UTC>",
  "lf:expires": "<ISO8601-UTC>",
  "lf:selfSignature": "<base64url>"
}
```

`lf:selfSignature` covers JCS canonicalization of the document with the `lf:selfSignature` field absent. Maximum validity: 2 years from `lf:registered`.

Projects using their own prefix (e.g. `kernel:`) use `kernel:tier`, `kernel:registered`, `kernel:expires`, `kernel:selfSignature` with the same semantics. The tool reads the project prefix from `policy/project.json`.

**Automation identity documents** add:
```json
"lf:automationScope": "<ref-glob>",
"lf:accountableDID": "did:key:<maintainer-fragment>",
"lf:keySource": "tpm|hsm"
```
Automation identities cannot endorse humans. Their `lf:tier` is always `automation`. Software keys for automation are rejected at registration time.

### Endorsement document

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://lf.org/ns/did/v1", "<project-ctx>"],
  "id": "did:key:<endorser>#endorsement-of-<subject-fragment>",
  "type": "lf:Endorsement",
  "lf:subject": "did:key:<subject-fragment>",
  "lf:endorser": "did:key:<endorser-fragment>",
  "lf:tierVouched": "<tier>",
  "lf:timestamp": "<ISO8601-UTC>",
  "lf:verificationMethod": "<human-readable note of how endorser verified identity>",
  "lf:signature": "<base64url>"
}
```

Path: `endorsements/<subject-fragment>/<endorser-fragment>.json`

`lf:verificationMethod` is public, permanent, part of the signed payload. It must describe what the endorser actually did. This is an accountability record.

### Delegation document

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://lf.org/ns/did/v1", "<project-ctx>"],
  "id": "did:key:<delegator>#delegation-to-<delegate-fragment>",
  "type": "lf:Delegation",
  "lf:delegator": "did:key:<delegator-fragment>",
  "lf:delegate": "did:key:<delegate-fragment>",
  "lf:scope": "<ref-glob>",
  "lf:expires": "<ISO8601-UTC>",
  "lf:timestamp": "<ISO8601-UTC>",
  "lf:signature": "<base64url>"
}
```

Path: `delegations/<delegator-fragment>/<delegate-fragment>.json`

Delegation does not chain. The tool must verify at delegation-creation time that the delegator's own authority did not come via a delegation. Delegates must be maintainer-equivalent or above (determined by tier policy, not hardcoded string).

### Revocation document

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://lf.org/ns/did/v1", "<project-ctx>"],
  "id": "did:key:<revoker>#revocation-of-<subject-fragment>",
  "type": "lf:Revocation",
  "lf:subject": "did:key:<subject-fragment>",
  "lf:revoker": "did:key:<revoker-fragment>",
  "lf:reason": "<string>",
  "lf:timestamp": "<ISO8601-UTC>",
  "lf:signature": "<base64url>"
}
```

Path: `revocations/<subject-fragment>.json`

Self-revocation: `lf:revoker == lf:subject`. Third-party revocation: revoker must have `can_revoke_up_to` >= subject's tier per policy.

### Rotation record

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://lf.org/ns/did/v1", "<project-ctx>"],
  "id": "did:key:<old-fragment>#rotation-to-<new-fragment>",
  "type": "lf:Rotation",
  "lf:oldDID": "did:key:<old-fragment>",
  "lf:newDID": "did:key:<new-fragment>",
  "lf:timestamp": "<ISO8601-UTC>",
  "lf:signature": "<base64url>"
}
```

Path: `rotations/<old-fragment>-to-<new-fragment>.json`

**Signed by the OLD key.** Old DID marked superseded in registry (not revoked — past signatures remain valid). Endorsements do not transfer.

### GPG bootstrap attestation

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://lf.org/ns/did/v1", "<project-ctx>"],
  "id": "did:key:<new-fragment>#gpg-bootstrap-from-<gpg-fingerprint>",
  "type": "lf:GPGBootstrapAttestation",
  "lf:gpgFingerprint": "<40-char-hex-fingerprint>",
  "lf:newDID": "did:key:<new-fragment>",
  "lf:timestamp": "<ISO8601-UTC>",
  "lf:gpgSignature": "<armored-gpg-signature-over-JCS-payload>",
  "lf:didSignature": "<base64url-signature-over-JCS-payload-by-new-key>"
}
```

Path: `rotations/gpg-<fingerprint-first-16>-to-<new-fragment>.json`

Both signatures cover the same JCS-canonicalized payload (document without both signature fields). This proves both the GPG key holder and the new DID key holder are the same person.

### Git signature document

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://lf.org/ns/did/v1", "<project-ctx>"],
  "type": "lf:GitSignature",
  "lf:objectType": "tag|commit|blob",
  "lf:objectSha": "<full-sha256-hex-of-git-object>",
  "lf:ref": "<fully-qualified-ref>",
  "lf:signer": "did:key:<fragment>",
  "lf:timestamp": "<ISO8601-UTC>",
  "lf:nonce": "<first-32-hex-chars-of-lf:objectSha>",
  "lf:signature": "<base64url>"
}
```

Stored at `refs/signatures/tags/<tagname>` for tag signatures (via `git update-ref`). Also written as `<file>.sig` for detached file signatures.

The nonce is the first 32 hex characters of `lf:objectSha`. It binds the signature to the specific object. Replaying a valid signature against a different object fails because the nonce won't match.

---

## VERIFICATION PIPELINE (NORMATIVE)

These steps apply to all git object signature verification. Each step is a separate function that raises a typed `VerificationError` on failure.

1. Parse and structurally validate the signature document
2. Verify `lf:nonce == lf:objectSha[:32]`
3. Resolve public key from `lf:signer` (local computation, no network)
4. Reconstruct JCS payload (all fields except `lf:signature`), verify signature
5. Fetch git object at `lf:objectSha`, verify its SHA-256 matches
6. Load registry, confirm signer DID has an identity document
7. Confirm signer is not revoked (check `revocations/<fragment>.json`)
8. Confirm signer is not expired (`lf:expires` in identity > signature timestamp)
9. Load `policy/tiers.json`, confirm signer tier has `can_sign_refs` matching `lf:ref`
10. If signer is acting under delegation: verify delegation document, confirm scope matches `lf:ref`, confirm delegation not expired, confirm delegator not revoked
11. Check registry clone freshness: warn >7d, fail >30d unless `--allow-stale`

Steps 1–5 are pure cryptography, no registry needed.
Steps 6–10 require a registry clone.
Step 11 requires the registry clone's git metadata.

---

## SUBPROCESS INTERFACE (gpg.program shim, normative)

When git calls `lf-did` as its signing/verification program:

**Signing:**
```
lf-did sign-object [--project <p>] [--registry <path>] --output <sigfile> <payload-file>
```
- `<payload-file>` contains the raw git object bytes
- Write signature document JSON to `<sigfile>`
- Exit 0 on success
- Stderr for human-readable errors
- No stdout

**Verification:**
```
lf-did verify-object [--project <p>] [--registry <path>] \
    --signature <sigfile> --payload <payload-file> \
    [--minimum-tier <tier>]
```
- Exit 0 = verified, nonzero = failure
- Stdout: structured key=value pairs, one per line:

```
RESULT: GOOD|BAD|EXPIRED|REVOKED|UNTRUSTED|ERROR
SIGNER: did:key:<fragment>
NAME: <display name from identity doc>
TIER: <tier name>
PROJECT: <project identifier>
SIGNED: <ISO8601>
EXPIRES: <ISO8601> (valid|expired)
REVOKED: yes|no
CHAIN: <human-readable trust chain, e.g. "contributor→maintainer:gregkh→anchor:torvalds">
TIER_CHECK: pass|fail|n/a
```

Git parses these fields. Unknown fields are ignored. Do not add fields not listed above without versioning them.

Also implement `VerificationResult.from_subprocess_output(text: str) → VerificationResult` as the inverse parser (used by test harnesses and potentially by git-side tooling).

---

## REGISTRY LAYOUT (NORMATIVE)

```
lf-did.json                        # project auto-detection (read by CLI)
policy/
  trust-anchors.json               # anchor DIDs + fingerprints, signed by root
  registry-admins.json             # who has merge rights
  tiers.json                       # tier definitions + capability mappings
  project.json                     # machine-readable project metadata
  POLICY.md                        # governance (human-readable, not parsed)
identities/
  <tier-name>/                     # directory per tier, names from tiers.json
    INDEX.md                       # GENERATED — do not hand-edit
    <fragment>.json                # identity files, named by DID fragment
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
TRANSITION.md
MAINTAINERS
```

`policy/tiers.json` example (kernel):
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

`policy/project.json`:
```json
{
  "project": "kernel",
  "registry_url": "https://kernel.org/pub/scm/kernel/did-registry.git",
  "lf_root": "https://linuxfoundation.org/pub/scm/lf-did-root.git",
  "context_url": "https://kernel.org/ns/did/v1",
  "context_prefix": "kernel"
}
```

`lf-did.json` (root of registry, triggers auto-detection):
```json
{
  "project": "kernel",
  "registry_url": "https://kernel.org/pub/scm/kernel/did-registry.git"
}
```

---

## BUNDLED JSON-LD CONTEXTS

The following contexts are shipped with the tool as static files and NEVER fetched at runtime. Any code path that makes an HTTP request to resolve a context URL is a bug.

- `https://www.w3.org/ns/did/v1`
- `https://www.w3.org/ns/did/v1.1`
- `https://lf.org/ns/did/v1`
- `https://kernel.org/ns/did/v1`

Store them in `lf_did/contexts/data/` as `.json` files. The bundled context loader maps URLs to these files. New project contexts are added by PRing new files to this directory and releasing a new tool version.

---

## KEY STORAGE AND HARDWARE TOKEN INTERFACE

Key storage tiers (ascending security):

1. **Filesystem** — `~/.config/lf-did/private/<fragment>.pem` — acceptable for `contributor` tier only
2. **Encrypted USB** — LUKS/VeraCrypt; tool treats this as filesystem once mounted
3. **Hardware token** (YubiKey, Nitrokey, PKCS#11 / SSH agent) — required for tiers where `requires_hardware_key: true`. Key generated on device, never exported. Interface via SSH agent protocol.
4. **TPM 2.0 / HSM** — required for `automation` identities. Interface via ssh-agent or PKCS#11.

The hardware interface must:
- Enumerate tokens via ssh-agent (`ssh-add -L` equivalent)
- Generate a key on a token (`--generate-on-token`) without ever having the private key exist in software
- Sign using the SSH agent protocol (forward the signing request to the agent)
- Degrade gracefully if no agent is running: print an actionable error, exit nonzero
- Never extract or store private key material from a hardware token

---

## USER-FACING CONFIG

`~/.config/lf-did/projects.json`:
```json
{
  "kernel": {
    "registry": "~/src/kernel-did-registry",
    "context": "https://kernel.org/ns/did/v1"
  }
}
```

Project auto-detection algorithm:
1. Look for `lf-did.json` in the current directory and parent directories (same walk as `.git`)
2. If found, match `registry_url` against `registry_url` fields in all known project registry `policy/project.json` files
3. If match found, return that project name
4. If no match, return None (require explicit `--project` flag)
5. `--project <n>` always overrides

Registry freshness is checked against the mtime of the registry clone's `FETCH_HEAD` or the output of `git -C <path> log -1 --format=%ct`.

---

## COMPLETE COMMAND SPECIFICATION

All commands take `--project <n>` and `--registry <path>` as global overrides.

### Identity

| Command | Description |
|---------|-------------|
| `lf-did init [--generate-on-token] [--token] [--key-type ed25519\|p256\|p384] [--no-interactive]` | Create identity, prompt for details, output .json file for PR |
| `lf-did whoami` | Print own DID, fingerprint, tier, expiry |
| `lf-did edit` | Open identity doc in $EDITOR, re-sign on save |
| `lf-did set --field <f> --value <v> [--context <url>]` | Set field non-interactively, re-sign |
| `lf-did renew` | Extend lf:expires by up to 2 years, re-sign, output for PR |
| `lf-did rotate` | Generate new keypair, sign rotation record with old key, output both files for PR |
| `lf-did export-pubkey [--format ssh\|pem\|minisign]` | Export public key in requested format |

### Trust

| Command | Description |
|---------|-------------|
| `lf-did endorse <did> --tier <tier> --note <note>` | Build and sign endorsement, output for PR |
| `lf-did delegate --to <did> --scope <glob> --expires <date>` | Build and sign delegation, output for PR |
| `lf-did delegation list [--from-me] [--to-me]` | List active delegations |
| `lf-did delegation revoke --to <did>` | Revoke a delegation you created |
| `lf-did revoke <did> --reason <reason>` | Revoke someone else's DID |
| `lf-did self-revoke --reason <reason>` | Self-revoke |

### Signing

| Command | Description |
|---------|-------------|
| `lf-did tag <tagname> -m <message> [--detach]` | Create signed tag, store sig at refs/signatures/tags/<tagname> |
| `lf-did sign-file <file> [--format minisign]` | Sign file, write <file>.sig or <file>.minisig |
| `lf-did sign-object --output <sigfile> <payload-file>` | gpg.program shim signing |
| `lf-did countersign <sigfile>` | Countersign an existing signature document |

### Verification

| Command | Description |
|---------|-------------|
| `lf-did verify-tag <tagname> [--require-did <did>] [--minimum-tier <tier>] [--allow-stale]` | Verify tag signature |
| `lf-did verify-file <file> <file.sig> [--minimum-tier <tier>] [--allow-stale]` | Verify file signature |
| `lf-did verify-chain HEAD --anchor-commit <sha> [--allow-stale]` | Walk ancestry, verify all signed merges |
| `lf-did verify-object --signature <sigfile> --payload <payload-file> [--minimum-tier <tier>]` | gpg.program shim verification |
| `lf-did verify-identity <path>` | Verify a single identity document's selfSignature |
| `lf-did verify-registry [--against-root] [--fix] [--allow-stale]` | Full registry fsck |

### Registry management

| Command | Description |
|---------|-------------|
| `lf-did registry sync` | git fetch --prune against registry clone |
| `lf-did init-project <n>` | Create projects.json entry, clone registry |
| `lf-did project init` | Initialize new empty project registry |
| `lf-did project verify` | Alias for verify-registry |
| `lf-did project onboard` | Generate onboarding PR bundle for LF root |

### Devices

| Command | Description |
|---------|-------------|
| `lf-did device list` | List hardware tokens visible via ssh-agent / PKCS#11 |
| `lf-did device info` | Detailed info on connected token |
| `lf-did device attest` | Attest hardware key provenance |

### GPG interop

| Command | Description |
|---------|-------------|
| `lf-did import-from-gpg --fingerprint <fp>` | Create bootstrap attestation linking GPG key to new DID |
| `lf-did link-gpg --fingerprint <fp>` | Produce GpgLinkAttestation JSON signed by DID key |
| `lf-did import-key --from-pem\|--from-ssh\|--from-agent\|--from-gpg --key <path> [--fingerprint <fp>]` | Import key from various sources |

### Cross-project

| Command | Description |
|---------|-------------|
| `lf-did find-did <did>` | Search all configured project registries for DID |
| `lf-did cross-verify <did> --in-project <project>` | Verify DID chains to LF root across projects |
| `lf-did contributor-profile <did>` | Show all projects a DID is registered in |

### Automation

| Command | Description |
|---------|-------------|
| `lf-did init-automation --name <n> --scope <glob> --key-source tpm\|hsm --accountable-did <did>` | Register automation identity |

---

## PACKAGE STRUCTURE

```
src/lf_did/
  __init__.py
  py.typed

  cli/
    __init__.py
    main.py          # click group root, global flags
    init.py          # lf-did init, init-project, init-automation
    identity.py      # whoami, edit, set, export-pubkey
    endorse.py       # endorse
    delegate.py      # delegate, delegation list
    revoke.py        # revoke, self-revoke
    rotate.py        # rotate, renew
    sign.py          # sign-object, sign-file, countersign, tag
    verify.py        # verify-object, verify-tag, verify-file, verify-chain
    registry.py      # registry sync, verify-registry
    device.py        # device list, device info, device attest
    gpg.py           # import-from-gpg, link-gpg, import-key

  core/
    __init__.py
    did.py           # DID parsing, key extraction, multibase/multicodec
    crypto.py        # sign, verify, keygen for ed25519/P-256/P-384
    agent.py         # SSH agent protocol client
    jcs.py           # JCS canonicalization wrapper (RFC 8785)
    registry.py      # RegistryReader: loads and validates registry files
    tier.py          # TierGraph: derives ordering from tiers.json at runtime
    chain.py         # ChainVerifier: walks endorsement chain to anchor
    policy.py        # PolicyEnforcer: reads tiers.json, checks capabilities
    documents.py     # Typed dataclasses for all JSON-LD document types
    verifier.py      # SignatureVerifier: full 11-step verification sequence
    fsck.py          # RegistryFsck: exhaustive consistency checker
    linker.py        # RegistryLinker: resolves cross-document references
    formats.py       # minisign, SSH pubkey, PEM export/import

  contexts/
    __init__.py
    loader.py        # URL to bundled file mapping, never fetches
    data/
      w3c_did_v1.json
      w3c_did_v1_1.json
      lf_did_v1.json
      kernel_did_v1.json

  config/
    __init__.py
    projects.py      # ~/.config/lf-did/projects.json read/write
    detection.py     # auto-detect project from git remote / lf-did.json walk

  verify/
    __init__.py
    pipeline.py      # VerificationError, all 11 verification step functions
    tag.py           # verify-tag implementation
    file.py          # verify-file
    chain.py         # verify-chain (ancestry walk)
    object.py        # verify-object (shim)
    identity.py      # verify-identity (single doc)

  fsck/
    __init__.py
    checks.py        # individual fsck check functions, each returns list[FsckIssue]
    runner.py        # FsckRunner: runs all checks, aggregates, reports
    repair.py        # safe auto-repair operations

  shim/
    __init__.py
    gpg.py           # gpg.program subprocess interface, structured output

  gpg_import/
    __init__.py
    importer.py      # bootstrap attestation creation (only file that calls gpg subprocess)

  automation/
    __init__.py
    identity.py      # automation identity management
    tpm.py           # TPM 2.0 interface (graceful degrade if unavailable)

  project/
    __init__.py
    init.py          # new project registry initialization
    onboard.py       # LF root onboarding PR bundle

  cross/
    __init__.py
    find.py          # find-did across registries
    verify.py        # cross-project trust verification

  exceptions.py      # all custom exceptions, each with docstring
  constants.py       # multicodec prefixes, accepted key types

tests/
  __init__.py
  conftest.py        # shared fixtures, tmp registry setup helpers
  unit/
    test_multibase.py
    test_did_key.py
    test_jcs.py      # RFC 8785 test vectors + edge cases
    test_keys.py
    test_signing.py
    test_documents.py
    test_identity.py
    test_endorsement.py
    test_delegation.py
    test_revocation.py
    test_rotation.py
    test_git_signature.py
    test_gpg_bootstrap.py
    test_trust_chain.py
    test_tier_policy.py
    test_freshness.py
    test_registry_layout.py
    test_context_loader.py
    test_fsck_checks.py  # one test per fsck check ID
    test_shim_output.py
    test_agent.py
  integration/
    test_init_flow.py
    test_endorse_flow.py
    test_revoke_flow.py
    test_rotate_flow.py
    test_delegate_flow.py
    test_sign_verify_tag.py
    test_sign_verify_file.py
    test_verify_chain.py
    test_fsck_clean.py
    test_fsck_broken.py
    test_import_gpg.py
    test_automation.py
    test_cross_project.py
    test_shim_interface.py
    test_no_network.py   # proves no network calls made during any operation
    test_full_flow.py
    test_subprocess_interface.py
    test_multi_project.py
    test_adversarial.py
    test_tier_graph_exhaustive.py
  fixtures/
    registry/            # complete valid registry
    registry_broken/     # deliberately seeded with known errors
    keys/                # test key material
    documents/           # sample JSON for parse tests
    jcs_vectors/         # RFC 8785 appendix test vectors
    generate_fixtures.py # deterministic generator script

pyproject.toml
Makefile
README.md
.github/workflows/ci.yml
```

---

## LINKER SPECIFICATION

`lf_did/core/linker.py` (or `lf_did/trust/linker.py`) — `RegistryLinker` class.

The linker loads and indexes all documents from a registry clone into memory. It is the authoritative source of truth for verification and fsck. Instantiate once per verification operation; do not re-instantiate per check.

```python
class RegistryLinker:
    def __init__(self, registry_path: Path, tiers: TierPolicy) -> None: ...

    # Identity
    def get_identity(self, did: str) -> IdentityDocument | None: ...
    def get_all_dids(self) -> set[str]: ...
    def get_tier_for_did(self, did: str) -> str | None: ...

    # Endorsements
    def get_endorsements_for(self, did: str) -> list[EndorsementDocument]: ...
    def get_endorsements_by(self, did: str) -> list[EndorsementDocument]: ...

    # Delegations
    def get_delegations_from(self, did: str) -> list[DelegationDocument]: ...
    def get_active_delegation(
        self, delegator: str, delegate: str, ref: str, at_time: datetime
    ) -> DelegationDocument | None: ...
    def is_delegated_authority(self, did: str) -> bool: ...

    # Revocations
    def is_revoked(self, did: str) -> bool: ...
    def get_revocation(self, did: str) -> RevocationDocument | None: ...

    # Rotations
    def is_superseded(self, did: str) -> bool: ...
    def get_rotation(self, old_did: str) -> RotationRecord | None: ...

    # Trust
    def resolve_trust_chain(self, did: str) -> TrustChain: ...
    def get_effective_tier(self, did: str) -> str | None: ...
    def check_capability(self, did: str, capability: str) -> bool: ...
```

```python
@attrs.define
class TrustChain:
    subject: str
    links: list[TrustLink]   # ordered subject to anchor
    valid: bool
    reason: str | None
    chain_summary: str       # "contributor->maintainer:gregkh->anchor:torvalds"

@attrs.define
class TrustLink:
    did: str
    tier: str
    endorser_did: str | None
    endorsement_timestamp: datetime | None
```

`resolve_trust_chain` must detect and break cycles (max depth 20, raise `CircularTrustError` if exceeded). It must not recurse infinitely.

---

## FSCK CHECK CATALOG (IMPLEMENT ALL 41, MISS NONE)

Each check is a function `check_<ID>(linker, registry_path, tiers) -> list[FsckIssue]`.

```python
@attrs.define
class FsckIssue:
    check_id: str
    severity: Literal["ERROR", "WARNING", "INFO"]
    affected: list[str]      # file paths or DID strings
    description: str
    remediation: str
    auto_fixable: bool
```

### Structural (STRUCT)

- `STRUCT_001` ERROR: Required policy files missing (`trust-anchors.json`, `registry-admins.json`, `tiers.json`, `project.json`)
- `STRUCT_002` ERROR: Identity file not named by its DID fragment
- `STRUCT_003` ERROR: Identity file in wrong tier directory
- `STRUCT_004` ERROR: Endorsement file at wrong path
- `STRUCT_005` ERROR: Delegation file at wrong path
- `STRUCT_006` ERROR: Revocation file at wrong path
- `STRUCT_007` ERROR: Rotation file naming doesn't match oldDID/newDID
- `STRUCT_008` ERROR: `identities/` contains directory not named in `tiers.json`

### Cryptographic (CRYPTO)

- `CRYPTO_001` ERROR: Identity selfSignature fails verification
- `CRYPTO_002` ERROR: Endorsement signature fails verification
- `CRYPTO_003` ERROR: Delegation signature fails verification
- `CRYPTO_004` ERROR: Revocation signature fails verification
- `CRYPTO_005` ERROR: Rotation record not signed by old key
- `CRYPTO_006` ERROR: Git signature document has invalid nonce
- `CRYPTO_007` ERROR: DID fragment decodes to invalid or unsupported key type
- `CRYPTO_008` ERROR: GPG bootstrap attestation: either signature fails

### Trust graph (TRUST)

- `TRUST_001` ERROR: Identity tier exceeds what endorsement chain supports
- `TRUST_002` ERROR: Endorser lacks capability to endorse at tierVouched
- `TRUST_003` ERROR: Circular endorsement chain detected
- `TRUST_004` ERROR: Delegation issued by DID whose authority came via delegation
- `TRUST_005` ERROR: Anchor DID in trust-anchors.json has no identity file
- `TRUST_006` ERROR: Non-anchor identity has no valid endorsement at required tier
- `TRUST_007` WARNING: Identity endorsed by a subsequently revoked DID
- `TRUST_008` ERROR: Endorsement tierVouched exceeds endorser's can_endorse_up_to
- `TRUST_009` ERROR: Automation identity lf:accountableDID points to revoked or absent DID
- `TRUST_010` ERROR: Automation identity missing lf:accountableDID
- `TRUST_011` ERROR: Delegation delegate is below minimum tier for delegation recipients

### Expiry (EXPIRY)

- `EXPIRY_001` ERROR: Expired identity with no revocation and no rotation record
- `EXPIRY_002` WARNING: Delegation document is expired — auto-fixable
- `EXPIRY_003` WARNING: Identity expires within 60 days
- `EXPIRY_004` ERROR: lf:expires is more than 2 years after lf:registered

### Revocation (REVOKE)

- `REVOKE_001` ERROR: Revocation file for a DID with no identity file
- `REVOKE_002` ERROR: Self-revocation signature doesn't verify against subject's key
- `REVOKE_003` ERROR: Third-party revocation revoker lacks can_revoke_up_to >= subject tier
- `REVOKE_004` WARNING: Endorsements exist issued after revocation timestamp
- `REVOKE_005` ERROR: Revocation document lf:revoker is itself revoked

### Rotation (ROTATE)

- `ROTATE_001` ERROR: Rotation record signature doesn't verify against old key
- `ROTATE_002` ERROR: Old DID identity file absent from registry
- `ROTATE_003` WARNING: New DID has no identity file yet
- `ROTATE_004` WARNING: Signatures from old DID timestamped after rotation record

### Delegation (DELEG)

- `DELEG_001` ERROR: Delegate DID is below required tier for delegation recipients
- `DELEG_002` ERROR: lf:scope is not a valid ref glob
- `DELEG_003` WARNING: Expired delegation document with no revocation
- `DELEG_004` ERROR: Delegation from DID acting under delegation
- `DELEG_005` ERROR: Delegator lacks can_delegate capability

### Context (CTX)

- `CTX_001` ERROR: Document missing required base contexts
- `CTX_002` ERROR: Document uses project-prefix terms without project context URL
- `CTX_003` WARNING: Document references context URL not bundled with tool

### Consistency (CONS)

- `CONS_001` ERROR: lf:project in identity file doesn't match policy/project.json
- `CONS_002` ERROR: Duplicate DID fragment across multiple tier directories
- `CONS_003` WARNING: INDEX.md content is stale — auto-fixable
- `CONS_004` ERROR: Fingerprints in trust-anchors.json don't match actual key material
- `CONS_005` ERROR: registry-admins.json references DID not present as anchor-tier identity

### Auto-repair (`--fix`)

Only these checks are auto-fixable. Never auto-repair crypto failures or trust violations.

- `CONS_003`: Regenerate INDEX.md files in place
- `EXPIRY_002`: Write companion `.expired` marker file alongside expired delegation
- `STRUCT_008`: Report unknown tier directories, do NOT delete them

---

## PHASE DEFINITIONS

Execute phases in order. Each phase is a discrete Claude Code session. Commit after every phase before starting the next. If a phase returns `STATUS: BLOCKED` or `STATUS: FAILED`, resolve it before proceeding.

**Phase execution order:**
```
0 → 1 → 2 → 3 → 4 → 5a → 5b → 5c → 5d → 6 → 7a → 7b → 8a → 8b → 8c → 8d → 9a → 9b
```

**Session startup template** — paste at the top of every session after phase 0:
```
We are building lf-did. The following phases are complete and committed: [list].
Read the current state of src/ and tests/ before proceeding.
Constraints: no hardcoded tier names in core/, no network calls, mypy --strict must pass.
Proceed with phase [X] only. Stop when that phase's acceptance criteria all pass.
```

**Token budget note:** Phases 5a–5d and 8a–8d are the heaviest. Feed only the relevant
phase section plus the NORMATIVE REQUIREMENTS SUMMARY when starting those sessions.
Do not paste the full prompt — the spec sections (document formats, fsck catalog, etc.)
are in the codebase by that point and Claude Code can read them from disk.

---

### PHASE 0: Project Scaffold

**TASK_ID:** `phase-0-scaffold`
**DEPENDS_ON:** none
**INPUTS:** This prompt document
**DELIVERABLES:**
- `pyproject.toml` with full metadata, dependencies, and entry points
- `src/lf_did/__init__.py`
- `src/lf_did/py.typed`
- `tests/__init__.py`
- `tests/conftest.py` with shared fixtures
- `Makefile` with targets: `test`, `lint`, `typecheck`, `fsck-demo`
- `.github/workflows/ci.yml` running all checks

**ACCEPTANCE_CRITERIA:**
1. `pip install -e ".[dev]"` succeeds in a clean virtualenv
2. `lf-did --help` prints usage without error
3. `pytest tests/` collects tests (may be 0 at this stage, must not error)
4. `mypy src/lf_did` passes with zero errors
5. `ruff check src/` passes

**INSTRUCTIONS:**

Package name: `lf_did`. Entry point CLI command: `lf-did`.

Dependencies (production): `cryptography>=42`, `jcs>=0.2`, `click>=8.1`, `attrs>=23`, `cattrs>=23`, `gitpython>=3.1`, `platformdirs>=4`

Dependencies (dev/test): `pytest>=8`, `pytest-cov`, `mypy`, `ruff`, `hypothesis`

`conftest.py` must define:
- `fixture: tmp_registry(tmp_path)` — creates a minimal valid registry directory tree with a synthetic anchor, one maintainer, one contributor, valid tiers.json
- `fixture: synthetic_did_key(key_type)` — generates a fresh did:key for each key type
- `fixture: mock_ssh_agent` — a pytest fixture that stands up an in-process mock SSH agent (`MockAgentClient`)

---

### PHASE 1: DID Primitives and Cryptography

**TASK_ID:** `phase-1-crypto`
**DEPENDS_ON:** `phase-0-scaffold`

**DELIVERABLES:**
- `src/lf_did/core/did.py` (complete)
- `src/lf_did/core/crypto.py` (complete)
- `src/lf_did/core/agent.py` (complete)
- `src/lf_did/core/jcs.py` (complete)
- `src/lf_did/constants.py` (complete)
- `tests/unit/test_did_key.py`, `test_crypto.py`, `test_agent.py`, `test_jcs.py`, `test_multibase.py`, `test_keys.py`, `test_signing.py`

**ACCEPTANCE_CRITERIA:**
1. `DIDKey.from_string("did:key:z6Mk...")` correctly decodes ed25519 public key bytes for known test vectors
2. `DIDKey.from_string("did:key:zDn...")` correctly decodes P-256
3. `DIDKey.from_string("did:key:z82...")` correctly decodes P-384
4. secp256k1 keys raise `UnsupportedKeyTypeError`
5. Round-trip: generate ed25519 key → encode as did:key → decode → verify original bytes match
6. Round-trips for P-256 and P-384
7. `sign_bytes(private_key, payload)` + `verify_bytes(public_key, payload, sig)` round-trips for all three key types
8. JCS canonicalization of `{"b": 2, "a": 1}` produces `{"a":1,"b":2}` (per RFC 8785 test vectors)
9. JCS of nested objects with unicode matches RFC 8785 test vectors
10. SSH agent mock: `AgentClient.sign(key_fingerprint, data)` returns bytes that verify against the corresponding public key
11. `AgentClient.list_keys()` returns the keys loaded into the mock agent
12. All DID round-trips pass under `hypothesis` property-based testing
13. Zero mypy errors in these modules

**INSTRUCTIONS:**

`did.py` — implement `DIDKey`:
- Parse `did:key:<multibase>` strings; only `z` prefix (base58btc) accepted
- Multicodec prefixes: `0xed01` = ed25519, `0x1200` = P-256, `0x1201` = P-384
- Reject any other multicodec prefix with `UnsupportedKeyTypeError`
- `DIDKey.fragment` property returns the multibase string (everything after `did:key:`)
- `DIDKey.public_key_bytes` returns raw key bytes
- `DIDKey.to_verification_method_id()` returns `did:key:<fragment>#<fragment>`
- `DIDKey.fingerprint()` returns `SHA256:<base64>` matching ssh-keygen's format for the equivalent SSH key

`crypto.py` — implement `KeyPair` and signing:
- `KeyPair.generate(key_type: KeyType)` → generates fresh key, returns `KeyPair`
- `KeyPair.from_private_key_pem(pem: bytes)` → loads from PKCS#8 PEM
- `KeyPair.to_private_key_pem()` → exports to PKCS#8 PEM (encrypted with passphrase if provided)
- `KeyPair.to_did_key()` → returns `DIDKey`
- `KeyPair.sign(payload: bytes) → bytes` — signs; ed25519 produces raw 64-byte sig; P-256/P-384 produce DER-encoded ECDSA
- `verify_signature(did_key: DIDKey, payload: bytes, signature: bytes) → bool`
- All operations use `cryptography` library exclusively

`agent.py` — SSH agent client (binary protocol, RFC 4253 / OpenSSH extensions):
- Connect to `$SSH_AUTH_SOCK`
- `AgentClient.list_keys() → list[AgentKey]` — SSH2_AGENTC_REQUEST_IDENTITIES
- `AgentClient.sign(key_blob: bytes, data: bytes, flags: int) → bytes` — SSH2_AGENTC_SIGN_REQUEST
- `AgentClient.find_key_by_fingerprint(fp: str) → AgentKey | None`
- `MockAgentClient` backed by in-memory `KeyPair` list, conforming to same interface
- For ed25519 agent keys: flags=0; for P-256/P-384: flags=0

`jcs.py` — thin wrapper:
- `canonicalize(obj: dict) → bytes`
- `canonicalize_excluding(obj: dict, exclude_keys: set[str]) → bytes` — used for self-signature computation (exclude the signature field itself)

**Public API handoff:**
```python
# lf_did.core.did
class DIDKey: ...
# lf_did.core.crypto
class KeyPair: ...
def verify_signature(did_key: DIDKey, payload: bytes, signature: bytes) -> bool: ...
# lf_did.core.agent
class AgentClient: ...
class MockAgentClient: ...
# lf_did.core.jcs
def canonicalize(obj: dict) -> bytes: ...
def canonicalize_excluding(obj: dict, exclude_keys: set[str]) -> bytes: ...
# lf_did.constants
def multibase_encode(data: bytes) -> str: ...
def multibase_decode(s: str) -> bytes: ...
def did_key_from_public_key(key_type: str, public_key_bytes: bytes) -> str: ...
def public_key_from_did_key(did: str) -> tuple[str, bytes]: ...
def generate_keypair(key_type: str) -> tuple[bytes, bytes]: ...
def jcs_canonicalize(obj: dict) -> bytes: ...
def sign(private_key_bytes: bytes, key_type: str, payload: bytes) -> bytes: ...
def verify(public_key_bytes: bytes, key_type: str, payload: bytes, sig: bytes) -> bool: ...
def base64url_encode(data: bytes) -> str: ...
def base64url_decode(s: str) -> bytes: ...
```

---

### PHASE 2: Document Types, Tier Graph, and Policy

**TASK_ID:** `phase-2-documents`
**DEPENDS_ON:** `phase-1-crypto`

**DELIVERABLES:**
- `src/lf_did/core/documents.py` (complete)
- `src/lf_did/core/tier.py` (complete)
- `src/lf_did/core/policy.py` (complete)
- `tests/unit/test_documents.py`, `test_identity.py`, `test_endorsement.py`, `test_delegation.py`, `test_revocation.py`, `test_rotation.py`, `test_git_signature.py`, `test_gpg_bootstrap.py`, `test_tier.py`, `test_policy.py`

**ACCEPTANCE_CRITERIA:**
1. `IdentityDocument` parses and round-trips all example JSON-LD documents from the spec
2. `EndorsementDocument`, `DelegationDocument`, `RevocationDocument`, `RotationDocument`, `GitSignatureDocument`, `GPGBootstrapAttestation` parse correctly
3. `TierGraph.from_tiers_json(tiers_dict)` constructs a graph from any valid `tiers.json`
4. `TierGraph.ordering()` returns tiers sorted highest-to-lowest by deriving order from `can_endorse_up_to` edges — no hardcoded names
5. `TierGraph.ordering()` works for both kernel (anchor→maintainer→contributor→automation) and Kubernetes (steering→lead→approver→reviewer→member→automation) examples
6. `TierGraph.is_at_least(tier_a, tier_b)` returns True iff tier_a is same or higher rank than tier_b
7. `TierGraph.top_minus_one()` returns the tier one below anchor
8. `PolicyEnforcer.can_endorse(endorser_tier, target_tier)` enforces `can_endorse_up_to`
9. `PolicyEnforcer.can_sign_ref(tier, ref)` enforces `can_sign_refs` glob matching
10. `PolicyEnforcer.can_revoke(revoker_tier, target_tier)` enforces `can_revoke_up_to`
11. `PolicyEnforcer.can_delegate(tier)` enforces `can_delegate`
12. Tier graph with a cycle raises `TierGraphCycleError`
13. Tier graph with multiple roots raises `TierGraphMultipleRootsError`
14. All document types validate required fields and raise `DocumentValidationError` with field name on missing/invalid fields
15. Zero mypy errors

**INSTRUCTIONS:**

`documents.py` — typed dataclasses using `attrs` with validators for every document type:

```python
@attrs.define
class IdentityDocument:
    context: list[str]
    id: str               # did:key URI
    verification_method: list[VerificationMethod]
    authentication: list[str]
    name: str
    email: str
    also_known_as: list[str]
    project: str          # lf:project
    tier: str             # lf:tier
    registered: datetime
    expires: datetime
    self_signature: str   # base64url; field name varies by project prefix
    extra_fields: dict    # unknown fields preserved for round-trip
    raw: dict             # original parsed dict, preserved for signature verification

    @classmethod
    def from_dict(cls, d: dict, project_prefix: str) -> "IdentityDocument": ...
    def to_dict(self) -> dict: ...
    def compute_self_signature_payload(self) -> bytes:
        # JCS canonicalize with self_signature field absent
    def verify_self_signature(self, did_key: DIDKey) -> bool: ...
    def is_expired(self, at_time: datetime) -> bool: ...
```

Similarly for all other document types. Include `VerificationError(result: VerificationResult, detail: str)` in `documents.py`. Include `VerificationResult` enum: `GOOD`, `BAD`, `EXPIRED`, `REVOKED`, `UNTRUSTED`, `ERROR`.

`tier.py` — `TierGraph`:

The tier ordering algorithm: build a directed graph where edge A→B means "A can endorse up to B" (i.e., A is above B). Find the unique root (no incoming edges). BFS/topological sort to assign ranks. Detect cycles and multiple roots as errors. The `automation` tier has `can_endorse_up_to: null` and is always a leaf — handle this: automation is always last regardless of ordering. **The algorithm must never inspect tier names. It operates purely on the graph structure.**

`policy.py` — `PolicyEnforcer`:
- Reads `policy/tiers.json` from registry
- Delegates ordering to `TierGraph`
- Glob matching for `can_sign_refs`: use `fnmatch.fnmatch`
- All capability checks log their decision (DEBUG level) with tier, capability, and result

---

### PHASE 3: Registry Reader and Chain Verifier

**TASK_ID:** `phase-3-registry`
**DEPENDS_ON:** `phase-2-documents`

**DELIVERABLES:**
- `src/lf_did/core/registry.py` (complete)
- `src/lf_did/core/chain.py` (complete)
- `tests/unit/test_registry_layout.py`, `test_context_loader.py`, `test_trust_chain.py`, `test_freshness.py`

**ACCEPTANCE_CRITERIA:**
1. `RegistryReader(path)` loads all identity documents from all tier subdirectories under `identities/` without knowing tier names in advance
2. `RegistryReader.get_identity(did_fragment)` returns the `IdentityDocument` or raises `IdentityNotFoundError`
3. `RegistryReader.get_endorsements_for(did_fragment)` returns all endorsement documents in `endorsements/<fragment>/`
4. `RegistryReader.get_delegation(delegator_fragment, delegate_fragment)` returns delegation or None
5. `RegistryReader.is_revoked(did_fragment)` checks `revocations/<fragment>.json` existence and validates the revocation document
6. `RegistryReader.get_rotation(old_fragment)` returns the rotation document if present
7. `RegistryReader.get_trust_anchors()` reads `policy/trust-anchors.json`
8. Atomic file writer: write to `.tmp`, rename
9. INDEX.md generator: sort by name; columns: Name, Email, DID Fragment first 16 chars + ..., Tier, Expires
10. Clone freshness checker: warn >7d, fail >30d
11. Context loader: maps all four URLs to bundled files, raises `UnknownContextError` on unmapped URL
12. `ChainVerifier.verify(did: DIDKey, registry: RegistryReader) → ChainResult` walks endorsements from subject to anchor
13. Chain walk correctly handles: direct anchor endorsement, multi-hop chain, delegation path
14. Chain walk fails if any intermediate endorser is revoked or expired
15. Chain walk fails if any endorsement document's signature is invalid
16. `ChainResult.chain_summary` produces: `did:key:z6Mk... → did:key:z6Mk... → LF root anchor`
17. `ChainVerifier` with missing anchor returns `ChainResult.terminated_at_unknown_anchor = True` with warning (not hard failure)
18. All tests pass with synthetic registry from `tmp_registry` fixture

**INSTRUCTIONS:**

`registry.py` — `RegistryReader`:
- Takes a filesystem path to a cloned registry repo
- Lazy-loads documents on first access, caches them
- Must scan all tier subdirectories without knowing their names in advance
- Context bundling: JSON-LD `@context` URIs resolved from `src/lf_did/contexts/data/` bundle — never network fetched

`chain.py` — `ChainVerifier`:

The endorsement chain walk algorithm:
1. Load identity document for target DID
2. Verify identity document self-signature
3. Check identity not revoked
4. Check identity not expired
5. Load all endorsements for target DID
6. For each endorsement: verify endorsement signature using endorser's DID key (decoded from `did:key` — local computation)
7. Check endorser is in registry, not revoked, not expired
8. Check endorser's tier satisfies `can_endorse_up_to >= target_tier` (using TierGraph)
9. Check if endorser is a trust anchor (in `policy/trust-anchors.json`)
10. If yes: chain terminates successfully
11. If no: recurse on endorser (depth limit: 20, raise `ChainDepthExceededError` beyond that)
12. Return `ChainResult` with full path, success/fail, and reason

---

### PHASE 4: Signature Verifier (11-Step)

**TASK_ID:** `phase-4-verifier`
**DEPENDS_ON:** `phase-3-registry`

**DELIVERABLES:**
- `src/lf_did/core/verifier.py` (complete)
- `src/lf_did/verify/pipeline.py` (complete — all 11 step functions)
- `src/lf_did/verify/tag.py`, `file.py`, `chain.py`, `object.py`, `identity.py`
- `tests/unit/test_verifier.py`, `test_shim_output.py`

**ACCEPTANCE_CRITERIA:**
1. `SignatureVerifier.verify(sig_doc, object_sha, registry, policy) → VerificationResult` implements all 11 steps
2. Step 1: Parses signature document, extracts signer DID and signature bytes
3. Step 2: Verifies nonce equals first 32 hex chars of `lf:objectSha`
4. Step 3: Decodes public key from `did:key` (local computation)
5. Step 4: Verifies cryptographic signature over JCS-canonicalized payload
6. Step 5: Looks up signer in registry
7. Step 6: Verifies identity document self-signature
8. Step 7: Walks endorsement chain to project anchor
9. Step 8: Checks LF root chain if root registry clone available (skips gracefully if not)
10. Step 9: Checks revocation records
11. Step 10: Checks identity expiry
12. Step 11: Checks tier satisfies minimum tier policy if configured
13. Clock skew tolerance: accept signatures up to 5 minutes in the future
14. `VerificationResult.to_subprocess_output()` produces the key-value line format
15. `VerificationResult.from_subprocess_output(text) → VerificationResult` inverse parser
16. Failing step 3 (bad crypto sig) → `BAD`; step 4 (nonce mismatch) → `BAD`
17. Failing step 9 (revoked) → `REVOKED`; step 10 (expired) → `EXPIRED`; step 11 (tier too low) → `UNTRUSTED`
18. Exception during any step → `ERROR` with diagnostic
19. Zero network calls (verified by patching `socket.create_connection` — must never be reached)

**INSTRUCTIONS:**

Subprocess output format (stdout, key: value, one per line):
```
RESULT:      GOOD
SIGNER:      did:key:z6Mk...
NAME:        Linus Torvalds <torvalds@linux-foundation.org>
TIER:        anchor
PROJECT:     kernel
SIGNED:      2025-01-20T14:32:00Z
EXPIRES:     2026-01-01T00:00:00Z (valid)
REVOKED:     no
CHAIN:       did:key:z6Mk... → LF root anchor
TIER_CHECK:  pass
```

---

### PHASE 5a: Fsck Infrastructure + Structural + Crypto Checks

**TASK_ID:** `phase-5a-fsck-struct-crypto`
**DEPENDS_ON:** `phase-4-verifier`

**DELIVERABLES:**
- `src/lf_did/fsck/__init__.py`
- `src/lf_did/fsck/checks.py` — `FsckCheck` base, `FsckIssue` dataclass, and checks `STRUCT_001`–`STRUCT_008`, `CRYPTO_001`–`CRYPTO_008` (16 checks total)
- `src/lf_did/fsck/runner.py` — `FsckRunner` skeleton (wires whatever checks exist)
- `src/lf_did/core/fsck.py` — `RegistryFsck` facade
- `tests/unit/test_fsck_checks.py` — positive and negative test for each of the 16 checks above

**ACCEPTANCE_CRITERIA:**
1. `FsckCheck` base class defined with `name`, `description`, `run(linker, registry_path, tiers) -> list[FsckIssue]`
2. `FsckIssue` dataclass: `check_id`, `severity`, `affected`, `description`, `remediation`, `auto_fixable`
3. All 8 STRUCT checks implemented and individually testable
4. All 8 CRYPTO checks implemented and individually testable
5. `FsckRunner.run(registry_path)` executes all registered checks and returns `FsckReport`
6. `FsckReport` has `.errors`, `.warnings`, `.ok` (True only if zero errors), `.to_text()`
7. `pytest tests/unit/test_fsck_checks.py -k "STRUCT or CRYPTO"` exits 0
8. Zero mypy errors

**INSTRUCTIONS:**

Implement `FsckCheck` as a collection of objects, each with a `run()` method, so individual checks can be invoked in isolation. `FsckRunner` discovers all registered checks automatically (no manual list maintenance — use a class registry or module-level list).

Do not implement TRUST, EXPIRY, REVOKE, ROTATE, DELEG, CTX, or CONS checks yet. Leave stubs or pass-through if the runner needs them — they come in 5b–5d.

---

### PHASE 5b: Trust Graph Checks

**TASK_ID:** `phase-5b-fsck-trust`
**DEPENDS_ON:** `phase-5a-fsck-struct-crypto`

**DELIVERABLES:**
- Add `TRUST_001`–`TRUST_011` (11 checks) to `src/lf_did/fsck/checks.py`
- Add tests for all 11 to `tests/unit/test_fsck_checks.py`

**ACCEPTANCE_CRITERIA:**
1. All 11 TRUST checks implemented per the FSCK CHECK CATALOG
2. `TRUST_003` (circular chain): genuine A→B→A cycle detected, no infinite loop
3. `TRUST_004` (delegation from delegated authority): correctly walks delegation chain to detect
4. `TRUST_009` and `TRUST_010` (automation accountableDID): both present and absent cases tested
5. `pytest tests/unit/test_fsck_checks.py -k "TRUST"` exits 0
6. Full `pytest tests/unit/test_fsck_checks.py` still exits 0 (5a checks not broken)
7. Zero mypy errors

**INSTRUCTIONS:**

Each TRUST check gets one positive test (error condition seeded into a `tmp_registry`) and one negative test (clean registry). Use real crypto for seeded errors — do not mock signature verification.

---

### PHASE 5c: Expiry, Revocation, and Rotation Checks

**TASK_ID:** `phase-5c-fsck-expiry-revoke-rotate`
**DEPENDS_ON:** `phase-5b-fsck-trust`

**DELIVERABLES:**
- Add `EXPIRY_001`–`EXPIRY_004`, `REVOKE_001`–`REVOKE_005`, `ROTATE_001`–`ROTATE_004` (13 checks) to `src/lf_did/fsck/checks.py`
- Add tests for all 13 to `tests/unit/test_fsck_checks.py`

**ACCEPTANCE_CRITERIA:**
1. All 13 checks implemented per the FSCK CHECK CATALOG
2. `EXPIRY_003` warns (not errors) for identities expiring within 60 days
3. `EXPIRY_004` errors for `lf:expires` > 2 years after `lf:registered`
4. `REVOKE_004` correctly timestamps comparison (endorsement after revocation timestamp)
5. `ROTATE_001` uses the OLD key for verification (not new key)
6. `pytest tests/unit/test_fsck_checks.py -k "EXPIRY or REVOKE or ROTATE"` exits 0
7. Full `pytest tests/unit/test_fsck_checks.py` still exits 0
8. Zero mypy errors

---

### PHASE 5d: Delegation, Context, Consistency Checks + Linker + Repair

**TASK_ID:** `phase-5d-fsck-deleg-ctx-cons-linker`
**DEPENDS_ON:** `phase-5c-fsck-expiry-revoke-rotate`

**DELIVERABLES:**
- Add `DELEG_001`–`DELEG_005`, `CTX_001`–`CTX_003`, `CONS_001`–`CONS_005` (13 checks) to `src/lf_did/fsck/checks.py`
- Add tests for all 13 to `tests/unit/test_fsck_checks.py`
- `src/lf_did/fsck/repair.py` — `repair()` for `CONS_003`, `EXPIRY_002`, `STRUCT_008`
- `src/lf_did/core/linker.py` — complete `RegistryLinker` per the LINKER SPECIFICATION section
- Add `tests/unit/test_linker.py`

**ACCEPTANCE_CRITERIA:**
1. All 13 checks implemented per the FSCK CHECK CATALOG
2. `DELEG_004` and `DELEG_005` correctly interact with delegation chain detection from TRUST_004
3. `CTX_003` warns (not errors) for unknown context URLs
4. `CONS_003` is marked `auto_fixable=True`; `repair()` regenerates INDEX.md correctly
5. `EXPIRY_002` is marked `auto_fixable=True`; `repair()` writes `.expired` marker file
6. `STRUCT_008` repair reports but does NOT delete unknown directories
7. `RegistryLinker` implements full API from LINKER SPECIFICATION section
8. `RegistryLinker.resolve_trust_chain()` raises `CircularTrustError` at depth >20, not infinite loop
9. `RegistryLinker.dangling_references()` returns endorsements/delegations/revocations referencing absent DIDs
10. Verify all 41 check IDs present: `grep -o 'check_id="[A-Z_0-9]*"' src/lf_did/fsck/checks.py | wc -l` prints 41
11. `pytest tests/unit/test_fsck_checks.py` exits 0 — all 82 test cases (41 positive + 41 negative)
12. `pytest tests/unit/test_linker.py` exits 0
13. Zero mypy errors

---

### PHASE 6: Signing Operations and Key Formats

**TASK_ID:** `phase-6-signing`
**DEPENDS_ON:** `phase-5d-fsck-deleg-ctx-cons-linker`

**DELIVERABLES:**
- `src/lf_did/cli/sign.py` (complete)
- `src/lf_did/cli/verify.py` (complete — subprocess interface)
- `src/lf_did/core/formats.py` (complete)
- `tests/unit/test_sign.py`, `test_verify_cli.py`, `test_formats.py`

**ACCEPTANCE_CRITERIA:**
1. `lf-did sign-object --output <sigfile> <payload-file>` writes a valid `GitSignatureDocument` JSON
2. The written document passes `SignatureVerifier.verify()` against the same registry
3. `lf:nonce` field equals first 32 hex chars of SHA-256 of the payload file
4. `lf:objectSha` equals full SHA-256 of the payload file
5. `lf-did verify-object --signature <sigfile> --payload <payload-file>` exits 0 and prints structured output for valid signature
6. `lf-did verify-object` exits non-zero for tampered payload, tampered signature, revoked signer, expired signer
7. `lf-did verify-object --minimum-tier maintainer` exits non-zero when signer is contributor tier
8. `lf-did sign-file <file>` produces detached `.sig` file in same JSON-LD format
9. `lf-did sign-file --format minisign <file>` produces `.minisig` file that structurally validates
10. `lf-did verify-file <file> <file.sig>` verifies a detached signature file
11. `lf-did export-pubkey --format ssh` outputs valid SSH public key line
12. `lf-did export-pubkey --format pem` outputs valid PEM public key
13. `lf-did export-pubkey --format minisign` outputs valid minisign public key line
14. Minisign key ID derived deterministically from the DID public key (not random)
15. All sign/verify operations use `MockAgentClient` in tests (no real SSH agent required)

**INSTRUCTIONS:**

`formats.py`:

SSH public key format: `ssh-ed25519 <base64> <did:key>` where comment is full DID URI. P-256: `ecdsa-sha2-nistp256 <base64> <did:key>`. P-384: `ecdsa-sha2-nistp384 <base64> <did:key>`.

Minisign format:
- Public key line: `RW<base64>` where base64 encodes: 2-byte algorithm identifier (`Ed`) + 8-byte key ID + 32-byte ed25519 public key
- Key ID derivation: first 8 bytes of SHA-256 of the raw ed25519 public key bytes (deterministic from DID)
- Signature file: one-line comment (`untrusted comment: ...`), then base64 of: 2-byte algorithm identifier + 8-byte key ID + 64-byte ed25519 signature
- P-256 and P-384 keys produce a native `.sig` file (JSON-LD format) when `--format minisign` is requested, with a warning

Git signature payload construction:
```python
def build_git_signature_payload(
    object_sha: str,     # SHA-256 hex of git object
    ref: str,            # e.g. "refs/tags/v6.12"
    signer_did: DIDKey,
    project: str,
    project_prefix: str, # "kernel", "lf", etc.
    context_urls: list[str],
) -> dict:
    nonce = object_sha[:64]  # first 32 bytes = 64 hex chars
    payload = {
        "@context": context_urls,
        "type": f"{project_prefix}:GitSignature",
        f"{project_prefix}:objectType": "tag",
        f"{project_prefix}:objectSha": object_sha,
        f"{project_prefix}:ref": ref,
        f"{project_prefix}:signer": str(signer_did),
        f"{project_prefix}:timestamp": datetime.utcnow().isoformat() + "Z",
        f"{project_prefix}:nonce": nonce,
    }
    return payload
```

Sign the JCS-canonicalized payload, append `lf:signature` (base64url, no padding), write JSON to output file.

---

### PHASE 7a: Core Identity Lifecycle

**TASK_ID:** `phase-7a-lifecycle-core`
**DEPENDS_ON:** `phase-6-signing`

**DELIVERABLES:**
- `src/lf_did/cli/init.py` (complete)
- `src/lf_did/cli/identity.py` (complete — `whoami`, `edit`, `set`, `renew`, `export-pubkey`)
- `src/lf_did/cli/endorse.py` (complete)
- `src/lf_did/cli/delegate.py` (complete)
- `src/lf_did/cli/revoke.py` (complete)
- `src/lf_did/cli/rotate.py` (complete)
- `src/lf_did/config/projects.py` (complete)
- `src/lf_did/config/detection.py` (complete)
- `tests/unit/test_lifecycle_core.py`

**ACCEPTANCE_CRITERIA:**
1. `lf-did init --no-interactive` generates valid identity document JSON with correct self-signature
2. Generated identity document passes `IdentityDocument.verify_self_signature()`
3. `lf-did whoami` prints DID and fingerprint
4. `lf-did endorse <did> --tier contributor --note "..."` produces valid `EndorsementDocument` with correct signature
5. Endorsement fails with `PolicyViolationError` if endorser's tier cannot endorse to target tier
6. `lf-did delegate --to <did> --scope "refs/tags/v*-stable" --expires <date>` produces valid `DelegationDocument`
7. `lf-did delegate` fails if delegator's `can_delegate` is false
8. `lf-did revoke <did> --reason "..."` produces valid `RevocationDocument`
9. `lf-did revoke` fails if revoker's tier cannot revoke target's tier
10. `lf-did self-revoke --reason "..."` produces `RevocationDocument` signed by subject's own key
11. `lf-did rotate` produces: updated identity document with new key, `RotationDocument` linking old→new; old key signs rotation, new key signs new identity
12. `lf-did renew` produces updated identity document with new `expires` date (max 2 years from `registered`), re-signed
13. `lf-did edit --field <f> --value <v>` updates field and re-signs
14. Project auto-detection: `detection.py` walks parent dirs for `lf-did.json`, matches `registry_url` against configured projects
15. All operations use `MockAgentClient` in tests

**INSTRUCTIONS:**

`init.py`:
- `--generate-on-token`: enumerates hardware keys via `AgentClient`; uses first ed25519 key; fails if none
- `--token`: same but prompts user to select from list
- Default: generates software key, stores at `~/.config/lf-did/private/key.pem` (encrypted)
- `--no-interactive`: non-interactive with defaults, for CI and testing
- `lf-did init-project <n>`: adds entry to `projects.json`, clones registry

`rotate.py`:
- Old key signs rotation document (proves possession of old key)
- New key signs new identity document (proves possession of new key)
- Both documents produced atomically
- Old key must still be accessible during rotation

---

### PHASE 7b: Device, GPG Interop, Registry, and Cross-Project Commands

**TASK_ID:** `phase-7b-lifecycle-edge`
**DEPENDS_ON:** `phase-7a-lifecycle-core`

**DELIVERABLES:**
- `src/lf_did/cli/device.py` (complete — `device list`, `device info`, `device attest`)
- `src/lf_did/cli/gpg.py` (complete — `import-from-gpg`, `link-gpg`, `import-key`)
- `src/lf_did/cli/registry.py` (complete — `registry sync`, `verify-registry`, `project init`, `project onboard`)
- `src/lf_did/gpg_import/importer.py` (complete)
- `src/lf_did/automation/identity.py` (complete)
- `src/lf_did/automation/tpm.py` (graceful degrade stub if TPM not available)
- `src/lf_did/cross/find.py`, `cross/verify.py` (complete)
- `src/lf_did/project/init.py`, `project/onboard.py` (complete)
- `tests/unit/test_lifecycle_edge.py`

**ACCEPTANCE_CRITERIA:**
1. `lf-did device list` with `MockAgentClient` lists keys; with no agent raises `AgentNotAvailableError`
2. `lf-did link-gpg --fingerprint <fp>` produces `GpgLinkAttestation` JSON signed by DID key; does NOT import GPG private key
3. `lf-did import-from-gpg --fingerprint <fp>` produces dual-signed `GPGBootstrapAttestation` via `gpg` subprocess; both signatures verify against respective keys
4. `lf-did import-key --from-pem --key <path>` produces identity document for imported key
5. `lf-did import-key --from-ssh --key <path>` reads SSH private key and produces identity document
6. `lf-did import-key --from-agent --fingerprint <fp>` reads from SSH agent by fingerprint
7. `import-key --from-gpg` errors on RSA/DSA keys (only ed25519/P-256/P-384 accepted)
8. `lf-did registry verify-registry` runs `RegistryFsck`, exits 0 on clean registry, non-zero on errors
9. `lf-did init-automation --key-source tpm --accountable-did <did> --scope <glob>` rejects software keys
10. `lf-did find-did <did>` searches all configured project registries
11. `lf-did --help` lists all commands without error; all subcommands have `--help`
12. `subprocess.run(["gpg", ...])` only appears in `lf_did/gpg_import/importer.py` — verified by grep
13. All operations use `MockAgentClient` in tests; no real SSH agent or GPG required

**INSTRUCTIONS:**

`gpg.py`:
- `link-gpg`: produces `GpgLinkAttestation` — does NOT import GPG private key
- `import-key --from-gpg`: calls `gpg --export-secret-key <fp>` via subprocess, extracts key bytes, errors on RSA/DSA
- `import-key --from-ssh`, `--from-agent`, `--from-pem`: as specified in COMPLETE COMMAND SPECIFICATION

`automation/tpm.py`: wrap TPM interface with graceful degrade — if `tpm2-tools` or equivalent not found, raise `TpmNotAvailableError` with actionable message. Do not fail import.

---

### PHASE 8a: Integration — Happy Path Flows

**TASK_ID:** `phase-8a-integration-happy`
**DEPENDS_ON:** `phase-7b-lifecycle-edge`

**DELIVERABLES:**
- `tests/integration/test_full_flow.py`
- `tests/integration/test_subprocess_interface.py`
- `tests/integration/test_init_flow.py`
- `tests/integration/test_endorse_flow.py`
- `tests/integration/test_revoke_flow.py`
- `tests/integration/test_rotate_flow.py`
- `tests/integration/test_delegate_flow.py`
- `tests/integration/test_sign_verify_tag.py`
- `tests/integration/test_sign_verify_file.py`
- `tests/integration/test_verify_chain.py`

**ACCEPTANCE_CRITERIA:**
1. Full flow (kernel-style): anchor → maintainer (endorsed) → contributor (endorsed) → contributor signs fake git object → `verify-object` returns `RESULT: GOOD` → `verify-registry` returns 0 errors
2. Full flow (Kubernetes-style): synthetic registry with `steering/lead/approver/reviewer/member` tiers — same lifecycle passes
3. `lf-did sign-object` as subprocess → `lf-did verify-object` as subprocess → exit 0, structured output parsed correctly
4. `init` → `rotate` → old-key signatures still verify; new key required for new ops
5. `init` → `delegate --scope "refs/tags/v*"` → sign tag under delegation → `verify-tag`: GOOD
6. `delegate` → attempt re-delegate of delegated authority: rejected with correct error
7. `sign-file` → `verify-file`: GOOD
8. `sign-file` → corrupt `.sig` → `verify-file`: BAD, non-zero exit
9. `tag` + `verify-tag`: GOOD
10. `tag` → stale registry (mock `FETCH_HEAD` mtime > 7d): warn but continue
11. `tag` → stale registry (mock mtime > 30d): fail unless `--allow-stale`
12. `verify-chain` on 5 signed merges: exit 0
13. `verify-chain` with one invalid sig: reports correct commit, non-zero exit
14. All tests use real git repos (`git init` in `tmp_path`), `MockAgentClient`, real crypto — no mocking of git or crypto
15. `pytest tests/integration/test_full_flow.py tests/integration/test_subprocess_interface.py -v` exits 0

**INSTRUCTIONS:**

`test_full_flow.py`: Build from scratch in `tmp_path`. Create `TmpRegistry` helper. Use `MockAgentClient` with generated keys. Assert every produced document passes its validator. Assert `RegistryFsck.run()` returns `ok=True`. Assert `verify-object` stdout contains `RESULT: GOOD`.

`test_subprocess_interface.py`: Use `subprocess.run(['lf-did', ...])` throughout — real process boundary. Parse structured output from `verify-object`. Assert exit codes match expected results.

---

### PHASE 8b: Integration — Multi-Project and Adversarial

**TASK_ID:** `phase-8b-integration-adversarial`
**DEPENDS_ON:** `phase-8a-integration-happy`

**DELIVERABLES:**
- `tests/integration/test_multi_project.py`
- `tests/integration/test_adversarial.py`
- `tests/integration/test_fsck_clean.py`
- `tests/integration/test_fsck_broken.py`
- `tests/fixtures/registry/` — complete valid registry per FIXTURE REQUIREMENTS
- `tests/fixtures/registry_broken/` — 8 seeded errors per FIXTURE REQUIREMENTS
- `tests/fixtures/generate_fixtures.py`
- `tests/fixtures/keys/` — all 9 test keypairs

**ACCEPTANCE_CRITERIA:**
1. Multi-project: same `did:key` registered in two separate project registries → endorsement in project A does not grant trust in project B
2. Adversarial: tampered identity (self-signature byte-flipped) → fsck fires `CRYPTO_001`, chain verify returns `BAD`
3. Adversarial: endorsement with inflated tier claim → chain verify fails
4. Adversarial: revoked signer → `verify-object` returns `RESULT: REVOKED`
5. Adversarial: expired identity → `verify-object` returns `RESULT: EXPIRED`
6. Adversarial: signature from object A replayed against object B → `BAD` (nonce mismatch)
7. Adversarial: delegation scope mismatch → `UNTRUSTED`
8. Adversarial: delegation used past expiry → `UNTRUSTED`
9. Adversarial: manufactured chain depth > 20 → `ChainDepthExceededError`, no infinite loop
10. `test_adversarial.py` has at least 20 distinct adversarial cases; at least 10 driven by `hypothesis`
11. `verify-registry` on clean fixture: 0 errors, 0 warnings
12. `verify-registry` on broken fixture: exactly the 8 seeded error IDs — no false positives, no missed errors
13. `verify-registry --fix` on fixture with stale INDEX.md: regenerates correctly, re-run shows 0 warnings
14. `generate_fixtures.py` runs to completion and produces byte-for-byte identical output given the same test keys
15. `pytest tests/integration/test_multi_project.py tests/integration/test_adversarial.py tests/integration/test_fsck_clean.py tests/integration/test_fsck_broken.py -v` exits 0

---

### PHASE 8c: Integration — Tier Graph Exhaustive and No-Network Proof

**TASK_ID:** `phase-8c-integration-tier-network`
**DEPENDS_ON:** `phase-8b-integration-adversarial`

**DELIVERABLES:**
- `tests/integration/test_tier_graph_exhaustive.py`
- `tests/integration/test_no_network.py`

**ACCEPTANCE_CRITERIA:**
1. Tier graph: all permutations of 4-tier hierarchy produce consistent ordering; `is_at_least` is transitive across all permutations
2. Tier graph: arbitrary opaque tier names (`foo`, `bar`, `baz`, `qux`) — ordering derived purely from `can_endorse_up_to` graph, not string comparison
3. Tier graph: minimum viable registry (one tier, no endorsement required) — valid, no cycle error
4. Tier graph: two roots → `TierGraphMultipleRootsError`
5. Tier graph: cycle → `TierGraphCycleError`
6. `test_no_network.py`: patches `socket.create_connection` and `urllib.request.urlopen` to unconditionally raise `ConnectionRefusedError`; then calls every verification operation: `verify-object`, `verify-tag`, `verify-file`, `verify-chain`, `verify-registry`, `verify-identity`; asserts none of them trigger the network patch
7. `pytest tests/integration/test_tier_graph_exhaustive.py tests/integration/test_no_network.py -v` exits 0

**INSTRUCTIONS:**

`test_no_network.py`: The patch must be at the socket level, not at the HTTP library level. This catches any code path that opens a socket, regardless of which library it goes through. The test fails if the mock is ever called — meaning the test passes only if the production code never reaches a network call.

---

### PHASE 8d: Integration — Remaining Flows

**TASK_ID:** `phase-8d-integration-remaining`
**DEPENDS_ON:** `phase-8c-integration-tier-network`

**DELIVERABLES:**
- `tests/integration/test_import_gpg.py`
- `tests/integration/test_automation.py`
- `tests/integration/test_cross_project.py`
- `tests/integration/test_shim_interface.py`

**ACCEPTANCE_CRITERIA:**
1. `import-from-gpg`: both `lf:gpgSignature` and `lf:didSignature` verify against their respective keys
2. `init-automation --key-source tpm`: software key rejected at registration time with clear error
3. Automation identity with valid TPM stub: sign within `lf:automationScope` → GOOD; sign outside scope → UNTRUSTED
4. `find-did <did>` across two configured project registries: finds DID in correct registry
5. Shim end-to-end: git configured with `gpg.program = lf-did` → `git tag -s` calls `lf-did sign-object` → `git verify-tag` calls `lf-did verify-object` → output contains `RESULT: GOOD`
6. `pytest tests/integration/ -v` exits 0 — all integration tests pass
7. Total integration test runtime under 30 seconds

---

### PHASE 9a: Fixes and Final Gate

**TASK_ID:** `phase-9a-fixes`
**DEPENDS_ON:** `phase-8d-integration-remaining`

**DELIVERABLES:**
- All source and test fixes needed to pass the verification checklist
- No new features — fix only

**ACCEPTANCE_CRITERIA (run these commands exactly, in order):**

```bash
# 1. Full test suite
pytest tests/ -x --tb=short --cov=src/lf_did --cov-report=term-missing

# 2. Coverage gate
pytest --cov=src/lf_did --cov-fail-under=90

# 3. Type check
mypy src/lf_did --strict

# 4. Lint
ruff check src/ tests/

# 5. No hardcoded tier names in core
grep -rn '"anchor"\|"maintainer"\|"contributor"\|"steering"\|"lead"\|"approver"\|"reviewer"\|"member"' src/lf_did/core/ && echo FAIL || echo PASS

# 6. No network calls in core
grep -rn 'urllib\|requests\|httpx\|http\.client\|socket\.create_connection\|socket\.connect' src/lf_did/core/ && echo FAIL || echo PASS

# 7. GPG subprocess isolation
grep -rn 'subprocess.*gpg\|gpg.*subprocess' src/lf_did/ | grep -v gpg_import/importer.py && echo FAIL || echo PASS

# 8. Subprocess smoke test
make fsck-demo
```

All 8 must exit 0 / print PASS. Fix everything that doesn't before declaring complete. Report what was fixed and why it was broken.

---

### PHASE 9b: Documentation

**TASK_ID:** `phase-9b-docs`
**DEPENDS_ON:** `phase-9a-fixes`

**DELIVERABLES:**
- `SPEC_TRACEABILITY.md` — table: normative requirement | source location | test function(s)
- `ARCHITECTURE.md` — module map, key design decisions, data flow for sign and verify paths
- `README.md` — install, quickstart (5 commands to go from zero to first verified tag), subprocess interface reference, hardware key setup

**ACCEPTANCE_CRITERIA:**
1. Every normative "must" in the spec has a row in `SPEC_TRACEABILITY.md` with at least one passing test function name
2. `ARCHITECTURE.md` covers: package structure, tier graph algorithm, verification pipeline steps, trust chain walk, fsck check registration mechanism
3. `README.md` quickstart works as written — the 5 commands produce a `RESULT: GOOD` output
4. `lf-did --help` and all subcommand `--help` are complete and accurate
5. No broken internal links in any `.md` file
6. `make fsck-demo` exits 0

---

## ORCHESTRATOR INTEGRATION STEPS

After all phases complete, run these in sequence to confirm the build is clean end-to-end:

1. `pip install -e .`
2. `pytest tests/unit/ -v --cov=lf_did --cov-report=term-missing` — fix any failures (common cause: API mismatch between phases)
3. `pytest tests/integration/ -v` — fix integration failures
4. Run `lf-did verify-registry` against `tests/fixtures/registry/` — confirm 0 errors
5. Run `lf-did verify-registry` against `tests/fixtures/registry_broken/` — confirm exactly the 8 seeded error IDs reported, no extras
6. `pytest tests/integration/test_no_network.py -v` — must pass
7. `grep -c 'def check_' src/lf_did/fsck/checks.py` — must print 41

---

## TESTING REQUIREMENTS

### Coverage targets

- ≥90% line coverage across all non-hardware-interface code
- 100% coverage on `core/crypto.py` and `core/did.py`
- 100% coverage on all document types
- 100% coverage on `fsck/checks.py`
- 100% coverage on `verify/pipeline.py`

### Required unit test cases

**Crypto:**
- Key generation for all three types; verify prefix
- ed25519/P-256/P-384: sign → verify happy path
- Verify with wrong key: fail
- Verify with corrupted signature: fail
- multibase encode/decode round-trip
- did:key → public key bytes → did:key round-trip for all three types
- secp256k1 key rejected
- All RFC 8785 appendix A JCS test vectors
- JCS edge cases: empty object, nested arrays, Unicode, numbers
- base64url: encode no padding, decode no padding, decode with padding (accept both, never emit)

**Documents:**
- Each type: valid parses cleanly
- Each type: missing required field raises typed error
- Each type: invalid signature raises `VerificationError`
- Each type: wrong `@context` raises error
- Identity: expired document detected
- Identity: `lf:expires` > 2 years after `lf:registered` rejected
- Identity: selfSignature over wrong payload fails
- Endorsement: tierVouched above endorser capability flagged
- Delegation: chained delegation flagged
- Rotation: signed by new key (not old) rejected
- Git signature: nonce mismatch fails
- Git signature: replay against different object fails

**Trust:**
- `resolve_trust_chain`: 3-hop valid chain
- `resolve_trust_chain`: broken chain (missing intermediate)
- `resolve_trust_chain`: circular chain raises `CircularTrustError`
- `resolve_trust_chain`: cycle at depth >20 raises `CircularTrustError`, no infinite loop
- `check_capability`: all capabilities for a known policy
- `is_revoked`: true for revoked, false for active
- `is_superseded`: true for rotated-away DID

**fsck:**
- One test per check ID: trigger error condition, verify check reports it
- One test per check ID: clean condition, verify check reports nothing
- `TRUST_003`: genuine cycle (A endorses B, B endorses A), must not infinite-loop

**Shim output:**
- `RESULT: GOOD` on valid signature, exit 0
- `RESULT: REVOKED` on revoked signer, nonzero exit
- `RESULT: EXPIRED` on expired signer
- `RESULT: BAD` on corrupted signature
- `TIER_CHECK: fail` when minimum tier not met
- All required fields present in structured output

### Required integration test scenarios

Use real git repos via `git init` in `tmp_path`. No mocking of git operations.

- `init` → produces valid identity document with verifiable selfSignature
- `init` → `endorse` → `verify-registry`: all checks pass
- `endorse` → `revoke` → `verify-tag` with signature from revoked DID: REVOKED
- `init` → `rotate` → old-key signature still verifies, new key required for new ops
- `init` → `delegate` → sign tag under delegation → `verify-tag`: VALID
- `delegate` → attempt `delegate` of delegated authority: rejected
- `sign-file` → `verify-file`: VALID
- `sign-file` → corrupt .sig → `verify-file`: BAD
- `tag` + `verify-tag`: VALID
- `tag` → stale registry (mock FETCH_HEAD mtime) → warn at 7d, fail at 30d
- `tag` → stale + `--allow-stale` → proceeds with warning in output
- `verify-chain` on 5 signed merges: exit 0
- `verify-chain` with one invalid sig: reports correct commit
- `verify-registry` on clean fixture: 0 errors, 0 warnings
- `verify-registry` on broken fixture: exactly the 8 seeded error IDs, no extras, no misses
- `verify-registry --fix` on stale INDEX.md: regenerates correctly
- `import-from-gpg`: both signatures verify
- `init-automation --key-source tpm`: software key rejected
- Automation identity: sign within scope: VALID; sign outside scope: UNTRUSTED
- `find-did` across two configured project registries: finds DID in both
- Shim: git calls `sign-object`, then `verify-object`: succeeds end-to-end
- `test_no_network.py`: patch `socket.create_connection` and `urllib.request.urlopen` to raise; run every verification operation; assert no exception from network blocking

### Fixture requirements

`tests/fixtures/registry/` — complete valid registry:
- 2 anchor identities
- 3 maintainer identities (with correct endorsement chains from anchors)
- 5 contributor identities (with maintainer endorsements)
- 1 automation identity (TPM key source, valid accountable DID)
- 6 endorsement files
- 1 valid delegation (scope and expiry set correctly)
- 1 revocation (third-party, revoker tier valid)
- 1 rotation record (signed by old key)
- 1 identity expiring within 60 days (triggers EXPIRY_003)
- Correct INDEX.md files
- Valid policy/ files including tiers.json

`tests/fixtures/registry_broken/` — seeded with exactly these 8 errors:
- Invalid selfSignature on one identity (`CRYPTO_001`)
- Endorser below required tier on one endorsement (`TRUST_002`)
- One identity with no endorsement (`TRUST_006`)
- Circular endorsement A→B→A (`TRUST_003`)
- Delegation from DID acting under delegation (`TRUST_004`, `DELEG_004`)
- Expired identity with no revocation or rotation (`EXPIRY_001`)
- Stale INDEX.md (`CONS_003`)
- Automation identity missing `lf:accountableDID` (`TRUST_010`)

`tests/fixtures/generate_fixtures.py` — runnable script that regenerates all fixtures using real crypto. Must be deterministic given fixed test keys. Commit generated fixtures; the generator is for reproducibility documentation.

`tests/fixtures/keys/` — test keypairs:
- `test_ed25519_{1..5}.pem`
- `test_p256_{1..2}.pem`
- `test_p384_1.pem`
- All clearly marked `# TEST KEY ONLY - NOT FOR PRODUCTION`
- `keys.json` mapping short names to DID fragments

---

## NORMATIVE REQUIREMENTS SUMMARY

The following are hard requirements that all agents must enforce.

**Cryptography:**
- Accepted key types: ed25519 (`z6Mk`), P-256 (`zDn`), P-384 (`z82`). secp256k1 rejected unconditionally.
- Signature over JCS-canonicalized (RFC 8785) payload only.
- Nonce = first 32 hex-encoded bytes (64 chars) of `lf:objectSha`. Non-negotiable.
- Self-signature covers all fields except the self-signature field itself.

**Network:**
- Zero network calls during sign, verify, chain-verify, fsck, or any other operation.
- `did:key` resolution is local computation: decode multibase, extract key bytes.
- JSON-LD contexts are bundled with the package. Never fetched at runtime.
- SSH agent socket is the only permitted socket connection, and only during signing.

**Tier system:**
- Tier ordering is derived at runtime from `policy/tiers.json` by graph traversal.
- No tier name is hardcoded anywhere in `src/lf_did/core/`. Tier names are opaque strings.
- `can_endorse_up_to` edges define the graph. The unique root is the anchor tier.
- `automation` tier is always a leaf (no `can_endorse_up_to` target).

**Registry layout:**
- Identity files named `<did-fragment>.json`.
- Tier subdirectories under `identities/` named after tier names from `tiers.json`.
- Endorsements at `endorsements/<subject-fragment>/<endorser-fragment>.json`.
- Delegations at `delegations/<delegator-fragment>/<delegate-fragment>.json`.
- Revocations at `revocations/<subject-fragment>.json`.
- Rotations at `rotations/<old-fragment>-to-<new-fragment>.json`.

---

## CONSTRAINTS FOR ALL AGENTS

1. **Python 3.11+ only.** Use `match` statements where appropriate. Use `tomllib` (stdlib). Use `pathlib.Path` everywhere.
2. **No shell scripts as logic.** `subprocess` is permitted only for: calling `git` commands, calling `gpg` in `lf_did/gpg_import/importer.py` only, running the CLI as a subprocess in integration tests.
3. **`attrs` for all dataclasses.** No plain `@dataclass`. Use `attrs.define` with validators.
4. **Type annotations on every function.** `mypy --strict` must pass.
5. **No global mutable state.** All state flows through function arguments and return values.
6. **Tests are first-class.** Every function in `core/` has at least one test. Every error path has a test.
7. **Fixtures are self-contained.** Tests must not depend on external files, network, or real SSH agent. All use `tmp_path` and `MockAgentClient`.
8. **Tier names in test fixtures use real project names** (kernel, kubernetes) to validate that the generic machinery handles them correctly. The production code must not reference these names.
9. **Every exception type is defined in `exceptions.py`** with a docstring explaining when it is raised.
10. **Logging is structured.** Use Python `logging` with logger names matching module paths. DEBUG for crypto operations. INFO for registry operations. WARNING for policy near-misses. ERROR for verification failures.

---

## ACCEPTANCE CRITERIA (FINAL)

Done when all of these are true (verified in phase 9a):

1. `pytest tests/ -v --cov=lf_did` exits 0 with ≥90% overall coverage
2. `lf-did init` produces an identity document whose selfSignature verifies with `lf-did verify-identity`
3. `lf-did verify-registry` on clean fixture: 0 errors, 0 warnings
4. `lf-did verify-registry` on broken fixture: exactly the 8 seeded error IDs, no false positives, no missed errors
5. `sign-object` followed by `verify-object`: stdout contains `RESULT: GOOD`, exit 0
6. `pytest tests/integration/test_no_network.py`: exit 0
7. `python -c "from lf_did.contexts.loader import resolve_context; print(resolve_context('https://lf.org/ns/did/v1'))"` prints a dict, no I/O exceptions
8. `mypy src/lf_did --strict` exits 0
9. `ruff check src/ tests/` exits 0
10. `make fsck-demo` exits 0
11. `grep -c 'def check_' src/lf_did/fsck/checks.py` prints 41
12. `grep -rn 'subprocess.*gpg\|gpg.*subprocess' src/lf_did/ | grep -v gpg_import/importer.py` prints nothing

---

## VERIFICATION CHECKLIST FOR EVALUATING AI

Run these commands exactly. All must pass for the project to be considered COMPLETE.

```bash
# 1. Clean install
pip install -e ".[dev]"

# 2. Full test suite
pytest tests/ -x --tb=short --cov=src/lf_did --cov-report=term-missing

# 3. Coverage gate
pytest --cov=src/lf_did --cov-fail-under=90

# 4. Type check
mypy src/lf_did --strict

# 5. Lint
ruff check src/ tests/

# 6. No hardcoded tier names in core
grep -rn '"anchor"\|"maintainer"\|"contributor"\|"steering"\|"lead"\|"approver"\|"reviewer"\|"member"' src/lf_did/core/ && echo FAIL || echo PASS

# 7. No network calls in core
grep -rn 'urllib\|requests\|httpx\|http\.client\|socket\.create_connection\|socket\.connect' src/lf_did/core/ && echo FAIL || echo PASS

# 8. GPG subprocess isolation
grep -rn 'subprocess.*gpg\|gpg.*subprocess' src/lf_did/ | grep -v gpg_import/importer.py && echo FAIL || echo PASS

# 9. All 41 fsck checks present
test "$(grep -c 'def check_' src/lf_did/fsck/checks.py)" -eq 41 && echo PASS || echo FAIL

# 10. Subprocess interface smoke test
make fsck-demo
```

---

## THINGS THAT MUST NEVER APPEAR IN THE CODEBASE

- Any HTTP client (`requests`, `httpx`, `aiohttp`, `urllib.request`) used to fetch a context URL
- Any reference to blockchain, DHT, or consensus
- `sort_keys=True` in `json.dumps` on documents that will be JCS-canonicalized
- Tier name strings `"anchor"`, `"maintainer"`, `"contributor"` used in capability logic outside of tests and fixture data (read from policy)
- `base64.b64encode` without `.rstrip(b'=')` on signature output
- `subprocess.run(["gpg", ...])` outside `lf_did/gpg_import/importer.py`
- Auto-transfer of endorsements during key rotation
- Acceptance of delegated authority being re-delegated
- Acceptance of secp256k1 keys

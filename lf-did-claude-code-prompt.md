# Claude Code Prompt: `lf-did` Python Implementation

> **Superseded.** Kept for history; [DESIGN.md](DESIGN.md) is the current design. Statements here about key types (P-384 accepted, RSA refused, importing GPG secret keys) and status do not describe git-vouch.
## Agentic Fleet Execution with Explicit Subagent Handoff Protocol

---

## PREAMBLE FOR ORCHESTRATOR AGENT

You are the **Orchestrator Agent** for this build. You will spawn and coordinate a fleet of subagents. Each subagent receives an explicit handoff packet (defined below) and returns an explicit result packet. You must not proceed to the next phase until the current phase's subagent returns `STATUS: COMPLETE` and all acceptance criteria pass. If a subagent returns `STATUS: BLOCKED` or `STATUS: FAILED`, you must resolve the blocker before continuing.

**Project:** `lf-did` — a Python 3.11+ CLI implementing the LF DID identity and signing system for git-based open source project governance.

**Excluded from scope:** Changes to git itself. You are implementing the external tooling that git calls via `gpg.did.program = lf-did`. The git subprocess interface is defined below; implement the `lf-did` side of it only.

**Language:** Python 3.11+ exclusively. No shell scripts as primary logic. No Go, Rust, or C.

**Output structure:** A single installable Python package named `lf_did` with a `lf-did` entry point. All tests in `tests/`. The project must pass `pytest` with zero failures and zero warnings.

**You will be evaluated by another AI agent.** Every design decision must be defensible. Every normative requirement from the spec must be traceable to a test. No hardcoded tier names or tier orderings anywhere in the codebase — tier ordering is always derived from `policy/tiers.json` at runtime.

---

## SYSTEM OVERVIEW

`lf-did` implements a W3C DID-based identity and signing system where:

- **Identity** is a `did:key` URI encoding an ed25519, P-256, or P-384 public key directly (no resolver, no network, local computation only)
- **Registry** is a git repository containing JSON-LD identity documents, endorsements, delegations, revocations, and rotations
- **Trust** is a tree (not web): anchor → top-minus-one tier → lower tiers, defined per-project in `policy/tiers.json`
- **Signatures** on git objects are JSON-LD documents stored in `refs/signatures/` (the tooling writes and reads these; git stores them)
- **Tier ordering** is derived at runtime by graph-walking `can_endorse_up_to` edges in `policy/tiers.json` — never hardcoded
- **No network calls ever** during sign, verify, endorse, revoke, rotate, or chain-verify operations. Zero. DNS not queried. HTTP not opened. SSH agent is the only socket allowed, and only during signing.

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

## PHASE DEFINITIONS

Execute phases in order. Each phase is a subagent dispatch.

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

Create the project skeleton. Package name: `lf_did`. Entry point CLI command: `lf-did`.

Dependencies (production): `cryptography>=42`, `jcs>=0.2`, `click>=8.1`, `attrs>=23`, `cattrs>=23`, `gitpython>=3.1`, `platformdirs>=4`

Dependencies (dev/test): `pytest>=8`, `pytest-cov`, `mypy`, `ruff`, `hypothesis`

The package structure:

```
src/lf_did/
  __init__.py
  cli/
    __init__.py
    main.py          # click group root
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
    lf_v1.json       # bundled LF base context (offline)
    w3c_did_v1.json  # bundled W3C DID v1 context (offline)
    w3c_did_v1_1.json
  exceptions.py      # all custom exceptions
  constants.py       # multicodec prefixes, accepted key types
```

`conftest.py` must define:
- `fixture: tmp_registry(tmp_path)` — creates a minimal valid registry directory tree with a synthetic anchor, one maintainer, one contributor, valid tiers.json
- `fixture: synthetic_did_key(key_type)` — generates a fresh did:key for each key type
- `fixture: mock_ssh_agent` — a pytest fixture that stands up an in-process mock SSH agent

---

### PHASE 1: DID Primitives and Cryptography

**TASK_ID:** `phase-1-crypto`
**DEPENDS_ON:** `phase-0-scaffold`
**INPUTS:** `src/lf_did/core/did.py` (stub), `src/lf_did/core/crypto.py` (stub), `src/lf_did/constants.py`
**DELIVERABLES:**
- `src/lf_did/core/did.py` (complete)
- `src/lf_did/core/crypto.py` (complete)
- `src/lf_did/core/agent.py` (complete)
- `src/lf_did/core/jcs.py` (complete)
- `src/lf_did/constants.py` (complete)
- `tests/test_did.py`
- `tests/test_crypto.py`
- `tests/test_agent.py`
- `tests/test_jcs.py`

**ACCEPTANCE_CRITERIA:**
1. `DIDKey.from_string("did:key:z6Mk...")` correctly decodes ed25519 public key bytes for known test vectors
2. `DIDKey.from_string("did:key:zDn...")` correctly decodes P-256
3. `DIDKey.from_string("did:key:z82...")` correctly decodes P-384
4. secp256k1 keys raise `UnsupportedKeyTypeError`
5. Round-trip: generate ed25519 key → encode as did:key → decode → verify original bytes match
6. Round-trip for P-256 and P-384
7. `sign_bytes(private_key, payload)` + `verify_bytes(public_key, payload, sig)` round-trips for all three key types
8. JCS canonicalization of `{"b": 2, "a": 1}` produces `{"a":1,"b":2}` (per RFC 8785 test vectors)
9. JCS of nested objects with unicode matches RFC 8785 test vectors
10. SSH agent mock: `AgentClient.sign(key_fingerprint, data)` returns bytes that verify against the corresponding public key
11. `AgentClient.list_keys()` returns the keys loaded into the mock agent
12. All 11 tests pass under `hypothesis` property-based testing for DID round-trips
13. Zero mypy errors in these modules

**INSTRUCTIONS:**

`did.py` — implement `DIDKey`:
- Parse `did:key:<multibase>` strings
- Multibase: only `z` prefix (base58btc) is accepted for security-relevant keys
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
- Mock: `MockAgentClient` backed by in-memory `KeyPair` list, conforming to same interface
- For ed25519 agent keys: flags=0; for P-256/P-384: flags=0 (SHA-512 hash for ECDSA via agent)

`jcs.py` — thin wrapper around the `jcs` library:
- `canonicalize(obj: dict) → bytes`
- `canonicalize_excluding(obj: dict, exclude_keys: set[str]) → bytes` — used for self-signature computation (exclude the signature field itself)
- Include RFC 8785 test vectors as inline assertions in the test file

---

### PHASE 2: Document Types and Registry Layout

**TASK_ID:** `phase-2-documents`
**DEPENDS_ON:** `phase-1-crypto`
**INPUTS:** Phase 1 deliverables
**DELIVERABLES:**
- `src/lf_did/core/documents.py` (complete)
- `src/lf_did/core/tier.py` (complete)
- `src/lf_did/core/policy.py` (complete)
- `tests/test_documents.py`
- `tests/test_tier.py`
- `tests/test_policy.py`

**ACCEPTANCE_CRITERIA:**
1. `IdentityDocument` parses and round-trips all example JSON-LD documents from the spec
2. `EndorsementDocument`, `DelegationDocument`, `RevocationDocument`, `RotationDocument`, `GitSignatureDocument` parse correctly
3. `TierGraph.from_tiers_json(tiers_dict)` constructs a graph from any valid `tiers.json`
4. `TierGraph.ordering()` returns tiers sorted highest-to-lowest by deriving order from `can_endorse_up_to` edges (graph traversal — no hardcoded names)
5. `TierGraph.ordering()` works correctly for both kernel (anchor→maintainer→contributor→automation) and Kubernetes (steering→lead→approver→reviewer→member→automation) examples
6. `TierGraph.is_at_least(tier_a, tier_b)` returns True iff tier_a is same or higher rank than tier_b
7. `TierGraph.top_minus_one()` returns the tier one below anchor
8. `PolicyEnforcer.can_endorse(endorser_tier, target_tier)` enforces `can_endorse_up_to`
9. `PolicyEnforcer.can_sign_ref(tier, ref)` enforces `can_sign_refs` glob matching
10. `PolicyEnforcer.can_revoke(revoker_tier, target_tier)` enforces `can_revoke_up_to`
11. `PolicyEnforcer.can_delegate(tier)` enforces `can_delegate`
12. Tier graph with a cycle raises `TierGraphCycleError`
13. Tier graph with multiple roots (multiple tiers with nothing endorsing them) raises `TierGraphMultipleRootsError` — exactly one tier may be un-endorsable-to (the anchor)
14. All document types validate required fields and raise `DocumentValidationError` with field name on missing/invalid fields
15. Zero mypy errors

**INSTRUCTIONS:**

`documents.py` — typed dataclasses (use `attrs` with validators) for every document type:

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
```

Similarly for `EndorsementDocument`, `DelegationDocument`, `RevocationDocument`, `RotationDocument`, `GitSignatureDocument`.

`tier.py` — `TierGraph`:

The tier ordering algorithm: build a directed graph where edge A→B means "A can endorse up to B" (i.e., A is above B). Find the unique root (no incoming edges from other tiers). BFS/topological sort to assign ranks. Detect cycles and multiple roots as errors. The `automation` tier is special: it may have `can_endorse_up_to: null` and `can_sign_refs` that don't overlap with others — it's a leaf at the bottom regardless of ordering. Handle this: automation is always last.

The algorithm must never inspect tier names. It operates purely on the graph structure.

`policy.py` — `PolicyEnforcer`:
- Reads `policy/tiers.json` from registry
- Delegates ordering to `TierGraph`
- Glob matching for `can_sign_refs`: use `fnmatch.fnmatch`
- All capability checks log their decision (DEBUG level) with the tier, capability, and result

---

### PHASE 3: Registry Reader and Chain Verifier

**TASK_ID:** `phase-3-registry`
**DEPENDS_ON:** `phase-2-documents`
**INPUTS:** Phase 2 deliverables, `conftest.py` fixtures
**DELIVERABLES:**
- `src/lf_did/core/registry.py` (complete)
- `src/lf_did/core/chain.py` (complete)
- `tests/test_registry.py`
- `tests/test_chain.py`

**ACCEPTANCE_CRITERIA:**
1. `RegistryReader(path)` loads all identity documents from all tier subdirectories under `identities/`
2. `RegistryReader.get_identity(did_fragment)` returns the `IdentityDocument` or raises `IdentityNotFoundError`
3. `RegistryReader.get_endorsements_for(did_fragment)` returns all endorsement documents in `endorsements/<fragment>/`
4. `RegistryReader.get_delegation(delegator_fragment, delegate_fragment)` returns delegation or None
5. `RegistryReader.is_revoked(did_fragment)` checks `revocations/<fragment>.json` existence and validates the revocation document
6. `RegistryReader.get_rotation(old_fragment)` returns the rotation document if present
7. `RegistryReader.get_trust_anchors()` reads `policy/trust-anchors.json`
8. `ChainVerifier.verify(did: DIDKey, registry: RegistryReader) → ChainResult` walks endorsements from subject to anchor
9. Chain walk correctly handles: direct anchor endorsement, multi-hop chain, delegation path
10. Chain walk fails if any intermediate endorser is revoked
11. Chain walk fails if any intermediate endorser's identity is expired
12. Chain walk fails if any endorsement document's signature is invalid
13. Chain walk fails if endorser's claimed tier does not match their identity document tier
14. `ChainResult.chain_summary` produces a human-readable string matching the format: `did:key:z6Mk... → did:key:z6Mk... → LF root anchor`
15. `ChainVerifier` with a missing anchor (trust-anchors.json not listing any anchor that the chain terminates at) returns `ChainResult.terminated_at_unknown_anchor = True` with a specific warning, not a hard failure (per spec: LF root is optional if root registry clone not available)
16. All tests pass with synthetic registry from `tmp_registry` fixture

**INSTRUCTIONS:**

`registry.py` — `RegistryReader`:
- Takes a filesystem path to a cloned registry repo
- Lazy-loads documents on first access, caches them
- File naming convention: `<did-fragment>.json` — the fragment is the multibase string after `did:key:`
- `identities/` has subdirectories named after tiers (these are derived from `tiers.json`, not hardcoded)
- Must scan all tier subdirectories without knowing their names in advance
- Context bundling: JSON-LD `@context` URIs referencing `https://lf.org/ns/did/v1`, `https://www.w3.org/ns/did/v1`, `https://www.w3.org/ns/did/v1.1` are resolved from `src/lf_did/contexts/` bundle — never network fetched

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
**INPUTS:** Phase 3 deliverables
**DELIVERABLES:**
- `src/lf_did/core/verifier.py` (complete)
- `tests/test_verifier.py`

**ACCEPTANCE_CRITERIA:**
1. `SignatureVerifier.verify(sig_doc: GitSignatureDocument, object_sha: str, registry: RegistryReader, policy: PolicyEnforcer) → VerificationResult` implements all 11 steps from the spec
2. Step 1: Parses signature document, extracts signer DID and signature bytes
3. Step 2: Decodes public key from `did:key` (local computation — `DIDKey.from_string()`)
4. Step 3: Verifies cryptographic signature over JCS-canonicalized payload (all fields except `lf:signature`)
5. Step 4: Verifies nonce equals first 32 bytes of `lf:objectSha` hex-encoded
6. Step 5: Looks up signer in registry (`RegistryReader.get_identity`)
7. Step 6: Verifies identity document self-signature
8. Step 7: Walks endorsement chain to project anchor (`ChainVerifier.verify`)
9. Step 8: Checks LF root chain if root registry clone available (skips gracefully if not)
10. Step 9: Checks revocation records
11. Step 10: Checks identity expiry
12. Step 11: Checks tier satisfies minimum tier policy if configured
13. `VerificationResult.result` is one of: `GOOD`, `BAD`, `EXPIRED`, `REVOKED`, `UNTRUSTED`, `ERROR`
14. `VerificationResult.to_subprocess_output()` produces the key-value line format from Appendix B
15. Failing step 3 (bad crypto sig) → `BAD`
16. Failing step 4 (nonce mismatch) → `BAD`
17. Failing step 9 (revoked) → `REVOKED`
18. Failing step 10 (expired) → `EXPIRED`
19. Failing step 11 (tier too low) → `UNTRUSTED`
20. Exception during any step → `ERROR` with diagnostic
21. Zero network calls (verify with `unittest.mock.patch('socket.create_connection')` raising an error — must never be reached)

**INSTRUCTIONS:**

`verifier.py`:

The subprocess output format (stdout, key: value, one per line):
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

Implement `VerificationResult.from_subprocess_output(text: str) → VerificationResult` as the inverse parser (used by test harnesses and potentially by git-side tooling).

The subprocess interface from Appendix B:
- `lf-did sign-object [--project p] [--registry path] --output <sigfile> <payload-file>` — exit 0 on success, writes JSON to sigfile
- `lf-did verify-object [--project p] [--registry path] --signature <sigfile> --payload <payload-file> [--minimum-tier <tier>]` — exit 0 on success, structured output on stdout

These CLI entry points must be implemented in `cli/sign.py` and `cli/verify.py` respectively. They are the git integration points.

---

### PHASE 5: Registry Fsck, Linker, and Integrity Tools

**TASK_ID:** `phase-5-fsck`
**DEPENDS_ON:** `phase-4-verifier`
**INPUTS:** Phase 4 deliverables
**DELIVERABLES:**
- `src/lf_did/core/fsck.py` (complete)
- `src/lf_did/core/linker.py` (complete)
- `tests/test_fsck.py`
- `tests/test_linker.py`

**ACCEPTANCE_CRITERIA:**
1. `RegistryFsck.run(registry_path) → FsckReport` performs exhaustive consistency check
2. Fsck check: every identity document's `id` field matches its filename (`<fragment>.json`)
3. Fsck check: every identity document's self-signature verifies against its `id`'s public key
4. Fsck check: every identity document's tier matches the subdirectory it lives in
5. Fsck check: every identity's `lf:tier` is a tier defined in `policy/tiers.json`
6. Fsck check: every endorsement document's endorser exists in the registry
7. Fsck check: every endorsement document's subject exists in the registry
8. Fsck check: every endorsement document's signature verifies against the endorser's DID key
9. Fsck check: every endorsement document's `tierVouched` is reachable from endorser's tier via `can_endorse_up_to`
10. Fsck check: every delegation document's delegator is `can_delegate = true`
11. Fsck check: every delegation document's delegate is `maintainer` tier or above (derived from tier ordering)
12. Fsck check: every delegation document's signature verifies against delegator's DID key
13. Fsck check: every delegation document's `scope` is a valid ref glob (does not contain `..`, starts with `refs/`)
14. Fsck check: every revocation document's revoker has authority to revoke the subject (per tier policy)
15. Fsck check: every revocation document's signature verifies against revoker's DID key
16. Fsck check: every rotation document's old fragment actually existed (or was itself revoked)
17. Fsck check: every rotation document's new identity document exists
18. Fsck check: no identity document has `expires` more than two years after `registered`
19. Fsck check: endorsement chain from every non-anchor identity terminates at an anchor
20. Fsck check: `policy/trust-anchors.json` exists and is non-empty
21. Fsck check: `policy/tiers.json` is valid, parses, tier graph has no cycle, has exactly one root
22. `FsckReport.errors` lists all failures; `FsckReport.warnings` lists all non-fatal issues; `FsckReport.ok` is True only if zero errors
23. `FsckReport.to_text()` produces human-readable output like git fsck
24. `RegistryLinker.resolve(did: str, registry: RegistryReader) → LinkedIdentity` returns identity with all referenced documents resolved
25. `RegistryLinker.dangling_references(registry: RegistryReader) → list[DanglingRef]` returns endorsements/delegations/revocations referencing non-existent identities
26. Introducing any of the error conditions above into the `tmp_registry` fixture causes the corresponding fsck check to fire
27. All 26 checks have corresponding negative test cases

**INSTRUCTIONS:**

`fsck.py` — implement as a collection of `FsckCheck` objects, each with a `name`, `description`, and `run(registry) → list[FsckIssue]` method. `RegistryFsck.run()` collects all checks and runs them. This design allows individual checks to be run in isolation (useful for CI hooks).

`FsckIssue` has: `severity` (ERROR | WARNING | INFO), `check_name`, `subject` (the file or DID that failed), `message`.

`linker.py` — `RegistryLinker`:
- `resolve(did)` returns a `LinkedIdentity` with attributes: `identity`, `endorsements`, `delegations_granted`, `delegations_received`, `revocation` (or None), `rotation` (or None), `chain` (ChainResult)
- `dangling_references()` scans all endorsement/delegation/revocation files and reports any that reference a DID fragment not present in `identities/`

---

### PHASE 6: Signing Operations

**TASK_ID:** `phase-6-signing`
**DEPENDS_ON:** `phase-5-fsck`
**INPUTS:** Phase 5 deliverables
**DELIVERABLES:**
- `src/lf_did/cli/sign.py` (complete)
- `src/lf_did/cli/verify.py` (complete — subprocess interface)
- `src/lf_did/core/formats.py` (complete)
- `tests/test_sign.py`
- `tests/test_verify_cli.py`
- `tests/test_formats.py`

**ACCEPTANCE_CRITERIA:**
1. `lf-did sign-object --output <sigfile> <payload-file>` writes a valid `GitSignatureDocument` JSON
2. The written document passes `SignatureVerifier.verify()` against the same registry
3. The `lf:nonce` field equals the first 32 bytes of the SHA-256 of the payload file, hex-encoded
4. The `lf:objectSha` equals the full SHA-256 of the payload file
5. `lf-did verify-object --signature <sigfile> --payload <payload-file>` exits 0 and prints structured output for a valid signature
6. `lf-did verify-object` exits non-zero for a tampered payload
7. `lf-did verify-object` exits non-zero for a tampered signature
8. `lf-did verify-object` exits non-zero for a revoked signer
9. `lf-did verify-object` exits non-zero for an expired signer
10. `lf-did verify-object --minimum-tier maintainer` exits non-zero when signer is contributor tier
11. `lf-did sign-file <file>` produces a detached `.sig` file in the same JSON-LD format
12. `lf-did sign-file --format minisign <file>` produces a `.minisig` file that structurally validates (header line format, base64 body)
13. `lf-did verify-file <file> <file.sig>` verifies a detached signature file
14. `lf-did export-pubkey --format ssh` outputs a valid SSH public key line
15. `lf-did export-pubkey --format pem` outputs a valid PEM public key
16. `lf-did export-pubkey --format minisign` outputs a valid minisign public key line
17. Minisign key ID in the `.minisig` header is derived deterministically from the DID public key (not random)
18. All sign/verify operations use `MockAgentClient` in tests (no real SSH agent required)

**INSTRUCTIONS:**

`formats.py`:

SSH public key format: ed25519 key serialized as `ssh-ed25519 <base64> <did:key>` where the comment field is the full DID URI. P-256: `ecdsa-sha2-nistp256 <base64> <did:key>`. P-384: `ecdsa-sha2-nistp384 <base64> <did:key>`.

Minisign format:
- Public key line: `RW<base64>` where the base64 encodes: 2-byte algorithm identifier (`Ed`) + 8-byte key ID + 32-byte ed25519 public key
- Key ID derivation: first 8 bytes of SHA-256 of the raw ed25519 public key bytes (deterministic from DID)
- Signature file format: one-line comment (`untrusted comment: ...`), then base64 of: 2-byte algorithm identifier + 8-byte key ID + 64-byte ed25519 signature
- P-256 and P-384 keys produce a native `.sig` file (JSON-LD format) when `--format minisign` is requested, with a warning that minisign only supports ed25519

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

### PHASE 7: Identity Lifecycle Operations

**TASK_ID:** `phase-7-lifecycle`
**DEPENDS_ON:** `phase-6-signing`
**INPUTS:** Phase 6 deliverables
**DELIVERABLES:**
- `src/lf_did/cli/init.py` (complete)
- `src/lf_did/cli/identity.py` (complete)
- `src/lf_did/cli/endorse.py` (complete)
- `src/lf_did/cli/delegate.py` (complete)
- `src/lf_did/cli/revoke.py` (complete)
- `src/lf_did/cli/rotate.py` (complete)
- `src/lf_did/cli/device.py` (complete)
- `src/lf_did/cli/gpg.py` (complete)
- `src/lf_did/cli/registry.py` (complete)
- `tests/test_lifecycle.py`

**ACCEPTANCE_CRITERIA:**
1. `lf-did init` (with `--no-interactive` flag for testing) generates a valid identity document JSON with correct self-signature
2. Generated identity document passes `IdentityDocument.verify_self_signature()`
3. `lf-did whoami` prints DID and fingerprint
4. `lf-did endorse <did> --tier contributor --note "..."` produces a valid `EndorsementDocument` with correct signature
5. Endorsement document passes signature verification using endorser's DID public key
6. `lf-did endorse` fails with `PolicyViolationError` if endorser's tier cannot endorse to target tier
7. `lf-did delegate --to <did> --scope "refs/tags/v*-stable" --expires <date>` produces valid `DelegationDocument`
8. `lf-did delegate` fails if delegator's `can_delegate` is false
9. `lf-did revoke <did> --reason "..."` produces valid `RevocationDocument`
10. `lf-did revoke` fails if revoker's tier cannot revoke target's tier
11. `lf-did self-revoke --reason "..."` produces `RevocationDocument` signed by subject's own key (self-revocation)
12. `lf-did rotate` produces: updated identity document with new key, `RotationDocument` linking old→new, signed by old key
13. `lf-did renew` produces updated identity document with new `expires` date (max 2 years from `registered`), re-signed
14. `lf-did edit` (with `--field` and `--value` flags) updates a field and re-signs
15. `lf-did set --field sameAs --value "https://github.com/foo"` updates field correctly
16. `lf-did registry verify-registry` runs `RegistryFsck` and exits 0 on clean registry, non-zero on errors
17. `lf-did device list` with mock agent lists keys; with no agent raises `AgentNotAvailableError`
18. `lf-did import-key --from-pem --key <path>` produces identity document for the imported key
19. `lf-did link-gpg --fingerprint <fp>` produces a GPG link attestation JSON (signed by DID key, containing GPG fingerprint)
20. All operations except `init` and `import-key` use `MockAgentClient` in tests

**INSTRUCTIONS:**

`init.py` — `lf-did init`:
- `--generate-on-token`: calls `AgentClient` to enumerate hardware keys; uses first ed25519 key found; fails if none
- `--token`: same but prompts user to select
- Default (no flag): generates software key, stores at `~/.config/lf-did/private/key.pem` (encrypted)
- `--no-interactive`: non-interactive mode with defaults, for CI and testing
- Reads project config from `~/.config/lf-did/projects.json` — project auto-detected from current git remote URL matching known registry URLs
- `lf-did init-project <name>`: adds project entry to projects.json, clones registry

Project auto-detection algorithm:
1. Run `git remote get-url origin` in current directory
2. Match against `registry_url` fields in all known project registry `policy/project.json` files
3. If match found, return that project name
4. If no match, return None (require explicit `--project` flag)

`rotate.py` — key rotation:
- Old key signs the rotation document (proving possession of old key)
- New key signs the new identity document (proving possession of new key)
- Both documents produced in one operation
- Old key must still be accessible (via agent or filesystem) during rotation

`gpg.py` — GPG link attestation (not GPG import of key material):
- `link-gpg --fingerprint <fp>`: produces `GpgLinkAttestation` document: `{type: "lf:GpgLinkAttestation", lf:did: <current DID>, lf:gpgFingerprint: <fp>, lf:timestamp: ..., lf:signature: <sig-by-DID-key>}`
- This does NOT import the GPG private key
- `import-key --from-gpg --fingerprint <fp>`: uses `subprocess` to call `gpg --export-secret-key <fp>` and extract ed25519/P-256/P-384 key bytes (errors on RSA/DSA)
- `import-key --from-ssh --key <path>`: reads SSH private key file
- `import-key --from-agent --fingerprint <fp>`: reads from SSH agent by fingerprint
- `import-key --from-pem --key <path>`: reads PKCS#8 PEM

---

### PHASE 8: Integration Test Suite

**TASK_ID:** `phase-8-integration`
**DEPENDS_ON:** `phase-7-lifecycle`
**INPUTS:** All prior deliverables
**DELIVERABLES:**
- `tests/integration/test_full_flow.py`
- `tests/integration/test_subprocess_interface.py`
- `tests/integration/test_multi_project.py`
- `tests/integration/test_adversarial.py`
- `tests/integration/test_tier_graph_exhaustive.py`

**ACCEPTANCE_CRITERIA:**
1. Full flow test: generate anchor identity → generate maintainer identity → anchor endorses maintainer → generate contributor identity → maintainer endorses contributor → contributor signs a fake git object payload → verify chain validates fully → fsck passes
2. Full flow test for Kubernetes-style tier hierarchy (steering/lead/approver/reviewer/member) using a synthetic registry
3. Subprocess interface test: `lf-did sign-object` called as subprocess → `lf-did verify-object` called as subprocess → parsed structured output matches expectations
4. Multi-project test: same `did:key` registered in two different project registries → verify correctly isolates trust (endorsement in project A does not grant trust in project B)
5. Adversarial test: tampered identity document (self-signature modified) → fsck detects, chain verify fails
6. Adversarial test: endorsement with wrong tier claim (endorser claims anchor but is maintainer) → chain verify fails
7. Adversarial test: revoked signer → verify returns REVOKED
8. Adversarial test: expired identity → verify returns EXPIRED
9. Adversarial test: signature on object A replayed against object B → verify fails (nonce mismatch)
10. Adversarial test: delegation used beyond its scope glob → verify fails
11. Adversarial test: delegation used past expiry → verify fails
12. Adversarial test: chain depth > 20 (manufactured circular-ish structure) → ChainDepthExceededError, not infinite loop
13. Tier graph test: all permutations of 4-tier hierarchy; ordering always consistent; `is_at_least` transitive
14. Tier graph test: arbitrary tier names (`foo`, `bar`, `baz`, `qux`) — ordering derived purely from graph structure, not names
15. Tier graph test: minimum viable registry (one tier, no endorsement required) — valid
16. `test_adversarial.py` has at least 20 distinct adversarial cases
17. Zero network calls in any integration test (patched at socket level)
18. All integration tests pass in under 30 seconds total

**INSTRUCTIONS:**

`test_full_flow.py` — build everything from scratch in `tmp_path`:
1. Create a `TmpRegistry` helper that initializes the standard layout
2. Use `MockAgentClient` loaded with generated keys
3. Execute the full identity lifecycle: create anchor → create maintainer → endorse → create contributor → endorse → sign → verify → fsck
4. Assert every document produced is valid per its document type validator
5. Assert fsck returns `ok=True`
6. Assert verification returns `RESULT: GOOD`

`test_subprocess_interface.py` — test the actual CLI entry points as subprocesses:
1. Use `subprocess.run(['lf-did', 'sign-object', ...])` with a real temp registry on disk
2. Verify exit codes
3. Parse and validate structured output from verify

`test_adversarial.py` — property-based and enumerated adversarial cases:
- Use `hypothesis` to generate random mutations of valid documents and verify that the fsck and verifier correctly reject them
- Enumerate all specific attack scenarios from the threat model in the spec

---

### PHASE 9: Final Audit and Documentation

**TASK_ID:** `phase-9-audit`
**DEPENDS_ON:** `phase-8-integration`
**INPUTS:** All prior deliverables
**DELIVERABLES:**
- `SPEC_TRACEABILITY.md` — table mapping every normative requirement from the spec to one or more test IDs
- `ARCHITECTURE.md` — internal design document
- Updated `README.md` with install, quickstart, and subprocess interface reference
- Final `pytest` run with `--tb=short --cov=src/lf_did --cov-report=term-missing` showing ≥90% line coverage

**ACCEPTANCE_CRITERIA:**
1. `pytest tests/ -x --tb=short` exits 0
2. Line coverage ≥ 90% across all modules
3. `mypy src/lf_did --strict` exits 0
4. `ruff check src/ tests/` exits 0
5. Every normative "must" in the spec documents has a row in `SPEC_TRACEABILITY.md`
6. Every row in `SPEC_TRACEABILITY.md` has at least one passing test ID
7. No hardcoded tier names (grep for `"anchor"`, `"maintainer"`, `"contributor"`, `"steering"`, `"lead"`, `"approver"`, `"reviewer"`, `"member"` in `src/` — zero hits except in context/fixture/test data files and CLI help strings)
8. No network calls possible in production code paths (grep for `urllib`, `requests`, `httpx`, `socket.create_connection`, `http.client` — zero hits in `src/lf_did/core/`)
9. `lf-did --help` and all subcommand `--help` outputs are complete and accurate
10. `Makefile fsck-demo` target runs a complete demo with synthetic data and exits 0

**INSTRUCTIONS:**

The audit agent must:
1. Run the full test suite and capture output
2. Grep the source for hardcoded tier names and network calls as specified
3. Generate `SPEC_TRACEABILITY.md` by reading all normative requirements from the spec documents (this prompt, plus the design docs embedded in the handoff) and mapping each to test functions by name
4. Fix any issues found before declaring COMPLETE

---

## NORMATIVE REQUIREMENTS SUMMARY

The following are the hard requirements that all agents must enforce. These are not suggestions.

**Cryptography:**
- Accepted key types: ed25519 (`z6Mk`), P-256 (`zDn`), P-384 (`z82`). secp256k1 rejected unconditionally.
- Signature over JCS-canonicalized (RFC 8785) payload only. No other canonicalization.
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
- Identity files named `<did-fragment>.json` (fragment = everything after `did:key:`).
- Tier subdirectories under `identities/` named after tier names from `tiers.json`.
- Endorsements at `endorsements/<subject-fragment>/<endorser-fragment>.json`.
- Delegations at `delegations/<delegator-fragment>/<delegate-fragment>.json`.
- Revocations at `revocations/<subject-fragment>.json`.
- Rotations at `rotations/<old-fragment>-to-<new-fragment>.json`.

**Subprocess interface (normative, from Appendix B):**
- Sign: `lf-did sign-object [--project p] [--registry path] --output <sigfile> <payload-file>` — exit 0, write JSON to sigfile
- Verify: `lf-did verify-object [--project p] [--registry path] --signature <sigfile> --payload <payload-file> [--minimum-tier <tier>]` — exit 0 on success, structured key-value output on stdout

**Fsck must check all of:**
- Document filename matches DID fragment in `id` field
- Self-signatures valid
- Tier subdirectory matches `lf:tier` field
- Tier names exist in `tiers.json`
- Endorser exists, not revoked, not expired, has capability
- Endorsement signatures valid
- Delegation capability checks
- Delegation scope is valid ref glob
- Revocation authority checks
- Revocation signatures valid
- Expiry ≤ 2 years from registration
- Every non-anchor has a valid chain to anchor
- `policy/trust-anchors.json` exists and non-empty
- `policy/tiers.json` valid, acyclic, single root

---

## CONSTRAINTS FOR ALL AGENTS

1. **Python 3.11+ only.** Use `match` statements where appropriate. Use `tomllib` (stdlib). Use `pathlib.Path` everywhere.
2. **No shell scripts as logic.** `subprocess` is permitted only for: calling `git` commands, calling `gpg` for import operations, running the CLI as a subprocess in integration tests.
3. **`attrs` for all dataclasses.** No plain `@dataclass`. Use `attrs.define` with validators.
4. **Type annotations on every function.** `mypy --strict` must pass.
5. **No global mutable state.** All state flows through function arguments and return values.
6. **Tests are first-class.** Every function in `core/` has at least one test. Every error path has a test.
7. **Fixtures are self-contained.** Tests must not depend on external files, network, or real SSH agent. All use `tmp_path` and `MockAgentClient`.
8. **Tier names in test fixtures use real project names** (kernel, kubernetes) to validate that the generic machinery handles them correctly. The production code must not reference these names.
9. **Every exception type is defined in `exceptions.py`** with a docstring explaining when it's raised.
10. **Logging is structured.** Use Python `logging` with logger names matching module paths. DEBUG for crypto operations. INFO for registry operations. WARNING for policy near-misses. ERROR for verification failures.

---

## VERIFICATION CHECKLIST FOR EVALUATING AI

The following checks will be run by the evaluating AI against the completed codebase:

```bash
# 1. Clean install
pip install -e ".[dev]"

# 2. Full test suite
pytest tests/ -x --tb=short --cov=src/lf_did --cov-report=term-missing

# 3. Type check
mypy src/lf_did --strict

# 4. Lint
ruff check src/ tests/

# 5. No hardcoded tier names in core
grep -rn '"anchor"\|"maintainer"\|"contributor"\|"steering"\|"lead"\|"approver"\|"reviewer"\|"member"' src/lf_did/core/ && echo FAIL || echo PASS

# 6. No network calls in core
grep -rn 'urllib\|requests\|httpx\|http\.client\|socket\.create_connection\|socket\.connect' src/lf_did/core/ && echo FAIL || echo PASS

# 7. Coverage gate
pytest --cov=src/lf_did --cov-fail-under=90

# 8. Subprocess interface smoke test
# (run by Makefile fsck-demo target)
make fsck-demo
```

All 8 checks must pass for the project to be considered COMPLETE.

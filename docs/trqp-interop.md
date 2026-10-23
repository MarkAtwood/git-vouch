# verify-trust interop surface

**Status:** research spike for `git-vouch-trqp` (bead vouch-faq3.1),
2026-10-22. It records what OpenVTC's `verify-trust` actually sends and
accepts, read from source. It decides nothing: the mapping choices
belong to vouch-faq3.2.

## Verdict

`git-vouch-trqp` can interoperate over HTTPS. It must speak the Trust
Task envelope at `POST <base>/trust-tasks`, not plain TRQP
`/authorization`. Two gaps sit in verify-trust itself, and no bridge can
fix them:

1. **Blocker: FIDO and P-256 signers fail.** verify-trust accepts only
   plain `ssh-ed25519` signatures. A commit signed with
   `sk-ssh-ed25519@openssh.com` (kernel.org's default FIDO type),
   `ecdsa-sha2-nistp256` or `sk-ecdsa-sha2-nistp256@openssh.com` fails as
   `malformed` before the registry is asked, and so does `ssh-rsa`.
   git-vouch accepts all five types (DESIGN.md, did:key). Only signers with a plain software or
   agent-held `ssh-ed25519` key can pass verify-trust.
2. **Limitation: commits only, evaluated as of now.** verify-trust
   checks commit ranges, never tags. It never sends the TRQP
   `context.time`, so the registry answers for the present moment even
   for old commits.

Everything else works with no OpenVTC change. did:key resolves locally.
A git-vouch user can claim the DID with plain git config. The registry's
DID document needs one `TRQPRest` service entry.

## Sources

All citations are to these pinned trees. VGI paths are relative to its
`crates/` directory. Crate paths are relative to the crate root under
`~/.cargo/registry/src/index.crates.io-*/`, at the versions VGI's
`Cargo.lock` pins.

| Short name | Source | Version |
|---|---|---|
| VGI | `~/GIT/OpenVTC_verifiable-git-infrastructure` (verify-trust, vgi-core) | commit 5d9b9b6, 2026-10-19 |
| trql-client | crates.io `trql-client` | 0.27.0 |
| trust-tasks-rs | crates.io `trust-tasks-rs` | 0.32.1 |
| resolver | crates.io `affinidi-did-resolver-cache-sdk` | 0.8.41 |
| did-common | crates.io `affinidi-did-common` | 0.4.3 |
| ssh-key | crates.io `ssh-key` | 0.6.7 |

trql-client is not vendored in any local OpenVTC repo. It is the
published crate, fetched with `cargo fetch --locked`.

## 1. Wire format: a Trust Task envelope

The request is **not** plain TRQP `POST /authorization`. It is a Trust
Task document for `registry/authorization/0.1`, POSTed as JSON to
`<base>/trust-tasks`.

- verify-trust queries HTTPS as `POST <url>/trust-tasks`: VGI
  `verify-trust/src/registry.rs:366-368`, `verify-trust/src/lib.rs:94-95`.
- The transport appends `/trust-tasks` to the base URL (a trailing `/` is
  trimmed) and POSTs the document as JSON: trql-client
  `src/https.rs:1-3`, `src/https.rs:60-64`, `src/https.rs:85-86`. An
  optional bearer token exists (`src/https.rs:30-31`), but verify-trust
  never sets one (`registry.rs:368` uses `HttpsTransportConfig::new`
  defaults, `src/https.rs:36-43`).
- Envelope members on the wire: `id`, `threadId`, `type`, `issuer`,
  `recipient`, `issuedAt`, `payload`, and more that are optional:
  trust-tasks-rs `src/document.rs:33-107`.
- The client sets `id` to a fresh `urn:uuid:`, `type` to
  `https://trusttasks.org/spec/registry/authorization/0.1`, `recipient`
  to the registry DID, `issuer` to the client DID if one was set, and
  `issuedAt` to now: trql-client `src/client.rs:227-231`,
  `src/client.rs:335-337`; type URI at trust-tasks-rs
  `src/specs/registry/authorization/v0_1.rs:778`. Over HTTPS
  verify-trust sets no client DID, so `issuer` is absent
  (`registry.rs:367-374`; contrast `registry.rs:387-392`).
- Request `payload`: `entity_id`, `authority_id`, `action` and
  `resource` (all required), with optional `context` {`time`, `locator`}
  and `ext`: trust-tasks-rs `src/specs/registry/authorization/v0_1.rs:187-199`
  and the schema at `:780-781`. verify-trust sends no `context`
  (`verify-trust/src/lib.rs:1196`; context only when time or locator is
  set, trql-client `src/client.rs:164-174`).

Example request, as verify-trust sends it:

```json
{
  "id": "urn:uuid:7c0e…",
  "type": "https://trusttasks.org/spec/registry/authorization/0.1",
  "recipient": "did:web:registry.example",
  "issuedAt": "2026-10-22T12:00:00Z",
  "payload": {
    "entity_id": "did:key:z6Mk…",
    "authority_id": "did:web:vtc.example",
    "action": "git.commit.sign",
    "resource": "git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux"
  }
}
```

What the reply must be, or the client refuses it:

- **Any status:** the body must parse as a Trust Task document. On a 2xx
  a body that does not parse is a contract error. On a non-2xx it is a
  transport error, which means `registryUnavailable`: trql-client
  `src/https.rs:116-130`.
- **`threadId` equals the request `id`:** `src/client.rs:236-243`.
- **Success:** `type` is the request type with `#response`
  (`…/registry/authorization/0.1#response`), `src/client.rs:257-262`,
  trust-tasks-rs `src/specs/registry/authorization/v0_1.rs:785-786`.
- **The tuple is echoed verbatim:** `entity_id`, `authority_id`,
  `action` and `resource` must equal what was asked, or the reply is an
  `AnswerMismatch`: trql-client `src/client.rs:33-38`,
  `src/client.rs:284-300`.
- **Response payload:** `authorized` (bool) and `time_evaluated`
  (RFC 3339) are required with the four tuple members. `message`
  (≤1024 chars), `time_requested`, `context` and `ext` are optional, and
  `additionalProperties` is false: trust-tasks-rs
  `src/specs/registry/authorization/v0_1.rs:312-330` and the schema at
  `:788-789`.
- **Denial:** answer `authorized: false`. The client treats a missing
  record as a denial, not an error (`src/client.rs:158-159`). A
  `trust-task-error` document (`type` slug `trust-task-error`, any
  status) becomes `Rejected` (`src/client.rs:20`, `src/client.rs:245-255`),
  which verify-trust also counts as a denial and not as unavailability
  (VGI `verify-trust/src/lib.rs:1203-1208`).
- trust-tasks-rs's own `respond_with` builds a conforming reply: `type`
  plus `#response`, `threadId` from the request id, and `issuer` set to
  the request's `recipient`: `src/document.rs:376-408`. trql-client's
  HTTPS round-trip test pins the same contract:
  `tests/https_binding.rs:32-64`.

**Trust model over HTTPS:** the reply is unsigned. verify-trust trusts it
because the URL came from the registry DID's document:
VGI `verify-trust/src/lib.rs:21-24`, `verify-trust/src/registry.rs:56-58`.
Nothing else protects it:

- No scheme check. `select_route` returns any HTTPS-kind endpoint as is
  (VGI `verify-trust/src/registry.rs:226-227`), `Registry::https` passes
  the URL straight to `HttpsTransportConfig::new`
  (`verify-trust/src/registry.rs:366-368`), and trql-client only appends
  `/trust-tasks` and parses it (`src/https.rs:60-64`). An `http://`
  endpoint is accepted, and its answer can be forged on the path.
- Redirects are followed. The reqwest client is built with only timeouts,
  so reqwest's default redirect policy applies: trql-client
  `src/https.rs:65-68`. Neither crate sets `redirect` or `https_only`.
- The resolver's `PublicOnly` host policy (§2) covers DID resolution
  only, not the registry endpoint fetch.

So the answer's integrity rests entirely on the bridge publishing an
`https://` endpoint that answers directly.

## 2. DID-document service entry

`ServiceCapabilities::from_document` reads the document's `service`
array and puts an entry into `https` when its `type` is, or includes,
`TRQPRest` or `VTARest`. The endpoint is the **base URL**, and the
client appends `/trust-tasks` itself.

- Accepted REST types: `TRQPRest` and `VTARest`, trql-client
  `src/discovery.rs:55`, `src/discovery.rs:63`, `src/discovery.rs:76`.
  `VTARest` is for VTAs, and a registry must not advertise it
  (`src/discovery.rs:57-62`).
- `TrustRegistry` alone is **not** a transport. It is deliberately left
  out of the REST types (`src/discovery.rs:70-76`). In a VTC's document,
  a `TrustRegistry` entry whose endpoint is a DID is a referral
  (`src/discovery.rs:78-94`, `src/discovery.rs:297-305`; VGI
  `vgi-core/src/services.rs:51-56`). Using `["TRQPRest", "TrustRegistry"]`
  together is fine (VGI `vgi-core/src/services.rs:84-87`).
- `type` may be a string or an array: `src/discovery.rs:310-316`.
- `serviceEndpoint` may be a string, an object with `uri`, or an array of
  either. The first usable one wins: `src/discovery.rs:321-328`.
- An empty endpoint is skipped, and the first entry of each type wins.
  The `#id` fragment is ignored: `src/discovery.rs:10-14`,
  `src/discovery.rs:171-198`.
- verify-trust uses HTTPS only when the document advertises no TSP or
  DIDComm service. Its preference is TSP, then DIDComm, then HTTPS, with
  no fallback: VGI `verify-trust/src/registry.rs:92-99`,
  `verify-trust/src/registry.rs:219-239`. A TSP or DIDComm endpoint that
  is not a DID is skipped (`registry.rs:226-236`). So the bridge's
  document should carry only the `TRQPRest` entry, unless the bridge
  also serves the mediator bindings.
- verify-trust never guesses a URL from the DID's domain:
  `verify-trust/src/registry.rs:189-192`. `--registry-url` is the
  explicit override (`verify-trust/src/lib.rs:94-110`).

The minimal entry, shaped like verify-trust's own test fixture (VGI
`verify-trust/src/registry.rs:1364-1396`):

```json
{
  "id": "did:web:registry.example",
  "service": [
    { "id": "#rest", "type": "TRQPRest",
      "serviceEndpoint": "https://registry.example" }
  ]
}
```

The registry DID itself must resolve through the same resolver as
signer DIDs (VGI `verify-trust/src/registry.rs:199-206`). That resolver
fetches only from public hosts and follows no redirect
(`verify-trust/src/lib.rs:1020-1027`, `:1058`). This guard does **not**
apply to the `TRQPRest` endpoint itself, which may be any scheme and host
and is fetched with redirects followed (§1, trust model).

## 3. The signer DID in a commit, and plain git config

verify-trust reads the claim from the signed payload. It checks the
**`Signed-by-DID:` trailer first** and falls back to the committer
email for older commits. The module doc at `verify-trust/src/lib.rs:5-6`
mentions only the committer header and is out of date.

- Order (trailer, then committer): VGI `vgi-core/src/commit.rs:150-160`.
- Committer form: the `<…>` field of the `committer` header, read from
  the header block only, using the last `<`:
  `vgi-core/src/commit.rs:103-119`. It counts only when it starts with
  `did:`. Everything from the first `#`, `?` or `/` is stripped, so
  `did:…#key-0` becomes the bare DID: `vgi-core/src/commit.rs:121-148`.
- Trailer form: the last `Signed-by-DID` trailer in git's own trailer
  block (a port of git's `trailer.c`), value starting `did:`, with the
  same stripping: `vgi-core/src/commit.rs:9-14`, `:171-172`, `:191-225`.
- If the trailer and a DID committer both appear and disagree, the
  commit fails (`ConflictingSignerDids`): `vgi-core/src/commit.rs:162-169`,
  VGI `verify-trust/src/lib.rs:955-957`.
- The claim is read from the bytes the signature covers:
  `verify-trust/src/lib.rs:953-962`.

**A git-vouch user can do this with plain git config.** Checked with
git 2.55.0 on a throwaway repository:

```sh
# Option A (preferred): keep a real email, add the trailer.
git config alias.vc "commit --trailer 'Signed-by-DID: did:key:z6Mk…'"
git vc -m "…"        # git interpret-trailers --parse shows the trailer

# Option B (legacy): the DID as the committer email.
git config user.email did:key:z6Mk…
```

Option A needs `git commit --trailer` (git 2.32 or later) and keeps the
kernel's email-based attribution. Option B also works, and git still
verifies the SSH signature by key (`ssh-keygen -Y find-principals`), but
the committer email is then no longer an email. `git vouch did` gives
the did:key from the key text:
`git vouch did "$(cat ~/.ssh/id_ed25519.pub)"`. Passing the `.pub` path,
as DESIGN.md's Commands section allows, currently fails with `not an SSH
public key line` (tracked in vouch-ey47.14).

## 4. did:key resolves, locally

Yes. verify-trust's resolver resolves did:key itself, with no network
call, and the document has the shape vgi-core requires.

- verify-trust resolves signers through `tdk.did_resolver()`: VGI
  `verify-trust/src/lib.rs:1101-1107`. It builds the TDK with no cache
  service address, so it resolves locally: `verify-trust/src/lib.rs:1052-1065`.
- The resolver registers `KeyResolver` for the `key` method:
  resolver `src/lib.rs:788-795`. Methods are dispatched at
  `src/resolver/mod.rs:18-30`. A down cache server would still fall back
  to local resolution for did:key: `src/lib.rs:678-700`.
- Ed25519 did:key document: a `Multikey` method `did:key:z…#z…` with
  `publicKeyMultibase` equal to the identifier, `controller` equal to
  the DID, and listed in `assertionMethod`: did-common
  `src/did_method/resolve.rs:48-60`, `:95-118`. The resolver's own test:
  resolver `src/resolver/mod.rs:130-145`.
- vgi-core accepts exactly that: `assertionMethod` references to the
  document's own methods, `controller` equal to the document `id`,
  `publicKeyMultibase` with multicodec `0xED01`: VGI
  `vgi-core/src/did.rs:10-78` (multicodec prefix at 10, controller
  check at 36-40, `assertionMethod` walk at 55-76).

**Not exercised end to end.** No verify-trust test signs a commit as a
did:key signer. The did:key used in `verify-trust/tests/verify_trust_e2e.rs:1755`
is only a secret's key id. This answer comes from reading the code;
vouch-faq3.7 should prove it.

P-256 did:keys resolve too (did-common `src/did_method/resolve.rs:85-87`),
but vgi-core extracts only Ed25519 keys. Such a signer is reported as
`unresolvedSigner` with "DID document lists no Ed25519 key under
assertionMethod": VGI `verify-trust/src/lib.rs:1122-1131`.

## 5. Key types: plain ssh-ed25519 only

verify-trust parses the sshsig and accepts only `KeyData::Ed25519`.
Everything else is `malformed` with "unsupported signature algorithm":
VGI `verify-trust/src/lib.rs:941-950`.

- In ssh-key 0.6.7, FIDO keys are separate variants:
  `SkEd25519` and `SkEcdsaSha2NistP256`, and P-256 is `Ecdsa`
  (`src/public/key_data.rs:23`, `:26`, `:36`, `:41`). So
  `sk-ssh-ed25519@openssh.com`, `ecdsa-sha2-nistp256` and
  `sk-ecdsa-sha2-nistp256@openssh.com` signatures are all refused, as
  are `ssh-rsa` ones.
- Key extraction from DID documents is Ed25519-only as well: VGI
  `vgi-core/src/did.rs:10` (multicodec `0xED01`), `:41-44`.
  The sshsig helpers are Ed25519-only: `vgi-core/src/sshsig.rs:1`.
- The check runs before the registry query, so no bridge answer can
  rescue it.

For git-vouch this is the main interop gap. DESIGN.md accepts
`sk-ssh-ed25519`, P-256 and RSA for every tier and notes that kernel.org
issues `ed25519-sk` by default with `ecdsa-sk` as the fallback. Note that
`sk-ssh-ed25519` and `ssh-ed25519` share a did:key (DESIGN.md, did:key),
so the DID would resolve and the raw key bytes would match. Only the
sshsig parse refuses it.

## 6. Action and resource

**Action:** `--action`, default `git.commit.sign`, sent verbatim:
VGI `verify-trust/src/main.rs:67-69`, `verify-trust/src/lib.rs:122-123`,
`:1196`. trql-client documents the same example
(`src/client.rs:48`, `src/lib.rs:32-40`). verify-trust has no tag
action, because it only walks commits with `git rev-list`
(`verify-trust/src/lib.rs:81-84`, `:1271`, `:1287`). The bridge receives
whatever string the operator configured, and the default is
`git.commit.sign`.

**Resource:** forge-qualified, lowercased, validated:

```text
resource   = forge-host "/" segment *( "/" segment )
forge-host = lowercased DNS host (dotted) or localhost; no port
segment    = [a-z0-9._-]+, never "." or ".."
```

- Grammar and rules: VGI `vgi-core/src/resource.rs:1-28`. Length cap
  512 bytes (`:32-35`). verify-trust allows up to 21 path segments,
  because it calls `normalize_resource` with no forge depth
  (`vgi-core/src/resource.rs:37-40`, `:190-197`;
  `verify-trust/src/resource.rs:179-180`). A scheme, port, trailing
  slash, empty segment or `.`/`..` segment is refused, never rewritten
  (`vgi-core/src/resource.rs:219-221`, `:239-277`). The module doc says
  a `.git` suffix is refused too (`:20`), but the code does not refuse
  it: `.` is a legal segment character (`:317-319`), and `.git` is only
  stripped when building the suggestion for an input with a scheme
  (`:321-327`). So `…/linux.git` and `…/linux` are two different valid
  resources, and the bridge must match the resource exactly.
- verify-trust's own module repeats the grammar: `verify-trust/src/resource.rs:1-29`.
  The bare `owner/repo` form was removed in 0.8.0
  (`verify-trust/src/resource.rs:21-25`, `:71-76`).
- The default comes from Forgejo/GitHub CI variables. Otherwise
  `--resource` is required: `verify-trust/src/resource.rs:213-220`.
  A kernel run must therefore pass `--resource` explicitly, e.g.
  `git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux` (7 segments,
  valid).
- `--fallback-resource` is tried second, with OR semantics. It must
  contain the primary by whole-segment prefix:
  `verify-trust/src/lib.rs:132-137`, `:1185-1201`;
  `verify-trust/src/resource.rs:221-233`;
  `vgi-core/src/resource.rs:282-294`. So the bridge may receive the same
  signer twice, once per resource.
- `authority_id` is the **VTC's** DID (`--vtc-did`), not the registry's:
  `verify-trust/src/lib.rs:9-13`, `:119-121`, `:1195-1196`. The bridge
  must echo it verbatim (§1).

## Facts for later beads

- **vouch-faq3.2 (mapping):** the bridge sees `entity_id` = a did:key,
  `authority_id` = whatever the operator passes as `--vtc-did`, `action`
  = `git.commit.sign` unless overridden, and `resource` = an explicit
  forge-qualified path. Tags and files never arrive. Under §5, an
  `authorized: true` for a FIDO-only signer cannot help that signer's
  commits pass.
- **vouch-faq3.3 (`query --at`):** verify-trust never sends
  `context.time` (§1), so it always gets an answer for now. A commit
  made before a key's retirement is judged against the current registry,
  unlike `git verify-commit`'s `valid-before` handling.
- **vouch-faq3.4 (service):** listen at `POST /trust-tasks`, return a
  `#response` document with `threadId` equal to the request `id` and the
  tuple echoed, plus `authorized` and `time_evaluated`. Use
  `authorized: false` for no record, and non-2xx only with a
  `trust-task-error` body. Serve `POST /trust-tasks` directly, never by
  redirect: verify-trust follows redirects (§1, trust model).
- **vouch-faq3.5 (DID document):** one `TRQPRest` service whose endpoint
  is the base URL, at a DID verify-trust resolves from a public host.
  The `serviceEndpoint` must be `https://`: verify-trust accepts
  `http://` and the unsigned answer would then be forgeable on the path
  (§1, trust model).
- **vouch-faq3.7 (e2e):** prove §4 (did:key signer) and §5 (an
  `sk-ssh-ed25519` commit is refused) against real verify-trust.

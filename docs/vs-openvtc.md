# git-vouch and OpenVTC

**Status:** comparison, 2026-10-22; every OpenVTC claim re-checked
2026-11-15. OpenVTC facts come from its public repositories
(github.com/OpenVTC, mainly `verifiable-trust-infrastructure`, its
`docs/`, and the `wiki` repository) at their last commit on or before
2026-10-22, and from the ToIP specifications they implement. Where a
number has moved since, the 2026-11-15 value follows it. git-vouch facts
come from `DESIGN.md`. git-vouch is implemented but not released, and
its patatt and b4 forks are not upstream. OpenVTC runs a kernel
maintainer pilot; nothing of it is deployed in production, and its
browser wallet has never been published.

## Verdict

Both answer one question: is this kernel contributor a real person whom
real people vouch for, and may their key sign for the kernel? OpenVTC
answers it with an always-on agent per person, three transports, seven
credential types and over 1.5 million lines of code. git-vouch
answers it with the SSH keys and git that kernel developers already use,
a git repository of signed files, and one Python file of about 4,500
lines.

Both stacks use the same signature format: OpenVTC's git signing (VGI)
asks the person's agent to produce an SSHSIG, which OpenVTC's CI tool
`verify-trust` checks by resolving the signer's DID and querying the
trust registry. git-vouch has git produce the SSHSIG from the person's
own SSH key, and git itself verifies it against a file git-vouch
generates. OpenVTC adds machinery on both sides of that signature: an
agent before it, and DID resolution plus a registry query after it.

## Side by side

| | OpenVTC | git-vouch |
|---|---|---|
| Scope | Know Your Developer, plus data rooms, elections, directory, personas, agent hosting, forge namespace governance, OpenID4VP wallet interop | Kernel signing identity only |
| Size | About 900k lines of Rust and 97k of TypeScript in the core repo, `verifiable-trust-infrastructure`; about 515k more in 11 other repos; 1,104 crates in the core lockfile. On 2026-11-15: 1.05M Rust, 122k TypeScript, 1,136 crates; the core repo grows by about 100k lines a week | One file of about 4,500 lines; no dependencies beyond Python 3, git and OpenSSH |
| Spec | ToIP VTI specification, Working Draft 0.2.0: about 8,500 lines and 1,260 MUSTs (12,158 and 1,891 on 2026-11-15), plus the Trust Tasks registry: 946 task versions of 738 tasks (1,405 of 901) | `DESIGN.md`; the Python is the reference |
| Runtime | An always-on VTA per person and a VTC per community, plus mediator, DID host, push gateway and trust registry | None. Commands run and exit |
| Person's key | Derived from one seed held by the VTA | The SSH key the person already has: agent, FIDO token, gpg-agent |
| Identifier | did:webvh for public identities; did:key, did:peer, did:web elsewhere | did:key derived from each SSH key; any other DIDs listed in `alsoKnownAs`, never resolved |
| Vouching | VRC pairs for relationships; `vetted/1` statements by members with a vetter role | An endorsement file signed by the endorser, binding the subject's name and key, with an optional free-text note |
| Admission | Join-manifest criteria (automatic or human review), tightened by `join.rego` | An approver from a higher tier signs a tier record after reading the endorsements |
| Roles | VMC membership plus VAC role credentials, published to a TRQP registry | Four tiers: anchor, maintainer, contributor, automation |
| Revocation | Bitstring Status List | A signed revocation file; git rejects the key through `gpg.ssh.revocationFile` |
| Distribution | Trust Tasks over TSP, DIDComm v2 or HTTPS | `git fetch` of the registry; changes arrive as merges |
| CI check | `verify-trust` checks the signer DID against the registry and fails closed | Plain `git verify-tag` / `verify-commit` against the exported `allowed_signers` |
| Moving from PGP | `cnm vetting bootstrap-pgp` turns the strong set into founding vetters | `pgpkeys.git` is frozen and ported; on the flag day only Linus's tree and release tags stop accepting GPG, and every other tree switches by the late cutoff six months later; a GPG continuity proof unlocks locally generated endorsement drafts but grants no tier |
| Privacy | Correlation scopes; PCS hides which vetters vouched | None. Public by design |
| Release cadence | Breaking changes by policy: 203 in the Eucalyptus release | Formats are plain files and SSH signatures, chosen so a future git can read them unchanged |

## What OpenVTC has that git-vouch gives up

- **Fresh authorisation checks.** `verify-trust` queries the live
  registry on every CI run, and the VTC checks status lists at admission. A git-vouch
  copy is only as fresh as the last `git vouch sync`; git-vouch warns
  after 7 days and keeps working.
- **Vetter privacy.** git-vouch publishes who endorsed whom. OpenVTC's PCS
  can hide it. OpenVTC's own documents call PCS an unaudited research
  artifact, off by default, and note that hidden vetters make per-vetter
  accounting impossible.
- **Policy as code.** Rego can express and tighten admission rules;
  git-vouch has one fixed rule (the approver sits above the tier they
  grant).
- **Trust that travels.** OpenVTC credentials are W3C VCs usable across
  communities. git-vouch is one registry for one project, though its
  records are JSON-LD with did:keys that other tools can read.
- **Two-person control of everything the root does.** A 2026-10-02
  survey of VTC operations found three ways one administrator could get
  round the second-administrator rule (remove the others, lower the
  consent threshold, replace the policy) and closed all three. Second-party
  consent is on unless a community is installed in single-administrator
  mode, and the host can still write an admin entry with an offline
  break-glass command; both are audited and flagged. git-vouch needs two anchors' cosigns for any change
  to `anchors.json` after the first and for an anchor's or maintainer's
  unsigned key change (see Cosign in `DESIGN.md`). Review alone still
  covers the first `anchors.json`, a contributor's unsigned key change,
  and deleting a tier record.

## What git-vouch has that OpenVTC lacks

- **Nothing to run or operate.** No VTA or other always-on agent, no TEE, no mediator, no
  registry service. The optional TRQP bridge (below) serves outside
  verifiers; kernel developers never need it.
- **No new key custody.** Keys stay where people keep them today.
  OpenVTC had critical, since-fixed key-custody bugs: a context-scoped
  admin could derive any key, including another tenant's, and export it
  (VTI #1715, `docs/05-design-notes/key-custody.md`). It keeps a
  private-key export route on the VTA, behind its own capability, and a
  cached copy of VTA-minted keys on the VTC (`vtc-mvp.md`).
- **Small enough to audit.** One 4,500-line Python file and three
  programs every kernel developer already has, against over a million
  lines and 1,100 crates.
- **Stable formats.** Records are files signed over their exact bytes;
  no canonicalisation, transport or version negotiation to drift.
- **A path into git itself.** The formats are chosen so git can take over
  `git-vouch`'s job piece by piece (see Upstream path in `DESIGN.md`).

## Where they overlap

A minimal know-your-developer system built from OpenVTC's parts, as we
read them, would be close to git-vouch: did:webvh for the community and
did:key for people, one HTTPS transport, membership and authority
credentials, a status list, a trust registry, and commit signing checked
in CI. git-vouch differs in two ways: the registry is a git repository
rather than a service, and git checks the signatures rather than a
separate CI tool.

## Compatibility: the TRQP bridge

OpenVTC's `verify-trust` can check git-vouch signers through
`git-vouch-trqp`. The bridge answers verify-trust's Trust Task queries
(`registry/authorization/0.2` at `POST /trust-tasks`) from
`git vouch query`, and `git-vouch-trqp did-document` prints the registry
DID document with one `TRQPRest` endpoint. We expect LF devops to run
the canonical instance; `docs/bridge-deployment.md` covers running it,
and `docs/trqp-interop.md` records verify-trust's side.

The bridge speaks only 0.2, which verify-trust asks first from 0.27.0
on; earlier verify-trust, which asks only 0.1, gets `unsupportedVersion`.
The end-to-end test passes against verify-trust 0.33.0 (2026-11-15).

What a yes proves: the did:key is a current key of a registered person
with at least one endorsed email, any tier, in a registry copy synced
within 24 hours, from an answer at most 60 seconds old. Automation
identities, retired and revoked keys, and unknown keys get `false`
(DESIGN.md, TRQP bridge).

What it does not prove:

- **That the answer is authentic.** Answers over HTTPS are unsigned.
  verify-trust trusts one because its URL came from the registry DID's
  document, so trust rests on the DID-bound `https://` endpoint and on
  TLS to it. verify-trust 0.24.0 also accepted an `http://` endpoint and
  followed redirects (not rechecked since), so the bridge refuses to
  print a non-`https://` endpoint and serves `/trust-tasks` directly. Anyone can check an answer against the
  public registry.
- **That the signer may sign this repository.** Answers are not scoped
  to a repository, and any tier counts, so the bridge can say yes where
  `git verify-commit` against the default export (contributor and
  above) would not.
- **That the key was valid when the commit was made.** verify-trust
  never sends `context.time`, so every commit is judged against the
  registry as it is now.
- **Anything about RSA signers.** verify-trust refuses RSA as
  `malformed` before it asks the bridge. It accepts ed25519, P-256 and
  both FIDO types, and requires the FIDO user-presence flag, which
  `ssh-keygen -Y verify` does not check
  (https://github.com/OpenVTC/verifiable-git-infrastructure/pull/177).
- **Tags.** verify-trust checks commit ranges only.

A stale bridge (no sync for 24 hours) or a down one makes verify-trust
fail closed with `registryUnavailable`.

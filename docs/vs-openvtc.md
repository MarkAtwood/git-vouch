# git-vouch and OpenVTC

**Status:** comparison, 2026-10-22. OpenVTC facts come from
`~/PROJECT/ToIP/docs/openvtc-explainer.md` (OpenVTC HEAD 2026-10-22);
git-vouch facts come from `DESIGN.md`. git-vouch is a design under
implementation; OpenVTC is a running pilot with no production deployment.

## Verdict

**Both answer the same question, and git-vouch answers only that
question.** The question is "is this kernel contributor a real person whom
real people vouch for, and may their key sign for the kernel?" OpenVTC
answers it with an always-on agent per person, three transports, seven
credential types and over 900k lines of code. git-vouch
answers it with the SSH keys and git that kernel developers already use,
a git repository of signed files, and one Python file planned at
1,000–1,500 lines.

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
| Scope | Know Your Developer, plus data rooms, elections, directory, personas, agent hosting, chat bridges, EU wallet interop | Kernel signing identity only |
| Size | About 655k lines of Rust plus 75k of TypeScript in the core repo, and about 245k in satellites; 1,104 crates in the lockfile | One file, planned 1,000–1,500 lines; no dependencies beyond Python 3, git and OpenSSH |
| Spec | ToIP VTI Working Draft 0.2.0: 8,524 lines, about 1,250 MUSTs, plus 350–386 Trust Task versions | `DESIGN.md`; the Python is the reference |
| Runtime | An always-on VTA per person and a VTC per community, plus mediator, DID host, push gateway and trust registry | None. Commands run and exit |
| Person's key | Derived from one seed held by the VTA | The SSH key the person already has: agent, FIDO token, gpg-agent |
| Identifier | did:webvh for public identities; did:key, did:peer, did:web elsewhere | did:key derived from each SSH key; any other DIDs listed in `alsoKnownAs`, never resolved |
| Vouching | VRC pairs for relationships; `vetted/1` statements by members with a vetter role | An endorsement file signed by the endorser, binding the subject's name and key, with an optional free-text note |
| Admission | Join-manifest criteria (automatic or human review), tightened by `join.rego` | An approver from a higher tier signs a tier record after reading the endorsements |
| Roles | VMC membership plus VAC role credentials, published to a TRQP registry | Four tiers: anchor, maintainer, contributor, automation |
| Revocation | Bitstring Status List | A signed revocation file; git rejects the key through `gpg.ssh.revocationFile` |
| Distribution | Trust Tasks over TSP, DIDComm v2 or HTTPS | `git fetch` of the registry; changes arrive as merges |
| CI check | `verify-trust` checks the signer DID against the registry and fails closed | Plain `git verify-tag` / `verify-commit` against the exported `allowed_signers` |
| Moving from PGP | `cnm vetting bootstrap-pgp` turns the strong set into founding vetters | A single flag day: `pgpkeys.git` is frozen and ported, everyone re-signs with SSH keys, and a GPG continuity proof unlocks locally generated endorsement drafts but grants no tier |
| Privacy | Correlation scopes; PCS hides which vetters vouched | None. Public by design |
| Release cadence | Breaking changes by policy: 203 in the Eucalyptus release | Formats are plain files and SSH signatures, chosen so a future git can read them unchanged |

## What OpenVTC has that git-vouch gives up

These are real capabilities, deliberately left out of git-vouch:

- **Fresh authorisation checks.** `verify-trust` queries the live
  registry on every CI run, and the VTC checks status lists at admission. A git-vouch
  copy is only as fresh as the last `git vouch sync`; git-vouch warns
  after 7 days and keeps working.
- **Vetter privacy.** git-vouch publishes who endorsed whom. OpenVTC's PCS
  can hide it, though the explainer notes PCS is unaudited research code
  and that hiding vetters defeats per-vetter review.
- **Policy as code.** Rego can express and tighten admission rules;
  git-vouch has one fixed rule (the approver sits above the tier they
  grant).
- **Trust that travels.** OpenVTC credentials are W3C VCs usable across
  communities. git-vouch is one registry for one project, though its
  records are JSON-LD with did:keys that other tools can read.
- **Two-person control of the root.** OpenVTC found three single-admin
  takeover paths and closed them with second-party consent for VTC admin
  actions, on by default. The host can still waive it with
  single-administrator mode or offline break-glass, both audited and
  loudly flagged, so host control remains a risk there too. git-vouch
  lets one registry maintainer merge and treats control of the
  registry repository as an accepted risk (see Anchors in `DESIGN.md`).

## What git-vouch has that OpenVTC lacks

- **Nothing to run or operate.** No VTA or other always-on agent, no TEE, no mediator, no
  registry service.
- **No new key custody.** Keys stay where people keep them today.
  OpenVTC had a critical, since-fixed key-custody bug (a scoped admin
  could derive and export any key), keeps a private-key export route on
  the VTA, and keeps a cached copy of VTA-minted keys on the VTC.
- **Auditable in a sitting.** One file and three programs every kernel
  developer has, against over 900k lines and 1,104 crates.
- **Stable formats.** Records are files signed over their exact bytes;
  no canonicalisation, transport or version negotiation to drift.
- **A path into git itself.** The formats are chosen so git can take over
  `git-vouch`'s job piece by piece (see Upstream path in `DESIGN.md`).

## Where they overlap

The explainer's own "minimal KYD system" (did:webvh for communities and did:key for
people, one HTTPS transport, two credential types, a revocation list, a
registry, commit signing checked in CI) is close to git-vouch. git-vouch takes it one step further: the
registry is a git repository rather than a service, and git checks the
signatures rather than a separate CI tool.

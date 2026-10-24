# How Linux Foundation projects identify and sign

**Status:** reference, checked 2026-10-23 with `gh api` against each
project's latest release tag and against the cited documents. Projects
change; recheck before quoting a row.

Across the Linux Foundation, a contributor is a forge login plus a legal
attestation. The people who may approve or release are a git-reviewed
list of usernames. Keys appear only where a project signs, and few
projects sign tags. The kernel's pgpkeys and Node.js's release keys are
the only person-level signing chains found.

## Identity

| System | Binds | Key? |
|---|---|---|
| LF ID / LFX SSO | An OAuth login (email, GitHub, Google, LinkedIn) to LF services ([sign in with GitHub](https://docs.linuxfoundation.org/lfx/sso/sign-in/sign-in-with-github)) | No |
| EasyCLA | A GitHub/GitLab account or email to a signed individual or corporate CLA ([contributor docs](https://docs.linuxfoundation.org/lfx/easycla/v2-current/contributors/individual-contributor), [glossary](https://docs.linuxfoundation.org/lfx/easycla/v2-current/glossary)) | No |
| DCO apps | A `Signed-off-by` line whose email matches the commit author ([dcoapp](https://github.com/dcoapp/app)) | No |
| kernel.org pgpkeys | A PGP key, added with at least one signature from a key already in the keyring ([pgpkeys](https://korg.docs.kernel.org/pgpkeys.html)); a kernel.org account needs two signatures from account holders ([accounts](https://korg.docs.kernel.org/accounts.html)) | Yes |

kup uploads are checked against the uploader's PGP signature over the
tarball, using the kernel.org keyring ([kup](https://korg.docs.kernel.org/kup.html)).
No LFX service was found to bind a signing key.

## Membership lists

Every project keeps its list of maintainers in git and changes it by
pull request. None signs those changes.

| Mechanism | Used by |
|---|---|
| Peribolos YAML, applied to GitHub ([docs](https://docs.prow.k8s.io/docs/components/cli-tools/peribolos/)) | Kubernetes, etcd ([kubernetes/org](https://github.com/kubernetes/org/blob/main/config/kubernetes/org.yaml)) |
| CLOWarden YAML ([cncf/clowarden](https://github.com/cncf/clowarden)) | CNCF; LFDT and LFDT Labs ([config.yaml](https://github.com/LF-Decentralized-Trust-labs/governance/blob/main/config.yaml)); OpenVTC |
| Pulumi-applied YAML | Sigstore ([github-sync](https://github.com/sigstore/community/tree/main/github-sync)) |
| `.project/maintainers.yaml`, collected daily by CNCF | Envoy, containerd, Prometheus, Argo |
| OWNERS / MAINTAINERS.md / CODEOWNERS | Everyone; LFDT requires `MAINTAINERS.md` ([policy](https://github.com/lf-decentralized-trust/governance/blob/main/tac/governing-documents/MAINTAINERS-file.md)) |

## Release tags

Latest release tag of each project, as GitHub's API reports it.

| Signed | Unsigned |
|---|---|
| containerd v2.4.2, etcd v3.7.3 (PGP) | Kubernetes v1.37.1 (annotated) |
| Prometheus v3.15.1 (SSH) | Envoy v1.40.1, Argo CD v3.5.6 (lightweight) |
| Sigstore cosign v3.1.4, rekor v1.5.5 (SSH) | Besu 26.10.1, Fabric v3.1.5, Indy v1.13.2 (lightweight) |
| Node.js v26.12.1, jQuery 4.0.0 | PyTorch v2.14.1, ONNX v1.23.2, Milvus v3.0.3 (lightweight) |
| gitsign v0.18.0 (gitsign; GitHub: `bad_cert`) | Electron v45.0.0 (annotated) |

No project checked signs tags with Sigstore's gitsign except gitsign
itself. Branch protection ("require signed commits") needs admin access
to read and is unverified; most default branches had unsigned commits.

## Release artifacts

| Method | Projects |
|---|---|
| Keyless cosign | Kubernetes binaries and images ([verify](https://kubernetes.io/docs/tasks/administer-cluster/verify-signed-artifacts/)); Argo CD images, with SLSA L3 provenance ([doc](https://github.com/argoproj/argo-cd/blob/master/docs/operator-manual/signed-release-assets.md)); Besu images |
| GitHub build attestations | containerd |
| PyPI attestations | ONNX |
| GPG-signed checksum file | Node.js `SHASUMS256.txt.asc` ([release-keys](https://github.com/nodejs/release-keys)); Envoy `checksums.txt.asc` |
| Checksums only | Prometheus, etcd, PyTorch, Electron |

LFDT policy requires Sigstore signing documented in `RELEASE.md`, a
Scorecard badge and SLSA levels ([release-signing.md](https://github.com/lf-decentralized-trust/governance/blob/main/tac/governing-documents/release-signing.md)).
Besu signs only its images; Fabric shows no signing; neither has a
`RELEASE.md`.

## Node.js release keys

The closest precedent to git-vouch. The TSC approves releasers
([releases.md](https://github.com/nodejs/node/blob/main/doc/contributing/releases.md)).
Their GPG fingerprints are listed in the README and kept as a keyring in
[nodejs/release-keys](https://github.com/nodejs/release-keys). They sign
release tags, release-branch commits and `SHASUMS256.txt.asc`. Eight
active releasers; no endorsements, tiers or revocation records.

## Sigstore gitsign

From the [gitsign README](https://github.com/sigstore/gitsign) and
[Sigstore security model](https://docs.sigstore.dev/about/security/):

- Signing needs a browser OIDC login; Fulcio issues a certificate valid
  for about ten minutes; Rekor logs a hash of the commit and the
  certificate.
- Verification needs `gitsign verify` with the expected identity and
  issuer. `git verify-commit` "does not verify cert claims".
- No revocation: "users are responsible for monitoring the log for
  unauthorized certificates issued to their identities".
- Offline verification is experimental. The README warns against
  `commit.gpgsign` because signing needs the network.
- Certificates in the public log may include user emails.

When CPython moved release signing to Sigstore (PEP 761), distributions
objected that it "relies on a handful of providers" and is "missing
offline verification" ([LWN 993787](https://lwn.net/Articles/993787/)).
No kernel discussion of Sigstore was found.

## OpenSSF criteria

- Best Practices `signed_releases` is a MUST; `version_tags_signed` is
  SUGGESTED ([criteria](https://www.bestpractices.dev/en/criteria/1)).
- Scorecard Signed-Releases looks for signature files on release assets
  and does not verify them; Scorecard has no signed-commit check
  ([checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md)).
- SLSA Source v1.2 requires authenticated actors and protected tags, not
  signed commits ([spec](https://slsa.dev/spec/v1.2/source-requirements)).

## The kernel

- Konstantin Ryabitsev called OpenSSH `-Y` signing with FIDO2 keys "most
  promising" in January 2022
  ([LKML](https://lkml.rescloud.iu.edu/hypermail/linux/kernel/2201.2/01185.html)).
- patatt signs patches with ed25519, OpenPGP or OpenSSH keys and keeps
  its keyring in git ([patatt](https://github.com/mricon/patatt)).
- LF Decentralized Trust started OpenVTC at the LF CEO's request because
  the kernel's PGP web of trust does not scale; the kernel is its first
  target ([LFDT progress report](https://www.lfdecentralizedtrust.org/blog/decentralized-trust-infrastructure-at-lf-a-progress-report),
  [Prague demo](https://www.linuxfoundation.org/blog/lf-decentralized-trust-demonstrates-the-first-open-source-verifiable-trust-community-in-prague)).
  Whether kernel maintainers adopted it is unverified.

## What this means for git-vouch

- Every project already keeps a reviewed list of people in git.
  git-vouch puts keys and signatures in that list; a project that
  already runs Peribolos or CLOWarden is one tool away (vouch-9ogq).
- Signed tags cost nothing extra once the list holds keys: `git vouch
  export` writes the file `git verify-tag` reads.
- Recent signed tags are moving to SSH (Prometheus, Sigstore's own).
  gitsign's network dependence and lack of revocation are the objections
  distributions already raised.
- Release artifacts are a separate problem that projects solve with
  checksums, GPG or keyless cosign; git-vouch leaves them out of scope
  (vouch-omzm.15).

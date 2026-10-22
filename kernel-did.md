# Linux Kernel DID Identity and Signing System

**Replaces:** GPG web of trust, kernel.org keyserver, `gpg --sign-key` ceremonies  
**Status:** Adopted by the Linux Foundation  
**Part of:** LF DID Infrastructure (see `lf-did-architecture.md` for the full picture)  
**Tooling:** `lf-did` CLI (Python 3.11+, see install below)  
**Project config:** `kernel` (auto-detected in kernel trees)  
**Registry:** `kernel.org/pub/scm/kernel/did-registry.git`  
**Mailing list:** `kernel-did@vger.kernel.org`

---

## Why this exists

GPG has been the kernel's identity and signing infrastructure for decades. It works,
mostly, but the operational reality is bad: keyserver poisoning attacks are trivially
easy, key signing parties are security theater that nobody actually validates, `gpg`'s
UX causes real mistakes from experienced people, and the web of trust model has never
actually reflected how trust in the kernel project works anyway.

How trust actually works in the kernel: Linus trusts a small set of people. Those people
trust their subsystem maintainers. Maintainers vouch for contributors. It's a tree, not
a web, and it always has been. The new system models that directly instead of pretending
otherwise.

The replacement is built on **Decentralized Identifiers (DIDs)**, specifically the
`did:key` method.

DIDs have a reputation for complexity. That reputation is earned in deployments that
lack a substrate for storing and distributing identity documents -- so they bolt on
blockchains, distributed hash tables, resolution infrastructure, and consensus
protocols to fill the gap. Read the DID spec and you will find extensive machinery for
solving problems that, if you already have git, you simply do not have.

We have git. Git is a content-addressed, cryptographically integrity-protected,
distributed database with a replication protocol spoken by every developer on the
planet. It already stores the thing we care most about -- the code -- with full
auditable history. Putting identity documents in git gives us: no keyserver
infrastructure, no third-party registry, no blockchain, no DHT, no consensus protocol,
no availability dependency beyond the git hosting we already operate. The full history
of who trusted whom, when, and who approved it is a `git log` away. Verification is
entirely offline. Revocation is a merged PR. Key rotation is a commit. The audit log
is the reflog.

What DIDs contribute is the identifier format and the document schema -- a
well-specified, standards-track way to encode a public key as a self-describing URI and
attach a typed, extensible document to it. That part is genuinely useful and we adopt
it directly. The rest of the DID complexity stack we simply do not need.

The other thing worth saying: your identity in this system is a text file. A JSON file
you can read in less than a minute, diff against yesterday's version, grep, commit, and
review in a pull request like any other code change. Your endorsements are text files.
Revocations are text files. The entire trust graph is text files in a git repo. We are
developers. We do not need an app, a GUI, a browser extension, or a wallet. We need
`$EDITOR` and `git log`.

One more: the system is entirely self-contained. No DID dereferencer is ever contacted
during any operation -- not signing, not verifying, not endorsing, not revoking. The
`did:key` identifier encodes the public key directly; resolution is local arithmetic.
Everything else -- identity documents, endorsements, revocations -- is in the git
registry clone sitting on your disk. The system works in a network-dark build
environment, on a laptop on a plane, in an air-gapped datacenter. It works when
kernel.org is down. It works when the LF servers are unreachable. It works always,
because there is nothing external to reach.

If you want to dereference a contributor's `alsoKnownAs` entries -- verify their
Bluesky account, resolve their `did:web`, check their EU wallet credential -- you can.
Nothing stops you. But that is your choice, for your purposes. It is never part of the
operation flow. The security properties of this system do not depend on any external
service being available, honest, or uncompromised.

The system is entirely self-contained. No step in any operation flow -- signing,
verifying, endorsing, revoking, rotating -- makes a network call or requires a running
service beyond the git hosting you already have. There is no DID resolver to run, no
resolution endpoint to query, no internet connectivity required at verification time.
`did:key` identifiers resolve by local computation: decode the multibase string, extract
the key. That is it. If you want to dereference someone's DID against the W3C resolution
infrastructure to cross-check their identity claims, you can -- nothing prevents it --
but it is never part of the operation flow and never a requirement. A build system in an
air-gapped datacenter with a stale registry clone from this morning verifies kernel
release signatures exactly as well as a developer with a live internet connection.

---

## How it works

### Project configuration

`lf-did` detects which project you are working in via a global config file at
`~/.config/lf-did/projects.json`, which maps project names to local registry clone
paths. This is a deliberate design choice: project tooling config does not live in the
kernel source tree, it lives in your local tool config. The kernel source tree does not
need to know about `lf-did`.

```json
{
  "kernel": {
    "registry": "~/src/kernel-did-registry",
    "context": "https://kernel.org/ns/did/v1"
  }
}
```

`lf-did init-project kernel` creates this entry automatically during setup, pointing at
a freshly cloned registry repo. You do not need to pass `--project kernel` explicitly
when working inside a kernel tree -- `lf-did` infers the project from the git remote URL
of the current repo by matching against known project registry URLs. The flag is
documented here for cases where auto-detection does not apply (bare checkouts, CI
environments, working outside a git tree).

### Your identity is a did:key

A `did:key` is a self-contained identifier that encodes your public key directly:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

The `z6Mk` prefix identifies this as an ed25519 key. The rest is your public key,
multibase-encoded. There is no registry. There is no server. Anyone with this string and
your signature can verify you signed something with no network access required.

This is different from PGP key IDs, which are just hashes pointing to a keyserver
record. Your DID *is* your key, fully self-describing. Resolution is local computation.

Accepted key types:

| Prefix | Type    | Notes |
|--------|---------|-------|
| `z6Mk` | ed25519 | Default. Recommended for all new keys. |
| `zDn`  | P-256   | For HSM or EU wallet-generated keys. |
| `z82`  | P-384   | For high-assurance HSM requirements. |

secp256k1 is not accepted.

### Your identity lives in the git tree

Your public identity is a W3C DID document committed to the registry repo. DID documents
are JSON-LD: the `@context` array defines the vocabulary for every field in the document,
which makes them formally typed, interoperable with other DID tooling, and extensible
without breaking existing parsers.

A minimal identity document:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://www.w3.org/ns/did/v1.1",
    "https://lf.org/ns/did/v1",
    "https://kernel.org/ns/did/v1"
  ],
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{
    "id": "did:key:z6Mk...#z6Mk...",
    "type": "Multikey",
    "controller": "did:key:z6Mk...",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": ["did:key:z6Mk...#z6Mk..."],
  "name": "Greg Kroah-Hartman",
  "email": "gregkh@linuxfoundation.org",
  "alsoKnownAs": [
    "at://gregkh.bsky.social"
  ],
  "kernel:tier": "maintainer",
  "kernel:registered": "2025-01-15T00:00:00Z",
  "kernel:expires": "2027-01-15T00:00:00Z",
  "kernel:selfSignature": "base64url-encoded-signature-over-this-document"
}
```

`verificationMethod` is standard W3C DID. It contains your public key in multibase
encoding. `authentication` references it, declaring this key can be used to authenticate
as this DID. These are required fields understood by any conformant DID resolver.

`kernel:tier`, `kernel:registered`, `kernel:expires`, and `kernel:selfSignature` are
kernel-specific terms defined in the kernel context at `https://kernel.org/ns/did/v1`.
The `lf:` prefix covers LF-wide shared terms; `kernel:` covers kernel-specific terms.
Both contexts are bundled with the tooling and resolved offline.

`kernel:selfSignature` is a signature over the canonicalized document (RFC 8785 / JCS)
with the `kernel:selfSignature` field absent, using your own private key. It proves you
constructed this document and hold the corresponding private key.

`kernel:expires` is mandatory. Maximum validity is two years from `kernel:registered`.
Expired identities are treated as revoked by all tooling. Renew before expiry with
`lf-did --project kernel renew`.

`alsoKnownAs` is defined in the base W3C DID spec. Put your Bluesky handle, EU wallet
DID, whatever you like. The tooling ignores it for all security decisions.

### Extending your identity document

You can add arbitrary data to your identity document by including additional JSON-LD
context and using terms from it. Existing vocabularies cover most things people will
want: schema.org defines `sameAs`, `url`, `jobTitle`; ActivityStreams defines social
graph terms; the W3C DID spec itself defines `alsoKnownAs`. For anything not covered by
an existing vocabulary, define your own context and reference it.

An extended identity document:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://www.w3.org/ns/did/v1.1",
    "https://lf.org/ns/did/v1",
    "https://kernel.org/ns/did/v1",
    "https://schema.org/",
    "https://example.com/myvocab/v1"
  ],
  "id": "did:key:z6Mk...",
  "verificationMethod": [...],
  "authentication": [...],
  "name": "Greg Kroah-Hartman",
  "email": "gregkh@linuxfoundation.org",
  "alsoKnownAs": ["at://gregkh.bsky.social"],
  "url": "https://www.kroah.com",
  "sameAs": "https://github.com/gregkh",
  "myvocab:ircNick": "gregkh",
  "myvocab:pgpFingerprint": "ABCD 1234 ...",
  "kernel:tier": "maintainer",
  "kernel:registered": "2025-01-15T00:00:00Z",
  "kernel:expires": "2027-01-15T00:00:00Z",
  "kernel:selfSignature": "base64url-encoded-signature-over-this-document"
}
```

Tooling that does not understand a field ignores it. The `kernel:selfSignature` covers
the entire canonicalized document including any extension fields, so adding data requires
re-signing. Re-signing requires holding the private key, which is the access control.
No maintainer review is required for self-edits to your own identity document -- CI
verifies the signature and the PR merges automatically on pass.

To edit your identity document:

```bash
lf-did --project kernel edit
# opens your current identity document in $EDITOR
# on save, re-canonicalizes and re-signs with your key
# outputs the updated file ready for PR

# or non-interactively
lf-did --project kernel set --field sameAs --value "https://github.com/gregkh"
lf-did --project kernel set --field myvocab:ircNick --value "gregkh" \
  --context "https://example.com/myvocab/v1"
```

### Endorsements are separate files

Once your identity is in the registry, maintainers can endorse you:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://lf.org/ns/did/v1",
    "https://kernel.org/ns/did/v1"
  ],
  "id": "did:key:z6Mk...(endorser)#endorsement-of-z6Mk...(subject)",
  "type": "kernel:Endorsement",
  "kernel:subject": "did:key:z6Mk...(subject)",
  "kernel:endorser": "did:key:z6Mk...(endorser)",
  "kernel:tierVouched": "contributor",
  "kernel:timestamp": "2025-01-20T14:32:00Z",
  "kernel:verificationMethod": "mailing list post <msgid@lore.kernel.org>",
  "kernel:signature": "base64url-encoded-signature"
}
```

Endorsements live at `endorsements/<subject-fragment>/<endorser-fragment>.json`.

`verification_method` is a human-readable note from the endorser describing how they
verified the subject's identity. It is public, permanent, and part of the signed
document. Write something that would survive a post-incident review.

### Trust tiers and what they mean

| Tier | Who | Can do |
|------|-----|--------|
| `anchor` | Linus, designated LF contacts | Endorse maintainers, emergency revocations, registry governance |
| `maintainer` | Subsystem maintainers | Sign release tags in their scope, endorse contributors, revoke contributors |
| `contributor` | Active contributors | Sign commits, be endorsed |
| `automation` | CI/build systems | Sign build artifacts in registered scope only; cannot endorse humans |

Tier is not self-declared. Your identity file contains a `tier` field but it is set by
the maintainer who approves your registry PR. The tooling enforces capability checks at
operation time against the registry.

Endorsement requirements to reach a tier:

- `contributor`: one `maintainer`-or-above endorsement
- `maintainer`: two `maintainer` endorsements plus one `anchor` endorsement
- `automation`: one `maintainer` endorsement; a human accountable maintainer is required
- `anchor`: out-of-band Linux Foundation process, not via this tooling

### Delegation: signing on behalf of a scope

Maintainers can delegate signing authority for a ref namespace to another DID. This is
how Greg signs stable tree tags without Linus signing each one.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://lf.org/ns/did/v1",
    "https://kernel.org/ns/did/v1"
  ],
  "id": "did:key:z6Mk...(delegator)#delegation-to-z6Mk...(delegate)",
  "type": "kernel:Delegation",
  "kernel:delegator": "did:key:z6Mk...(Linus)",
  "kernel:delegate": "did:key:z6Mk...(Greg)",
  "kernel:scope": "refs/tags/v*-stable",
  "kernel:expires": "2026-01-01T00:00:00Z",
  "kernel:timestamp": "2025-01-15T00:00:00Z",
  "kernel:signature": "base64url-encoded-signature-by-delegator"
}
```

Delegations live at `delegations/<delegator-fragment>/<delegate-fragment>.json`. A
delegated signature on a tag within scope is as valid as a direct signature from the
delegator. Delegation does not chain: you cannot delegate authority you received via
delegation. Delegates must be `maintainer` tier or above.

### The signature format on git objects

When you sign a tag, the tooling constructs and signs this payload:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://lf.org/ns/did/v1",
    "https://kernel.org/ns/did/v1"
  ],
  "type": "kernel:GitSignature",
  "kernel:objectType": "tag",
  "kernel:objectSha": "abc123...full 64-char SHA256 of the git object",
  "kernel:ref": "refs/tags/v6.12",
  "kernel:signer": "did:key:z6Mk...",
  "kernel:timestamp": "2025-01-20T14:32:00Z",
  "kernel:nonce": "first 32 bytes of object_sha, hex encoded"
}
```

The nonce is derived from the object SHA, making the signature object-bound. Replaying a
valid signature against a different tag object fails because the nonce won't match. The
payload is canonicalized (RFC 8785), signed, and stored at
`refs/signatures/tags/<tagname>` in the repository. For release tarballs distributed
outside git, a detached `.sig` file is produced alongside the tarball using the same
format.

### Revocation is a PR

To revoke a DID, submit a PR adding a signed file to `revocations/<did-fragment>.json`:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://lf.org/ns/did/v1",
    "https://kernel.org/ns/did/v1"
  ],
  "id": "did:key:z6Mk...(revoker)#revocation-of-z6Mk...(subject)",
  "type": "kernel:Revocation",
  "kernel:subject": "did:key:z6Mk...",
  "kernel:revoker": "did:key:z6Mk...",
  "kernel:reason": "key compromise reported by owner",
  "kernel:timestamp": "2025-03-01T02:14:00Z",
  "kernel:signature": "base64url-encoded-signature-by-revoker"
}
```

Once merged, all tooling rejects signatures from the revoked DID. Past signatures are
not retroactively invalidated (same behavior as GPG). The git history is the audit log.

### Key rotation

Rotation is for scheduled key hygiene or suspected (not confirmed) exposure.

```bash
lf-did --project kernel rotate
```

This generates a new keypair and produces a rotation record signed by your old key,
proving you authorized the rotation. Submit as a PR. After merge, your old DID is marked
superseded -- not revoked, so past signatures remain valid.

**Endorsements do not transfer automatically.** Your endorsers are notified via a
registry-generated issue. They re-endorse at their discretion. This is intentional:
automatic transfer would mean a compromised key plus rotation gives an attacker inherited
trust. Contact your endorsers directly after rotation.

For active compromise, see the Compromise Response section.

---

## Key storage

You must hold your private key. Options in ascending order of security:

**Filesystem** (`~/.config/lf-did/private/key.pem`)  
Acceptable for contributors. Encrypt your home directory. Do not use this if you are
a subsystem maintainer or above.

**Encrypted USB drive**  
Keep it unplugged. Mount it to sign, unmount it immediately after. LUKS or VeraCrypt.
Reasonable for maintainers who find hardware tokens annoying.

**Hardware token** (YubiKey, Nitrokey, or any PKCS#11 / SSH agent-compatible device)  
Required for `maintainer` tier and above. The key is generated on the device and never
exists in software. `lf-did` speaks to the token via the SSH agent protocol. No GPG
card emulation required, though the YubiKey OpenPGP applet works if you already have a
key there.

```bash
lf-did --project kernel device list    # see what tokens are visible
lf-did --project kernel device info    # show key info for connected token
```

**Anything that speaks SSH agent works.** Because `lf-did` talks exclusively to an SSH
agent socket, any software that can present that interface is a valid key backend.
Beyond hardware tokens this includes: Apple Keychain and Secure Enclave (via the macOS
platform SSH agent), GNOME Keyring, 1Password (built-in SSH agent with touch-to-sign),
Bitwarden, HashiCorp Vault, AWS KMS, Azure Key Vault, GCP Cloud KMS, and TPM 2.0 via
`tpm2-pkcs11`. If your employer prohibits personal hardware tokens on work systems but
has approved cloud KMS infrastructure, that works. The key lives wherever you put it;
`lf-did` only ever sees the agent socket.

The tool cannot verify what is behind the agent. The key storage requirements for each
tier are project policy enforced during the endorsement process, not technical
constraints. Maintainer-tier contributors should be prepared to describe their key
storage to their endorser. If you are using hardware-backed storage (Secure Enclave,
TPM, hardware token), your device can produce a hardware attestation certificate proving
the key was generated on-device:

```bash
lf-did --project kernel device attest
# produces an attestation document you can include in your registration PR
```

Attestation is optional for contributor tier, strongly recommended for maintainer tier,
and required for anchor tier.

**You can import an existing key.** If you already have an ed25519, P-256, or P-384
key you want to reuse, you can import it. The resulting identity is treated as
filesystem-tier regardless of the key's origin -- if you want maintainer tier or above
you need a hardware-backed key. Key type compatibility:

| Key type | Import supported | Notes |
|----------|-----------------|-------|
| ed25519 | Yes | From GPG, SSH, or raw PEM |
| P-256 | Yes | From GPG or PKCS#8 PEM |
| P-384 | Yes | From GPG or PKCS#8 PEM |
| RSA (any size) | No | Not a supported key type; generate a new key |
| DSA | No | Not a supported key type; generate a new key |
| ed448 | No | Not a supported key type; generate a new key |

See the Importing an existing key section below for import instructions.

**For `automation` tier:** Keys must be generated in and bound to a hardware HSM or
platform TPM 2.0. Software-stored automation keys are not accepted. The maintainer
registering the automation identity is permanently accountable for its key custody.

---

## Registry governance

Push access to the registry repo is held by a small group of `anchor`-tier identities
listed in `policy/registry-admins.json`. Registry PRs are discussed on the mailing list
before merge.

Merge requirements by PR type:

| PR type | Required approvals | Merge window |
|---------|--------------------|--------------|
| New contributor identity | 1 maintainer | Standard |
| New maintainer identity | 2 maintainers + 1 anchor | Standard |
| New automation identity | 1 maintainer (accountable) | Standard |
| Endorsement | 24h no-objection after list post | Standard |
| Delegation | 1 anchor review | Standard |
| Revocation (routine) | 1 maintainer-or-above | Standard |
| Revocation (emergency) | 1 anchor | 4 hours |
| Key rotation | Same as original tier | Standard |
| Renewal | Same as original tier | Standard |
| Self-edit of own identity | Automated CI (signature check only) | Immediate on CI pass |

Emergency revocations bypass the standard review window. Post the revocation to the
mailing list simultaneously with the PR.

---

## Install

Verify the release before installing. Download the tarball and signature from
`linuxfoundation.org/pub/tools/lf-did/`:

```bash
# Verify SHA256 (hashes published at linuxfoundation.org/pub/tools/lf-did/SHA256SUMS)
sha256sum -c SHA256SUMS

# Or if you already have lf-did installed:
lf-did verify-release lf-did-1.0.tar.gz lf-did-1.0.tar.gz.sig
```

The SHA256SUMS file is signed by the release manager's DID. Their DID and fingerprint
are published on `kernel-did@vger.kernel.org` and in `MAINTAINERS` in the registry repo.

**First install is trust-on-first-use.** There is no way around this: verifying the
release signature requires the tool you are trying to install. The mitigation is
out-of-band verification of the release manager's DID fingerprint before you trust the
binary. The fingerprint is published in at least three places: the mailing list
announcement post, the `MAINTAINERS` file in the registry repo, and
`linuxfoundation.org/did/release-keys`. Check at least two of these against each other.
If they agree, you have reasonable confidence the binary is legitimate. This is the same
trust model as every Linux distribution package manager on first bootstrap.

```bash
# Install from verified tarball
pip install lf-did-1.0.tar.gz

# Or from source
git clone https://linuxfoundation.org/pub/scm/lf-did.git
cd lf-did && pip install -e .
```

Requires Python 3.11+. Dependencies: `cryptography`, `jcs`, `click`. No GPG required.

The LF base context (`https://lf.org/ns/did/v1`) and kernel context
(`https://kernel.org/ns/did/v1`) are both bundled with the tooling and resolved
offline. Context resolution never makes network calls during verification.

**Platform notes:**  
Linux: fully supported, all token types.  
macOS: supported. Hardware tokens via SSH agent work. Secure Enclave key generation
available via `--generate-on-token` on Apple Silicon.  
Windows: supported. YubiKey and Nitrokey tested via SSH agent. If `lf-did --project kernel device list`
shows nothing, ensure `ssh-agent` is running and the token's CCID interface is enabled.

---

## How the tool finds the registry

`lf-did` needs to know where the local clone of the identity registry lives on disk.
It resolves this using the following precedence, stopping at the first match:

1. **`LF_DID_REGISTRY` environment variable.** Full path to the registry clone root.
   Overrides everything. Useful for CI pipelines and scripting.

   ```bash
   LF_DID_REGISTRY=/mnt/registries/kernel lf-did verify-tag v6.12
   ```

2. **`--registry` flag.** Per-invocation override.

   ```bash
   lf-did --project kernel --registry /path/to/registry sign-tag v6.12
   ```

3. **Config file.** `~/.config/lf-did/projects.json` maps project names to registry
   paths. Written automatically by `lf-did init-project` and editable by hand.

   ```json
   {
     "kernel": {
       "registry": "~/.local/share/lf-did/kernel/registry",
       "remote": "https://git.kernel.org/pub/scm/lf-did/kernel-did-registry.git"
     }
   }
   ```

4. **Well-known default path.** If none of the above are set, the tool looks for the
   registry at `~/.local/share/lf-did/<project>/registry/`. This is where
   `lf-did init-project` clones by default, so the common case requires no
   configuration beyond running init once.

`lf-did init-project kernel` clones the registry to the well-known default path and
writes the config file entry. After that, `lf-did --project kernel <command>` works
from any directory.

**Project auto-detection from git remote.** If `--project` is omitted and the current
directory is inside a git repository, `lf-did` inspects the remote URLs and matches
them against known project patterns from the config file. A remote pointing to
`kernel.org` resolves to the `kernel` project automatically. If detection is ambiguous
or fails, the tool exits with a clear error asking for an explicit `--project` flag.

```bash
# inside a kernel tree with kernel.org remotes -- project auto-detected
lf-did sign-tag v6.12

# explicit is always unambiguous
lf-did --project kernel sign-tag v6.12
```

The registry itself is just a git clone. You can inspect it, `git log` it, `git fetch`
it manually, or point `lf-did` at any path where you have a valid clone. There is
nothing special about the well-known default path; it is a convenience, not a
requirement.

---

## Operations

---

### Creating yourself

```bash
lf-did --project kernel init
```

You will be prompted for key type (ed25519 default), storage location, display name,
email, and optional `also_known_as` entries. Output is a `.json` file ready to submit
as a PR and a fingerprint:

```
DID fingerprint: SHA256:abc123...xyz (ed25519)
Full DID: did:key:z6Mk...
```

**Before submitting your PR, announce your fingerprint on the mailing list** from your
known email address. The maintainer reviewing your PR uses this to verify you
out-of-band. The mailing list post is your proof of ownership for contributor tier.
For maintainer tier, a video call or in-person meeting with an anchor is required before
the PR will be approved.

Submit your identity file as a PR to:
- `identities/contributors/<did-fragment>.json` for contributor tier
- `identities/maintainers/<did-fragment>.json` for maintainer tier (discuss first on list)

The filename is the DID fragment -- the multibase-encoded key string after `did:key:`.
For example, `z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.json`. This is
intentional: the filename is unambiguous, requires no mapping table, and is consistent
with how endorsement and revocation files are named. `lf-did --project kernel init` outputs the
correct filename automatically.

A human-readable `INDEX.md` is generated automatically in each identity directory on
every PR merge. Browse it to find people; use the DID fragment to address files
directly.

**Generate the key on a hardware token (recommended for maintainers):**

```bash
lf-did --project kernel init --generate-on-token
```

**Use a key already on a token:**

```bash
lf-did --project kernel init --token
# enumerates keys on the token, you select which one
```

---

### Getting yourself endorsed

After your identity PR is merged, contact a maintainer who knows your work. Send them
your DID (`lf-did --project kernel whoami`), your fingerprint, and a link to your mailing list
fingerprint announcement post. They verify you via whatever channel they consider
sufficient and run `lf-did --project kernel endorse`.

---

### Endorsing someone

Verify their identity before endorsing. Minimum bar by tier:

- `contributor`: mailing list history plus video call is sufficient
- `maintainer`: in-person or video call where you confirm identity against a government
  document or equivalent

```bash
lf-did --project kernel endorse did:key:z6Mk...(their DID) \
  --tier contributor \
  --note "netdev contributor since 2019, verified via video call 2025-01-18"
```

The `--note` field is included in the signed endorsement document. It is public,
permanent, and part of the signed payload. Write what you actually did to verify them.
Submit the resulting file as a PR.

Your endorsement is signed, timestamped, and in git history forever. You are accountable
for it. Endorse people you actually know.

To endorse at `maintainer` tier you must be `maintainer` or above. The tooling enforces
this at signing time.

---

### Signing a git tag

```bash
# Create a signed tag
lf-did --project kernel tag v6.12 -m "Linux 6.12"
# Replaces: git tag -s v6.12 -m "Linux 6.12"
```

If your key is on a hardware token, touch it when prompted. If touch policy is not
enabled on your token, enable it. A token without touch policy required offers much
weaker security guarantees than intended.

The signature is stored in `refs/signatures/tags/v6.12`.

```bash
# Verify a tag
lf-did --project kernel verify-tag v6.12

# Output:
# Tag:          v6.12
# Object SHA:   abc123...
# Signed by:    did:key:z6Mk... (Linus Torvalds <torvalds@linux-foundation.org>)
# Tier:         anchor
# Delegated:    no
# Expires:      2026-01-01 (valid)
# Revocation:   none
# Registry age: 2 days (ok)
# Result:       VALID

# Verify against a specific DID (for scripting)
lf-did --project kernel verify-tag v6.12 --require-did did:key:z6Mk...
# Exit 0 = valid, non-zero = invalid
```

**Registry clone freshness.** Verification checks revocation records in your local
registry clone. A stale clone means recently-revoked keys still appear valid. The
tooling enforces freshness thresholds:

- Clone older than 7 days: warning printed, verification proceeds
- Clone older than 30 days: verification fails with `REGISTRY_STALE` error

Refresh your registry clone:

```bash
lf-did --project kernel registry sync
# equivalent to: git -C <registryPath> fetch --prune
```

Build and CI systems should sync the registry clone at the start of each build. If your
build environment has no network access, pre-sync and cache the clone. The
`--allow-stale` flag overrides the staleness check for air-gapped environments; document
this override explicitly in your build policy if you use it.

**Sign and verify a release tarball:**

```bash
lf-did --project kernel sign-file linux-6.12.tar.xz
# produces linux-6.12.tar.xz.sig

lf-did --project kernel verify-file linux-6.12.tar.xz linux-6.12.tar.xz.sig
```

**Verify a chain of signed merges** back to a known-good anchor commit:

```bash
lf-did --project kernel verify-chain HEAD --anchor-commit abc123...
# Walks git ancestry verifying each signed merge
# Reports the first invalid or missing signature
# Exit 0 = full chain valid
```

Run this when you want to verify a pulled tree is unmodified from a known-good signed
state.

---

### Delegating signing authority

```bash
# Authorize someone to sign tags in a scope on your behalf
lf-did --project kernel delegate \
  --to did:key:z6Mk...(their DID) \
  --scope "refs/tags/v*-stable" \
  --expires 2026-01-01

# List active delegations
lf-did --project kernel delegation list
lf-did --project kernel delegation list --from-me

# Revoke a delegation
lf-did --project kernel delegation revoke --to did:key:z6Mk...
```

Submit the delegation file as a PR. Requires one anchor review before merge.

---

### Renewing before expiry

```bash
lf-did --project kernel renew
# Generates updated identity document with new expiry
# Signed by your current key
# Submit as a PR; same approval requirements as original registration
```

The tooling warns 60 days before expiry. There is no grace period after expiry --
expired identities are treated as revoked immediately.

---

### Rotating your key

For scheduled rotation or suspected (not confirmed) exposure:

```bash
lf-did --project kernel rotate
```

Generates a new keypair, signs a rotation record with your old key, and prepares a PR.
After merge, contact your endorsers to request re-endorsement. They will not transfer
automatically.

---

### Revoking someone

```bash
lf-did --project kernel revoke did:key:z6Mk...(their DID) \
  --reason "maintainer left project, key no longer actively managed"
```

You must be `maintainer` or above, and can only revoke DIDs at your tier or below. For
urgent cases, mark the PR `[URGENT]` and post to the mailing list; an anchor merges
within 4 hours.

**Self-revoke** (you still have the key):

```bash
lf-did --project kernel self-revoke --reason "key material exposed, generating replacement"
```

**If you have lost access to your key entirely**, contact an anchor-tier maintainer
directly via a verified channel (your known email, phone, in person). They can issue a
third-party revocation signed by their anchor key. After revocation is confirmed,
start fresh with `lf-did --project kernel init`. You will need re-endorsement.

---

### Registering an automation identity

```bash
lf-did --project kernel init-automation \
  --name "kernel.org stable build system" \
  --scope "refs/tags/v*-stable-build" \
  --key-source tpm \
  --accountable-did did:key:z6Mk...(your DID)
```

Key must be TPM 2.0 or HSM bound. Software keys are rejected. The accountable
maintainer's DID is permanently recorded in the automation identity document. Automation
identities cannot endorse humans and cannot sign outside their registered scope.

---

## Compromise response

If your signing key is actively compromised (in an attacker's hands, not just possibly
observed):

**In this order:**

1. **Post to `kernel-did@vger.kernel.org` immediately.** Subject: `[COMPROMISE] <your DID fragment>`. Use your known email address. Do not wait to be certain. False alarms are fine.

2. **Self-revoke if you still have the key.** `lf-did --project kernel self-revoke --reason "active compromise"`. Mark the PR `[URGENT]`. An anchor merges within 4 hours.

3. **If you cannot self-revoke**, contact an anchor-tier maintainer directly by phone or
   in person. Have them issue a third-party revocation. Your mailing list post from step
   1 is your authorization.

4. **Do not use the compromised key for anything**, including signing your own revocation
   if there is any chance the attacker could be watching. A third-party revocation from
   an anchor is cleaner.

5. **After revocation is confirmed merged**, run `lf-did --project kernel init` to generate a new
   identity. Endorsements do not transfer after compromise revocation. Contact your
   endorsers directly.

**If you are an anchor receiving a compromise report:**

1. Verify the report came from the maintainer's known channel.
2. Merge the revocation PR or issue a third-party revocation. Do not wait for additional
   approvals. One anchor is sufficient for emergency revocation.
3. Reply to the mailing list thread confirming revocation is in effect.

---

## Verifying the registry itself

```bash
# Verify entire registry is internally consistent
lf-did --project kernel verify-registry

# Checks: all self_signatures valid, all endorsement signatures valid,
# endorsement graph consistent with tier assignments, no circular delegations,
# no expired identities without revocation record, revocation records properly signed.

# Verify a specific identity file
lf-did --project kernel verify-identity identities/maintainers/gregkh.json
```

The trust anchors are listed in `policy/trust-anchors.json`. Their fingerprints were
announced on LKML and are published on kernel.org. Everything else in the registry
chains to them.

---

## Importing an existing key

If you have an existing ed25519, P-256, or P-384 key you want to reuse, import it
directly. The resulting identity is filesystem-tier. If you need maintainer tier or
above, generate a new key on hardware instead.

### Import from GPG

First check your key type. RSA and DSA keys cannot be imported; you will need a new
key.

```bash
gpg --list-keys --with-colons <fingerprint> | grep "^pub" | cut -d: -f4
# algo 22 = ed25519  (supported)
# algo 19 = P-256 / ECDSA  (supported)
# algo 1  = RSA  (not supported, generate a new key)
# algo 17 = DSA  (not supported, generate a new key)
```

**If you have an ed25519 GPG key:**

The cleanest extraction path uses `sq` (Sequoia, a modern OpenPGP implementation).
Install it with `cargo install sequoia-sq` or from your distro packages.

```bash
# Export the secret key from GPG
gpg --export-secret-keys --armor <fingerprint> > secret.asc

# Extract the raw ed25519 key material and convert to PEM
sq key extract-secret secret.asc | sq packet dump --mpis 2>/dev/null
# Or use lf-did's built-in GPG import which wraps this:
lf-did --project kernel import-key --from-gpg --fingerprint <fingerprint>
```

`lf-did import-key --from-gpg` is the recommended path. It handles the extraction,
validates the key type, converts to the required format, and drops you into the normal
`init` flow to complete your identity document. The raw commands above are shown so you
understand what is happening.

**If you have a P-256 or P-384 GPG key (uncommon):**

```bash
gpg --export-secret-keys --armor <fingerprint> > secret.asc
lf-did --project kernel import-key --from-gpg --fingerprint <fingerprint>
# lf-did detects the curve and handles conversion
```

**After import, link your old GPG identity to your new DID:**

```bash
lf-did --project kernel link-gpg --fingerprint <fingerprint>
```

This uses your GPG key to sign an attestation linking your old GPG fingerprint to your
new DID. The attestation is included in your identity document as `kernel:gpgLink`.
After the cutover date the GPG key is no longer used for signing; the link is historical
metadata that lets people verify continuity of identity.

### Import from SSH

If your existing signing key is an SSH ed25519 key:

```bash
# Convert OpenSSH private key to PEM
ssh-keygen -p -m PEM -f ~/.ssh/id_ed25519 -N ""
# Then import
lf-did --project kernel import-key --from-ssh --key ~/.ssh/id_ed25519
# Restore passphrase protection afterwards
ssh-keygen -p -f ~/.ssh/id_ed25519
```

Or if the key is already loaded in your SSH agent:

```bash
# List keys in agent
ssh-add -l
# Import directly from agent by fingerprint
lf-did --project kernel import-key --from-agent --fingerprint SHA256:abc123...
```

### Import from minisign

If you have an existing minisign key and want to use it as your DID key:

```bash
lf-did --project kernel import-key --from-minisign   --key ~/.minisign/minisign.key
```

This extracts the ed25519 key material from the minisign secret key format and stores
it as a PKCS#8 PEM. The minisign key ID is not preserved -- your DID is derived from
the public key bytes, not the minisign ID.

### Import from PEM

If you have a raw PKCS#8 PEM file (ed25519, P-256, or P-384):

```bash
lf-did --project kernel import-key --from-pem --key path/to/key.pem
```

### After any import

The imported key is stored at `~/.config/lf-did/private/key.pem` (filesystem tier).
Proceed with `lf-did init` as normal -- the import flow deposits the key and then hands
off to the standard identity creation process. Your resulting identity document is
identical to one created with a freshly generated key; the import history is not
recorded anywhere in the registry.

### Signing release artifacts in minisign format

Minisign is common in the Rust and Go ecosystems for signing release tarballs. It uses
ed25519 and has no SSH agent support -- it requires the raw private key on disk, which
means exporting your DID key to minisign format would require extracting it from
hardware storage, defeating the point.

The solution: `lf-did sign-file` can produce minisign-compatible signature files
directly, using your hardware-backed DID key via the SSH agent. The private key never
leaves the token. The output is a standard `.minisig` file that `minisign -V` accepts.

```bash
# Sign a release tarball, producing a minisign-compatible signature
lf-did --project kernel sign-file --format minisign linux-6.12.tar.xz
# produces linux-6.12.tar.xz.minisig

# Consumers with minisign verify normally:
minisign -V -p kernel-release.pub -m linux-6.12.tar.xz

# Consumers with lf-did get the full chain verification:
lf-did --project kernel verify-file linux-6.12.tar.xz linux-6.12.tar.xz.minisig
```

The minisign signature format is: an ed25519 signature over the file contents (or a
hash of them for large files), wrapped in a header line containing the algorithm
identifier and a key ID. `lf-did` constructs this format using the signature bytes
returned by the SSH agent, without ever handling the private key scalar. The key ID
embedded in the `.minisig` header is derived deterministically from your DID public key
rather than being a random 64-bit number, which means `lf-did verify-file` can
automatically resolve it back to your DID document.

Publish your minisign public key alongside your releases. Generate it once from your
DID public key:

```bash
lf-did --project kernel export-pubkey --format minisign
# outputs the minisign public key line to stdout
# e.g. RWQ8ue4YPTR4pAkDTPFiCYj3dRaj+gSB1Z9MlRpIHHUOf0aFGfz2DSSE
```

Record it in your identity document so consumers can correlate your DID with your
minisign public key:

```bash
lf-did --project kernel set   --field kernel:minisignPublicKey   --value "RWQ8ue4YPTR4pAkDTPFiCYj3dRaj+gSB1Z9MlRpIHHUOf0aFGfz2DSSE"
```

**Exporting public keys to other formats** (private key never leaves storage):

```bash
lf-did --project kernel export-pubkey --format ssh
# outputs the SSH public key line, suitable for authorized_keys or publishing

lf-did --project kernel export-pubkey --format pem
# outputs the public key as PEM (PKCS#8 SubjectPublicKeyInfo)
```

Private key export to disk is intentionally not supported for keys stored in hardware
tokens or cloud KMS backends. For filesystem-tier keys, the key file is already at
`~/.config/lf-did/private/key.pem` and needs no export command.

---

## Transition from GPG

During the transition period, both systems are accepted for tag signing. The cutover
date is in `TRANSITION.md` in the registry repo.

If you are importing your GPG key to use as your DID key, follow the Import from GPG
section above. If you want to keep using a freshly generated DID key but link your GPG
identity for continuity:

```bash
lf-did --project kernel link-gpg --fingerprint ABCD1234...
```

This does not import your GPG private key. It uses your GPG key to sign a bootstrap
attestation linking your old GPG fingerprint to your new DID. After the cutover date,
only the DID key matters; the GPG link becomes historical metadata.

---

## Quick reference

| Operation | Command |
|-----------|---------|
| Create identity | `lf-did init` (auto-detects project) |
| Create identity on hardware token | `lf-did --project kernel init --generate-on-token` |
| Show your DID and fingerprint | `lf-did --project kernel whoami` |
| Endorse someone | `lf-did --project kernel endorse <did> --tier <tier> --note <note>` |
| Sign a tag | `lf-did --project kernel tag <tagname> -m <message>` |
| Verify a tag | `lf-did --project kernel verify-tag <tagname>` |
| Verify chain back to anchor | `lf-did --project kernel verify-chain HEAD --anchor-commit <sha>` |
| Sign a file | `lf-did --project kernel sign-file <file>` |
| Verify a file | `lf-did --project kernel verify-file <file> <file.sig>` |
| Delegate signing scope | `lf-did --project kernel delegate --to <did> --scope <glob> --expires <date>` |
| List delegations | `lf-did --project kernel delegation list` |
| Renew before expiry | `lf-did --project kernel renew` |
| Rotate key | `lf-did --project kernel rotate` |
| Revoke someone | `lf-did --project kernel revoke <did> --reason <reason>` |
| Self-revoke | `lf-did --project kernel self-revoke --reason <reason>` |
| Register automation identity | `lf-did --project kernel init-automation` |
| List devices | `lf-did --project kernel device list` |
| Verify registry | `lf-did --project kernel verify-registry` |
| Link GPG identity | `lf-did --project kernel import-from-gpg --fingerprint <fp>` |
| Clone registry + set up config | `lf-did init-project kernel` |
| Import key from GPG | `lf-did --project kernel import-key --from-gpg --fingerprint <fp>` |
| Import key from SSH | `lf-did --project kernel import-key --from-ssh --key <path>` |
| Import key from SSH agent | `lf-did --project kernel import-key --from-agent --fingerprint <fp>` |
| Import key from PEM | `lf-did --project kernel import-key --from-pem --key <path>` |
| Import key from minisign | `lf-did --project kernel import-key --from-minisign --key <path>` |
| Sign file (minisign-compatible) | `lf-did --project kernel sign-file --format minisign <file>` |
| Sign file (native) | `lf-did --project kernel sign-file <file>` |
| Verify file | `lf-did --project kernel verify-file <file> <file.sig>` |
| Export public key (minisign) | `lf-did --project kernel export-pubkey --format minisign` |
| Export public key (SSH) | `lf-did --project kernel export-pubkey --format ssh` |
| Export public key (PEM) | `lf-did --project kernel export-pubkey --format pem` |
| Link old GPG identity | `lf-did --project kernel link-gpg --fingerprint <fp>` |
| Sync registry clone | `lf-did --project kernel registry sync` |
| Edit your identity document | `lf-did --project kernel edit` |
| Set a field in your identity | `lf-did --project kernel set --field <field> --value <value>` |

---

## File layout of the registry repo

All identity, endorsement, delegation, revocation, and rotation files are named by DID
fragment -- the multibase-encoded key string after `did:key:`. For example, an identity
file for `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK` is stored as
`z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.json`. The filename is the key: no
mapping table, no collisions, no ambiguity. Tooling locates any file given only a DID
with a single path construction.

Each identity directory contains a generated `INDEX.md` -- a human-readable table of
display name, email, DID fragment, tier, and expiry, regenerated automatically on every
PR merge. Browse it to find people; tooling ignores it.

```
policy/
  trust-anchors.json        # anchor DIDs and fingerprints
  registry-admins.json      # who has merge rights
  capabilities.json         # tier capability definitions
  POLICY.md                 # governance and emergency procedures

identities/
  contributors/
    INDEX.md                            # generated, do not edit
    z6Mk<fragment>.json
  maintainers/
    INDEX.md
    z6Mk<fragment>.json
  automation/
    INDEX.md
    z6Mk<fragment>.json

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

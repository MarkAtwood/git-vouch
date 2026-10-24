# Flag day runbook

**Status:** runbook, 2026-10-22. Facts come from `DESIGN.md` (Flag day).

On one date, the flag day, the kernel stops accepting GPG-signed tags and
pulls and starts verifying SSH signatures against the git-vouch registry.
No period accepts both. Before that date every pgpkeys holder who still
signs registers an SSH key; after it, nothing new needs `gpg`. The kernel
team sets the dates and the anchor list, so this page leaves them blank.
The test suite runs every command block here end to end ([Rehearsal](#rehearsal)).

## Timeline

> **What this does:** lists the four phases, their dates and who acts in each.
> **Why:** one switch date with no dual period, so after it nothing new needs `gpg` ([rationale](rationale.md#one-flag-day)).

| Phase | When | Who acts | What happens |
|---|---|---|---|
| 1. Freeze | _freeze date_ | kernel.org | `pgpkeys.git` gets one last signed commit, the freeze commit, and becomes read-only. Its hash, the flag-day date and the late cutoff are published together. |
| 2. Window | freeze to flag day (_window length_) | anchors first, then everyone | The first registry merge holds the anchors' person files and `anchors.json`. Everyone else registers, adds a continuity proof if they had a pgpkeys key, signs endorsement drafts and gets approved. Everyone who signs or checks patches installs the patatt fork and sets its keyring sources. |
| 3. Flag day | _flag-day date_ | Linus, release tooling, every developer | Linus and the release tooling switch to files from `git vouch export`. GPG-signed tags and pulls stop being accepted. |
| 4. Late cutoff | six months after the flag day | nobody; every patch checker deletes one config line | Continuity claims against the freeze commit are accepted until this date. After it, people register as newcomers. The GPG fallback for patch signing ends. |

## Kernel-team calls

> **What this does:** names the values the kernel team sets; nothing below depends on them.
> **Why:** these are decisions, not design, and DESIGN gives no reason for the six-month cutoff or for leaving it to registry maintainers ([rationale](rationale.md#late-cutoff)).

The kernel team decides:

- the anchor list;
- the freeze date and the window length;
- who the registry maintainers are, who may merge into the registry
  (`DESIGN.md`, Open questions);
- the registry's repository path on git.kernel.org (kernel.org
  administrators), and how people submit branches to it. The commands
  below push a branch to the registry; a merge request works the same way.

**The late cutoff is six months after the flag day, and it is policy,
not code.** The anchors may extend it by announcement. After it, registry
maintainers do not merge any change that adds or alters a `migratedFrom`
field or adds a `people/*.json.asc`. The merge date counts, not the
commit date.

## Who does what

> **What this does:** maps each role to its job in the runbook.
> **Why:** a tier is a separate record its approver signs: anchors grant maintainer, maintainers grant contributor ([rationale](rationale.md#tiers)).

| Role | Does |
|---|---|
| kernel.org and the registry maintainer | Freezes pgpkeys and publishes the freeze commit. Merges each registry branch once `git vouch check` passes, and commits `anchors.json`. |
| Anchor | Registers first. Drafts and signs endorsements from their own GPG certifications. Approves maintainers. |
| pgpkeys holder | Ports pgpkeys, completes their person-file draft, adds a continuity proof. |
| Developer with no GPG key (about 80% of maintainers) | Registers fresh and collects fresh endorsements. |
| Certifier: any holder who certified others' GPG keys | Drafts endorsements locally, reads each one, signs the ones that are right. |
| Maintainer | Endorses, and approves contributors. |
| Linus and the release tooling | Switch to the exported allowed-signers files. |

GPG supplies no tiers. Linus certified 2 keys in pgpkeys, so the web of
trust says nothing about who is a maintainer. Anchors approve maintainers
on their own judgement, using MAINTAINERS and endorsements.

## What the commands assume

> **What this does:** lists the variables, tools and key every command expects.
> **Why:** each person runs the tools on their own machine against the published freeze commit; drafts are never generated centrally ([rationale](rationale.md#freeze-commit)).

Published with the freeze commit, and used as shell variables below:

- `$FREEZE_COMMIT`, the freeze commit's hash;
- `$SIGNER`, the primary fingerprint of the key that signed the freeze
  commit;
- `$PGPKEYS`, `$REGISTRY` and `$LINUX`, the repository URLs.

Run your own commands on your own machine, from your home directory, with
`git-vouch` and `git-vouch-migrate` on `PATH` and your SSH key loaded in
an agent. The commands use a key at `~/.ssh/id_ed25519`; any agent-backed
key works, and maintainers and anchors should use hardware. Put your own
name, handle and branch in place of the rehearsal's ([Rehearsal](#rehearsal)).

## 1. Freeze

> **What this does:** kernel.org freezes `pgpkeys.git` at one signed commit that every later step reads.
> **Why:** DESIGN gives no reason for reading one commit only; it says what reading it safely takes: `--no-replace-objects` and the tree's blobs ([rationale](rationale.md#freeze-commit)).

kernel.org makes the last commit to `pgpkeys.git`, the freeze commit,
signs it, makes the repository read-only, and publishes the freeze
commit, `$SIGNER`, the flag-day date and the late cutoff together.

Nobody needs to verify the freeze commit by hand: every `git-vouch-migrate`
command checks its signature by `$SIGNER` first and refuses to run
otherwise. It reads pgpkeys only at the freeze commit, never at a later
commit. It reads pgpkeys with `--no-replace-objects`, so `refs/replace`
in the pgpkeys clone (for example from `git clone --mirror` of an
untrusted mirror) cannot change the `keys/` content or the freeze commit
it checks. It reads `keys/` as the blobs in the freeze commit's tree, so
no `.gitattributes` (`export-ignore`, `export-subst`), `info/attributes`
or `core.attributesFile` can drop or change a `keys/` file.

## 2. Window

> **What this does:** everyone registers, proves continuity, endorses and gets approved, one reviewed branch at a time.
> **Why:** changes arrive as reviewed merges, and review is the only gate for three accepted risks ([rationale](rationale.md#nothing-pushes)).

### The first merge: the anchors

> **What this does:** puts the anchors' person files and `anchors.json` in the empty registry.
> **Why:** the registry is the root of trust: `anchors.json` in it names the anchors, and nothing is pinned locally ([rationale](rationale.md#registry-in-git)).

The registry maintainer clones the registry once, at the start of the
window:

```sh
git clone -q "$REGISTRY" registry
```

Each anchor ports pgpkeys, completes their own draft and signs it with
their GPG key as a continuity proof:

```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$FREEZE_COMMIT" --signer "$SIGNER" --out drafts
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/lena.json ~/.ssh/id_ed25519.pub
gpg --armor --detach-sign people/lena.json
git add people
git commit -q -m "people: register lena"
git push -q origin HEAD:register-lena
```

Find your own draft and read it before registering: the handle is
permanent. `port` writes one unsigned draft per person in pgpkeys, with a
proposed handle, the name, the emails from unrevoked user IDs and
`migratedFrom`. Everyone runs it themselves; its output is deterministic
from the public pgpkeys at the freeze commit, so there is no central copy
to trust. `register --from` adds your SSH key and signs the file.

The registry maintainer then merges the anchors' branches and commits
`anchors.json` on top:

```sh
cd registry
git fetch -q origin register-lena
git merge -q --ff-only FETCH_HEAD
echo '["lena"]' >anchors.json
git add anchors.json
git commit -q -m "anchors: lena"
git vouch check .
git push -q origin main
```

Merge the person files first: `check` fails if `anchors.json` names a
handle that has no person file. This first merge is the only
fast-forward, because the registry is still empty and git cannot make a
merge commit into an empty branch.

### Everyone else registers

> **What this does:** registers your SSH key by one of four routes, with a continuity proof if you had a pgpkeys key.
> **Why:** the proof only lets your old GPG certifiers draft endorsements for you; it grants no tier ([rationale](rationale.md#continuity-proof)).

Pick your route:

| You have | Route | Continuity proof |
|---|---|---|
| A pgpkeys key, not revoked by the freeze commit | Complete your draft | `people/<handle>.json.asc` |
| A pgpkeys key that expired (but was not revoked) by the freeze commit | Extend it locally, then the same | `people/<handle>.json.asc` |
| An ed25519, P-256 or RSA (2048+) authentication key or subkey on your pgpkeys key | Use it as your SSH key | The subkey signs your person file |
| No pgpkeys key, or one revoked by the freeze commit | Register fresh | None |

Every route needs an SSH key: ed25519, P-256, or RSA of 2048 to 4096
bits (no live RSA authentication key in pgpkeys is larger; see
[rationale](rationale.md#rsa-cap)). In `pgpkeys.git` at af88128
(2026-10-20), 602 of 645 unexpired keys are RSA and 4 are DSA; 188 have a
reusable authentication key, so most holders make a new key. If you do,
or if yours is RSA, upgrade now: `ed25519-sk` on a token, or `ecdsa-sk`
if the token has no ed25519. Any GPG key, RSA and DSA included, still
signs the continuity proof.

You need the continuity proof only to receive endorsement drafts ported
from GPG certifications. It grants no tier. Registering without it works;
you then collect fresh endorsements.

**With a detached GPG signature** over the person file's exact bytes:

```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$FREEZE_COMMIT" --signer "$SIGNER" --out drafts
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/alice.json ~/.ssh/id_ed25519.pub
gpg --armor --detach-sign people/alice.json
git add people
git commit -q -m "people: register alice"
git push -q origin HEAD:register-alice
```

**With an expired key.** Extend it in your local keyring first, because
gpg refuses to sign with an expired key. Never publish the new expiry
(do not send the key anywhere): the proof is judged against the key as it
was at the freeze commit, where expired is accepted.

```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$FREEZE_COMMIT" --signer "$SIGNER" --out drafts
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/bob.json ~/.ssh/id_ed25519.pub
fpr=$(gpg --list-secret-keys --with-colons | awk -F: '$1 == "fpr" {print $10; exit}')
gpg --quick-set-expire "$fpr" 1y
gpg --armor --detach-sign people/bob.json
git add people
git commit -q -m "people: register bob"
git push -q origin HEAD:register-bob
```

If you hold more than one secret key, set `fpr` to the fingerprint in
your draft's `migratedFrom`: the `fpr=` line takes the first secret key
in your keyring.

**With your authentication subkey.** `port` has already put it in your
draft as your SSH key. Expose it through gpg-agent's SSH support and sign
the person file with it:

```sh
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$FREEZE_COMMIT" --signer "$SIGNER" --out drafts
echo enable-ssh-support >>"${GNUPGHOME:-$HOME/.gnupg}/gpg-agent.conf"
gpg --list-secret-keys --with-colons --with-keygrip |
    awk -F: '$1 == "sec" || $1 == "ssb" {auth = $1 == "ssb" && $12 ~ /a/}
             $1 == "grp" && auth {print $10}' >>"${GNUPGHOME:-$HOME/.gnupg}/sshcontrol"
gpgconf --kill gpg-agent
gpgconf --launch gpg-agent
SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
export SSH_AUTH_SOCK
gpg --export-ssh-key dave@example.org >~/.ssh/gpg-auth.pub
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/dave.json --sign-with ~/.ssh/gpg-auth.pub
git add people
git commit -q -m "people: register dave"
git push -q origin HEAD:register-dave
```

The two files go in your gpg home: `$GNUPGHOME` if set, else `~/.gnupg`.
The subkey must sign the current version of your person file; merely
listing it proves nothing, because the public subkey is public.

**Fresh, with no GPG key:**

```sh
git clone -q "$REGISTRY" registry
cd registry
git vouch register --handle carol --name "Carol Fresh" --email carol@example.com \
    ~/.ssh/id_ed25519.pub
git add people
git commit -q -m "people: register carol"
git push -q origin HEAD:register-carol
```

### Merging a branch

> **What this does:** the registry maintainer reviews and merges each submitted branch with `--no-ff`.
> **Why:** tier removals and `--at` queries take their dates from commits, so the main line must carry the maintainer's committer dates ([rationale](rationale.md#no-ff-merges)).

The registry maintainer merges every submitted branch the same way: list
the paths it touches, merge, and push only if `git vouch check` exits 0
and the list is right. `--no-ff` makes every merge a commit of its own,
so the commits on the registry's main line carry the maintainer's
committer dates, not ones the submitter set. Never fast-forward a branch,
not even one whose tip is the submitter's own merge of main: its first
parent would be the submitter's branch, and its backdated commits would
become the main line:

```sh
branch=register-alice
cd registry
git fetch -q origin "$branch"
git diff --name-status HEAD...FETCH_HEAD
git merge -q --no-ff --no-edit FETCH_HEAD
git vouch check .
git push -q origin main
```

Reject a `register-*`, `endorse-*` or `approve-*` branch whose list shows
`anchors.json` or a `D` line. `check` does not cover two changes, which
rest on this review alone (`DESIGN.md`, Merging needs one person): any
change to `anchors.json`, and deleting a file, such as someone's tier
record under `tiers/`. Neither fails `check` or warns. A registration
touches only `people/`; endorsements and approvals add files under
`endorsements/` and `tiers/`.

Read `check`'s warnings as well as its exit code. Duplicate continuity
claims and person-file changes not signed by a previous key are
warnings, not failures, and each needs a reviewer's eye. During the
window nearly every new person file also warns that its emails are not
endorsed; that is expected until their endorsements merge.

### Checking continuity proofs

> **What this does:** checks every continuity proof in the registry against the freeze commit.
> **Why:** a proof is judged against the person-file version it was made for, so later signed edits do not undo it ([rationale](rationale.md#continuity-proof)).

Anyone can run the check:

```sh
git clone -q "$PGPKEYS" pgpkeys
cd registry
git-vouch-migrate verify-continuity ~/pgpkeys . --commit "$FREEZE_COMMIT" --signer "$SIGNER"
```

It prints one line per ported person file and exits 1 if any fails:

```text
ok alice: openpgp4fpr:<fingerprint> by .asc
ok dave: openpgp4fpr:<fingerprint> by auth subkey <subkey fingerprint>
fail <handle>: <reason>
```

A proof holds only if the GPG key is not revoked at the freeze commit
(expired is accepted), every email in the person file is on an unrevoked
user ID of that key, and no other person file claims the same
fingerprint. The proof is judged against the version of your person file
it was made for, found in the registry's history, so a later `add-key`,
`retire-key` or email change does not undo it, provided every version
since was signed by a key current in the version before it. Otherwise
`git vouch check` warns about the change, such as lost-key recovery or
registering a deleted handle again, and you make a fresh `.asc`.

### Endorsements from GPG certifications

> **What this does:** each certifier drafts endorsements from their own GPG certifications and signs only the right ones.
> **Why:** certifications are not ported as records; the draft is a reminder, and the certifier's new SSH signature is what counts ([rationale](rationale.md#continuity-proof)).

Each certifier drafts on their own machine, from the public pgpkeys at
the freeze commit and the registry. Drafts are never generated
centrally, and unsigned drafts never enter the registry.

```sh
cd registry
git fetch -q origin
git switch -q -c endorse-lena origin/main
git-vouch-migrate drafts ~/pgpkeys . --commit "$FREEZE_COMMIT" --signer "$SIGNER" --as lena \
    --out ~/endorsement-drafts
for f in ~/endorsement-drafts/endorsements/*/*.json; do
    cat "$f"
    git vouch endorse --from "$f"
done
git vouch approve alice maintainer
git add endorsements tiers
git commit -q -m "lena: endorsements from GPG certifications; approve alice"
git push -q origin HEAD:endorse-lena
```

`drafts --as` writes one draft per registered person whose continuity
proof holds and whose GPG key the key in your own `migratedFrom`
certified at the freeze commit. It uses the latest certification you did
not revoke, including SHA-1 certifications that GnuPG 2.4 rejects and
ones that had expired by the freeze commit: the draft is only a
reminder, and your new SSH signature is what counts. You need no
continuity proof yourself, only `migratedFrom` in your person file;
certifications made with your other GPG keys are not read.

**Read every draft before you sign it.** `subjectName` comes from the
subject's own person file, not from your certification; `subjectEmails`
are the person file's emails on the user IDs you certified; `note` names
the certified key, user IDs and dates. Before running the loop, delete
any draft you would not vouch for today (see `docs/vouching.md`); the
loop prints each remaining one again as it signs it.
`git vouch endorse --from FILE` checks that the draft's `endorser` and
`endorserKey` are you and your key, then signs its bytes unchanged and
writes it into the registry as your next endorsement of that subject.

The anchor approves maintainers in the same branch. The registry
maintainer merges it as above, with `branch=endorse-lena`.

### Fresh endorsements and approvals

> **What this does:** a maintainer endorses people they know and approves contributors, with no GPG history.
> **Why:** an endorsement is evidence about identity and grants nothing; only the approver needs authority ([rationale](rationale.md#endorse-vs-approve)).

```sh
cd registry
git fetch -q origin
git switch -q -c approve-alice origin/main
git vouch endorse carol --note "Reviewed her patches since 2019; met at LPC."
git vouch approve bob contributor
git vouch approve carol contributor
git add endorsements tiers
git commit -q -m "alice: endorse carol; approve bob and carol"
git push -q origin HEAD:approve-alice
```

The registry maintainer merges it as above, with `branch=approve-alice`.

## 3. Flag day

> **What this does:** Linus, the release tooling and every developer switch to SSH signatures checked against exported tiers.
> **Why:** after the flag day nothing new needs `gpg`; DESIGN gives no further reason for skipping a dual period ([rationale](rationale.md#one-flag-day)).

Linus points git at the export of maintainers and above:

```sh
git vouch setup --registry "$REGISTRY" --min-tier maintainer
git vouch check
git clone -q "$LINUX" linux
```

Every developer sets up git for SSH signing and signs their tags (here
`who=alice`):

```sh
who=alice
git vouch setup --registry "$REGISTRY"
git clone -q "$LINUX" linux
cd linux
git tag -s -m "for-6.99 from $who" "$who-6.99"
git push -q origin "$who-6.99"
```

Plain `git verify-tag` then applies the tier. A maintainer's tag
verifies; a contributor's does not ("No principal matched"):

```sh
cd linux
git fetch -q --tags
git verify-tag alice-6.99
git verify-tag bob-6.99    # fails: bob is a contributor
```

Release tooling verifies against anchors only, with its own exported
files. It names both files explicitly, so it also works on a machine
that never ran `git vouch setup`:

```sh
git vouch export --min-tier anchor --allowed-signers ~/release-signers \
    --revocation-file ~/release-revoked
git tag -s -m "Linux 6.99" v6.99
git -c gpg.ssh.allowedSignersFile="$HOME/release-signers" \
    -c gpg.ssh.revocationFile="$HOME/release-revoked" verify-tag v6.99
git -c gpg.ssh.allowedSignersFile="$HOME/release-signers" \
    -c gpg.ssh.revocationFile="$HOME/release-revoked" verify-tag alice-6.99    # fails: not an anchor
```

A tier, not a key, keeps a signer out. At contributor tier, bob's tag
verifies:

```sh
git vouch export --min-tier contributor --allowed-signers ~/contrib-signers \
    --revocation-file ~/contrib-revoked
git -c gpg.ssh.allowedSignersFile="$HOME/contrib-signers" \
    -c gpg.ssh.revocationFile="$HOME/contrib-revoked" verify-tag bob-6.99
```

From this date a GPG-signed tag or pull is not accepted.

## 4. Late cutoff

> **What this does:** ends continuity claims and the GPG patch fallback six months after the flag day.
> **Why:** it closes the window in which a stolen, unrevoked GPG key can claim its holder's identity ([rationale](rationale.md#late-cutoff)).

Continuity claims against the freeze commit are accepted until six
months after the flag day. Anyone who has not registered by then
registers fresh and collects fresh endorsements. From this date registry
maintainers merge no change that adds or alters `migratedFrom` or adds a
`people/*.json.asc`; a branch merged after it is late, whenever it was
committed.

GPG-signed tags from before the flag day stay valid in history.
Verifying them uses `gpg` with the archived `pgpkeys.git` at the freeze
commit. There is no manifest.

## Patch signing

> **What this does:** moves patch signing to registry keys through the patatt fork, with the frozen pgpkeys keyring as a fallback until the late cutoff.
> **Why:** the registry is the keyring, so nothing is generated or trusted in between; DESIGN gives no reason why patches get a fallback and tags do not ([rationale](rationale.md#patch-fallback)).

Patches are signed with patatt and checked with `b4 am`. A fork of
patatt adds the keyring source `vouch:`, which reads the registry
through `git vouch keys`. Unlike tags, patches get a fallback: the
frozen pgpkeys keyring keeps working, with a warning, until the late
cutoff, six months after the flag day. The commands are in each guide's
Patch signing section ([regulars](guide-regulars.md#patch-signing),
[captains](guide-captains.md#patch-signing),
[anchors](guide-anchors.md#patch-signing)).

- **Before the flag day:** everyone who signs or checks patches installs
  b4 and patatt from their forks' `git-vouch` branches
  (github.com/MarkAtwood/b4 and github.com/MarkAtwood/patatt), sets
  `patatt.signingkey` to their registry SSH key and `patatt.selector` to
  what `git vouch status` prints, and lists `keyringsrc = vouch:` first
  and their clone of the frozen pgpkeys keyring, checked out at the
  freeze commit, second. b4 ignores those sources while
  `b4.keyringsrc` is set, so they remove it. They set the b4 fork's
  `b4.attestation-recheck-hours` to 0, so b4 checks every signature
  again and a revocation takes effect at the next `git vouch sync`.
- **From the flag day to the late cutoff:** patches signed with a
  registry key verify through `vouch:`. Patches signed with a GPG key,
  or with a key `patatt genkey` made, verify through pgpkeys, for
  everyone, registered or not, and b4 prints a warning naming the legacy
  keyring each time it checks them.
- **After the late cutoff:** everyone deletes the legacy keyring line.
  No code changes. GPG-signed patches then show `No key`, and patches
  signed with a key `patatt genkey` made show `TOFU: new key`.

## What breaks and how to recover

> **What this does:** maps each error message to its cause and the fix.
> **Why:** most of the 20 rows below are continuity checks, which hold only for a key unrevoked at the freeze commit whose emails match and which nobody else claims ([rationale](rationale.md#continuity-proof)).

| Symptom | Cause | Recovery |
|---|---|---|
| `git vouch check` fails right after `anchors.json` is committed | It names a handle with no person file | Merge the anchors' person files first, as in the first merge. |
| gpg will not make your `.asc` | Your key has expired | Extend it locally with `gpg --quick-set-expire` and never publish the new expiry, as in the expired-key route. |
| `port` prints `skip <fpr>: revoked` or `skip <fpr>: invalid at the freeze commit` for your key | The key was revoked or invalid at the freeze commit | No continuity proof is possible. Register fresh and collect fresh endorsements. |
| `port` prints `skip <fpr>: not a person` | It is a kernel.org list key, not yours | Use the draft for your own key, or register fresh. |
| `port` prints `conflict <fpr>` or `skip <fpr>: no user ID with a usable name and email` for your key | Several keys share your email under different names, or no user ID gives a name or none gives an email | You can still prove continuity, which is all that endorsement drafts need. Copy any draft `port` wrote, set `keys` to `[]`, and put in your own `handle`, `name`, `emails` and `migratedFrom` (`openpgp4fpr:<fingerprint>`), with every email on an unrevoked user ID of that key; then continue with `register --from` and the `.asc` as above. The rehearsal does not cover a hand-written draft. |
| `port`, `verify-continuity` or `drafts` prints `skip keys/<file>: <reason>` or `partial keys/<file>: took <fingerprints>; <reason>` | gpg did not fully import that file: a PGP-2 (v3) key, a key gpg refuses (for example one with no user ID), or a revocation certificate whose key is in no keys/ file. A revocation filed before its key is not one of these: every file that fails is retried once after the rest are imported. | `skip`: nothing from the file is used. `partial`: the listed keys are used and the rest of the file is not. The run carries on either way. Before the freeze, fix or remove the file in pgpkeys and rerun; after it, a holder whose key is not used registers fresh. |
| `fail <handle>: <fpr> is revoked` | The key was revoked at the freeze commit | No continuity proof is possible. Register fresh (without `migratedFrom`). |
| `fail <handle>: <email> is not on an unrevoked user ID of <fpr>` | Your person file has an email your GPG key does not | Before your branch is merged: remove that email from your draft, register again in a fresh registry checkout, and make a new `.asc`. |
| `fail <handle>: no people/<handle>.json.asc, and no signature by an auth subkey of <fpr>` | No proof submitted, or the auth subkey is listed but another key signed the file | Add the `.asc`, or sign the person file with the auth subkey itself. |
| `fail <handle>: people/<handle>.json.asc: signed by <X>, not <Y>` | The `.asc` was made with a different GPG key | Sign with the key in `migratedFrom` (`gpg -u <fingerprint>`). |
| `check` warns `migratedFrom openpgp4fpr:<fpr> is also claimed by <handle>`; `verify-continuity` prints `duplicate` | Two person files claim the same GPG key | Neither gets drafts, whichever merged first. An anchor decides which claim is genuine, and the other claim comes out of the registry. Suspect a stolen GPG key. |
| `drafts --as` refuses: `no migratedFrom` | Your person file does not name your GPG key | Add `migratedFrom` before the late cutoff, or endorse people afresh. |
| A subject is missing from your drafts | They have not registered yet, or their proof does not hold | Run `drafts` again later, into a new `--out` directory. It drafts every subject again, including ones you already endorsed, so sign only the new ones. |
| Another user's git cannot read `allowed_signers` or `revoked_keys` | An earlier git-vouch wrote them with mode 0600, and `export` and `sync` keep an existing file's mode | Run `chmod 0644` on both files once. |
| `git verify-tag` says "No principal matched" | The signer has no tier at or above the export's minimum, has not been approved yet, or your registry copy is stale | Have them approved, or run `git vouch sync`. |
| A GPG-signed tag after the flag day | GPG is no longer accepted | Re-sign the tag with `git tag -s` after `git vouch setup`. |
| Missed the late cutoff | Continuity claims have ended | Register fresh and collect fresh endorsements. |
| `b4 am` prints `W: ... verified via legacy keyring ...` | The patch is signed with a GPG key or a key `patatt genkey` made | Register an SSH key and sign patches with it before the late cutoff. |
| `b4 am` prints `No key` for every registered signer | The patatt installed is not the patatt fork, so `vouch:` finds nothing; `b4.keyringsrc` is set, so b4 ignores `patatt.keyringsrc`; or your registry copy is stale | Install both forks with the guides' install line; run `git config --global --unset-all b4.keyringsrc`; run `git vouch sync`. |
| `b4 am` prints `✓ Signed: openssh/...` with no `(key: vouch:...)` after it | The b4 that runs is not the b4 fork: it ignores `b4.attestation-recheck-hours`, and upstream b4 newer than 0.16 keeps a revoked key's pass for up to 24 hours | Install both forks with the guides' install line, and check that `command -v b4` is the b4 it installed. |

**What continuity cannot catch.** Someone holding a GPG key that was
stolen and not revoked by the freeze commit can claim that person's
identity, just as they can sign tags with it today. The duplicate-claim
rule exposes this if the real holder also migrates, and the late cutoff
ends it. If you doubt who holds your GPG key, revoke it in pgpkeys
before the freeze and register fresh.

## Scale

> **What this does:** gives the measured size of the migration.
> **Why:** up to 1,538 of 1,935 people on MAINTAINERS `M:` lines (79.5%, an upper bound) have no unrevoked, unexpired pgpkeys user ID matching their `M:` emails, measured 2026-10-23 ([rationale](rationale.md#ssh-not-gpg)).

At research time pgpkeys held 645 live keys for about 606 people. 188 can
reuse an authentication key as an accepted SSH key; about 1,784
verified certification pairs become drafts; about 80% of maintainers have
no GPG key and register fresh.

## Out of scope

> **What this does:** names what stays on GPG.
> **Why:** git-vouch replaces the keyring and web of trust, not every use of `gpg` ([rationale](rationale.md#ssh-not-gpg)).

Encryption keys for the remail and security lists: kernel.org keeps a
small encryption-only GPG keyring.

## Rehearsal

> **What this does:** explains the test harness behind this page and its cast of names.
> **Why:** a command on this page is one the test suite ran, in the order it ran.

Every command block on this page is copied from
`tests/migrate/rehearsal.sh`, which the test suite runs end to end with
real `gpg`, `ssh-keygen` and `git` on a synthetic pgpkeys keyring.
`tests/migrate/test_flag_day_doc.py` fails if the two drift apart.

The names in the commands are the rehearsal's cast:

| Name | Role |
|---|---|
| `korg` | kernel.org and the registry maintainer |
| `lena` | the anchor; also the certifier, and Linus and the release tooling |
| `alice` | pgpkeys holder; also the maintainer |
| `bob` | pgpkeys holder whose key expired before the freeze commit |
| `dave` | pgpkeys holder who reuses his GPG authentication subkey |
| `carol` | developer with no GPG key, registering fresh |

lena certified alice (SHA-1), bob and dave in pgpkeys.

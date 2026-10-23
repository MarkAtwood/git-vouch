# Flag day runbook

**Status:** runbook, 2026-10-22. Facts come from `DESIGN.md` (Flag day).
Every command block on this page is copied from
`tests/migrate/rehearsal.sh`, which the test suite runs end to end with
real `gpg`, `ssh-keygen` and `git` on a synthetic pgpkeys keyring, and
`tests/migrate/test_flag_day_doc.py` fails if the two drift apart. The
dates and the anchor list are the kernel team's to set; this page leaves
them blank.

On one date, the flag day, the kernel stops accepting GPG-signed tags and
pulls and starts verifying SSH signatures against the git-vouch registry.
There is no period that accepts both. Before that date every pgpkeys
holder who still signs registers an SSH key; after it, nothing new needs
`gpg`.

## Timeline

| Phase | When | Who acts | What happens |
|---|---|---|---|
| 1. Freeze | _freeze date_ | kernel.org | `pgpkeys.git` gets one last signed commit, C, and becomes read-only. C's hash, the flag-day date and the late cutoff are published together. |
| 2. Window | freeze to flag day (_window length_) | anchors first, then everyone | The first registry merge holds the anchors' person files and `anchors.json`. Everyone else registers, adds a continuity proof if they had a pgpkeys key, signs endorsement drafts and gets approved. |
| 3. Flag day | _flag-day date_ | Linus, release tooling, every developer | Linus and the release tooling switch to files from `git vouch export`. GPG-signed tags and pulls stop being accepted. |
| 4. Late cutoff | _late-cutoff date_ | nobody | Continuity claims against C are accepted until this date. After it, people register as newcomers. |

## Kernel-team calls

These are decisions, not design, and nothing below depends on their
values:

- the anchor list;
- the freeze date, the window length and the late cutoff;
- who the registry maintainers are, who may merge into the registry
  (`DESIGN.md`, Open questions);
- the registry's repository path on git.kernel.org (kernel.org
  administrators), and how people submit branches to it. The rehearsal
  pushes a branch to the registry; a merge request works the same way.

**The late cutoff is policy, not code.** After it, registry maintainers
do not merge any change that adds or alters a `migratedFrom` field or
adds a `people/*.json.asc`. The merge date counts, not the commit date.

## Who does what

| Role | In the commands below | Does |
|---|---|---|
| kernel.org and the registry maintainer | `korg` | Freezes pgpkeys at C and publishes it. Merges each registry branch once `git vouch check` passes, and commits `anchors.json`. |
| Anchor | `lena` | Registers first. Drafts and signs endorsements from her own GPG certifications. Approves maintainers. |
| pgpkeys holder | `alice`, `bob`, `dave` | Ports pgpkeys, completes their person-file draft, adds a continuity proof. |
| Developer with no GPG key (about 80% of maintainers) | `carol` | Registers fresh and collects fresh endorsements. |
| Certifier: any holder who certified others' GPG keys | `lena` | Drafts endorsements locally, reads each one, signs the ones that are right. |
| Maintainer | `alice` | Endorses, and approves contributors. |
| Linus and the release tooling | `lena` | Switch to the exported allowed-signers files. |

GPG supplies no tiers. Linus certified 2 keys in pgpkeys, so the web of
trust says nothing about who is a maintainer. Anchors approve maintainers
on their own judgement, using MAINTAINERS and endorsements.

## What the commands assume

Published with C, and used as shell variables below:

- `$C`, the frozen commit;
- `$SIGNER`, the primary fingerprint of the key that signed C;
- `$PGPKEYS`, `$REGISTRY` and `$LINUX`, the repository URLs.

Each person runs their own commands on their own machine, from their home
directory, with `git-vouch` and `git-vouch-migrate` on `PATH` and their
SSH key loaded in an agent. The commands use a key at `~/.ssh/id_ed25519`;
any agent-backed key works, and hardware is recommended for maintainers
and anchors. Names, handles and branches are the rehearsal's: put your
own in their place.

## 1. Freeze

kernel.org makes the last commit C to `pgpkeys.git`, signs it, makes the
repository read-only, and publishes C, `$SIGNER`, the flag-day date and
the late cutoff together.

Nobody needs to verify C by hand: every `git-vouch-migrate` command
checks C's signature by `$SIGNER` first and refuses to run otherwise. It
reads pgpkeys only at C, never at a later commit.

## 2. Window

### The first merge: the anchors

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
git-vouch-migrate port pgpkeys --commit "$C" --signer "$SIGNER" --out drafts
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/lena.json ~/.ssh/id_ed25519.pub
gpg --armor --detach-sign people/lena.json
git add people
git commit -q -m "people: register lena"
git push -q origin HEAD:register-lena
```

`port` writes one unsigned draft per person in pgpkeys, with a proposed
handle, the name, the emails from unrevoked user IDs and `migratedFrom`.
Everyone runs it themselves; it is deterministic from the public pgpkeys
at C, so there is no central copy to trust. Find your own draft and read
it before registering: the handle is permanent. `register --from` adds
your SSH key and signs the file.

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

Order matters: `check` fails if `anchors.json` names a handle that has no
person file, so the anchors' person files go in first.

### Everyone else registers

Pick your route:

| You have | Route | Continuity proof |
|---|---|---|
| A pgpkeys key, not revoked by C | Complete your draft | `people/<handle>.json.asc` |
| A pgpkeys key that expired (but was not revoked) by C | Extend it locally, then the same | `people/<handle>.json.asc` |
| An ed25519, P-256 or RSA (2048+) authentication key or subkey on your pgpkeys key | Use it as your SSH key | The subkey signs your person file |
| No pgpkeys key, or one revoked by C | Register fresh | None |

Every route needs an SSH key: ed25519, P-256, or RSA of 2048 to 16384
bits. In `pgpkeys.git` at af88128 (2026-10-20), 602 of 645 unexpired
keys are RSA and 4 are DSA; 188 have a reusable authentication key, so
most holders make a new key. If you do, or if
yours is RSA, now is a good time to upgrade: `ed25519-sk` on a token,
or `ecdsa-sk` if the token has no ed25519. Any GPG key, RSA and DSA
included, still signs the continuity proof.

The continuity proof is needed only to receive endorsement drafts ported
from GPG certifications. It grants no tier. Registering without it works;
you then collect fresh endorsements.

**With a detached GPG signature** over the person file's exact bytes:

```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$C" --signer "$SIGNER" --out drafts
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/alice.json ~/.ssh/id_ed25519.pub
gpg --armor --detach-sign people/alice.json
git add people
git commit -q -m "people: register alice"
git push -q origin HEAD:register-alice
```

**With an expired key.** gpg refuses to sign with an expired key, so
extend it in your local keyring first. Never publish the new expiry (do
not send the key anywhere): the proof is judged against the key as it
was at C, where expired is accepted.

```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$C" --signer "$SIGNER" --out drafts
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

The `fpr=` line takes the first secret key in your keyring; if you hold
more than one, set `fpr` to the fingerprint in your draft's
`migratedFrom` instead.

**With your authentication subkey.** `port` has already put it in your
draft as your SSH key. Expose it through gpg-agent's SSH support and sign
the person file with it:

```sh
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$C" --signer "$SIGNER" --out drafts
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

The two files go in your gpg home: `$GNUPGHOME` if set, else
`~/.gnupg`. The subkey must sign
the current version of your person file; merely listing it proves
nothing, because the public subkey is public.

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

The registry maintainer merges each submitted branch the same way: list
the paths it touches, merge, and push only if `git vouch check` exits 0
and the list is right:

```sh
branch=register-alice
cd registry
git fetch -q origin "$branch"
git diff --name-status HEAD...FETCH_HEAD
git merge -q --no-edit FETCH_HEAD
git vouch check .
git push -q origin main
```

`check` does not cover two changes, which rest on this review alone
(`DESIGN.md`, Merging needs one person): any change to `anchors.json`,
and deleting a file, such as someone's tier record under `tiers/`.
Neither fails `check` or warns. Reject a `register-*`, `endorse-*` or
`approve-*` branch whose list shows `anchors.json` or a `D` line. A
registration touches only `people/`; endorsements and approvals add
files under `endorsements/` and `tiers/`.

Read `check`'s warnings as well as its exit code. Duplicate continuity
claims and person-file changes not signed by a previous key are
warnings, not failures, and each needs a reviewer's eye. During the
window nearly every new person file also warns that its emails are not
endorsed; that is expected until their endorsements merge.

### Checking continuity proofs

Anyone can check every continuity proof in the registry against C:

```sh
git clone -q "$PGPKEYS" pgpkeys
cd registry
git-vouch-migrate verify-continuity ~/pgpkeys . --commit "$C" --signer "$SIGNER"
```

It prints one line per ported person file and exits 1 if any fails:

```text
ok alice: openpgp4fpr:<fingerprint> by .asc
ok dave: openpgp4fpr:<fingerprint> by auth subkey <subkey fingerprint>
fail <handle>: <reason>
```

A proof holds only if the GPG key is not revoked at C (expired is
accepted), every email in the person file is on an unrevoked user ID of
that key, and no other person file claims the same fingerprint. The
proof is judged against the version of your person file it was made
for, found in the registry's history, so a later `add-key`,
`retire-key` or email change does not undo it. A change no current key
signed, such as lost-key recovery or registering a deleted handle again,
does: the current version then needs its own proof.

### Endorsements from GPG certifications

GPG certifications are not ported as records. Each certifier drafts their
own endorsements on their own machine, from the public pgpkeys at C and
the registry, and signs only the ones that are right. Drafts are never
generated centrally, and unsigned drafts never enter the registry.

```sh
cd registry
git fetch -q origin
git switch -q -c endorse-lena origin/main
git-vouch-migrate drafts ~/pgpkeys . --commit "$C" --signer "$SIGNER" --as lena \
    --out ~/endorsement-drafts
for f in ~/endorsement-drafts/endorsements/*/*.json; do
    cat "$f"
    ssh-keygen -q -Y sign -f ~/.ssh/id_ed25519.pub -n git-vouch-endorse "$f"
done
cp -R ~/endorsement-drafts/endorsements .
git vouch approve alice maintainer
git add endorsements tiers
git commit -q -m "lena: endorsements from GPG certifications; approve alice"
git push -q origin HEAD:endorse-lena
```

`drafts --as` writes one draft per registered person whose continuity
proof holds and whose GPG key the key in your own `migratedFrom`
certified at C. It uses the latest certification you did not revoke,
including SHA-1 certifications that GnuPG 2.4 rejects and ones that had
expired by C: the draft is only a reminder, and your new SSH signature
is what counts. You need no continuity proof yourself, only
`migratedFrom` in your person file; certifications made with your other
GPG keys are not read.

**Read every draft before you sign it.** `subjectName` comes from the
subject's own person file, not from your certification; `subjectEmails`
are the person file's emails on the user IDs you certified; `note` names
the certified key, user IDs and dates. Before running the loop, delete
any draft you would not vouch for today (see `docs/vouching.md`); the
loop prints each remaining one again as it signs it. No `git vouch`
command signs a prepared draft, so the loop calls `ssh-keygen -Y sign`
directly with the endorsement namespace.

The anchor approves maintainers in the same branch. The registry
maintainer merges it as above, with `branch=endorse-lena`.

### Fresh endorsements and approvals

Endorsements need no GPG history. A maintainer endorses people they know
and approves contributors:

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

Merged as above, with `branch=approve-alice`.

## 3. Flag day

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

A tier, not a key, is what keeps a signer out. At contributor tier,
bob's tag verifies:

```sh
git vouch export --min-tier contributor --allowed-signers ~/contrib-signers \
    --revocation-file ~/contrib-revoked
git -c gpg.ssh.allowedSignersFile="$HOME/contrib-signers" \
    -c gpg.ssh.revocationFile="$HOME/contrib-revoked" verify-tag bob-6.99
```

From this date a GPG-signed tag or pull is not accepted.

## 4. Late cutoff

Continuity claims against C are accepted until this date. Anyone who
has not registered by then registers fresh, as `carol` did, and collects
fresh endorsements. From this date registry maintainers merge no change
that adds or alters `migratedFrom` or adds a `people/*.json.asc`; a
branch merged after it is late, whenever it was committed.

GPG-signed tags from before the flag day stay valid in history.
Verifying them uses `gpg` with the archived `pgpkeys.git` at C. There is
no manifest.

## What breaks and how to recover

| Symptom | Cause | Recovery |
|---|---|---|
| `git vouch check` fails right after `anchors.json` is committed | It names a handle with no person file | Merge the anchors' person files first, as in the first merge. |
| gpg will not make your `.asc` | Your key has expired | Extend it locally with `gpg --quick-set-expire` and never publish the new expiry, as `bob` did. |
| `port` prints `skip <fpr>: revoked` or `skip <fpr>: invalid at C` for your key | The key was revoked or invalid at C | No continuity proof is possible. Register fresh and collect fresh endorsements. |
| `port` prints `skip <fpr>: not a person` | It is a kernel.org list key, not yours | Use the draft for your own key, or register fresh. |
| `port` prints `conflict <fpr>` or `skip <fpr>: no user ID with a usable name and email` for your key | Several keys share your email under different names, or no user ID gives a name or none gives an email | You can still prove continuity, which is all that endorsement drafts need. Copy any draft `port` wrote, set `keys` to `[]`, and put in your own `handle`, `name`, `emails` and `migratedFrom` (`openpgp4fpr:<fingerprint>`), with every email on an unrevoked user ID of that key; then continue with `register --from` and the `.asc` as above. The rehearsal does not cover a hand-written draft. |
| `port` prints `skip keys/<file>: <reason>` | gpg did not fully import that file: a PGP-2 (v3) key, a revocation certificate whose key is not in keys/, or a partial import | `port` carries on without it. Before the freeze, fix or remove the file in pgpkeys and rerun `port`; after it, the key's holder registers fresh. |
| `fail <handle>: <fpr> is revoked` | The key was revoked at C | No continuity proof is possible. Register fresh (without `migratedFrom`). |
| `fail <handle>: <email> is not on an unrevoked user ID of <fpr>` | Your person file has an email your GPG key does not | Before your branch is merged: remove that email from your draft, register again in a fresh registry checkout, and make a new `.asc`. |
| `fail <handle>: no people/<handle>.json.asc, and no signature by an auth subkey of <fpr>` | No proof submitted, or the auth subkey is listed but another key signed the file | Add the `.asc`, or sign the person file with the auth subkey itself. |
| `fail <handle>: people/<handle>.json.asc: signed by <X>, not <Y>` | The `.asc` was made with a different GPG key | Sign with the key in `migratedFrom` (`gpg -u <fingerprint>`). |
| `check` warns `migratedFrom openpgp4fpr:<fpr> is also claimed by <handle>`; `verify-continuity` prints `duplicate` | Two person files claim the same GPG key | Neither gets drafts, whichever merged first. An anchor decides which claim is genuine, and the other claim comes out of the registry. Suspect a stolen GPG key. |
| `drafts --as` refuses: `no migratedFrom` | Your person file does not name your GPG key | Add `migratedFrom` before the late cutoff, or endorse people afresh. |
| A subject is missing from your drafts | They have not registered yet, or their proof does not hold | Run `drafts` again later, into a new `--out` directory. It drafts every subject again, including ones you already endorsed, so sign only the new ones. |
| `git verify-tag` says "No principal matched" | The signer has no tier at or above the export's minimum, has not been approved yet, or your registry copy is stale | Have them approved, or run `git vouch sync`. |
| A GPG-signed tag after the flag day | GPG is no longer accepted | Re-sign the tag with `git tag -s` after `git vouch setup`. |
| Missed the late cutoff | Continuity claims have ended | Register fresh and collect fresh endorsements. |

**What continuity cannot catch.** Someone holding a GPG key that was
stolen and not revoked by C can claim that person's identity, just as
they can sign tags with it today. The duplicate-claim rule exposes this
if the real holder also migrates, and the late cutoff ends it. If you
doubt who holds your GPG key, revoke it in pgpkeys before the freeze and
register fresh.

## Scale

At research time pgpkeys held 645 live keys for about 606 people. 188 can
reuse an authentication key as an accepted SSH key; about 1,784
verified certification pairs become drafts; about 80% of maintainers have
no GPG key and register fresh.

## Out of scope

Encryption keys for the remail and security lists: kernel.org keeps a
small encryption-only GPG keyring. Patch signing with b4 and patatt is
not covered on this page.

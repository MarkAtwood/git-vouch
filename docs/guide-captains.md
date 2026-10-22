# Guide for captains

**Status:** user guide, 2026-10-22. Facts come from `DESIGN.md`. Every
command block on this page is run, in order, by
`tests/migrate/test_guide_captains.py` in a throwaway registry, with
real `git`, `ssh-keygen` and `gpg` and a synthetic `pgpkeys.git`. Who
runs each block is noted in the text.

A captain is a subsystem maintainer: someone an anchor has approved at
the `maintainer` tier. Your signed tags are what Linus pulls. You verify
the tags of the people who send you pull requests, approve contributors,
and endorse people you know. You cannot approve maintainers or revoke
other people's keys; anchors do that.

Before you endorse or approve anyone, read
[What vouching for a real person means](vouching.md). It says what an
endorsement binds, what evidence to ask for, and how to read the
endorsements you approve on.

## What the commands assume

- `$REGISTRY` is the registry's URL and `$LINUX` a kernel tree you push
  tags to. `$PGPKEYS`, `$C` and `$SIGNER` are the frozen `pgpkeys.git`,
  its last commit and the fingerprint that signed it, all published by
  kernel.org at the freeze (see [the flag-day runbook](flag-day.md)).
- `git-vouch` and `git-vouch-migrate` are on `PATH`, so `git vouch`
  works. You need `git-vouch-migrate` and `gpg` only on the flag day.
- Your SSH keys are loaded in an agent. The commands use
  `~/.ssh/id_ed25519` as your signing key and `~/.ssh/backup` as a
  backup key that stays in a drawer. Keep both on hardware tokens:
  kernel.org issues FIDO keys and backup tokens
  (korg.docs.kernel.org/fido2.html). `git-vouch` accepts any supported
  key, so this is advice, not a rule.
- `registry` is your checkout of the registry, and `linux` your kernel
  tree, both in your home directory.

The cast: `alice` is the captain (you), with a key in `pgpkeys.git`.
`lena` is an anchor. `bob` and `carol` are contributors who send alice
pull requests; bob had a pgpkeys key that alice certified, carol never
had one. `korg` is the registry maintainer who merges branches into the
registry. Put your own handle, name and email in their place.

No `git vouch` command pushes to the registry. Every change goes the
same way: a branch from the registry's `main`, a `git vouch` command
that writes and signs a record, a commit, a push, and a merge by the
registry maintainer once `git vouch check` passes.

## Flag day

[The flag-day runbook](flag-day.md) has the full timeline for everyone.
These are a captain's steps in it. The anchors register and merge first;
then everyone else registers during the window.

### Register with your pgpkeys key

If you hold a key in `pgpkeys.git` that was not revoked by C, register
from the draft `git-vouch-migrate` writes for you and sign the result
with your GPG key as a continuity proof (here as `alice`):

<!-- as alice -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$C" --signer "$SIGNER" --out drafts
cat drafts/people/alice.json
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/alice.json ~/.ssh/id_ed25519.pub
git vouch add-key ~/.ssh/backup.pub
gpg --armor --detach-sign people/alice.json
git add people
git commit -q -m "people: register alice"
git push -q origin HEAD:register-alice
```

`port` checks C's signature by `$SIGNER`, then writes one unsigned draft
per person in pgpkeys: a proposed handle, your name, the emails on your
unrevoked user IDs, and `migratedFrom`. Read yours before registering:
the handle is permanent. `register --from` adds your SSH key and signs
the file; `add-key` lists your backup key, signed by the main one.

Make the `.asc` last. It covers the person file's exact bytes, so any
later `add-key`, `retire-key` or email change needs a new one before the
late cutoff if you still want endorsement drafts. The proof only unlocks
drafts from your old GPG certifications (below). It grants no tier.

Other cases, such as an expired GPG key or reusing your GPG
authentication subkey as your SSH key, are in the runbook's
[Everyone else registers](flag-day.md#everyone-else-registers).

### Register without one

About 80% of maintainers have no pgpkeys key. Register fresh, with no
continuity proof; you then collect fresh endorsements (here as `carol`,
who has none, but the command is the same for a captain):

<!-- as carol -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$REGISTRY" registry
cd registry
git vouch register --handle carol --name "Carol Fresh" --email carol@example.com \
    ~/.ssh/id_ed25519.pub
git add people
git commit -q -m "people: register carol"
git push -q origin HEAD:register-carol
```

Add your backup key with `git vouch add-key` in the same branch, as
alice did.

### How your branch is merged

The registry maintainer merges every branch the same way (here as
`korg`, for `register-alice`):

<!-- as korg -->
```sh
branch=register-alice
cd registry
git fetch -q origin "$branch"
git diff --name-status HEAD...FETCH_HEAD
git merge -q --no-edit FETCH_HEAD
git vouch check .
```

and pushes only once `check` exits 0, the list of changed paths is
right, and every `git-vouch: warning:` line has been read. Until someone
endorses you, `check` warns that your emails are not endorsed; that is
expected. Then (here as `korg`):

<!-- as korg -->
```sh
cd registry
git push -q origin main
```

<!-- merge register-carol -->

### Get approved as a maintainer

GPG supplies no tiers: the web of trust says nothing about who is a
maintainer. An anchor approves you on their own judgement, using
MAINTAINERS and the endorsements in the registry. There is no minimum
number of endorsements. Ask people who know you in person to endorse
you, as [vouching.md](vouching.md) describes; your old GPG certifiers
get drafts for you if your continuity proof holds. The anchor then
approves you (here as `lena`):

<!-- as lena -->
```sh
cd registry
git fetch -q origin
git switch -q -c approve-alice origin/main
cat people/alice.json
git vouch endorse alice --note "Met at LPC 2026, checked passport; reviewed her patches since 2019."
git vouch approve alice maintainer
git add endorsements tiers
git commit -q -m "lena: endorse and approve alice"
git push -q origin HEAD:approve-alice
```

<!-- merge approve-alice -->

From the commit that adds that tier record, you can approve
contributors.

### Sign your endorsement drafts

GPG certifications are not ported as records. If you certified other
people's GPG keys, draft endorsements from those certifications on your
own machine, read each one, sign the ones you still stand behind, and
approve your contributors in the same branch (here as `alice`):

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c endorse-alice origin/main
git-vouch-migrate drafts ~/pgpkeys . --commit "$C" --signer "$SIGNER" --as alice \
    --out ~/endorsement-drafts
cat ~/endorsement-drafts/endorsements/*/*.json
```

`drafts --as` writes one draft for each registered person whose
continuity proof holds and whose GPG key your own proven key certified
at C. Your own proof must hold too, or it refuses. A subject who has not
registered yet gets no draft; run `drafts` again later into a new
`--out` directory and sign only the new ones.

**Read every draft before the loop signs it.** `subjectName` comes from
the subject's own person file, not from your certification;
`subjectEmails` are their emails on the user IDs you certified; `note`
names the certified key, user IDs and date. A certification never
covered the subject's new SSH key, so confirm the key and emails with
them as in
[Confirming the key and emails](vouching.md#confirming-the-key-and-emails).
Delete any draft you would not endorse today, and edit `note` or
`subjectEmails` before signing if you need to. Only then sign the drafts
that are left and approve your contributors (here as `alice`):

<!-- as alice -->
```sh
cd registry
for f in ~/endorsement-drafts/endorsements/*/*.json; do
    d=endorsements/$(basename "$(dirname "$f")")
    mkdir -p "$d"
    ssh-keygen -q -Y sign -f ~/.ssh/id_ed25519.pub -n git-vouch-endorse "$f" &&
        cp "$f" "$f.sig" "$d"/
done
git vouch approve bob contributor
git add endorsements tiers
git commit -q -m "alice: endorsements from GPG certifications; approve bob"
git push -q origin HEAD:endorse-alice
```

<!-- merge endorse-alice -->

No `git vouch` command signs a prepared draft, so the loop calls
`ssh-keygen -Y sign` directly with the endorsement namespace. A draft is
copied into the registry only once its signature is made.

### Switch git to SSH signing

`setup` records the registry, sets `gpg.format=ssh`, the allowed-signers
and revocation files, and runs a first `sync`. The default export is
contributor and above, which is what you verify your pull requests
against (here as `alice`):

<!-- as alice -->
```sh
git vouch setup --registry "$REGISTRY"
git vouch status
git clone -q "$LINUX" linux
cd linux
git tag -s -m "for-6.99 from alice" alice-6.99
git push -q origin alice-6.99
```

`status` prints the registry commit, its age, and your own tier. Your
tag is now what Linus verifies against his maintainer export. From the
flag day, a GPG-signed tag or pull is not accepted.

## Day to day

### Keep your copy current

<!-- as alice -->
```sh
git vouch sync
git vouch status
```

`sync` fetches the registry, refuses a rewritten history, runs `check`
and re-exports your allowed-signers and revocation files. It writes the
revocation file even when `check` fails on something else, so a
revocation always reaches you. Every command warns when your copy was
last fetched more than 7 days ago; withholding a revocation is the one
attack left to whoever hosts the registry, so sync before you verify.

### Verify pull request tags

A contributor signs the tag they ask you to pull (here as `bob`, who
pushes to the shared tree; yours will name their own):

<!-- as bob -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git vouch setup --registry "$REGISTRY"
git clone -q "$LINUX" linux
cd linux
git tag -s -m "for-alice-6.99 from bob" bob-6.99
git push -q origin bob-6.99
```

Fetch the tag named in the pull request and verify it with plain git
(here as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git fetch -q "$LINUX" tag bob-6.99
git verify-tag bob-6.99
git cat-file tag bob-6.99
```

git prints `Good "git" signature for bob`. The export holds every
approved contributor, so a good signature alone does not show who signed:
check that the name after `signature for` is the person who sent the
pull request, and that the `tag` line and message `git cat-file` prints
are the ones they asked you to pull. If verification fails, the
signer is not approved at contributor or above, or their key is retired
or revoked: do not pull. Run `git vouch sync` first if the signer says
they were approved recently.

## Rotating your key

Any one key current in the previous version of your person file may
sign the next, which is why the backup token can stay in a drawer. To
replace a key you still hold, add the new key and retire the old one in
one branch, both signed by the old key, and switch git to the new key
(here as `alice`):

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c rotate-alice origin/main
git vouch add-key ~/.ssh/id_new.pub
git vouch retire-key ~/.ssh/id_ed25519.pub
git config --global user.signingKey ~/.ssh/id_new.pub
git add people
git commit -q -m "alice: rotate to a new key"
git push -q origin HEAD:rotate-alice
```

<!-- merge rotate-alice -->

Retiring keeps everything the old key signed valid: your endorsements,
your approvals, and your old tags (here as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git verify-tag alice-6.99
```

Rotating re-signs your person file, so your `.asc` no longer covers it.
That matters only if you still want endorsement drafts before the late
cutoff; make a new `.asc` then.

## Endorsing and approving

carol has registered but nobody has approved her, so her tag fails (here
as `carol`, then `alice`):

<!-- as carol -->
```sh
git vouch setup --registry "$REGISTRY"
git clone -q "$LINUX" linux
cd linux
git tag -s -m "for-alice-6.99 from carol" carol-6.99
git push -q origin carol-6.99
```

<!-- as alice -->
```sh
cd linux
git fetch -q "$LINUX" tag carol-6.99
git verify-tag carol-6.99    # fails: carol has no tier yet
```

An endorsement says that carol's key and emails belong to the real,
named person, and that you know it first-hand. It grants nothing; any
registered human may endorse. Approval grants a tier, and as a captain
you may approve `contributor` and `automation`. Approve on your own
judgement: endorsements are evidence, not a count. If you know carol
yourself, check her identity, key and emails as
[vouching.md](vouching.md) describes, endorse her, and approve her in
one branch (here as `alice`):

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c approve-carol origin/main
cat people/carol.json
git vouch endorse carol --note "Video call 2026-11-02 with passport shown; key and email confirmed on the call; reviewed her patches since 2023."
git vouch approve carol contributor
git add endorsements tiers
git commit -q -m "alice: endorse and approve carol"
git push -q origin HEAD:approve-carol
```

<!-- merge approve-carol -->

Before approving someone others have endorsed, read each
`endorsements/<handle>/*.json`: who endorsed them, which emails, and
what the note says was checked. `endorse` covers the person's name,
first current key and every listed email; `--email` limits it to the
addresses you confirmed.

Once merged and synced, carol's tag verifies (here as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git verify-tag carol-6.99
```

To remove a contributor's tier without suspecting their key, ask the
registry maintainer to delete their `tiers/<handle>.json` in a reviewed
merge; their keys get `valid-before` set to that commit's date, and
signatures they made before stay valid. Your approvals are judged once,
at the commit that adds them, so they stay if you later step down. Only
a revoked key voids the records it signed (see If you lose a key).

## If you lose a key

Revoke rather than retire unless you are sure nobody else can use the
key: the signing time comes from the signer, so whoever holds a retired
key can backdate signatures. A revoked key's signatures all stop
verifying, past and future, and every endorsement and tier record it
signed becomes void.

### With your backup key

Revoke the lost key, retire it and add a replacement, all signed by the
backup (here as `alice`, who lost the key she rotated to):

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c lost-alice origin/main
git vouch revoke ~/.ssh/id_new.pub --reason lost --sign-with ~/.ssh/backup.pub
git vouch retire-key ~/.ssh/id_new.pub --sign-with ~/.ssh/backup.pub
git vouch add-key ~/.ssh/id_next.pub --sign-with ~/.ssh/backup.pub
git config --global user.signingKey ~/.ssh/id_next.pub
git vouch check .
```

`check` now reports every record the lost key signed as void, here
carol's tier and your endorsement of her:

```text
git-vouch: warning: tiers/carol.json: void: did:key:z6Mk... of alice is revoked
git-vouch: warning: endorsements/carol/alice-1.json: void: did:key:z6Mk... of alice is revoked
```

carol has no tier until you sign again. Re-approve and re-endorse
everyone listed, in the same branch, then push it (here as `alice`):

<!-- as alice -->
```sh
cd registry
git vouch approve carol contributor
git vouch endorse carol --note "Video call 2026-11-02 with passport shown; key and email confirmed on the call; reviewed her patches since 2023."
git add people revocations tiers endorsements
git commit -q -m "alice: replace a lost key; re-sign what it signed"
git push -q origin HEAD:lost-alice
```

<!-- merge lost-alice -->

The new tier record replaces the void one. The new endorsement is
`alice-2.json`; the void `alice-1.json` stays in the registry and
`check` keeps reporting it, which does no harm.

Records signed by your earlier, retired key, such as bob's approval,
are not affected. Once merged and synced, both tags verify again (here
as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git verify-tag bob-6.99
git verify-tag carol-6.99
```

Any tag the revoked key signed stops verifying; ask
Linus to pull again from a tag you re-sign with the new key.

### Without a backup key

You cannot revoke the lost key yourself: only the key, another of your
current keys, or an anchor may sign its revocation. Ask an anchor to
revoke it. Then register a new key in a change no previous key signed,
with `git vouch register --from people/<you>.json` and your new key, and
retire the lost one signed by the new key. The registry maintainer's
`check` prints an unsigned-change WARNING on that version, and they must
confirm the new key with you over a channel they already trust before
merging. Your tier carries over. Endorsements made with your revoked key
are void, so re-endorse and re-approve as above.
The anchors guide runs these steps for a maintainer who lost her only
key: [Revoke a compromised key](guide-anchors.md#revoke-a-compromised-key)
has the revocation, and the recovery follows the table in
[Read check warnings in registry merges](guide-anchors.md#read-check-warnings-in-registry-merges).

## Patch signing

Patch signing with b4 and patatt is not covered on this page yet.

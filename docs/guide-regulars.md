# Guide for regulars

**Status:** user guide, 2026-10-22. Facts come from `DESIGN.md`. Every
command block on this page but the first is run, in order, by
`tests/migrate/test_guide_regulars.py` in a throwaway registry, with
real `git`, `ssh-keygen` and `gpg` and a synthetic `pgpkeys.git`; the
first needs FIDO tokens, so it is not run. Who runs each block is noted
in the text.

A regular is a contributor: someone a maintainer has approved at the
`contributor` tier. You sign the commits and tags you ask maintainers to
pull, and you may endorse people you know. You cannot approve anyone or
revoke other people's keys.

Before you endorse anyone, read
[What vouching for a real person means](vouching.md). It says what an
endorsement binds and what evidence to ask for.

## What the commands assume

- `$REGISTRY` is the registry's URL and `$LINUX` a kernel tree you push
  to. `$PGPKEYS`, `$C` and `$SIGNER` are the frozen `pgpkeys.git`, its
  last commit and the fingerprint that signed it, all published by
  kernel.org at the freeze (see [the flag-day runbook](flag-day.md)).
- `git-vouch` and `git-vouch-migrate` are on `PATH`, so `git vouch`
  works. You need `git-vouch-migrate` and `gpg` only on the flag day.
- Your SSH keys are loaded in an agent: `~/.ssh/id_ed25519` is your
  signing key and `~/.ssh/backup` a backup that stays in a drawer.
- `registry` is your checkout of the registry, and `linux` your kernel
  tree, both in your home directory.

The cast: `bob` is the regular (you), with a key in `pgpkeys.git` that
`alice` certified. `alice` is a maintainer, `carol` a newcomer, and
`korg` the registry maintainer who merges branches into the registry.
Put your own handle, name and email in their place.

No `git vouch` command pushes to the registry. Every change is a branch
from the registry's `main`, a `git vouch` command that writes and signs
a record, a commit, a push, and a merge by the registry maintainer once
`git vouch check` passes.

## Flag day

[The flag-day runbook](flag-day.md) has the full timeline. Register
during the window, before the flag day; from the flag day, a GPG-signed
tag or pull is not accepted.

### Create your keys

ed25519, P-256 and RSA keys of 2048 bits or more are accepted, whether
software, on a token, or a GPG authentication subkey. If yours is RSA,
now is a good time to upgrade. Hardware is recommended, not required. kernel.org issues FIDO tokens
and backup tokens (korg.docs.kernel.org/fido2.html); make one key on
each, touching the token when asked:

<!-- not-run needs-fido-token -->
```sh
ssh-keygen -t ed25519-sk -C "bob main" -f ~/.ssh/id_ed25519
ssh-keygen -t ed25519-sk -C "bob backup" -f ~/.ssh/backup
```

If your token has no ed25519, use `-t ecdsa-sk`. Without tokens,
`ssh-keygen -t ed25519` makes software keys that work the same way. To
let endorsers check a key was made on a token, generate it with `-O challenge=<file> -O write-attestation=<file>` and pass both
files to `register` or `add-key` with `--challenge` and `--attestation`.

### Register

If you hold a key in `pgpkeys.git` that was not revoked by C, register
from the draft `git-vouch-migrate` writes for you, add your backup key,
and sign the result with your GPG key as a continuity proof (here as
`bob`):

<!-- as bob -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$C" --signer "$SIGNER" --out drafts
cat drafts/people/bob.json
git clone -q "$REGISTRY" registry
cd registry
git vouch register --from ~/drafts/people/bob.json ~/.ssh/id_ed25519.pub
git vouch add-key ~/.ssh/backup.pub
gpg --armor --detach-sign people/bob.json
git add people
git commit -q -m "people: register bob"
git push -q origin HEAD:register-bob
```

Read your draft before registering: the handle is permanent. The `.asc`
is optional. It only lets the people who certified your GPG key get
endorsement drafts for you, it grants no tier, and it covers the person
file's exact bytes, so make it last.

Expired GPG keys and reused authentication subkeys are in the runbook's
[Everyone else registers](flag-day.md#everyone-else-registers).

### Register without one

With no pgpkeys key, register fresh, with no continuity proof and no
`.asc` (here as `carol`):

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

Add your backup key with `git vouch add-key` in the same branch, as bob
did.

### How your branch is merged

The registry maintainer merges your branch (here as `korg`):

<!-- as korg -->
```sh
branch=register-bob
cd registry
git fetch -q origin "$branch"
git diff --name-status HEAD...FETCH_HEAD
git merge -q --no-edit FETCH_HEAD
git vouch check .
```

and pushes once `check` exits 0 and its warnings are read. Until someone
endorses you, it warns that your email is not endorsed; that is expected
(here as `korg`):

<!-- as korg -->
```sh
cd registry
git push -q origin main
```

<!-- merge register-carol -->

### Get endorsed and approved

Ask people who know you in person to endorse you; [vouching.md](vouching.md)
says what they should check. If your continuity proof holds, the people
who certified your GPG key get a draft endorsement for you, which they
read, confirm with you and sign. A maintainer then approves you as a
contributor on their own judgement; there is no minimum number of
endorsements. alice does both in one branch, first drafting her
endorsements (here as `alice`):

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c endorse-alice origin/main
git-vouch-migrate drafts ~/pgpkeys . --commit "$C" --signer "$SIGNER" --as alice \
    --out ~/endorsement-drafts
cat ~/endorsement-drafts/endorsements/*/*.json
```

**She reads every draft before the loop signs it.** A GPG certification
never covered your new SSH key, so she confirms your key and emails with
you as in
[Confirming the key and emails](vouching.md#confirming-the-key-and-emails)
and deletes any draft she has not confirmed. Then she signs the drafts
that are left and approves you (here as `alice`):

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
git commit -q -m "alice: endorse and approve bob"
git push -q origin HEAD:endorse-alice
```

<!-- merge endorse-alice -->

The [captains guide](guide-captains.md#sign-your-endorsement-drafts)
says what each draft field means. Someone with no GPG history
with you endorses with `git vouch endorse bob --note "..."` instead.

### Switch git to SSH signing

`setup` records the registry, sets `gpg.format=ssh`, the allowed-signers
and revocation files, and runs a first `sync`. `status` then shows your
tier (here as `bob`):

<!-- as bob -->
```sh
git vouch setup --registry "$REGISTRY"
git vouch status
```

## Day to day

### Sign commits and tags

git signs with `user.signingKey` through the agent (here as `bob`):

<!-- as bob -->
```sh
git clone -q "$LINUX" linux
cd linux
echo "Bob was here." >>README
git commit -q -a -s -S -m "README: add a line"
git tag -s -m "for-alice-6.99 from bob" bob-6.99
git push -q origin HEAD:bob-fixes bob-6.99
```

`git config --global commit.gpgSign true` and `tag.gpgSign true` make
`-S` and `-s` the default. Your maintainer verifies with plain git (here
as `alice`):

<!-- as alice -->
```sh
git vouch setup --registry "$REGISTRY"
git clone -q "$LINUX" linux
cd linux
git verify-commit origin/bob-fixes
git verify-tag bob-6.99
```

A zero exit only means that some key in the allowed-signers file signed:
git does not tie the signer to the commit's author or the tag's message.
Check that git prints `Good "git" signature for bob`, with the handle of
the person the pull claims to come from.

### Keep your copy current

<!-- as bob -->
```sh
git vouch sync
git vouch status
```

`sync` fetches the registry, refuses a rewritten history, runs `check`
and re-exports the allowed-signers and revocation files, so new
approvals and revocations reach your git. Every command warns once your
copy is more than 7 days old.

## Rotating your key

Any key current in the previous version of your person file may sign
the next. To replace a key you still hold, add the new one and retire
the old one, both signed by the old key (here as `bob`):

<!-- as bob -->
```sh
cd registry
git fetch -q origin
git switch -q -c rotate-bob origin/main
git vouch add-key ~/.ssh/id_new.pub
git vouch retire-key ~/.ssh/id_ed25519.pub
git config --global user.signingKey ~/.ssh/id_new.pub
git add people
git commit -q -m "bob: rotate to a new key"
git push -q origin HEAD:rotate-bob
```

<!-- merge rotate-bob -->

Retiring keeps everything the old key signed valid (here as `bob`):

<!-- as bob -->
```sh
git vouch sync
cd linux
git verify-tag bob-6.99
```

OpenSSH 9.6 reads the time git passes it as standard time, an hour
late while your timezone is on daylight saving time. The export allows
for that by ending every key an hour after its retirement, so a
signature made just before it still verifies (see DESIGN.md).

Your `.asc` no longer covers the re-signed person file. That matters
only if you still want endorsement drafts before the late cutoff; make a
new one then.

## Endorsing and approving

Only maintainers approve, but any registered human may endorse, whatever
their tier. An endorsement
says that the person's key and emails belong to the real, named person,
and that you know it first-hand. Check that as
[vouching.md](vouching.md) describes, then (here as `bob`):

<!-- as bob -->
```sh
cd registry
git fetch -q origin
git switch -q -c endorse-carol origin/main
cat people/carol.json
git vouch endorse carol --note "Colleague since 2021; met daily at the office; key and email confirmed in person."
git add endorsements
git commit -q -m "bob: endorse carol"
git push -q origin HEAD:endorse-carol
```

<!-- merge endorse-carol -->

`endorse` covers the name, first current key and every listed email;
`--email` limits it to the addresses you confirmed.

## If you lose a key

Revoke rather than retire unless you are sure nobody else can use the
key: the signing time comes from the signer, so whoever holds a retired
key can backdate signatures. A revoked key's signatures all stop
verifying, and every endorsement it signed becomes void.

### With your backup key

Revoke the lost key, retire it and add a replacement, all signed by the
backup (here as `bob`, who lost the key
he rotated to):

<!-- as bob -->
```sh
cd registry
git fetch -q origin
git switch -q -c lost-bob origin/main
git vouch revoke ~/.ssh/id_new.pub --reason lost --sign-with ~/.ssh/backup.pub
git vouch retire-key ~/.ssh/id_new.pub --sign-with ~/.ssh/backup.pub
git vouch add-key ~/.ssh/id_next.pub --sign-with ~/.ssh/backup.pub
git config --global user.signingKey ~/.ssh/id_next.pub
git vouch check .
```

`check` reports what the lost key signed as void, here your endorsement
of carol:

```text
git-vouch: warning: endorsements/carol/bob-1.json: void: did:key:z6Mk... of bob is revoked
```

Endorse again in the same branch and push it (here as `bob`):

<!-- as bob -->
```sh
cd registry
git vouch endorse carol --note "Colleague since 2021; met daily at the office; key and email confirmed in person."
git add people revocations endorsements
git commit -q -m "bob: replace a lost key; re-endorse carol"
git push -q origin HEAD:lost-bob
```

<!-- merge lost-bob -->

Your tier is untouched, and what your earlier, retired key signed still
verifies (here as `bob`):

<!-- as bob -->
```sh
git vouch sync
cd linux
git verify-tag bob-6.99
```

Re-sign and push again anything you signed with the lost key.

### Without a backup key

Ask an anchor to revoke the lost key, then
register a new key with `git vouch register --from people/bob.json` and
retire the lost one signed by the new key. That change is signed by no
previous key, so `check` warns and the registry maintainer must confirm
the new key with you over a channel they already trust before merging.
Your tier carries over; endorsements you made with the revoked key do
not. The anchors guide runs these steps for a maintainer:
[Revoke a compromised key](guide-anchors.md#revoke-a-compromised-key)
has the revocation, and the recovery follows the table in
[Read check warnings in registry merges](guide-anchors.md#read-check-warnings-in-registry-merges).

## Patch signing

Patch signing with b4 and patatt is not covered on this page yet.

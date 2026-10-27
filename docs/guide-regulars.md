# Guide for regulars

A regular is a contributor: a maintainer has approved you at the
`contributor` tier. You sign the commits and tags you ask maintainers to
pull, and you may endorse people you know. You cannot approve anyone or
revoke other people's keys.

Before you endorse anyone, read
[What vouching for a real person means](vouching.md). It says what an
endorsement binds and what evidence to ask for.

**Status:** user guide, 2026-10-23. Facts come from `DESIGN.md`, and
[rationale.md](rationale.md) gives the reason for each design choice.
Tests run the command blocks; [How this page is tested](#how-this-page-is-tested)
says which.

## What the commands assume

> **What this does:** names the URLs, keys and checkouts the commands use.\
> **Why:** changes arrive as reviewed merges, and review is the only gate for three accepted risks ([rationale](rationale.md#nothing-pushes)).

- `$REGISTRY` is the registry's URL and `$LINUX` a kernel tree you push
  to. `$PGPKEYS`, `$FREEZE_COMMIT` and `$SIGNER` are the frozen
  `pgpkeys.git`, its last commit (the freeze commit) and the fingerprint
  that signed it, all published by kernel.org at the freeze (see
  [the flag-day runbook](flag-day.md)).
- `git-vouch` and `git-vouch-migrate` are on `PATH`, so `git vouch`
  works. You need `git-vouch-migrate` and `gpg` only on the flag day.
- Your SSH keys are loaded in an agent: `~/.ssh/id_ed25519` is your
  signing key and `~/.ssh/backup` a backup that stays in a drawer.
- `registry` is your checkout of the registry, and `linux` your kernel
  tree, both in your home directory.

No `git vouch` command pushes to the registry. Every change is a branch
from the registry's `main`, a `git vouch` command that writes and signs
a record, a commit, a push, and a merge by the registry maintainer once
`git vouch check` passes. The examples run as `bob`, the regular; other
people are named where they act.

## Flag day

> **What this does:** gets you registered before GPG-signed tags and pulls stop being accepted.\
> **Why:** there is one flag day and no period that accepts both GPG and SSH on new tags or pulls ([rationale](rationale.md#one-flag-day)).

Register during the window, before the flag day. From the flag day, a
GPG-signed tag or pull is not accepted. [The flag-day runbook](flag-day.md)
has the full timeline.

Patch signing has a fallback that tags do not. Before the flag day,
install the patatt fork and list `keyringsrc = vouch:` first and the
frozen pgpkeys keyring second, as [Patch signing](#patch-signing) shows.
Patches signed with a GPG key, or a key `patatt genkey` made, then keep
verifying through pgpkeys, with a warning, for everyone until the late
cutoff, six months after the flag day.

### Create your keys

> **What this does:** makes a main key and a backup key, on hardware tokens if you have them.\
> **Why:** the tool cannot prove what holds a key, so hardware is advice that endorsers and approvers ask about, not a rule ([rationale](rationale.md#hardware-keys)).

ed25519, P-256 and RSA keys of 2048 to 4096 bits are accepted, whether
software, on a token, or a GPG authentication subkey
([key types](rationale.md#rsa-cap)). If yours is RSA, upgrade now.
Hardware is recommended, not required. kernel.org issues FIDO tokens
and backup tokens (korg.docs.kernel.org/fido2.html); make one key on
each, touching the token when asked:

<!-- not-run needs-fido-token -->
```sh
ssh-keygen -t ed25519-sk -C "bob main" -f ~/.ssh/id_ed25519
ssh-keygen -t ed25519-sk -C "bob backup" -f ~/.ssh/backup
```

If your token has no ed25519, use `-t ecdsa-sk`. Without tokens,
`ssh-keygen -t ed25519` makes software keys that work the same way. To
let endorsers check a key was made on a token, generate it with
`-O challenge=<file> -O write-attestation=<file>` and pass both files to
`register` or `add-key` with `--challenge` and `--attestation`.

### Register

> **What this does:** registers you from your pgpkeys draft, adds your backup key and signs a continuity proof.\
> **Why:** the proof lets the people who certified your GPG key get endorsement drafts for you; it grants no tier ([rationale](rationale.md#continuity-proof)).

If you hold a key in `pgpkeys.git` that the freeze commit does not
revoke, register from the draft `git-vouch-migrate` writes for you, add
your backup key, and sign the result with your GPG key:

<!-- as bob -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$FREEZE_COMMIT" --signer "$SIGNER" --out drafts
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
is optional. It covers the person file's exact bytes, so make it last
([rationale](rationale.md#exact-bytes)).

The runbook's [Everyone else registers](flag-day.md#everyone-else-registers)
covers expired GPG keys and reused authentication subkeys.

### Register without one

> **What this does:** registers you fresh when you have no pgpkeys key, with no continuity proof and no `.asc`.\
> **Why:** a continuity proof grants no tier; it only gets you endorsement drafts from your old GPG certifiers, and you have none ([rationale](rationale.md#continuity-proof)).

As `carol`, a newcomer:

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

To use the key a forge lists at its `.keys` URL, such as
`https://github.com/<user>.keys`, save your key's line as a `.pub` file
and register that file.

### How your branch is merged

> **What this does:** shows what the registry maintainer runs before your change reaches `main`.\
> **Why:** a `--no-ff` merge puts the maintainer's committer dates on the main line, and effective dates come from them ([rationale](rationale.md#no-ff-merges)).

The registry maintainer, `korg`, merges your branch:

<!-- as korg -->
```sh
branch=register-bob
cd registry
git fetch -q origin "$branch"
git diff --name-status HEAD...FETCH_HEAD
git merge -q --no-ff --no-edit FETCH_HEAD
git vouch check .
```

`korg` pushes once `check` exits 0 and its warnings are read. The merge
never fast-forwards, not even your merge of main, so the dates on the
main line are the maintainer's clock, not yours. Until someone endorses
you, `check` warns that your email is not endorsed; that is expected:

<!-- as korg -->
```sh
cd registry
git push -q origin main
```

<!-- merge register-carol -->

### Get endorsed and approved

> **What this does:** gets endorsements from people who know you, then an approval from a maintainer.\
> **Why:** an endorsement is evidence about identity and grants nothing; only the approver needs authority, and the approver decides ([rationale](rationale.md#endorse-vs-approve)).

Ask people who know you in person to endorse you; [vouching.md](vouching.md)
says what they should check. If your continuity proof holds, the people
who certified your GPG key get a draft endorsement for you, which they
read, confirm with you and sign. A maintainer then approves you as a
contributor on their own judgement; there is no minimum number of
endorsements. `alice`, a maintainer, does both in one branch, first
drafting her endorsements:

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c endorse-alice origin/main
git-vouch-migrate drafts ~/pgpkeys . --commit "$FREEZE_COMMIT" --signer "$SIGNER" --as alice \
    --out ~/endorsement-drafts
cat ~/endorsement-drafts/endorsements/*/*.json
```

**She reads every draft before the loop signs it.** A GPG certification
never covered your new SSH key, so she confirms your key and emails with
you as in
[Confirming the key and emails](vouching.md#confirming-the-key-and-emails)
and deletes any draft she has not confirmed. Then she signs the drafts
that are left and approves you:

<!-- as alice -->
```sh
cd registry
for f in ~/endorsement-drafts/endorsements/*/*.json; do
    git vouch endorse --from "$f"
done
git vouch approve bob contributor
git add endorsements tiers
git commit -q -m "alice: endorse and approve bob"
git push -q origin HEAD:endorse-alice
```

<!-- merge endorse-alice -->

The [captains guide](guide-captains.md#sign-your-endorsement-drafts)
says what each draft field means. Someone with no GPG history with you
endorses with `git vouch endorse bob --note "..."` instead. Before
signing, `endorse` prints the key's SHA256 fingerprint: compare it with
the one you checked in person, and run `endorse` on the merged registry,
not on a pull-request checkout.

### Switch git to SSH signing

> **What this does:** points git at the registry's allowed-signers and revocation files and shows your tier.\
> **Why:** the registry is a git repository, and `git vouch export` writes git's own allowed-signers format, so plain git verifies against it ([rationale](rationale.md#registry-in-git)).

`setup` records the registry, sets `gpg.format=ssh`, the allowed-signers
and revocation files, and runs a first `sync`. It refuses, changing
nothing, if git already signs with a GPG key or points at other
allowed-signers or revocation files ([What setup changes](../README.md#what-git-vouch-setup-changes), and how to do it by
hand). `status` then shows your tier:

<!-- as bob -->
```sh
git vouch setup --registry "$REGISTRY"
git vouch status
```

## Day to day

> **What this does:** signs your work and keeps your registry copy current.\
> **Why:** git and OpenSSH already sign and verify, so `git-vouch` adds only the approval rules ([rationale](rationale.md#ssh-not-gpg)).

### Sign commits and tags

> **What this does:** signs a commit and a tag with your SSH key and shows how your maintainer verifies them.\
> **Why:** every exported key carries its handle and endorsed emails as principals, so git names who signed ([rationale](rationale.md#endorsed-emails)).

git signs with `user.signingKey` through the agent:

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
`-S` and `-s` the default. Your maintainer, `alice`, verifies with plain
git:

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

> **What this does:** fetches the registry and re-exports the files git verifies with.\
> **Why:** the one attack left to the registry's host is withholding updates, so `sync` refuses rewinds and commands warn on a stale copy ([rationale](rationale.md#sync-refuses-rewinds)).

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

> **What this does:** replaces a key you still hold, signed by the old key.\
> **Why:** any key current in the previous version of your person file may sign the next, which is how rotation works ([rationale](rationale.md#backup-key)).

Add the new key and retire the old one, both signed by the old key:

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

Retiring keeps everything the old key signed valid:

<!-- as bob -->
```sh
git vouch sync
cd linux
git verify-tag bob-6.99
```

OpenSSH 9.6 reads the time git passes it as standard time, an hour
late while your timezone is on daylight saving time. The export allows
for that by ending every key an hour after its retirement, so a
signature made just before it still verifies
([rationale](rationale.md#extra-hour)).

Your `.asc` no longer covers the re-signed person file. That matters
only if you still want endorsement drafts before the late cutoff; make a
new one then.

If you sign patches, the selector changes with the key: once the
rotation is merged and synced, run the two lines in
[Sign with your registry key](#sign-with-your-registry-key) again.
Patches signed with the retired key stop verifying when the people who
check them sync, which matters little once they are merged.

## Endorsing and approving

> **What this does:** endorses someone whose key and emails you confirmed first-hand.\
> **Why:** an endorsement grants nothing, so any registered human may make one, whatever their tier; only maintainers approve ([rationale](rationale.md#endorse-vs-approve)).

An endorsement says that the person's key and emails belong to the real,
named person, and that you know it first-hand. Check that as
[vouching.md](vouching.md) describes, then:

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
`--email` limits it to the addresses you confirmed. Before signing,
`endorse` prints the key's SHA256 fingerprint: compare it with the one
you checked in person, and run `endorse` on the merged registry, not on
a pull-request checkout.

## If you lose a key

> **What this does:** revokes a lost key so nothing it signed verifies.\
> **Why:** the signer sets the signing time, so whoever holds a retired key can backdate; revoke whenever there is doubt ([rationale](rationale.md#revoke-vs-retire)).

Revoke rather than retire unless you are sure nobody else can use the
key. A revoked key's signatures all stop verifying, and every
endorsement it signed becomes void. That includes patches: once someone
checking your patches has synced, patatt no longer finds the key. With
the b4 fork set up as in
[Check other people's patches](#check-other-peoples-patches), b4 checks
a signature again every time. Upstream b4 newer than 0.16 remembers a
verdict for up to 24 hours, so a series it already checked can keep its
tick until then.

### With your backup key

> **What this does:** revokes the lost key, retires it and adds a replacement, all signed by the backup.\
> **Why:** a key current in the previous version signs the change, so the backup in the drawer can recover you ([rationale](rationale.md#backup-key)).

Here bob has lost the key he rotated to:

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

Endorse again in the same branch and push it:

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
verifies:

<!-- as bob -->
```sh
git vouch sync
cd linux
git verify-tag bob-6.99
```

Re-sign and push again anything you signed with the lost key.

### Without a backup key

> **What this does:** recovers through an anchor and registry review when no current key can sign.\
> **Why:** a change no previous key signed only warns, and review is the gate, so the registry maintainer confirms the new key with you ([rationale](rationale.md#backup-key)).

Ask an anchor to revoke the lost key, then register a new key with
`git vouch register --from people/bob.json` and retire the lost one
signed by the new key. No previous key signs that change, so `check`
warns and the registry maintainer must confirm the new key with you over
a channel they already trust before merging. Your tier carries over;
endorsements you made with the revoked key do not. The anchors guide
runs these steps for a maintainer:
[Revoke a compromised key](guide-anchors.md#revoke-a-compromised-key)
has the revocation, and the recovery follows the table in
[Read check warnings in registry merges](guide-anchors.md#read-check-warnings-in-registry-merges).

## Patch signing

> **What this does:** signs the patches you email and checks other people's against the registry.\
> **Why:** the registry is the keyring, so nothing is generated, published or trusted in between ([rationale](rationale.md#patch-fallback)).

Patches you email are signed with patatt, the signer built into b4. It
adds an `X-Developer-Signature` header, and the maintainer's `b4 am`
checks it. A fork of patatt adds one keyring source, `vouch:`, which
asks `git vouch keys` for the signer's current keys. Your patch
verifies when one of your current keys signed it and it comes from an
email someone has endorsed.

### Install the forks

> **What this does:** installs b4 and patatt from their forks' `git-vouch` branches.\
> **Why:** the patatt fork adds the `vouch:` keyring, and the b4 fork can check every signature again so a revocation takes effect at once ([rationale](rationale.md#patch-fallback)).

Install both in one command, so b4 gets the patatt fork in place of
released patatt:

<!-- patch not-run needs-network -->
```shell
pip install 'b4 @ git+https://github.com/MarkAtwood/b4@git-vouch' \
    'patatt @ git+https://github.com/MarkAtwood/patatt@git-vouch'
```

If you run b4 from a checkout with `b4.sh`, clone the b4 fork's
`git-vouch` branch and put the patatt fork in its `patatt` submodule.
The submodule points at kernel.org, which has no `git-vouch` branch, so
fetch that branch from github.com/MarkAtwood/patatt and check it out
there.

`misc/vouch-check.sh` in the b4 fork tests the pair offline in a
throwaway home: it signs a series with a registry key and checks that
`b4 am` passes it, then fails it once the key is revoked. Unless
git-vouch and the patatt fork are checked out next to b4 and b4 has a
`.venv`, set `GIT_VOUCH` to the git-vouch script, `PATATT_FORK` to a pip
requirement for the patatt fork and `PYTHON` to a Python with b4's
dependencies. It also needs `uv`, with setuptools in its cache. It sets
up its own config: set yours as this page does, not as the script's
header shows.

### Sign with your registry key

> **What this does:** makes patatt sign with your git signing key, under the selector derived from it.\
> **Why:** patatt identities are endorsed emails only, so your `user.email` must be one ([rationale](rationale.md#endorsed-emails)).

patatt signs with the key git signs with, under the selector
`git vouch status` prints. It signs as your `user.email`, so that must
be an endorsed email:

<!-- patch as bob -->
```shell
git config --global patatt.signingkey "openssh:$(git config --global user.signingKey)"
git config --global patatt.selector "$(git vouch status | sed -n 's/^patatt.selector: //p')"
```

### Check other people's patches

> **What this does:** tells patatt and b4 to look up keys in the registry first, then in pgpkeys at the freeze commit.\
> **Why:** the legacy keyring is pgpkeys at the freeze commit, never a later state of it ([rationale](rationale.md#freeze-commit)).

Use the frozen pgpkeys clone from the flag day, checked out at the
freeze commit:

<!-- patch as bob -->
```shell
git -C ~/pgpkeys checkout -q --detach "$FREEZE_COMMIT"
git config --global --unset-all b4.keyringsrc || true
git config --global patatt.keyringsrc vouch:
git config --global --add patatt.keyringsrc ~/pgpkeys/.keyring
git config --global b4.attestation-recheck-hours 0
```

patatt reads the keyring as files on disk, so leave that clone at the
freeze commit: a key added after it would verify too. The checkout
fails if the clone does not hold the freeze commit.

b4 ignores `patatt.keyringsrc` while `b4.keyringsrc` is set, as b4's
documentation suggests, so the second line removes `b4.keyringsrc`.

`b4.attestation-recheck-hours = 0` is a setting of the b4 fork: b4
checks every signature again instead of remembering a verdict for up to
24 hours, so a revoked key stops verifying at your next `git vouch
sync`. Any other b4 ignores it, and upstream b4 newer than 0.16 keeps a
pass for up to 24 hours. The fork names the keyring after every registry
pass: if `b4 am` prints `✓ Signed: openssh/...` with no
`(key: vouch:...)` after it, the b4 you run is not the fork. Check
`command -v b4`.

### Send

> **What this does:** sends signed patches with `b4 send` or `git send-email`.\
> **Why:** recipients check each message's signature against your current registry keys ([rationale](rationale.md#patch-fallback)).

`b4 send` signs every message before it sends it, through git's
`sendemail.*` settings or a b4 web endpoint. Press Enter when it asks:

<!-- patch as bob -->
```shell
cd linux
b4 prep -n readme-line -f HEAD
echo "Another line." >>README
git commit -q -a -s -m "README: add another line"
b4 send --to alice@example.org
```

With `git send-email`, install patatt's hook once in each tree; it signs
each message as it goes out:

<!-- patch as bob -->
```shell
cd linux
patatt install-hook
git send-email --to alice@example.org -1
```

### What recipients see

> **What this does:** shows the `b4 am` lines for a verified patch and for a missing key.\
> **Why:** only endorsed emails are exported, so an unendorsed address shows as no key ([rationale](rationale.md#endorsed-emails)).

`b4 am` ticks the patch and names the signer and the keyring that held
the key:

```console
  ✓ [PATCH] README: add another line
  ✓ Signed: openssh/bob@example.org (key: vouch:bob@example.org/...)
```

`✗ No key: openssh/bob@example.org` means your email is not endorsed,
the key is not current in the registry, `patatt.selector` is not the
selector of the key that signed, or the checker's registry copy predates
your key and needs `git vouch sync`.

### Keys `patatt genkey` made

> **What this does:** moves patatt from a `patatt genkey` key to your registry SSH key.\
> **Why:** the registry holds SSH keys only, and the pgpkeys fallback ends at the late cutoff ([rationale](rationale.md#patch-fallback)).

`vouch:` serves nothing but SSH keys. A key `patatt genkey` made
(`patatt.signingkey = ed25519:...`) verifies only through the pgpkeys
keyring, with the warning, until the late cutoff. After it, b4 marks
such patches `? (TOFU: new key)` instead of verified. Register an SSH
key and switch patatt to it with the lines in
[Sign with your registry key](#sign-with-your-registry-key).

### After the late cutoff

> **What this does:** removes the legacy pgpkeys keyring from patatt.\
> **Why:** the late cutoff ends the window in which a stolen, unrevoked GPG key can claim someone's identity ([rationale](rationale.md#late-cutoff)).

Delete the legacy keyring line; nothing else changes:

<!-- patch as bob -->
```shell
git config --global --unset patatt.keyringsrc pgpkeys
```

GPG-signed patches then show `✗ No key`.

## How this page is tested

> **What this does:** says which test runs each block and who the examples' people are.\
> **Why:** the cast has a maintainer to approve and a registry maintainer to merge, because every change is a reviewed merge ([rationale](rationale.md#nothing-pushes)).

`tests/migrate/test_guide_regulars.py` runs every command block on this
page but the first, in order, in a throwaway registry, with real `git`,
`ssh-keygen` and `gpg` and a synthetic `pgpkeys.git`. The first block
needs FIDO tokens, so it is not run. `tests/patatt/test_patch_docs.py`
runs the `shell` blocks under [Patch signing](#patch-signing) with the
b4 and patatt forks, mail going to a local sink.

The cast: `bob` is the regular (you), with a key in `pgpkeys.git` that
`alice` certified. `alice` is a maintainer, `carol` a newcomer, and
`korg` the registry maintainer who merges branches into the registry.
Put your own handle, name and email in their place.

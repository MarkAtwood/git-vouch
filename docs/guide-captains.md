# Guide for captains

**Status:** user guide, 2026-10-22. Facts come from `DESIGN.md`;
[the rationale](rationale.md) gives the reason for each choice.
[About the examples](#about-the-examples) says who runs each block and
how the tests run them.

A captain is a subsystem maintainer an anchor has approved at the
`maintainer` tier. Linus pulls your signed tags. You verify the tags of
people who send you pull requests, approve contributors, and endorse
people you know. Anchors, not you, approve maintainers and revoke other
people's keys.

Read [What vouching for a real person means](vouching.md) before you
endorse or approve anyone. It says what an endorsement binds, what
evidence to ask for, and how to read the endorsements you approve on.

## What the commands assume

> **What this does:** lists the variables, tools and keys every block below uses, and the one path every change takes.
> **Why:** commands only write and sign files; every change arrives as a reviewed merge ([rationale](rationale.md#nothing-pushes)).

- `$REGISTRY` is the registry's URL and `$LINUX` a kernel tree you push
  tags to. kernel.org publishes `$PGPKEYS`, `$FREEZE_COMMIT` and
  `$SIGNER` at the freeze: the frozen `pgpkeys.git`, its last commit
  (the freeze commit) and the fingerprint that signed it (see
  [the flag-day runbook](flag-day.md)).
- `git-vouch` and `git-vouch-migrate` are on `PATH`, so `git vouch`
  works. You need `git-vouch-migrate` and `gpg` only on the flag day.
- An agent holds your SSH keys: `~/.ssh/id_ed25519` signs, and
  `~/.ssh/backup` is a backup key that stays in a drawer. Keep both on
  hardware tokens; kernel.org issues FIDO keys and backup tokens
  (korg.docs.kernel.org/fido2.html). `git-vouch` accepts any supported
  key, so this is advice, not a rule
  ([rationale](rationale.md#hardware-keys)).
- `registry` is your checkout of the registry and `linux` your kernel
  tree, both in your home directory.

No `git vouch` command pushes to the registry. Every change takes the
same path: branch from the registry's `main`, run a `git vouch` command
that writes and signs a record, commit, push, and the registry
maintainer merges once `git vouch check` passes.

## Flag day

> **What this does:** registers you, gets you approved, signs your endorsement drafts and switches git to SSH.
> **Why:** one day switches tags and pulls to SSH, with no period that accepts both ([rationale](rationale.md#one-flag-day)).

These are a captain's steps in [the flag-day runbook](flag-day.md),
which has the full timeline. The anchors register and merge first;
everyone else registers during the window.

Set up patch signing before the flag day: install the patatt fork and
list `keyringsrc = vouch:` first and the frozen pgpkeys keyring second,
as [Patch signing](#patch-signing) shows. Patches signed with a GPG key,
or a key `patatt genkey` made, then keep verifying through pgpkeys, with
a warning, for everyone until the late cutoff, six months after the flag
day. Tags get no such fallback.

### Register with your pgpkeys key

> **What this does:** registers you from your pgpkeys draft and signs a continuity proof with your GPG key.
> **Why:** the proof lets your old GPG certifiers draft endorsements for you; it grants no tier ([rationale](rationale.md#continuity-proof)).

Use this if you hold a key in `pgpkeys.git` that the freeze commit had
not revoked. Register from the draft `git-vouch-migrate` writes, then
sign the result with your GPG key (as `alice`):

<!-- as alice -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$PGPKEYS" pgpkeys
git-vouch-migrate port pgpkeys --commit "$FREEZE_COMMIT" --signer "$SIGNER" --out drafts
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

`port` checks the freeze commit's signature by `$SIGNER`, then writes
one unsigned draft per person in pgpkeys: a proposed handle, your name,
the emails on your unrevoked user IDs, and `migratedFrom`. Read yours
before registering: the handle is permanent. `register --from` adds your
SSH key and signs the file; `add-key` lists your backup key, signed by
the main one.

Make the `.asc` last. It covers the person file's exact bytes
([rationale](rationale.md#exact-bytes)), so any later `add-key`,
`retire-key` or email change needs a new one before the late cutoff if
you still want endorsement drafts. The proof only unlocks drafts from
your old GPG certifications (below).

The runbook's
[Everyone else registers](flag-day.md#everyone-else-registers) covers
the other cases, such as an expired GPG key or reusing your GPG
authentication subkey as your SSH key.

### Register without one

> **What this does:** registers you fresh, with no continuity proof.
> **Why:** the proof only unlocks endorsement drafts, so without it you collect fresh endorsements and lose no tier ([rationale](rationale.md#continuity-proof)).

About 80% of maintainers have no pgpkeys key. Register fresh, then
collect fresh endorsements. The example runs as `carol`, a contributor with no
pgpkeys key; a captain runs the same command:

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

> **What this does:** shows how the registry maintainer reviews, merges and checks your branch.
> **Why:** a `--no-ff` merge keeps the maintainer's commit dates on the main line, and tier removals take their dates from it ([rationale](rationale.md#no-ff-merges)).

The registry maintainer merges every branch the same way (as `korg`,
for `register-alice`):

<!-- as korg -->
```sh
branch=register-alice
cd registry
git fetch -q origin "$branch"
git diff --name-status HEAD...FETCH_HEAD
git merge -q --no-ff --no-edit FETCH_HEAD
git vouch check .
```

They push only once `check` exits 0, the list of changed paths is right,
and they have read every `git-vouch: warning:` line. They never
fast-forward, not even your merge of main, so the dates on the main line
are the maintainer's clock, not yours. Until someone endorses you,
`check` warns that your emails are not endorsed; that is expected. Then
(as `korg`):

<!-- as korg -->
```sh
cd registry
git push -q origin main
```

<!-- merge register-carol -->

### Get approved as a maintainer

> **What this does:** an anchor endorses you and grants you the `maintainer` tier.
> **Why:** a tier is a separate record the approver signs, so nobody promotes themselves ([rationale](rationale.md#tiers)).

Ask people who know you in person to endorse you, as
[vouching.md](vouching.md) describes; your old GPG certifiers get drafts
for you if your continuity proof holds. An anchor approves you on their
own judgement, using MAINTAINERS and the endorsements in the registry.
There is no minimum number of endorsements. GPG supplies no tiers: the
web of trust says nothing about who is a maintainer. The anchor then
approves you (as `lena`):

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

You can approve contributors from the commit that adds that tier record.

### Sign your endorsement drafts

> **What this does:** turns your old GPG certifications into endorsement drafts, which you read and sign, and approves your contributors.
> **Why:** the tool reads pgpkeys only at the freeze commit, on your own machine; no one generates drafts centrally ([rationale](rationale.md#freeze-commit)).

GPG certifications are not ported as records. If you certified other
people's GPG keys, draft endorsements from those certifications on your
own machine, read each one, sign the ones you still stand behind, and
approve your contributors in the same branch (as `alice`):

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c endorse-alice origin/main
git-vouch-migrate drafts ~/pgpkeys . --commit "$FREEZE_COMMIT" --signer "$SIGNER" --as alice \
    --out ~/endorsement-drafts
cat ~/endorsement-drafts/endorsements/*/*.json
```

`drafts --as` writes one draft for each registered person whose
continuity proof holds and whose GPG key your own proven key certified
at the freeze commit. It refuses unless your own proof holds too. A
subject who has not registered yet gets no draft; run `drafts` again
later into a new `--out` directory and sign only the new ones.

**Read every draft before the loop signs it.** `subjectName` comes from
the subject's own person file, not from your certification;
`subjectEmails` are their emails on the user IDs you certified; `note`
names the certified key, user IDs and date. A certification never
covered the subject's new SSH key, so confirm the key and emails with
them as in
[Confirming the key and emails](vouching.md#confirming-the-key-and-emails).
Delete any draft you would not endorse today, and edit `note` or
`subjectEmails` before signing if you need to. Then sign the drafts that
are left and approve your contributors (as `alice`):

<!-- as alice -->
```sh
cd registry
for f in ~/endorsement-drafts/endorsements/*/*.json; do
    git vouch endorse --from "$f"
done
git vouch approve bob contributor
git add endorsements tiers
git commit -q -m "alice: endorsements from GPG certifications; approve bob"
git push -q origin HEAD:endorse-alice
```

<!-- merge endorse-alice -->

`endorse --from` refuses a draft whose `endorser` or `endorserKey` is
not you and your signing key. Otherwise it signs the draft exactly as
you read it and writes it and its signature into the registry under the
next free number. It leaves the draft where it is.

### Switch git to SSH signing

> **What this does:** points git at the registry's export and signs your first SSH tag.
> **Why:** git and OpenSSH already sign and verify, so `git-vouch` adds only the approval rules and no cryptography ([rationale](rationale.md#ssh-not-gpg)).

`setup` records the registry, sets `gpg.format=ssh` and the
allowed-signers and revocation files, and runs a first `sync`. The
default export is contributor and above, which is what you verify your
pull requests against (as `alice`):

<!-- as alice -->
```sh
git vouch setup --registry "$REGISTRY"
git vouch status
git clone -q "$LINUX" linux
cd linux
git tag -s -m "for-6.99 from alice" alice-6.99
git push -q origin alice-6.99
```

`status` prints the registry commit, its age, and your own tier. Linus
now verifies your tag against his maintainer export. From the flag day,
nobody accepts a GPG-signed tag or pull.

## Day to day

> **What this does:** keeps your registry copy current and verifies the tags people ask you to pull.
> **Why:** `git fetch` distributes the registry, so staying current is one `sync` ([rationale](rationale.md#registry-in-git)).

### Keep your copy current

> **What this does:** fetches the registry and re-exports your allowed-signers and revocation files.
> **Why:** withholding a revocation is the one attack left to whoever hosts the registry ([rationale](rationale.md#sync-refuses-rewinds)).

<!-- as alice -->
```sh
git vouch sync
git vouch status
```

`sync` fetches the registry, refuses a rewritten history, runs `check`
and re-exports your allowed-signers and revocation files. It writes the
revocation file even when `check` fails on something else, so a
revocation always reaches you. Every command warns when your copy was
last fetched more than 7 days ago. Sync before you verify.

### Verify pull request tags

> **What this does:** checks a contributor's tag with plain `git verify-tag` against your export.
> **Why:** every exported key carries its handle as a principal, so git names the signer and you check that name ([rationale](rationale.md#endorsed-emails)).

A contributor signs the tag they ask you to pull (as `bob`, who pushes
to the shared tree; yours will name their own):

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
(as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git fetch -q "$LINUX" tag bob-6.99
git verify-tag bob-6.99
git cat-file tag bob-6.99
```

git prints `Good "git" signature for bob`. The export holds every
approved contributor, so a good signature alone does not show who signed.
Check that the name after `signature for` is the person who sent the
pull request, and that the `tag` line and message `git cat-file` prints
are the ones they asked you to pull. A failed verification means the
signer is not approved at contributor or above, or their key is retired
or revoked: do not pull. Run `git vouch sync` first if the signer says
they were approved recently.

## Rotating your key

> **What this does:** replaces a key you still hold, signed by the old key.
> **Why:** any one key current in the previous person file may sign the next, so the backup token can stay in a drawer ([rationale](rationale.md#backup-key)).

Add the new key and retire the old one in one branch, both signed by the
old key, and switch git to the new key (as `alice`):

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
your approvals, and your old tags (as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git verify-tag alice-6.99
```

Rotating re-signs your person file, so your `.asc` no longer covers it.
Make a new `.asc` only if you still want endorsement drafts before the
late cutoff.

If you sign patches, the selector changes with the key: once the
rotation is merged and synced, run the two lines in
[Sign with your registry key](#sign-with-your-registry-key) again.
Patches signed with the retired key stop verifying when the people who
check them sync, which matters little once they are merged.

## Endorsing and approving

> **What this does:** endorses a contributor you know and grants them the `contributor` tier.
> **Why:** an endorsement is evidence about identity and grants nothing; only the approver needs authority ([rationale](rationale.md#endorse-vs-approve)).

carol has registered but nobody has approved her, so her tag fails (as
`carol`, then `alice`):

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
named person, and that you know it first-hand. Any registered human may
endorse. Approval grants a tier; as a captain you may approve
`contributor` and `automation`. Approve on your own judgement:
endorsements are evidence, not a count. If you know carol yourself,
check her identity, key and emails as [vouching.md](vouching.md)
describes, then endorse and approve her in one branch (as `alice`):

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
addresses you confirmed. Before signing, `endorse` prints the key's
SHA256 fingerprint: compare it with the one you checked in person. Run
`endorse` on the merged registry, not on a pull-request checkout.

Once merged and synced, carol's tag verifies (as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git verify-tag carol-6.99
```

To remove a contributor's tier without suspecting their key, ask the
registry maintainer to delete their `tiers/<handle>.json` in a reviewed
merge. Their keys get `valid-before` set to that commit's date, and
signatures they made before stay valid. `check` judges your approvals
once, at the commit that adds them, so they stay if you later step down.
Only a revoked key voids the records it signed (see
[If you lose a key](#if-you-lose-a-key)).

## If you lose a key

> **What this does:** revokes a lost key and re-signs what it signed, with or without a backup key.
> **Why:** the signer sets the signing time, so whoever holds a retired key can backdate; revoke when in doubt ([rationale](rationale.md#revoke-vs-retire)).

Revoke rather than retire unless you are sure nobody else can use the
key. A revoked key's signatures all stop verifying, past and future,
and every endorsement and tier record it signed becomes void. That
includes patches: once someone checking them has synced, patatt no
longer finds the key. The b4 fork, set up as in
[Check incoming patches](#check-incoming-patches), checks a signature
again every time. Upstream b4 newer than 0.16 remembers a verdict for up
to 24 hours, so a series it already checked can keep its tick until
then.

### With your backup key

> **What this does:** revokes and retires the lost key and adds a replacement, all signed by the backup.
> **Why:** a backup key registered in advance signs the change, so recovery needs no unsigned change ([rationale](rationale.md#backup-key)).

Here alice lost the key she rotated to (as `alice`):

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
everyone listed, in the same branch, then push it (as `alice`):

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

The lost key's revocation leaves records your earlier, retired key
signed, such as bob's approval, untouched. Once merged and synced, both
tags verify again (as `alice`):

<!-- as alice -->
```sh
git vouch sync
cd linux
git verify-tag bob-6.99
git verify-tag carol-6.99
```

Any tag the revoked key signed stops verifying; ask Linus to pull again
from a tag you re-sign with the new key.

### Without a backup key

> **What this does:** recovers through an anchor's revocation and a new key no previous key signed.
> **Why:** that change prints a WARNING and registry review is the only gate, so the merger confirms the key with you first ([rationale](rationale.md#backup-key)).

Ask an anchor to revoke the lost key: only the key itself, another of
your current keys, or an anchor may sign its revocation. Then register a
new key in a change no previous key signed, with
`git vouch register --from people/<you>.json` and your new key, and
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

> **What this does:** signs your patches with your registry key and checks incoming ones against the registry, then pgpkeys.
> **Why:** the registry is the keyring, so nothing is generated or trusted in between; pgpkeys stays second until the late cutoff ([rationale](rationale.md#patch-fallback)).

patatt, the signer built into b4, adds an `X-Developer-Signature`
header that `b4 am` checks. A fork of patatt adds one keyring source,
`vouch:`, which asks `git vouch keys` for the signer's current keys. A
patch verifies when one of the signer's current keys signed it and it
comes from an endorsed email, whatever the signer's tier.

### Install the forks

> **What this does:** installs b4 and patatt from their forks' `git-vouch` branches.
> **Why:** the b4 fork can check every patch afresh, so a revocation takes effect at once ([rationale](rationale.md#patch-fallback)).

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

> **What this does:** tells patatt to sign with your git signing key and its selector.
> **Why:** only endorsed emails are exported, so your `user.email` must be one ([rationale](rationale.md#endorsed-emails)).

patatt signs with the key git signs with, under the selector
`git vouch status` prints, which is derived from the key. It signs as
your `user.email`, so that must be an endorsed email. `b4 send`, or
`git send-email` after `patatt install-hook`, then signs every patch
(as `alice`):

<!-- patch as alice -->
```shell
git config --global patatt.signingkey "openssh:$(git config --global user.signingKey)"
git config --global patatt.selector "$(git vouch status | sed -n 's/^patatt.selector: //p')"
```

[The regulars guide](guide-regulars.md#send) shows both ways of
sending.

### Check incoming patches

> **What this does:** points patatt and b4 at the registry first and the frozen pgpkeys keyring second, then checks a series.
> **Why:** the registry is the keyring; pgpkeys at the freeze commit stays second, with a warning, until the late cutoff ([rationale](rationale.md#patch-fallback)).

Tell patatt and b4 where to find keys: the registry first, then the
frozen pgpkeys keyring you cloned on the flag day, checked out at the
freeze commit (as `alice`):

<!-- patch as alice -->
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

Sync, then fetch the series by its message-id, here `$MSGID`, bob's
patch from your mailbox; without `-m`, b4 fetches it from lore (as
`alice`):

<!-- patch as alice -->
```shell
git vouch sync
cd linux
b4 am -m ~/mail.mbox "$MSGID"
```

`b4 am` prints one of these for each signature:

```console
  ✓ Signed: openssh/bob@example.org (key: vouch:bob@example.org/...)
W: dave@example.org/default verified via legacy keyring .../.keyring/openpgp/example.org/dave/default, not the vouch registry; legacy keyrings stop working six months after flag day
  ✓ Signed: openpgp/dave@example.org (key: .../pgpkeys/.keyring)
  ✗ BADSIG: openssh/bob@example.org
  ✗ No key: openssh/carol@example.org
```

| Result | Means | Tell the contributor |
|---|---|---|
| `✓ Signed: ... (key: vouch:...)` | A current key of a registered person signed it, from an endorsed email; `git vouch keys <email>` lists the registry's keys for the signer. | Nothing. |
| `W: ... verified via legacy keyring` and `✓ Signed: ... (key: .../pgpkeys/.keyring)` | It verified through pgpkeys, not the registry: a GPG key, or a key `patatt genkey` made. With `b4.attestation-recheck-hours = 0`, the warning shows on every check. | Register an SSH key and sign with it before the late cutoff. |
| `✗ BADSIG` | The message changed after it was signed, or the signature is broken. | Resend it; mail in transit may have rewritten it. |
| `✗ No key` | The email is not endorsed, the key is not current in the registry, the selector is not that key's, or your copy is stale. | Run `git vouch sync` and check again. Otherwise ask them to get the email endorsed and to sign with a current key and its selector from `git vouch status`. |

Read the result before you apply the series: under its default
`attestation-policy` of `softfail`, b4 does not reject a patch over
`No key`.

### Keys `patatt genkey` made

> **What this does:** says what happens to patches signed with a key `patatt genkey` made.
> **Why:** the late cutoff ends the pgpkeys fallback, the only place such keys verify ([rationale](rationale.md#late-cutoff)).

Tell those contributors to register an SSH key and switch patatt to it.
The registry holds SSH keys only, and `vouch:` serves nothing else. A
key `patatt genkey` made (`patatt.signingkey = ed25519:...`) verifies
only through the pgpkeys keyring, with the warning, until the late
cutoff. After it, b4 marks such patches `? (TOFU: new key)` instead of
verified.

### After the late cutoff

> **What this does:** removes the legacy pgpkeys keyring from your patatt config.
> **Why:** the cutoff ends the window in which a stolen, unrevoked GPG key can claim someone's identity ([rationale](rationale.md#late-cutoff)).

Delete the legacy keyring line; nothing else changes (as `alice`):

<!-- patch as alice -->
```shell
git config --global --unset patatt.keyringsrc pgpkeys
```

GPG-signed patches then show `✗ No key`.

## About the examples

Every command block on this page runs, in order, in
`tests/migrate/test_guide_captains.py`, in a throwaway registry with
real `git`, `ssh-keygen` and `gpg` and a synthetic `pgpkeys.git`. The
`shell` blocks under [Patch signing](#patch-signing) run in
`tests/patatt/test_patch_docs.py` with the b4 and patatt forks, mail
going to a local sink. The "(as ...)" note before each block names who
runs it.

The cast: `alice` is the captain (you), with a key in `pgpkeys.git`.
`lena` is an anchor. `bob` and `carol` are contributors who send alice
pull requests; bob had a pgpkeys key that alice certified, carol never
had one. `korg` is the registry maintainer who merges branches into the
registry. Put your own handle, name and email in their place.

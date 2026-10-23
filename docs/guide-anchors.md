# Guide for anchors

**Status:** user guide, 2026-10-22. Facts come from `DESIGN.md`. Every
command block on this page is run, in order, by
`tests/test_guide_anchors.py` in a throwaway registry, with real `git`
and `ssh-keygen`. The `shell` blocks under
[Patch signing](#patch-signing) are run by
`tests/patatt/test_patch_docs.py` with the b4 and patatt forks,
mail going to a local sink. Who runs each block is noted in the text.

An anchor is one of the few people `anchors.json` in the registry lists:
Linus and whoever the kernel team designates. Anchors are the root of
the tree. You approve maintainers, you can revoke anyone's key, and your
own key signs releases. Nothing grants the anchor tier except
`anchors.json`, and a tier record for an anchor fails `check`.

Before you endorse or approve anyone, read
[What vouching for a real person means](vouching.md). It says what an
endorsement binds, what evidence to ask for, and how to read the
endorsements you approve on.

## What the commands assume

- `$REGISTRY` is the registry's URL and `$LINUX` is a kernel tree you
  push tags to. The kernel's registry path on git.kernel.org is for the
  kernel.org administrators to choose. `$PGPKEYS` and `$FREEZE_COMMIT` are
  the frozen `pgpkeys.git` and its last commit, the freeze commit, published by kernel.org at
  the freeze (see [the flag-day runbook](flag-day.md)).
- `git-vouch` is on `PATH`, so `git vouch` works.
- Your SSH keys are loaded in an agent. The commands use
  `~/.ssh/id_ed25519` as your signing key and `~/.ssh/backup` as a
  backup key that stays in a drawer. Keep both on hardware tokens:
  kernel.org issues FIDO keys and backup tokens
  (korg.docs.kernel.org/fido2.html). `git-vouch` accepts any supported
  key, so this is advice, not a rule.
- `registry` is your checkout of the registry, and `linux` your kernel
  tree, both in your home directory.

The cast: `lena` is the anchor (you), `alice` is a maintainer, and `korg`
is the registry maintainer who merges branches into the registry. Put
your own handle, name and email in their place.

## Flag day

[The flag-day runbook](flag-day.md) has the full timeline for everyone.
These are the anchors' steps in it.

Patch signing has a fallback that tags do not. Before the flag day,
everyone who signs or checks patches installs the patatt fork and lists
`keyringsrc = vouch:` first and the frozen pgpkeys keyring second, as
[Patch signing](#patch-signing) shows. Patches signed with a GPG key, or
a key `patatt genkey` made, then keep verifying through pgpkeys, with a
warning, for everyone until the late cutoff, six months after the flag
day.

### Register and merge first

The first registry merge holds the anchors' person files and
`anchors.json`, before anyone else can be approved. Register with your
main key, add your backup key, and push a branch (here as `lena`):

<!-- as lena -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$REGISTRY" registry
cd registry
git vouch register --handle lena --name "Lena Anchor" --email lena@example.org \
    ~/.ssh/id_ed25519.pub
git vouch add-key ~/.ssh/backup.pub
git add people
git commit -q -m "people: register lena"
git push -q origin HEAD:register-lena
```

Register your backup key now, while your main key can sign for it. A
person file change needs a signature from a key in the previous version,
so with a backup listed, losing your main key is a signed change rather
than one that rests on review (see Lost key).

**If you hold a key in `pgpkeys.git`,** register from your
`git-vouch-migrate` draft and add a GPG continuity proof instead, as in
the runbook's [first merge](flag-day.md#the-first-merge-the-anchors).
The proof only unlocks endorsement drafts from your old GPG
certifications. It grants no tier: yours comes from `anchors.json`.

The registry maintainer merges the anchors' branches, then commits
`anchors.json` on top (here as `korg`):

<!-- as korg -->
```sh
git clone -q "$REGISTRY" registry
cd registry
git fetch -q origin register-lena
git merge -q --ff-only FETCH_HEAD
echo '["lena"]' >anchors.json
git add anchors.json
git commit -q -m "anchors: lena"
git vouch check .
git push -q origin main
```

`check` fails if `anchors.json` names a handle with no person file, so
the person files go in first.

Nothing but review protects `anchors.json`: whoever can merge into the
registry can add an anchor, and that anchor can approve anyone. Adding
or removing an anchor later is the same edit, in a reviewed merge. An
edit that passes `check` prints no warning about itself. Two cases are
not silent: promoting someone who has a tier record fails `check` unless
the same merge deletes their `tiers/<handle>.json`, and a tier record
granted on a branch concurrent with removing its approver from
`anchors.json` is void, with a warning, until someone re-approves it.
Who the registry maintainers are is a kernel-team decision, and it
matters as much as the anchor list. Registry maintainers also enforce
the late cutoff, which no tool checks: after it they merge no change
that adds or alters `migratedFrom` or adds a `people/*.json.asc`.

### Approve the first maintainers

Maintainers register like everyone else (here as `alice`):

<!-- as alice -->
```sh
git config --global user.signingKey ~/.ssh/id_ed25519.pub
git clone -q "$REGISTRY" registry
cd registry
git vouch register --handle alice --name "Alice Example" --email alice@example.org \
    ~/.ssh/id_ed25519.pub
git add people
git commit -q -m "people: register alice"
git push -q origin HEAD:register-alice
```

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

Stop here. Push only once `check` exits 0, the list of changed paths is
right, and you have read every `git-vouch: warning:` line (see Read
check warnings in registry merges). For an unsigned-change WARNING,
first confirm the new key with its owner over a channel you already
trust. If anything is wrong, `git reset -q --hard origin/main` drops the
merge. Then push (here as `korg`):

<!-- as korg -->
```sh
cd registry
git push -q origin main
```

GPG supplies no tiers: Linus certified 2 keys in pgpkeys, so the web of
trust says nothing about who is a maintainer. Approve maintainers on
your own judgement, using MAINTAINERS and their endorsements. There is
no minimum number of endorsements; you read them and decide. If you know
the person yourself, endorse them too, following
[vouching.md](vouching.md). Then approve (here as `lena`):

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

Merged and pushed as above, with `branch=approve-alice`. Before approving someone
endorsed by others, read each `endorsements/<handle>/*.json`: who
endorsed them, which emails, and what the note says was checked.
`vouching.md` has a checklist.

Your approval is judged once, at the commit that adds it. If you later
step down, the tiers you granted stay. Only a revoked key voids the tier
records it signed (see Lost key).

### Switch Linus's git to the maintainer export

On the flag day, Linus points `gpg.ssh.allowedSignersFile` at the
export of maintainers and above. `setup` records the registry, sets
`gpg.format=ssh` and both git files, and runs a first `sync`
(here as `lena`):

<!-- as lena -->
```sh
git vouch setup --registry "$REGISTRY" --min-tier maintainer
git config --global gpg.ssh.allowedSignersFile
git vouch status
```

From now on plain `git verify-tag` and `git pull` verification apply the
tier. A maintainer signs a tag for a pull (here as `alice`):

<!-- as alice -->
```sh
git vouch setup --registry "$REGISTRY"
git clone -q "$LINUX" linux
cd linux
git tag -s -m "for-6.99 from alice" alice-6.99
git push -q origin alice-6.99
```

and it verifies against your export (here as `lena`):

<!-- as lena -->
```sh
git clone -q "$LINUX" linux
cd linux
git verify-tag alice-6.99
```

A signer below maintainer gets "No principal matched". From the flag
day, a GPG-signed tag or pull is not accepted.

### Release tooling and the first SSH release tag

Release tooling verifies against anchors only. It names its own files,
so it also works on a machine that never ran `git vouch setup` (export
reads the synced copy here; pass a registry checkout as `DIR` elsewhere).
Sign the first SSH release tag and check it the way the tooling will
(here as `lena`):

<!-- as lena -->
```sh
git vouch export --min-tier anchor --allowed-signers ~/release-signers \
    --revocation-file ~/release-revoked
cd linux
git tag -s -m "Linux 6.99" v6.99
git -c gpg.ssh.allowedSignersFile="$HOME/release-signers" \
    -c gpg.ssh.revocationFile="$HOME/release-revoked" verify-tag v6.99
git -c gpg.ssh.allowedSignersFile="$HOME/release-signers" \
    -c gpg.ssh.revocationFile="$HOME/release-revoked" verify-tag alice-6.99    # fails: not an anchor
git push -q origin v6.99
```

Re-run that `export` after every `git vouch sync`, so the release files
see new revocations.

## Day to day

Every change you make to the registry goes the same way: a branch from
the registry's `main`, one `git vouch` command that writes and signs the
record, a commit, a push, and a merge by the registry maintainer. No
`git vouch` command pushes.

### Keep your copy current

<!-- as lena -->
```sh
git vouch sync
git vouch status
```

`sync` fetches the registry, refuses a rewritten history, runs `check`
and re-exports your allowed-signers and revocation files with the tier
you chose at `setup`. It writes the revocation file even when `check`
fails on something else, so a revocation always reaches you. Every
command warns when your copy was last fetched more than 7 days ago;
withholding a revocation is the one attack left to whoever hosts the
registry, so sync often. `status` shows the registry commit, its age,
and your own tier.

### Rotate your key

To replace a key you still hold, add the new key and retire the old one
in one branch, both signed by the old key, and switch git to the new
key (here as `lena`):

<!-- as lena -->
```sh
cd registry
git fetch -q origin
git switch -q -c rotate-lena origin/main
git vouch add-key ~/.ssh/id_new.pub
git vouch retire-key ~/.ssh/id_ed25519.pub
git config --global user.signingKey ~/.ssh/id_new.pub
git add people
git commit -q -m "lena: rotate to a new key"
git push -q origin HEAD:rotate-lena
```

<!-- merge rotate-lena -->

Sign both changes with a key from the version already in the registry:
a version signed only by a key it adds gets the unsigned-change WARNING.
Retiring keeps everything the old key signed valid, so the release tag
it made still verifies once you have synced (here as `lena`):

<!-- as lena -->
```sh
git vouch sync
git vouch export --min-tier anchor --allowed-signers ~/release-signers \
    --revocation-file ~/release-revoked
cd linux
git -c gpg.ssh.allowedSignersFile="$HOME/release-signers" \
    -c gpg.ssh.revocationFile="$HOME/release-revoked" verify-tag v6.99
```

If you sign patches, the selector changes with the key: once the
rotation is merged and synced, run the two lines in
[Sign with your registry key](#sign-with-your-registry-key) again.
Patches signed with the retired key stop verifying when the people who
check them sync.

### Approve and demote maintainers

Approving is the step under Approve the first maintainers. Demoting
replaces the tier record with a lower one (here as `lena`):

<!-- as lena -->
```sh
cd registry
git fetch -q origin
git switch -q -c demote-alice origin/main
git vouch approve alice contributor
git add tiers
git commit -q -m "lena: alice steps down to contributor"
git push -q origin HEAD:demote-alice
```

<!-- merge demote-alice -->

Her maintainer tier ends at the new record's `date`; the export adds an
hour to every end, to get around an OpenSSH 9.6 time-zone bug (see
DESIGN.md). A tag she signs more than an hour after it (here dated two
hours on, as `alice`):

<!-- as alice -->
```sh
cd linux
GIT_COMMITTER_DATE="$(($(date +%s) + 7200)) +0000" \
    git tag -s -m "for-7.0 from alice" alice-7.0
git push -q origin alice-7.0
```

fails against the maintainer export, while signatures she made before
the demotion still verify (here as `lena`):

<!-- as lena -->
```sh
git vouch sync
cd linux
git fetch -q --tags origin
git verify-tag alice-6.99
git verify-tag alice-7.0    # fails: below maintainer
```

To remove someone's tier entirely, without suspecting their key, the
registry maintainer deletes their file under `tiers/` in a reviewed
merge; their keys then get `valid-before` set to that commit's date, plus
the hour. The deletion is unsigned, so like `anchors.json` it rests on
review alone.

### Revoke a compromised key

Any anchor may revoke any key, as may the key itself or another current
key of its owner. Revoke whenever there is any doubt about who holds a
key. A revocation invalidates every signature the key ever made, past
and future, and voids every endorsement and tier record it signed.

Here `alice` reports that her laptop was stolen, and gives you her
key's did:key or its `ssh` line from `people/alice.json` over a channel
you trust; `$STOLEN` holds it (here as `lena`):

<!-- as lena -->
```sh
cd registry
git fetch -q origin
git switch -q -c revoke-alice origin/main
git vouch revoke "$STOLEN" --subject alice --reason compromise
git add revocations
git commit -q -m "lena: revoke alice's stolen key"
git push -q origin HEAD:revoke-alice
```

<!-- merge revoke-alice -->

A revocation never fails `check`, so it can always be merged. Once you
sync, even her old tag fails:

<!-- as lena -->
```sh
git vouch sync
cd linux
git verify-tag alice-6.99    # fails: the key is revoked
```

Once committed, a revocation holds even if its file is later deleted.

### Read check warnings in registry merges

`git vouch check` exits 0 on warnings, so every merge needs a human to
read them as well as the exit code. Each has one line, starting
`git-vouch: warning:`.

| Warning | Meaning | What to do |
|---|---|---|
| `people/<h>.json: <email> is not endorsed, so not exported` | Nobody has endorsed that address yet | Expected for every new person until an endorsement merges |
| `people/<h>.json: WARNING: changed at <commit> without a signature` | No key from the previous version signed this one: a lost key, or a swapped-in key | Confirm with the person, over a channel you already trust, that the new key is theirs before merging |
| `people/<h>.json: <did> is revoked but not retired` | A revoked key is still listed as current | The owner should retire it |
| `people/<h>.json: migratedFrom openpgp4fpr:<fpr> is also claimed by <h2>` | Two person files claim the same GPG key | Neither gets GPG endorsement drafts; an anchor decides which claim is genuine and the other comes out. Suspect a stolen GPG key |
| `<record>: void: ...` | A valid record with no effect, for example one signed by a key since revoked | Re-sign what still should hold (see Lost key) |
| `the registry copy was last fetched <n> days ago` | Your copy is stale | `git vouch sync` |

Some changes get neither an error nor a warning: an `anchors.json`
edit that passes `check`, and deleting a tier record (that person's keys
get `valid-before`), an endorsement, or a revocation (no effect: a
revocation holds once committed). Read `git diff --name-status` in the
merge for those. Deleting a person file that other records still name
fails `check`.

`alice` has no other key, so she recovers with a change no previous key
signed: she adds a new key to her person file signed only by the new
key, then retires the stolen one with it (here as `alice`):

<!-- as alice -->
```sh
cd registry
git fetch -q origin
git switch -q -c recover-alice origin/main
git vouch register --from people/alice.json ~/.ssh/id_new.pub
git vouch retire-key ~/.ssh/id_ed25519.pub --sign-with ~/.ssh/id_new.pub
git config --global user.signingKey ~/.ssh/id_new.pub
git add people
git commit -q -m "alice: recover from a stolen key"
git push -q origin HEAD:recover-alice
```

<!-- merge recover-alice -->

The merge's `check` prints the warning, which is the registry
maintainer's cue to confirm her new key with her before the push block:

```text
git-vouch: warning: people/alice.json: WARNING: changed at <commit> without a signature by any unrevoked key current in the previous version; only registry review let it through (old keys: did:key:z6Mk...; new keys: did:key:z6Mk...)
```

The version she first registered warns the same way from the moment
her key is revoked, because a revoked key's signatures count for
nothing; only the new warning needs a decision.

A merger who let a swapped key through would hand its holder alice's
tier and endorsements, so this check is the only thing standing between
a lost-key recovery and an account takeover. Her tier carries over.
Your endorsement of her named the key now revoked; it still carries over
to her new key, as on rotation, so her email stays exported. Confirming
her new key as `vouching.md` describes and endorsing it again is
encouraged, not enforced (here as `lena`):

<!-- as lena -->
```sh
cd registry
git fetch -q origin
git switch -q -c endorse-alice origin/main
git vouch endorse alice --note "Confirmed her new key by video call after her laptop was stolen."
git add endorsements
git commit -q -m "lena: endorse alice's new key"
git push -q origin HEAD:endorse-alice
```

<!-- merge endorse-alice -->

### Endorse

Any registered human may endorse anyone; anchors are no different.
`git vouch endorse <handle> --note "..."` endorses the person's name,
first current key and every listed email (`--email` limits it), as in
the steps above. What to check first and what to write in the note is
in [vouching.md](vouching.md).

### Lost key

**With your backup key,** revoke the lost key, retire it and add a
replacement, all signed by the backup (here as `lena`, who lost the key
she rotated to):

<!-- as lena -->
```sh
cd registry
git fetch -q origin
git switch -q -c lost-lena origin/main
git vouch revoke ~/.ssh/id_new.pub --reason lost --sign-with ~/.ssh/backup.pub
git vouch retire-key ~/.ssh/id_new.pub --sign-with ~/.ssh/backup.pub
git vouch add-key ~/.ssh/id_next.pub --sign-with ~/.ssh/backup.pub
git config --global user.signingKey ~/.ssh/id_next.pub
git vouch check .
```

Revoke rather than retire unless you are sure nobody else can use the
key: the signing time comes from the signer, so whoever holds a retired
key can backdate signatures. Revoking an anchor's key costs the most,
though. `check` now reports every record the lost key signed as void,
here alice's demotion and the endorsement you made after her recovery:

```text
git-vouch: warning: tiers/alice.json: void: did:key:z6Mk... of lena is revoked
git-vouch: warning: endorsements/alice/lena-2.json: void: did:key:z6Mk... of lena is revoked
```

Those people have no tier and lose that evidence until you sign again.
Re-approve and re-endorse each one in the same branch, then push it
(here as `lena`):

<!-- as lena -->
```sh
cd registry
git vouch approve alice contributor
git vouch endorse alice --note "Confirmed her new key by video call after her laptop was stolen."
git add people revocations tiers endorsements
git commit -q -m "lena: replace a lost key; re-sign what it signed"
git push -q origin HEAD:lost-lena
```

<!-- merge lost-lena -->

Every tag the revoked key signed also stops verifying, which for an
anchor can include release tags: one more reason to keep signing keys on
hardware tokens with a PIN, and the backup in a drawer. So do patches:
once someone checking them has synced, patatt no longer finds the key.
With the b4 fork set up as in
[Check incoming patches](#check-incoming-patches), b4 checks a signature
again every time. Upstream b4 newer than 0.16 remembers a verdict for
up to 24 hours, so a series it already checked can keep its tick until
then.

**Without a backup key,** the only way back is a change no previous key
signed, as `alice` made above. It rests on the registry maintainer's
review, and `check` warns about it. Another anchor revokes the lost key
with their own.

## Patch signing

Patches are signed with patatt, the signer built into b4: an
`X-Developer-Signature` header that `b4 am` checks. A fork of patatt
adds one keyring source, `vouch:`, which asks `git vouch keys` for the
signer's current keys. A patch verifies when one of the signer's current
keys signed it and it comes from an endorsed email, whatever the
signer's tier, automation identities included.

### Install the forks

Install b4 and patatt from their forks' `git-vouch` branches in one
command, so b4 gets the patatt fork in place of released patatt:

<!-- patch not-run needs-network -->
```shell
pip install 'b4 @ git+https://github.com/MarkAtwood/b4@git-vouch' \
    'patatt @ git+https://github.com/MarkAtwood/patatt@git-vouch'
```

The b4 fork can check every patch afresh, which makes a revocation take
effect at once. If you run b4 from a checkout with `b4.sh`, clone the b4
fork's `git-vouch` branch and put the patatt fork in its `patatt`
submodule. The submodule points at kernel.org, which has no `git-vouch`
branch, so fetch that branch from github.com/MarkAtwood/patatt and check
it out there.

`misc/vouch-check.sh` in the b4 fork tests the pair offline in a
throwaway home: it signs a series with a registry key and checks that
`b4 am` passes it, then fails it once the key is revoked. Unless
git-vouch and the patatt fork are checked out next to b4 and b4 has a
`.venv`, set `GIT_VOUCH` to the git-vouch script, `PATATT_FORK` to a pip
requirement for the patatt fork and `PYTHON` to a Python with b4's
dependencies. It also needs `uv`, with setuptools in its cache. It sets up its own
config: set yours as this page does, not as the script's header shows.

### Sign with your registry key

patatt signs with the key git signs with, under the selector
`git vouch status` prints, which is derived from the key. It signs as
your `user.email`, so that must be an endorsed email. `b4 send`, or
`git send-email` after `patatt install-hook`, then signs every patch
(here as `lena`):

<!-- patch as lena -->
```shell
git config --global patatt.signingkey "openssh:$(git config --global user.signingKey)"
git config --global patatt.selector "$(git vouch status | sed -n 's/^patatt.selector: //p')"
```

[The regulars guide](guide-regulars.md#send) shows both ways of
sending.

### Check incoming patches

Tell patatt and b4 where to find keys: the registry first, then the
frozen pgpkeys keyring, checked out at the freeze commit (here as
`lena`):

<!-- patch as lena -->
```shell
git clone -q "$PGPKEYS" ~/pgpkeys
git -C ~/pgpkeys checkout -q --detach "$FREEZE_COMMIT"
git config --global --unset-all b4.keyringsrc || true
git config --global patatt.keyringsrc vouch:
git config --global --add patatt.keyringsrc ~/pgpkeys/.keyring
git config --global b4.attestation-recheck-hours 0
```

patatt reads the keyring as files on disk, so leave that clone at the
freeze commit: a key added after it would verify too. The checkout
fails if the clone does not hold the freeze commit.

`b4.attestation-recheck-hours = 0` is a setting of the b4 fork: b4
checks every signature again instead of remembering a verdict for up to
24 hours, so a revoked key stops verifying at your next `git vouch
sync`. Any other b4 ignores it, and upstream b4 newer than 0.16 keeps a
pass for up to 24 hours. The fork names the keyring after every registry
pass: if `b4 am` prints `✓ Signed: openssh/...` with no
`(key: vouch:...)` after it, the b4 you run is not the fork. Check
`command -v b4`.

b4 ignores `patatt.keyringsrc` while `b4.keyringsrc` is set, as b4's
documentation suggests, so the block removes `b4.keyringsrc`. Then
check a series by its message-id, here `$MSGID`, a patch from bob in your
mailbox; without `-m`, b4 fetches it from lore (here as `lena`):

<!-- patch as lena -->
```shell
git vouch sync
cd linux
b4 am -m ~/mail.mbox "$MSGID"
```

[The captains guide](guide-captains.md#check-incoming-patches) lists
what `b4 am` prints and what to tell a contributor whose patch does not
verify.

### Kernel-wide settings

Nothing in the kernel tree can set the keyring for people: b4 ignores
`keyringsrc` in a tree's `.b4-config`. Each developer sets the lines
of [Check incoming patches](#check-incoming-patches) in their own git
config, so publish them with the flag-day announcement, together with
the install line and the date they stop needing the legacy keyring
line.

### Dropping the GPG fallback

The fallback ends at the late cutoff, six months after the flag day
(the anchors may extend it by announcement). No code changes: everyone
deletes the legacy keyring line (here as `lena`):

<!-- patch as lena -->
```shell
git config --global --unset patatt.keyringsrc pgpkeys
```

From then, GPG-signed patches show `✗ No key`, and patches signed with a
key `patatt genkey` made show `? (TOFU: new key)` instead of verified.
Those contributors register an SSH key and sign with it.

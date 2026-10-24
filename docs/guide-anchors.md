# Guide for anchors

This guide takes an anchor through the flag day, day-to-day registry
work and patch signing. An anchor is one of the few people
`anchors.json` in the registry lists: Linus and whoever the kernel team
designates. Anchors are the root of the tree. You approve maintainers,
you can revoke anyone's key, and your own key signs releases. Only
`anchors.json` grants the anchor tier, and a tier record for an anchor
fails `check`.

Read [What vouching for a real person means](vouching.md) before you
endorse or approve anyone. It says what an endorsement binds, what
evidence to ask for, and how to read the endorsements you approve on.

## What the commands assume

> **What this does:** lists the variables and checkouts, and the keys you sign with and where to keep them.\
> **Why:** the tool cannot prove what holds a key, so hardware tokens are advice for you, not a rule it enforces ([rationale](rationale.md#hardware-keys)).

- `$REGISTRY` is the registry's URL and `$LINUX` is a kernel tree you
  push tags to. The kernel.org administrators choose the kernel's
  registry path on git.kernel.org. `$PGPKEYS` is the frozen
  `pgpkeys.git` and `$FREEZE_COMMIT` its last commit, the freeze commit;
  kernel.org publishes both at the freeze (see
  [the flag-day runbook](flag-day.md)).
- `git-vouch` is on `PATH`, so `git vouch` works.
- Your SSH keys are loaded in an agent. `~/.ssh/id_ed25519` is your
  signing key and `~/.ssh/backup` a backup key that stays in a drawer.
  Keep both on hardware tokens: kernel.org issues FIDO keys and backup
  tokens (korg.docs.kernel.org/fido2.html). `git-vouch` accepts any
  supported key, so this is advice, not a rule.
- `registry` is your checkout of the registry and `linux` your kernel
  tree, both in your home directory.

The cast: `lena` is the anchor (you), `alice` is a maintainer, and
`korg` is the registry maintainer who merges branches into the registry.
Put your own handle, name and email in their place.

## Flag day

> **What this does:** gives the anchors' steps in the flag-day timeline.\
> **Why:** one switch date with no dual period, so after it nothing new needs `gpg` ([rationale](rationale.md#one-flag-day)).

[The flag-day runbook](flag-day.md) has the full timeline for everyone.

Patch signing has a fallback that tags do not. Before the flag day,
everyone who signs or checks patches installs the patatt fork and lists
`keyringsrc = vouch:` first and the frozen pgpkeys keyring second, as
[Patch signing](#patch-signing) shows. Patches signed with a GPG key, or
with a key `patatt genkey` made, then keep verifying through pgpkeys,
with a warning, for everyone until the late cutoff, six months after the
flag day.

### Register and merge first

> **What this does:** puts the anchors' person files and `anchors.json` in the registry before anyone else can be approved.\
> **Why:** the registry names its own anchors, so the first merge sets the root of trust and only review guards it ([rationale](rationale.md#registry-in-git)).

Register with your main key, add your backup key, and push a branch:

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

Register the backup key now, while your main key can sign for it. A
person file change needs a signature from a key in the previous version,
so with a backup listed, losing your main key is a signed change and
not one that rests on review (see Lost key and
[rationale](rationale.md#backup-key)).

**If you hold a key in `pgpkeys.git`,** register from your
`git-vouch-migrate` draft and add a GPG continuity proof instead, as in
the runbook's [first merge](flag-day.md#the-first-merge-the-anchors).
The proof only unlocks endorsement drafts from your old GPG
certifications. It grants no tier: yours comes from `anchors.json`.

The registry maintainer merges the anchors' branches, then commits
`anchors.json` on top:

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

The person files go in first because `check` fails if `anchors.json`
names a handle with no person file.

Only review protects `anchors.json`: whoever can merge into the registry
can add an anchor, and that anchor can approve anyone. Adding or
removing an anchor later is the same edit, in a reviewed merge. An edit
that passes `check` prints no warning about itself. Two cases do warn or
fail. Promoting someone who has a tier record fails `check` unless the
same merge deletes their `tiers/<handle>.json`. A tier record granted on
a branch concurrent with removing its approver from `anchors.json` is
void, with a warning, until someone re-approves it.

The kernel team decides who the registry maintainers are, and that list
matters as much as the anchor list. Registry maintainers also enforce
the late cutoff, which no tool checks: after it they merge no change
that adds or alters `migratedFrom` or adds a `people/*.json.asc`.

### Approve the first maintainers

> **What this does:** registers maintainers, merges their branches, and approves them on your own judgement.\
> **Why:** an endorsement is evidence about identity, and the approver reads it and decides; no count of endorsements grants a tier ([rationale](rationale.md#endorse-vs-approve)).

Maintainers register like everyone else:

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

The registry maintainer merges every branch the same way, here
`register-alice`:

<!-- as korg -->
```sh
branch=register-alice
cd registry
git fetch -q origin "$branch"
git diff --name-status HEAD...FETCH_HEAD
git merge -q --no-ff --no-edit FETCH_HEAD
git vouch check .
```

Registry maintainers always merge with `--no-ff`, never a fast-forward,
not even of a contributor's merge of main, so the dates on the main
line are the maintainer's clock and not the contributor's
([rationale](rationale.md#no-ff-merges)).

Stop here. Push only once `check` exits 0, the list of changed paths is
right, and you have read every `git-vouch: warning:` line (see Read
check warnings in registry merges). For an unsigned-change WARNING,
first confirm the new key with its owner over a channel you already
trust. If anything is wrong, `git reset -q --hard origin/main` drops the
merge. Then the registry maintainer pushes:

<!-- as korg -->
```sh
cd registry
git push -q origin main
```

Approve maintainers on your own judgement, using MAINTAINERS and their
endorsements. GPG supplies no tiers: Linus certified 2 keys in pgpkeys,
so the web of trust says nothing about who is a maintainer. No minimum
number of endorsements applies; you read them and decide. If you know
the person yourself, endorse them too, following
[vouching.md](vouching.md). Then approve:

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

The registry maintainer merges and pushes it as above, with
`branch=approve-alice`. Before you approve someone others endorsed, read
each `endorsements/<handle>/*.json`: who endorsed them, which emails,
and what the note says was checked. `vouching.md` has a checklist.

`check` judges your approval once, at the commit that adds it. If you
later step down, the tiers you granted stay. Only a revoked key voids
the tier records it signed (see Lost key).

### Switch Linus's git to the maintainer export

> **What this does:** points Linus's `gpg.ssh.allowedSignersFile` at the export of maintainers and above, so plain `git verify-tag` applies the tier.\
> **Why:** requiring a tier needs no wrapper: `git verify-tag` against the `--min-tier maintainer` export rejects anyone below it ([rationale](rationale.md#tiers)).

Do this on the flag day. `setup` records the registry, sets
`gpg.format=ssh` and both git files, and runs a first `sync`:

<!-- as lena -->
```sh
git vouch setup --registry "$REGISTRY" --min-tier maintainer
git config --global gpg.ssh.allowedSignersFile
git vouch status
```

A maintainer signs a tag for a pull:

<!-- as alice -->
```sh
git vouch setup --registry "$REGISTRY"
git clone -q "$LINUX" linux
cd linux
git tag -s -m "for-6.99 from alice" alice-6.99
git push -q origin alice-6.99
```

and it verifies against your export:

<!-- as lena -->
```sh
git clone -q "$LINUX" linux
cd linux
git verify-tag alice-6.99
```

A tag from a key below maintainer tier and a tag from a key the registry
does not hold fail the same way. `git verify-tag` exits 1 and prints:

    Good "git" signature with ED25519 key SHA256:<fingerprint>
    No principal matched.

"Good" means only that the signature matches the key; "No principal
matched" means the key is not in your export. `git pull` of that tag does
not fail. It merges, exits 0, and puts the same two lines in the merge
message only as `#` comments; `git log --show-signature` repeats them
under `merged tag '<tag>'`. `git pull --verify-signatures` checks commit
signatures, not the tag, so it rejects even a maintainer's good tag on
unsigned commits. Run `git verify-tag` on the tag before you merge it.

Reply to the sender with what they must do; `git vouch status` shows
them their own tier:

- **Not registered:** register, collect endorsements, and get approved
  as maintainer. Then re-sign the tag: git checks the tag's signing time
  against the key's registration time, so a tag signed before the
  registration merge keeps failing.
- **Below maintainer:** an anchor approves them as maintainer. The
  existing tag then verifies.
- **Approved, but your copy predates it:** nothing; you run
  `git vouch sync`.

Run `git vouch sync` before you verify again. From the flag day, a
GPG-signed tag or pull is not accepted.

### Release tooling and the first SSH release tag

> **What this does:** signs the first SSH release tag and checks it against anchors only, as the release tooling will.\
> **Why:** release tags move to SSH; release files and kup stay with kernel.org on GPG, because a tarball is `git archive` of a signed tag ([rationale](rationale.md#ssh-not-gpg)).

Release tooling verifies against anchors only. It names its own files,
so it also works on a machine that never ran `git vouch setup`. Here
`export` reads the synced copy; elsewhere, pass a registry checkout as
`DIR`.

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

> **What this does:** gives the one path every registry change takes.\
> **Why:** changes arrive as reviewed merges, and review is the only gate for three accepted risks ([rationale](rationale.md#nothing-pushes)).

Make each change on a branch from the registry's `main`: one
`git vouch` command writes and signs the record, you commit and push,
and the registry maintainer merges. No `git vouch` command pushes.

### Keep your copy current

> **What this does:** fetches the registry, checks it, and re-exports your allowed-signers and revocation files.\
> **Why:** withholding updates, such as a revocation, is the one attack left to whoever hosts the registry ([rationale](rationale.md#sync-refuses-rewinds)).

<!-- as lena -->
```sh
git vouch sync
git vouch status
```

`sync` fetches the registry, refuses a rewritten history, runs `check`
and re-exports your allowed-signers and revocation files with the tier
you chose at `setup`. It writes the revocation file even when `check`
fails on something else, so a revocation always reaches you. Every
command warns when your copy was last fetched more than 7 days ago, so
sync often. `status` shows the registry commit, its age, and your own
tier.

### Rotate your key

> **What this does:** replaces a key you still hold: add the new key and retire the old one in one branch, both signed by the old key.\
> **Why:** retiring keeps every earlier signature valid, so your past tags still verify ([rationale](rationale.md#revoke-vs-retire)).

Switch git to the new key in the same step:

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
Once you have synced, the release tag the old key made still verifies:

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

> **What this does:** demotes a maintainer by replacing their tier record with a lower one.\
> **Why:** only someone above the tier being taken away may sign the lower record, so only an anchor can demote a maintainer ([rationale](rationale.md#tiers)).

Approving is the step under Approve the first maintainers. A
maintainer's record lowering a peer is void.

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

Her maintainer tier ends at the new record's `date`. The export adds an
hour to every end, to get around an OpenSSH 9.6 time-zone bug
([rationale](rationale.md#extra-hour)). A tag she signs more than an
hour after it, here dated two hours on:

<!-- as alice -->
```sh
cd linux
GIT_COMMITTER_DATE="$(($(date +%s) + 7200)) +0000" \
    git tag -s -m "for-7.0 from alice" alice-7.0
git push -q origin alice-7.0
```

fails against the maintainer export, while signatures she made before
the demotion still verify:

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
merge. Their keys then get `valid-before` set to that commit's date,
plus the hour. The deletion is unsigned, so like `anchors.json` it rests
on review alone.

### Revoke a compromised key

> **What this does:** invalidates every signature a key ever made, past and future, and voids every endorsement and tier record it signed.\
> **Why:** the signer sets the signing time, so whoever holds a merely retired key can backdate; revoke whenever there is any doubt about who holds a key ([rationale](rationale.md#revoke-vs-retire)).

Any anchor may revoke any key, as may the key itself or another current
key of its owner.

Here `alice` reports that her laptop was stolen and gives you, over a
channel you trust, her key's did:key or its `ssh` line from
`people/alice.json`; `$STOLEN` holds it:

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

`alice` has no other key, so she recovers with a change no previous key
signed. She adds a new key to her person file, signed only by the new
key, then retires the stolen one with it:

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

The merge's `check` prints the warning, the registry maintainer's cue
to confirm her new key with her before the push block:

```text
git-vouch: warning: people/alice.json: WARNING: changed at <commit> without a signature by any unrevoked key current in the previous version; only registry review let it through (old keys: did:key:z6Mk...; new keys: did:key:z6Mk...)
```

The version she first registered warns the same way from the moment her
key is revoked, because a revoked key's signatures count for nothing;
only the new warning needs a decision.

This check is the only thing standing between a lost-key recovery and
an account takeover: a merger who let a swapped key through would hand
its holder alice's tier and endorsements. Her tier carries over. Your
endorsement of her named the key now revoked; it still carries over to
her new key, as on rotation, so her email stays exported. Confirming her
new key as `vouching.md` describes and endorsing it again is encouraged,
not enforced:

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

### Read check warnings in registry merges

> **What this does:** lists each `check` warning, what it means, and what to do before merging.\
> **Why:** `check` exits 0 on warnings, and review is the only gate for the changes they flag ([rationale](rationale.md#nothing-pushes)).

Every merge needs a human to read the warnings as well as the exit
code. Each warning is one line, starting `git-vouch: warning:`.

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

### Endorse

> **What this does:** signs your statement that a person's name, key and emails belong together.\
> **Why:** an email becomes an exported principal only once a valid endorsement covers it ([rationale](rationale.md#endorsed-emails)).

Any registered human may endorse anyone; anchors are no different.
`git vouch endorse <handle> --note "..."` endorses the person's name,
first current key and every listed email (`--email` limits it), as in
the steps above. [vouching.md](vouching.md) says what to check first
and what to write in the note. Before signing, `endorse` prints the
key's SHA256 fingerprint: compare it with the one you checked in person.
Run `endorse` on the merged registry, not on a pull-request checkout.

### Lost key

> **What this does:** replaces a lost key, signed by your backup key, and re-signs what the lost key signed.\
> **Why:** with a backup listed, recovery is a signed change; without one, it is a change only review lets through ([rationale](rationale.md#backup-key)).

**With your backup key,** revoke the lost key, retire it and add a
replacement, all signed by the backup. Here `lena` has lost the key she
rotated to:

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
key can backdate signatures. Revoking an anchor's key costs the most.
`check` now reports every record the lost key signed as void, here
alice's demotion and the endorsement you made after her recovery:

```text
git-vouch: warning: tiers/alice.json: void: did:key:z6Mk... of lena is revoked
git-vouch: warning: endorsements/alice/lena-2.json: void: did:key:z6Mk... of lena is revoked
```

Those people have no tier and lose that evidence until you sign again.
Re-approve and re-endorse each one in the same branch, then push it:

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
anchor can include release tags. Keep signing keys on hardware tokens
with a PIN, and the backup in a drawer. Patches stop verifying too: once
someone checking them has synced, patatt no longer finds the key. With
the b4 fork set up as in
[Check incoming patches](#check-incoming-patches), b4 checks a signature
again every time. Upstream b4 newer than 0.16 remembers a verdict for
up to 24 hours, so a series it already checked can keep its tick until
then.

**Without a backup key,** the only way back is a change no previous key
signed, as `alice` made above. It rests on the registry maintainer's
review, and `check` warns about it. Another anchor revokes the lost key
with their own.

## Patch signing

> **What this does:** signs and checks patches with patatt against the registry, with the frozen pgpkeys keyring as a fallback until the late cutoff.\
> **Why:** the registry is the keyring, so nothing is generated, published or trusted in between ([rationale](rationale.md#patch-fallback)).

Patches are signed with patatt, the signer built into b4: an
`X-Developer-Signature` header that `b4 am` checks. A fork of patatt
adds one keyring source, `vouch:`, which asks `git vouch keys` for the
signer's current keys. A patch verifies when one of the signer's current
keys signed it and it comes from an endorsed email, whatever the
signer's tier, automation identities included.

### Install the forks

> **What this does:** installs b4 and patatt from their forks' `git-vouch` branches in one command, so b4 gets the patatt fork in place of released patatt.\
> **Why:** the b4 fork can check every patch afresh, so a revocation takes effect at once ([rationale](rationale.md#patch-fallback)).

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

> **What this does:** makes patatt sign with the key git signs with, under the selector `git vouch status` prints.\
> **Why:** patatt signs as your `user.email`, and only endorsed emails are exported as identities ([rationale](rationale.md#endorsed-emails)).

The selector is derived from the key. Your `user.email` must be an
endorsed email. `b4 send`, or `git send-email` after
`patatt install-hook`, then signs every patch:

<!-- patch as lena -->
```shell
git config --global patatt.signingkey "openssh:$(git config --global user.signingKey)"
git config --global patatt.selector "$(git vouch status | sed -n 's/^patatt.selector: //p')"
```

[The regulars guide](guide-regulars.md#send) shows both ways of
sending.

### Check incoming patches

> **What this does:** tells patatt and b4 to find keys in the registry first, then in the frozen pgpkeys keyring at the freeze commit.\
> **Why:** patatt reads the keyring as files on disk, so a key added after the freeze would verify too ([rationale](rationale.md#freeze-commit)).

<!-- patch as lena -->
```shell
git clone -q "$PGPKEYS" ~/pgpkeys
git -C ~/pgpkeys checkout -q --detach "$FREEZE_COMMIT"
git config --global --unset-all b4.keyringsrc || true
git config --global patatt.keyringsrc vouch:
git config --global --add patatt.keyringsrc ~/pgpkeys/.keyring
git config --global b4.attestation-recheck-hours 0
```

Leave that clone at the freeze commit: patatt reads the keyring as files
on disk, so a key added after the freeze would verify too. The checkout
fails if the clone does not hold the freeze commit.

`b4.attestation-recheck-hours = 0` is a setting of the b4 fork: b4
checks every signature again instead of remembering a verdict for up to
24 hours, so a revoked key stops verifying at your next `git vouch
sync`. Any other b4 ignores it, and upstream b4 newer than 0.16 keeps a
pass for up to 24 hours. The fork names the keyring after every registry
pass: if `b4 am` prints `✓ Signed: openssh/...` with no
`(key: vouch:...)` after it, the b4 you run is not the fork. Check
`command -v b4`.

The block removes `b4.keyringsrc` because b4 ignores `patatt.keyringsrc`
while `b4.keyringsrc` is set, as b4's documentation suggests. Then check
a series by its message-id, here `$MSGID`, a patch from bob in your
mailbox; without `-m`, b4 fetches it from lore:

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

> **What this does:** says what to publish with the flag-day announcement, since no file in the kernel tree can set the keyring for people.\
> **Why:** the fallback keyring line is temporary, so everyone needs the date it stops ([rationale](rationale.md#patch-fallback)).

b4 ignores `keyringsrc` in a tree's `.b4-config`. Each developer sets
the lines of [Check incoming patches](#check-incoming-patches) in their
own git config. Publish them with the flag-day announcement, together
with the install line and the date they stop needing the legacy keyring
line.

### Dropping the GPG fallback

> **What this does:** ends the GPG fallback at the late cutoff, six months after the flag day; the anchors may extend it by announcement.\
> **Why:** the cutoff ends the window in which someone holding a stolen, unrevoked GPG key can claim that person's identity ([rationale](rationale.md#late-cutoff)).

No code changes: everyone deletes the legacy keyring line:

<!-- patch as lena -->
```shell
git config --global --unset patatt.keyringsrc pgpkeys
```

From then, GPG-signed patches show `✗ No key`, and patches signed with a
key `patatt genkey` made show `? (TOFU: new key)` instead of verified.
Those contributors register an SSH key and sign with it.

## About this page

**Status:** user guide, 2026-10-22. Facts come from `DESIGN.md`.

`tests/test_guide_anchors.py` runs every command block on this page, in
order, in a throwaway registry, with real `git` and `ssh-keygen`.
`tests/patatt/test_patch_docs.py` runs the `shell` blocks under
[Patch signing](#patch-signing) with the b4 and patatt forks, sending
mail to a local sink. A hidden marker above each block names who runs
it.

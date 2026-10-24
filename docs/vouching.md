# Vouching for a real person

Endorse someone only when you know first-hand that their key and emails
belong to them. This page says what an endorsement binds, what evidence
to hold, and how approvers read it.

**Status:** shared reference for the user guides, 2026-10-22. Facts come
from `DESIGN.md`. Sections marked **Proposal for kernel review** are
recommendations, not rules: the evidence standard is the kernel
community's call, and `git-vouch` enforces none of it.

## What an endorsement says

> **What this does:** binds a person's name, one of their keys and the emails you list to your first-hand knowledge.\
> **Why:** an endorsement is evidence about identity, not a grant of authority ([rationale](rationale.md#endorse-vs-approve)).

An endorsement says: **this key and these email addresses belong to this
real, named person, and I know that first-hand.** It does not say the
person writes good code, deserves a tier, or should be trusted with
anything.

The signed record binds exactly three things about the subject:

- `subjectName`, their name
- `subjectKey`, the did:key of one of their keys
- `subjectEmails`, the addresses you vouch for

Only they sign anything else in their person file, such as other DIDs
in `alsoKnownAs` or a homepage. You are not vouching for it.

What follows from the binding:

- **A later rename is not endorsed.** If they change `name`, your
  endorsement no longer covers it.
- **Only the emails you list are endorsed.** An email nobody has endorsed
  stays in their file but is not exported, so git never shows it as a
  verified signer, and `check` warns about it. An endorsed email is also
  what makes their patches verify in b4.
- **Your endorsement follows their key rotations.** It carries over to
  every key added in later versions of their person file. Along a chain
  of signed versions that is sound. It also carries over an unsigned
  change that registry review lets through, whether lost-key recovery or
  a swapped-in key. If a merger lets a swapped key through, its holder
  inherits your endorsement; the only traces are `check`'s WARNING on
  that version and git history.
- **Your key's fate matters.** Retiring the key you endorsed with leaves
  the endorsement valid. Revoking it voids every endorsement it made, and
  the people you endorsed lose that evidence. If that key may be lost or
  stolen, revoke it, not retire it: the signer sets the signing time, so
  whoever holds a retired key can backdate endorsements. Then re-endorse
  with a new key.
- **Their key's fate matters less.** If the key you endorsed lands in
  the revocation file, your endorsement is not void: it carries over to
  their later keys, as on rotation. After a compromise, confirming that the new key is theirs and
  endorsing it is encouraged but not enforced.
- **It is public.** The registry, including who endorsed whom and your
  note, is public by design, with no privacy features.

`git-vouch` checks that a registered human validly signed the
endorsement. It never reads or judges your note.

## Who may endorse

> **What this does:** sets who can sign an endorsement.\
> **Why:** only an approver can grant authority, so widening who may endorse costs nothing ([rationale](rationale.md#endorse-vs-approve)).

Any registered human, with or without a tier. Automation identities
cannot endorse.

## Evidence standard (proposal for kernel review)

> **What this does:** proposes the evidence to hold before you endorse: strong, acceptable, or not enough.\
> **Why:** `check` verifies signatures and authority, never judgement, so the evidence behind an endorsement is yours to check ([rationale](rationale.md#endorse-vs-approve)).

> **Proposal for kernel review.** Everything in this section, including
> how to confirm the key and emails, is a draft standard for discussion.
> `git-vouch` checks none of it. It is what endorsers would hold
> themselves to and what approvers could expect to read in notes.

**Strong, enough on its own:**

- **Met in person, checked government photo ID**, and confirmed the key
  and emails with them (see below). LPC and the Maintainers Summit are
  the usual places.

**Acceptable:**

- **Video call with photo ID shown**, with the key and emails confirmed
  during or right after the call over a channel you already trust.
- **Long, verifiable collaboration under the real name**: years of
  reviewed patches, list threads and in-person or video contact that
  together leave you in no doubt who they are. Say in the note what the
  collaboration was and how long.

**Not enough, do not endorse:**

- **You know them only online, by handle or email**, however long or
  however good their patches are. That is the identity an attacker can
  build. Their patches give an approver a reason to grant a tier once
  someone else has vouched for the person; they give you no reason to
  vouch.
- **Someone asked you to on another person's behalf**, or you are relying
  on what a third party told you.
- **You cannot tell them apart from a sock puppet**: no face, no voice,
  no history outside the account.
- **A bulk request.** Endorse people one at a time, each on your own
  evidence.

### Confirming the key and emails

> **What this does:** checks with the person that the key and each email you endorse are theirs.\
> **Why:** the endorsement binds key and emails as well as the name, and an address you did not vouch for is not endorsed ([rationale](rationale.md#endorsed-emails)).

Confirm the key and emails with the person directly: an ID proves a
name, not a key.

**The key.** Ask them to read or send you their did:key over a channel
you trust (in person, on the video call), and compare it with the one in
their person file. They print it with:

```
git vouch did "$(cat ~/.ssh/id_ed25519_sk.pub)"
```

Print the did:key of each key in their person file the same way, from
the `ssh` value in `people/<handle>.json`. A did:key does not record
whether a key is a FIDO (`sk-`) key, so compare the `ssh` line too if
that matters to you.

**The emails.** Send a short random string to each address you are
about to endorse and have them read it back to you over the channel you
trust. Endorse only the addresses that pass, and leave any you could not
confirm out of `subjectEmails`.

## What to write in the note

> **What this does:** tells the approver how you know the person, when, and what you checked.\
> **Why:** the approver reads the endorsements and decides; `git-vouch` never interprets the note ([rationale](rationale.md#endorse-vs-approve)).

The `note` is optional free text. A good one says how you know the
person, when, and what you checked:

```
Met at LPC 2026, checked passport; reviewed her patches since 2019.
```

> **Proposal for kernel review.** Write a note on every endorsement.
> Include where and when you met or spoke, what kind of ID you saw (not
> its number), how you confirmed the key and each email, and how long you
> have worked with them. Because the registry is public, never put an ID
> number, date of birth, home address or anything else you would not
> publish about yourself.

## How approvers use endorsements

> **What this does:** an approver reads the endorsements, then grants a tier with a signed tier record.\
> **Why:** the tier is a separate record signed by the approver, so nobody can promote themselves ([rationale](rationale.md#tiers)).

The approver grants a tier by signing a tier record
(`git vouch approve <handle> <tier>`). Endorsements never grant one, and
neither does the person's own file.

| Tier | Granted by |
|---|---|
| `anchor` | Listed in `anchors.json` |
| `maintainer` | An anchor |
| `contributor` | A maintainer or an anchor |
| `automation` | A maintainer or an anchor |

- **The approver must sit above the tier they grant** at the commit that
  adds the tier record. `check` enforces that.
- **Endorsements are evidence, not a count.** There is no minimum number.
  The approver reads the endorsements and decides. `check` verifies that
  someone with the authority to make each endorsement and tier record
  validly signed it; it does not second-guess the approver.
- **Approval without endorsements still works.** Every exported key gets
  its handle as a principal, so a person approved with no endorsements
  still verifies, just without any email principal.
- **Hardware is advice, not a rule.** Maintainers and anchors should
  keep their keys on a hardware token, but every tier accepts any
  supported key type. The tool cannot prove what holds a key, so
  endorsers and approvers ask about it
  ([rationale](rationale.md#hardware-keys)).
- **Automation identities** sign files only, never tags or commits. Their
  person file must name the accountable maintainer in `accountable`.
- **The GPG web of trust does not supply tiers.** Anchors approve
  maintainers on their own judgement, using MAINTAINERS and endorsements.

> **Proposal for kernel review.** When approving, look for:
>
> - At least one endorsement at the strong level, or several acceptable
>   ones, from endorsers you can judge.
> - Endorsers who are independent of each other: different employers,
>   different subsystems, and ideally another community (see below). Ten
>   endorsements from one team are weaker than two from unrelated people.
> - Notes that say what was checked. Treat an empty or vague note as weak
>   evidence.
> - For a maintainer: a MAINTAINERS entry under the name being endorsed.
> - That the endorsed name and emails are the ones you will see on their
>   signatures and pulls.
> - That `git vouch check` prints no unsigned-key-change WARNING on their
>   person file after the version holding an endorsement's `subjectKey`.
>   Where it does, the endorser never saw the current key; give that
>   endorsement no weight unless the endorser confirms the new key.
>
> Hold anchors and maintainers to the strongest evidence, since their
> tier lets them approve others.

## Endorsements across communities

> **What this does:** lets someone from another community vouch for a kernel developer they know.\
> **Why:** an attacker would then have to infiltrate two social graphs, not one ([rationale](rationale.md#endorse-vs-approve)).

Someone from another community (Apache, another LF project) endorses a
kernel developer in three steps:

1. They register a person file in the kernel registry, with no tier.
2. They list their other identities in `alsoKnownAs`.
3. They endorse as usual.

There is no federation and no lookup in the other registry. If they use
the same key in both registries, it has the same did:key in both, so
anyone can compare the two with `git vouch did` and nothing else.
`git-vouch` never resolves an `alsoKnownAs` DID or checks that it links
back; those DIDs are the endorser's own claim. A DID that also lists the
person's did:key in its own `alsoKnownAs` is a stronger claim, but
checking that is left to tools that resolve DIDs.

## Flag-day endorsement drafts

> **What this does:** turns your old GPG certifications into unsigned endorsement drafts for you to review and sign.\
> **Why:** GPG certifications are not ported as records; the draft is a reminder, and your new SSH signature is what counts ([rationale](rationale.md#continuity-proof)).

Run `git-vouch-migrate drafts --as <handle>` on your own machine. You get
one unsigned draft per subject who has proved continuity with the old
GPG key you certified. The draft takes `subjectName` from the person
file, fills `subjectEmails` from the UIDs you certified, and puts the
certified fingerprint, UID and date in `note`. Nobody generates drafts
centrally, and unsigned drafts never enter the registry. Read each one
and sign only those you still stand behind.

> **Proposal for kernel review.** A draft records only that you once
> certified a GPG key. That certification never covered the SSH key in
> `subjectKey`, and `subjectName` comes from the subject's own person
> file. Before signing, confirm both as in "Confirming the key and
> emails". Sign it only if you would endorse
> that person today on the evidence above. If the certification came from
> a keysigning party long ago and you have had no contact since, do not
> sign it. If you have newer evidence, add it to the note before signing.
> Drop any email from `subjectEmails` that you would not vouch for now.

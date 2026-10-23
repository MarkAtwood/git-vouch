#!/usr/bin/env bash
# Flag-day rehearsal: the runbook docs/flag-day.md prints, run end to end.
#
# tests/migrate/test_rehearsal.py runs this after building the world as it
# stands on the freeze: pgpkeys.git frozen at a signed commit C, an empty
# registry, a kernel tree, and a home per person. Published with C:
#   $C        the frozen commit
#   $SIGNER   the primary fingerprint of the key that signed C
#   $PGPKEYS, $REGISTRY, $LINUX   the repository URLs
#
# Cast: korg runs kernel.org and merges into the registry; lena is the
# anchor; alice, bob and dave hold pgpkeys keys (bob's expired before C,
# dave reuses his GPG authentication subkey); carol has no GPG key. lena
# certified alice (SHA-1), bob and dave in pgpkeys.
#
# The helpers marked "harness" stand in for each person's own machine
# and are not runbook steps. Every other line is one.
set -euo pipefail

home() { # harness: become person $1, on their own machine
    export HOME="$WORLD/$1" GNUPGHOME="$WORLD/$1/gnupg"
    cd "$HOME"
}

agent() { # harness: an ssh-agent holding the person's SSH key
    eval "$(ssh-agent -s)" >/dev/null
    trap 'ssh-agent -k >/dev/null' EXIT
    ssh-add -q ~/.ssh/id_ed25519
}

merge() { # The registry maintainer merges a submitted branch once check passes.
    (
        home korg
        cd registry
        git fetch -q origin "$1"
        git diff --name-status HEAD...FETCH_HEAD
        git merge -q --no-edit FETCH_HEAD
        git vouch check .
        git push -q origin main
    )
}

# 1. Freeze. pgpkeys.git is read-only at C; C, $SIGNER, the flag-day date
#    and the late cutoff are published together.

# 2. Window. The first merge holds the anchors' person files and anchors.json.
(
    home korg
    git clone -q "$REGISTRY" registry
)
(
    home lena
    agent
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
)
(
    home korg
    cd registry
    git fetch -q origin register-lena
    git merge -q --ff-only FETCH_HEAD
    echo '["lena"]' >anchors.json
    git add anchors.json
    git commit -q -m "anchors: lena"
    git vouch check .
    git push -q origin main
)

# Everyone else registers. A pgpkeys holder completes their draft and adds a
# continuity proof: a detached GPG signature over the person file...
(
    home alice
    agent
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
)
merge register-alice

# ...made after extending an expired key locally (never publish the new
# expiry: the proof is judged against the key as it was at C)...
(
    home bob
    agent
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
)
merge register-bob

# ...or the GPG authentication subkey, which port already put in the draft,
# signing the person file through gpg-agent.
(
    home dave
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
)
merge register-dave

# Someone with no GPG key registers fresh.
(
    home carol
    agent
    git clone -q "$REGISTRY" registry
    cd registry
    git vouch register --handle carol --name "Carol Fresh" --email carol@example.com \
        ~/.ssh/id_ed25519.pub
    git add people
    git commit -q -m "people: register carol"
    git push -q origin HEAD:register-carol
)
merge register-carol

# Anyone can check the continuity proofs against C.
(
    home korg
    git clone -q "$PGPKEYS" pgpkeys
    cd registry
    git-vouch-migrate verify-continuity ~/pgpkeys . --commit "$C" --signer "$SIGNER"
)

# Each certifier drafts endorsements from their own GPG certifications, on
# their own machine, reads each one, and signs it only if it is right: the
# subject's name comes from the subject's own person file. An anchor approves
# maintainers.
(
    home lena
    agent
    cd registry
    git fetch -q origin
    git switch -q -c endorse-lena origin/main
    git-vouch-migrate drafts ~/pgpkeys . --commit "$C" --signer "$SIGNER" --as lena \
        --out ~/endorsement-drafts
    for f in ~/endorsement-drafts/endorsements/*/*.json; do
        cat "$f"
        git vouch endorse --from "$f"
    done
    git vouch approve alice maintainer
    git add endorsements tiers
    git commit -q -m "lena: endorsements from GPG certifications; approve alice"
    git push -q origin HEAD:endorse-lena
)
merge endorse-lena

# Fresh endorsements, and a maintainer approves contributors.
(
    home alice
    agent
    cd registry
    git fetch -q origin
    git switch -q -c approve-alice origin/main
    git vouch endorse carol --note "Reviewed her patches since 2019; met at LPC."
    git vouch approve bob contributor
    git vouch approve carol contributor
    git add endorsements tiers
    git commit -q -m "alice: endorse carol; approve bob and carol"
    git push -q origin HEAD:approve-alice
)
merge approve-alice

# 3. Flag day. Linus switches to the export at --min-tier maintainer.
(
    home lena
    git vouch setup --registry "$REGISTRY" --min-tier maintainer
    git vouch check
    git clone -q "$LINUX" linux
)

# Developers sign tags with SSH keys.
for who in alice bob; do
    (
        home "$who"
        agent
        git vouch setup --registry "$REGISTRY"
        git clone -q "$LINUX" linux
        cd linux
        git tag -s -m "for-6.99 from $who" "$who-6.99"
        git push -q origin "$who-6.99"
    )
done

# Plain git verify-tag accepts a maintainer's tag and rejects a contributor's.
(
    home lena
    agent
    cd linux
    git fetch -q --tags
    git verify-tag alice-6.99
    if git verify-tag bob-6.99; then
        exit 1
    fi
    # Release tooling verifies against anchors only.
    git vouch export --min-tier anchor --allowed-signers ~/release-signers \
        --revocation-file ~/release-revoked
    git tag -s -m "Linux 6.99" v6.99
    git -c gpg.ssh.allowedSignersFile="$HOME/release-signers" \
        -c gpg.ssh.revocationFile="$HOME/release-revoked" verify-tag v6.99
    if git -c gpg.ssh.allowedSignersFile="$HOME/release-signers" \
        -c gpg.ssh.revocationFile="$HOME/release-revoked" verify-tag alice-6.99; then
        exit 1
    fi
    # At contributor tier bob's tag verifies: his tier, not his key, kept him out.
    git vouch export --min-tier contributor --allowed-signers ~/contrib-signers \
        --revocation-file ~/contrib-revoked
    git -c gpg.ssh.allowedSignersFile="$HOME/contrib-signers" \
        -c gpg.ssh.revocationFile="$HOME/contrib-revoked" verify-tag bob-6.99
)

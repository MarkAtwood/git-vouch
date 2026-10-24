# Running the TRQP bridge

**Status:** deployment note for `git-vouch-trqp`, 2026-10-23 (bead
vouch-faq3.8). Behaviour comes from `git-vouch-trqp`, `git-vouch` and
DESIGN.md, TRQP bridge. The unit files were checked with
`systemd-analyze verify`; the verify-trust results are from
`tests/trqp/test_verify_trust.py` against verify-trust 0.24.0.

## Verdict

**The bridge is optional, and kernel.org runs the one instance that
counts.** `git vouch`, patatt and b4 read the registry directly, so no
kernel developer needs it. It exists for verifiers outside the kernel's
tools, such as OpenVTC's `verify-trust`, which asks a TRQP registry
whether a DID may sign. The canonical instance is LF devops' (the
kernel.org admins), and verifiers find it through the registry's DID
document, not through this page.

## Who runs it

- **The canonical instance:** LF devops, beside the registry repository.
  DESIGN.md proposes the DID `did:web:registry.kernel.org`, so its
  document sits at `https://registry.kernel.org/.well-known/did.json`;
  kernel.org decides the name. The `TRQPRest` endpoint in that document
  is the instance's URL.
- **Your own, against a mirror:** anyone may run one. The bridge holds no
  state, no credentials and no database, and the registry is public, so
  a bridge on a fresh mirror gives the same answers as the canonical one.
  Verifiers reach it through its own DID document or verify-trust's
  `--registry-url`.
- **On localhost, next to verify-trust:** `verify-trust` resolves
  `did:web` only from public hosts, so a local bridge is reached with
  `--registry-url` instead of a DID document (see Checking with
  verify-trust).

The whole operating burden is one Python process behind a TLS reverse
proxy, an hourly `git vouch sync`, and no secrets. The one duty is
staying in sync: the bridge refuses every query once its copy is 24 hours
old.

## Install

The host needs Python 3.9 or later, git and OpenSSH (`ssh-keygen` checks
the registry's signatures). Put `git-vouch` and `git-vouch-trqp` in
`/usr/local/bin`; git finds `git vouch` on `PATH`.

Run everything as one system user, here `git-vouch`, with a home
directory. Its `~/.gitconfig` holds `vouch.registry`, and its
`~/.local/share/git-vouch/registry` is the copy both the sync and the
bridge read. The bridge finds that copy the way `git vouch query` does:
`$XDG_DATA_HOME`, else `~/.local/share`, then `git-vouch/registry`. So
the sync and the bridge must share `User=` and `HOME` (or
`XDG_DATA_HOME`).

```sh
useradd --system --create-home git-vouch
sudo -u git-vouch -H git vouch setup
```

`setup` with no `--registry` uses the kernel's registry,
`https://git.kernel.org/pub/scm/linux/kernel/git/vouch/registry.git`.
For a mirror, pass `--registry URL`. `setup` also sets that user's
`gpg.format` and allowed-signers paths and runs the first sync.

## systemd units

```ini
# /etc/systemd/system/git-vouch-sync.service
[Unit]
Description=Sync the git-vouch registry copy
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=git-vouch
ExecStart=/usr/bin/git vouch sync
```

```ini
# /etc/systemd/system/git-vouch-sync.timer
[Unit]
Description=Sync the git-vouch registry copy hourly

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/git-vouch-trqp.service
[Unit]
Description=git-vouch TRQP bridge
Wants=network-online.target
After=network-online.target

[Service]
User=git-vouch
ExecStart=/usr/local/bin/git-vouch-trqp serve --did did:web:registry.kernel.org --bind 127.0.0.1 --port 8080
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
systemctl enable --now git-vouch-sync.timer git-vouch-trqp.service
```

The timer has no `Persistent=`: systemd.timer(5) says it acts only on
`OnCalendar=` timers, and `OnBootSec=` already syncs after a boot.
`--bind` defaults to 127.0.0.1 and `--port` to 8080; only the proxy
should reach the bridge. On start the bridge prints `git-vouch-trqp:
serving DID at http://127.0.0.1:8080/trust-tasks`. A port it cannot
take prints `git-vouch-trqp: cannot listen on HOST:PORT: reason` and
exits 1, and `Restart=on-failure` retries it.

## DID document

```sh
git-vouch-trqp did-document --did did:web:registry.kernel.org \
    --endpoint https://registry.kernel.org
```

It prints the document on stdout and where to serve it on stderr
(`serve it at https://registry.kernel.org/.well-known/did.json`):

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:registry.kernel.org",
  "service": [
    { "id": "did:web:registry.kernel.org#rest", "type": "TRQPRest",
      "serviceEndpoint": "https://registry.kernel.org" }
  ]
}
```

Serve that file as static JSON at that exact URL, on a public host, with
no redirect: verify-trust's resolver fetches only from public hosts and
follows no redirect (`docs/trqp-interop.md`, section 2). The endpoint is
a base URL; verify-trust appends `/trust-tasks`. `did-document` refuses
any endpoint that is not `https://`, or that has a query, fragment,
userinfo or backslash. The document carries one `TRQPRest` entry and
nothing else, because verify-trust prefers TSP and DIDComm over HTTPS
with no fallback. For `did:webvh`, sign the document into the log with
an existing webvh tool; `git-vouch-trqp` adds no cryptography.

## Reverse proxy

The bridge speaks plain HTTP. The proxy in front of it must:

- **Terminate TLS** for the host the DID document names. The answers are
  unsigned, so HTTPS on that endpoint is their only protection.
- **Pass `POST /trust-tasks`** to `http://127.0.0.1:8080/trust-tasks`
  directly, never by redirect. verify-trust follows redirects
  (`docs/trqp-interop.md`, section 1), so a redirect would move the
  answer off the endpoint the DID document vouches for.
- **Buffer each whole request and bound how long it may take.** The
  bridge limits each socket read to 30 s, not a whole request, and starts
  a thread per connection, so a client that trickles bytes holds a
  thread.

The bridge refuses a body over 64 KiB with a 400 `malformedRequest`,
answers other paths 404 and other methods on `/trust-tasks` 405, and
sends `Cache-Control: no-store` on every answer. Do not cache it.

## Freshness

`git vouch sync` touches `vouch-fetched` in the copy's git directory
after each successful fetch. The bridge reads that stamp before every
answer and refuses with 503 `unavailable` when the stamp is missing,
over 24 hours old, or dated more than 5 minutes in the future. An hourly
sync leaves 23 failed attempts before the refusal. `git vouch` itself
only warns after 7 days and keeps working.

Every answer carries the copy's state in
`ext["org.kernel.git-vouch"]` as `{"commit": ..., "synced": ...}`.
`synced` is an RFC 3339 time, not an age. `commit` is read just before
the query, so a sync between the two can leave it one commit behind.

Failures, and where they show:

| Failure | What happens |
|---|---|
| The fetch fails | `git vouch sync` exits 1 with the reason on stderr (`systemctl status git-vouch-sync`, `journalctl -u git-vouch-sync`). The stamp keeps its old time; the bridge answers until it is 24 hours old. |
| The registry host rewrote history | `sync` refuses (`cannot fetch the registry; a rewritten history is refused`), since its refspec has no `+`. Same as a failed fetch. |
| The fetch works but `git vouch check` fails | `sync` exits 1 and writes only the revocation file. The stamp is fresh, but every query fails the check, so the bridge answers 503 and logs `git-vouch-trqp: git vouch query exited 1: ...`. |
| No sync for 24 hours | 503 `unavailable`, message `the registry copy was last synced TIME, over 24h ago`. |
| The bridge is down | The proxy's own error. verify-trust reports `registryUnavailable` (measured, `test_bridge_down_fails_closed`). |

**What verify-trust reports for a stale bridge.** Today the 503 carries a
retryable `trust-task-error` document. trql-client reads any
trust-task-error as a rejection, so verify-trust reports the commit
`unauthorized`, not `registryUnavailable` (measured,
`test_stale_bridge_fails_closed`). Either way the check fails closed.
Bead vouch-faq3.16 changes the freshness refusal to a bare HTTP 503
(`Retry-After`, a short text body, no Trust Task document), which
trql-client treats as a transport error, so verify-trust will report
`registryUnavailable`. OpenVTC/verifiable-git-infrastructure#170 asks
OpenVTC to treat a retryable trust-task-error that way instead.

## Registry merges

Registry maintainers merge with `git merge --no-ff`, never a
fast-forward (DESIGN.md, Merging needs one person). Every commit on the
first-parent line then carries a maintainer's committer date, and the
bridge's answers for a past time (`context.time`, run as `git vouch
query --at`) read effective dates from that line. A fast-forward of a
contributor's branch would put the contributor's own dates there. The
bridge itself never merges and never writes to its copy.

## Answer cache

Answers for now come from one `git vouch query --all` run, shared by
every DID and every concurrent request. The bridge reruns it when the
copy's commit changes and after 60 seconds.

- **Staleness:** an answer can be up to 60 s old. A key retirement or a
  tier end that passes with no new commit shows up within that minute.
- **Latency:** the first request after a sync, or after a minute, waits
  for a whole registry check (about 12 s for 600 people, DESIGN.md,
  Caching); the rest answer in milliseconds.
- **Always checked fresh:** a request with `context.time` (one DID's
  `query --at` each time) and a served copy with local changes. Do not
  edit the copy; `sync` checks it out with `--force` anyway.
- **Limits:** each git run gets 30 s, and at most 4 run at once. A check
  that times out, or a request that finds all 4 slots taken, gets a
  retryable 503 at once, never a queue. Each such 503 writes one line to
  the bridge's stderr, so to the journal: `git-vouch-trqp: git vouch
  query exited N: ...` or `git-vouch-trqp: git vouch timed out after
  30s`. The reply to the client stays generic.

## Checking with verify-trust

verify-trust's `--registry-did` is the query's recipient and
`--vtc-did` is its `authority_id`. Both must be the bridge's `--did`: a
different recipient gets `wrongRecipient`, a different authority gets
`authorized: false`. Against the canonical instance:

```sh
verify-trust --range origin/master..HEAD \
    --registry-did did:web:registry.kernel.org \
    --vtc-did did:web:registry.kernel.org \
    --resource git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux
```

Against a local bridge, add `--registry-url http://127.0.0.1:8080`, and
pass the local bridge's `--did` as both DIDs. verify-trust accepts only
plain `ssh-ed25519` signatures today
(https://github.com/OpenVTC/verifiable-git-infrastructure/issues/169), so
a FIDO, P-256 or RSA signer the bridge authorizes still fails as
`malformed`.

**The end-to-end test** (`tests/trqp/test_verify_trust.py`) is opt-in:
it skips unless `VERIFY_TRUST` names a verify-trust binary or one is on
`PATH`. Build verify-trust 0.24.0 at the commit the tests pin (needs Rust
1.95.0 or later):

```sh
git clone https://github.com/OpenVTC/verifiable-git-infrastructure
cd verifiable-git-infrastructure
git checkout 5d9b9b6
cargo build --locked --release -p verify-trust
```

Then run the tests with `VERIFY_TRUST` set to
`target/release/verify-trust` in that tree:

```sh
VERIFY_TRUST=/path/to/verifiable-git-infrastructure/target/release/verify-trust \
    python -m pytest tests/trqp
```

No release gates on it and no script builds it.

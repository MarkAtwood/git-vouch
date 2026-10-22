# patatt and b4 interop (spike vouch-mzkw.1)

The `vouch:` keyring source fits patatt with one new branch in
`get_public_key` and a helper of about 30 lines, plus about 5 lines in
`validate_message` for the fallback warning. b4 needs no change: it
passes its keyring source strings straight through to patatt. Nothing
blocks the work. The main caveats are that b4 caches verdicts for up to
24 hours, which delays revocation, and that a warning raised inside
patatt is invisible on b4 cache hits.

Sources read (all citations are to these trees):

- **P** = `~/GIT/patatt/src/patatt/__init__.py` at `a8a3d23`. The fork
  `~/PROJECT/patatt` (branch `git-vouch`) is at the same commit with an
  identical file, so the line numbers apply to the fork too.
- **B** = `~/GIT/b4/src/b4/__init__.py` at `ce4c115`, plus other b4
  files named in full.
- **O** = `~/GIT/openssh-portable` at `26b1363`. The installed tool is
  `OpenSSH_9.6p1`.

## 1. Selector semantics

**Signing.** The selector comes from git config `patatt.selector`, or
`patatt.<section>.selector` with `-s/--section` (P:1546-1548,
P:1521-1523). It is written as `s=` only when set (P:837-838). The key
comes from `patatt.signingkey`, prefixed `openssh:<path>` (P:1503-1505),
or falls back to `user.signingkey` with `gpg.format=ssh` (P:1452-1463).
`patatt genkey` suggests `selector = <keyname>` (P:1822-1823). The
`X-Developer-Key` header carries `fpr=` set to the `SHA256:...`
fingerprint from `ssh-keygen -l` (P:500-510, P:859-860). It is
informational only and never used for lookup.

**Verifying.** The selector is read from `s=` in `X-Developer-Signature`
(P:1627). If `s=` is missing it defaults to `default` (P:1629-1630).
Identity is `i=`, falling back to the `From:` address (P:994-997).

**Allowed characters and length.** patatt does no validation, and there
is no length limit anywhere. The parser imposes these constraints:

- Every whitespace character is removed from the header value before it
  is split (P:148).
- Fields are split on `;` (P:149), and each field is split on its first
  `=` (P:150). A selector therefore cannot contain whitespace or `;`. It
  can contain `=`, `+` and `/`.

For filesystem and `ref:` keyrings, the selector is lowercased and then
`quote_plus`-encoded into the path `openssh/<domain>/<local>/<selector>`
(P:1195-1207). Two selectors that differ only in case therefore name the
same file.

`get_public_key` receives the selector as written in the header, not
lowercased (P:1654). A `vouch:` source should compare case-insensitively
to match file-keyring behaviour.

> **Recommendation:** derive `k-` + lowercase **hex** of the key
> fingerprint, not the base64 `SHA256:` form. Base64 is case-sensitive,
> and P:1200 folds case. A hex prefix survives every path patatt and b4
> take.

**A signer with several keys.** Each config section has one
`signingkey` and one `selector` (P:1469, P:1521). Each `sign` call
writes one `X-Developer-Signature` (P:849-852). A person with a main
token and a backup token picks a selector per machine or section. The
verifier needs a key filed under each selector.

When a message carries two signatures with the same `i=`,
`validate_message` loops over both (P:1623). However,
`PatattMessage.validate` always checks the *first* signature whose `i=`
matches (P:890-893). The second signature is therefore checked against
the wrong key and reports BADSIG. This is a pre-existing upstream quirk,
outside this work's scope; avoid signing twice with one identity.

A key file holding several keys does not help either. Only the first
two whitespace tokens (`<type> <base64>`) of the returned key data are
used (P:525-531), so a source must return exactly one key per selector.

## 2. Keyring lookup

**Standard path vs by-hash.** The standard path is
`<source>/openssh/<domain>/<local>/<selector>` (P:1181-1207). The
by-hash path is `<source>/by-hash/XX/<62 hex>`, the SHA-256 of the
standard path string (P:1210-1229).

`get_public_key` (P:1232-1358) tries the standard path first and falls
back to by-hash:

| Source type | Lookup order |
|---|---|
| `ref:repo:ref:subpath` | git object at the standard path (P:1294-1311), with one level of symlink (P:1298-1309); on-disk standard path (P:1313-1318); git object at by-hash (P:1320-1328); on-disk by-hash (P:1330-1335) |
| plain directory, `~` and `$VAR` expanded | standard path (P:1341-1348), then by-hash (P:1350-1356) |

The source type is chosen by prefix: `startswith('ref:')` (P:1258), and
anything else is treated as a disk path (P:1339).

**Source order.**

- **patatt CLI:** `keyringsrc` values in git config order. They are
  collected as a multivalue (P:1090, P:1123-1132, P:1547). Then
  `ref:::.keys`, `ref:::.local-keys` and `ref::refs/meta/keyring:` are
  appended (P:1553-1557), and `cmd_validate` appends
  `$XDG_DATA_HOME/patatt/public` (P:1706-1715).
- **b4:** uses `b4.keyringsrc`, else `patatt.keyringsrc`, else the same
  three `ref:` defaults. It appends `<b4 datadir>/keyring` (B:4115-4141).
  b4 never calls patatt's `get_main_config` for verification, so
  patatt's own defaults are not added on top.

**Iteration** (P:1651-1662). The first source that returns a key wins
(`break` at P:1655). A source only falls through to the next one by
raising `KeyError` (P:1656-1657). There is no retry on the next source
after a BADSIG. A wrong key in an earlier source therefore *shadows* a
correct key later in the list.

If no source has an ed25519 or openssh key, the result is RES_NOKEY
(P:1659-1662). For openpgp, a missing key falls through to the default
GnuPG keyring (P:1664-1668, P:632-634).

**Where `vouch:` hooks in.** Insert a branch in `get_public_key`
between P:1255 and P:1257, before the `ref:` branch and the disk-path
fallthrough, which would otherwise treat `vouch:` as a relative
directory. The callers are:

- patatt's `validate_message` (P:1654), the only patatt caller;
- b4's TOFU keyring scan, `tofu.keyring_keys`, at
  `~/GIT/b4/src/b4/tofu.py:341`. It catches
  `(KeyError, patatt.Error, OSError)` (tofu.py:344), only asks for
  ed25519, and enumerates selectors by listing directories
  (tofu.py:265-316). For `vouch:` it finds no directory and contributes
  nothing, which is harmless.

**Contract.** Return `tuple[bytes, str]`: the key data as
`<type> <base64>` and a description of where it came from, which
becomes `keysrc` in the result (P:1234, P:1248). On a miss, raise
`KeyError` (P:1251, P:1656). Map every other failure to `KeyError` as
well: `git vouch` missing, a non-zero exit, an unknown email, or a
non-openssh `keytype`. Any other exception escapes `validate_message`,
which catches only `KeyError` around lookup. `cmd_validate` catches only
`RuntimeError` (P:1752), and b4 calls `validate_message` with no
`try` at all (B:2323), so a stray exception crashes `b4 am`. It also
skips the GPG fallback source.

Cache the `git vouch keys` output per email for the life of the
process. b4 validates every message in a series, possibly twice because
of the trimmed-body retry (B:2324-2332). patatt's `KEYCACHE` pattern
(P:57-61) is the in-style precedent.

## 3. Is `t=` checked?

**patatt:** no. For openssh and ed25519, `t=` must only be present
(P:383-386, P:392-395). It is returned as the signing time and compared
to nothing. It is also not covered by the ssh signature's own timestamp:
`ssh-keygen -Y verify` is run without `-Overify-time` (P:543-554). The
signer sets it to `time.time()` (P:844-846).

**b4:** compares it to the message `Date:` only when
`attestation-staleness-days` is non-zero (default `30`, B:326). The
check is one-sided: it fails only if `t` is *later* than `Date` by more
than that many days (B:3990-4002; TOFU path B:2716-2730). A failed check
turns a pass into a non-pass (B:2624-2630). Nothing compares `t` to key
validity, so the registry's key dates cannot be enforced through patatt.

## 4. sk-ssh-ed25519, sk-ecdsa and ecdsa-p256

All of them work, because patatt never looks at the key type. It writes
the first two tokens of the key data into a temporary allowed-signers
file as `patatter@local namespaces="patatt" <type> <base64>`
(P:519-534), then runs
`ssh-keygen -Y verify -n patatt -I patatter@local -f signers -s sig`
(P:543-560). Signing runs `ssh-keygen -Y sign -n patatt -f <keyfile>`
(P:483-489). `a=` is always `openssh-sha256` (P:843) and the keyring
type directory is always `openssh` (P:1643-1645), whatever the
algorithm.

**Tested locally** (OpenSSH 9.6p1, patatt reference tree imported
read-only): an ed25519 key and an ecdsa-p256 key, each signed through
`patatt.sign_message(..., 'openssh', ...)` and verified through a
directory keyring. Results:

| Case | Result code |
|---|---|
| untouched message | 0 (RES_VALID) |
| tampered body | 32 (RES_BADSIG) |
| no key under that selector | 8 (RES_NOKEY) |

**sk- keys** were not tested; that needs hardware. From source:

- Signing prompts for PIN and touch according to the key's flags
  (O:ssh-keygen.c:2611-2626).
- Verifying only logs `sk_flags` at debug2 (O:ssh-keygen.c:2849-2852).
  It checks revocation (2856-2861) and the allowed-signers file
  (2863-2867), and has no touch or verify-required check.
- `sshsig.c` has no user-presence check either (grep of O:sshsig.c for
  touch, presence and verify-required returns nothing).

So sk- signatures verify, but patatt does **not** enforce
user-presence or user-verification. If the registry's tier rules depend
on UP or UV, patatt verification cannot carry that.

## 5. How results surface, and how b4 uses patatt

**Codes** (P:47-52): `RES_VALID=0`, `RES_NOSIG=4`, `RES_NOKEY=8`,
`RES_ERROR=16`, `RES_BADSIG=32`. `validate_message` returns one tuple
per signature: `(code, identity, signtime, keysrc, algo, errors)`
(P:33-35, P:1597-1681).

| Code | Cause |
|---|---|
| NOSIG | message is unsigned (P:1615-1620) |
| ERROR | missing `a=` or `i=`, or unknown algorithm (P:1631-1649) |
| NOKEY | no source had the key (P:1659-1662); or, for openpgp, gpg `NO_PUBKEY` (P:637-638, P:1670-1673) |
| BADSIG | any `ValidationError`, including body hash mismatch (P:335) and ssh-keygen failure (P:556-560); handled at P:1674-1679 |
| VALID | success; `keysrc` is the source string, or `(default keyring)/<fpr>` (P:1665-1669) |

**patatt CLI output:** `PASS | identity, file`, with `| key: <keysrc>`
when verbose; `NOKEY`, `ERROR` and `BADSIG` print with their errors.
The exit code is the highest code seen (P:1722-1756).

**How b4 gets patatt.** b4 imports the *installed* package
(`import patatt`, B:66), with dependency `patatt>=0.7,<2.0` in
`~/GIT/b4/pyproject.toml:34`, pinned to `patatt==0.8.0` in
`requirements.txt:223`. `patatt/` in the b4 tree is a git submodule
(`~/GIT/b4/.gitmodules`), not initialised in this clone. It is used only
by `b4.sh`, which puts `patatt/src` on `PYTHONPATH` to run from a
checkout (`~/GIT/b4/b4.sh:10`). The DESIGN.md plan, installing the fork
in place of patatt, works for pip/uv installs. For `b4.sh` users it
means pointing the submodule at the fork.

**Where b4 calls patatt:**

- Verify: `LoreMessage._validate_patatt` calls
  `patatt.validate_message(msgbytes, sources)`, and retries with
  `trim_body=True` only on BADSIG (B:2311-2350).
  `_load_patatt_attestors` sets `patatt.logger = logger` and
  `patatt.GPGBIN` (B:2352-2365).
- Results become `LoreAttestorPatatt`: VALID means passing and
  `have_key`; BADSIG or worse means `have_key` (B:4283-4304).
- Sign: `patatt.rfc2822_sign` (B:6529; `~/GIT/b4/src/b4/ez.py:281`),
  with key lookup via `patatt.get_algo_keydata`
  (`~/GIT/b4/src/b4/ez.py:183-192`).
- `b4 kr show-keys` uses `patatt.make_pkey_path`
  (`~/GIT/b4/src/b4/kr.py:264`) and skips openssh keys entirely
  (kr.py:236-243).

**What `b4 am` prints:**

| Outcome | Printed | Source |
|---|---|---|
| pass | `✓ Signed: openssh/<email>`, plus `(From: <addr>)` on identity mismatch | B:2785-2792, trailer format B:3975-3988 |
| fail with key | `✗ BADSIG: openssh/<email>` | B:2795-2796 |
| no key | `✗ No key: openssh/<email>` | B:2797-2798 |

- With the default `softfail` policy (B:324), "no key" is not fatal
  even under `hardfail` (B:2645-2654). BADSIG under `hardfail` exits
  128 (B:1323-1331).
- Marks are `✓`/`✗` in colour, or `v`/`x` with simple checkmarks
  (B:268-271).
- When all patches agree, the mark goes on the subject line and the
  trailers print once (B:1200-1213, B:1309-1321).
- TOFU applies only to ed25519 NOKEY (B:2389-2395), so it never
  triggers for openssh.

**b4 never shows patatt's `errors` list or `keysrc` to the user**
except in a debug `__repr__` (B:4043-4054). b4's console handler runs
at INFO by default (`~/GIT/b4/src/b4/command.py:1552-1563`), and since
b4 installs its logger into patatt (B:2360), a `logger.warning` from
patatt *is* printed.

**b4 result cache.** VALID and BADSIG results are stored in
`patatt-checked.sqlite3` for 20-24 hours (B:4106-4112, B:2367-2378,
B:4206-4227). The cache key covers the message bytes, the sources list
and `gpgbin`, plus the cwd when there are `ref::` sources (B:4162-4176).
It does not cover registry state. Two consequences:

- A key that leaves `git vouch keys` keeps showing `✓` for up to a day.
  b4 documents this window (`~/GIT/b4/docs/config.rst:554-557`).
- On a cache hit patatt is not called, so a warning logged in patatt
  appears only on the first check.

**How kernel.org publishes the keyring today.** b4 documents cloning
`pgpkeys.git` and setting `b4.keyringsrc = ~/path/to/pgpkeys/.keyring`
(`~/GIT/b4/docs/config.rst:542-552`). patatt documents the same
directory or `ref:` forms
(`~/GIT/patatt/docs/maintainer-guide.rst:196-207`). Neither tool fetches
anything itself: the user's `git pull` is the update mechanism.

## 6. Smallest upstream-style patch, and CI the fork must pass

**`vouch:` source.** Add one branch in `get_public_key` after P:1255:

```python
    if source.startswith('vouch:'):
        return _get_vouch_key(keytype, identity, selector)
```

Add a module-level helper of about 30 lines, beside `make_byhash_path`.
It must:

1. Raise `KeyError` unless `keytype == 'openssh'`, so ed25519 and
   openpgp fall through to later sources.
2. Run `['git', 'vouch', 'keys', identity]` via `_run_command` (P:1037),
   once per identity, cached in a module dict like `KEYCACHE`.
3. Treat a non-zero exit as `KeyError`, logging stderr at debug, as
   `_get_git_mailinfo` does at P:1010-1012.
4. Parse lines of the form `<selector> <type> <base64> [comment]`.
5. Return `(f'{type} {base64}'.encode(), f'vouch:{identity}/{selector}')`
   on a case-insensitive selector match, otherwise raise `KeyError`.

Update the `source` description in the docstring (P:1241-1242). The
total is about 35 lines in one function plus one call site.

**Fallback warning.** In `validate_message`, after the RES_VALID append
(P:1669), add about 5 lines:

```python
            if not keysrc.startswith('vouch:') and any(
                src.startswith('vouch:') for src in sources
            ):
                logger.warning('W: %s verified via %s, not the vouch registry', i, keysrc)
```

Gating on "a `vouch:` source is configured" means stock configurations
behave exactly as upstream. This is the only place that knows both the
configured sources and which source produced the key. The warning does
not go in `get_public_key`, because a non-vouch hit there does not yet
mean the signature verified.

Do not put the warning in `errors`: b4 drops `errors` for passing
attestors, as shown in section 5. A warning that survives b4's cache
would need a b4 change (for example, flagging a `keysrc` without the
`vouch:` prefix in `get_attestation_trailers`). That is out of scope
here.

**Tests and CI the fork must keep passing.**

- `ci.sh` runs, in order: `uv sync`, `ruff format --check`,
  `ruff check` (rule set in `~/GIT/patatt/pyproject.toml:56-77`, which
  includes the `G` logging-format rules: use `%s` arguments, not
  f-strings, in `logger.*`), `ty check`, `mypy`, `pyright`,
  `pytest` (`~/GIT/patatt/ci.sh:22-28`).
- `ci-matrix.sh` runs pytest on Python 3.9 through 3.15
  (`~/GIT/patatt/ci-matrix.sh:20`; `requires-python = ">=3.9"`,
  pyproject.toml:14). New code must be 3.9-safe: no `match`, and PEP 604
  unions only in annotations, which is fine under
  `from __future__ import annotations` (P:5).
- Existing tests that exercise this path:
  - `~/GIT/patatt/tests/unit/test_byhash.py:44-106`: `get_public_key`
    lookup order and the `KeyError` contract.
  - `~/GIT/patatt/tests/test_validation.py:9-43`: samples incl.
    `openssh-signed.txt` against `.keys`.
- A `vouch:` test with an independent oracle: stub `_run_command` to
  return the line
  `20211115 <contents of .keys/openssh/linuxfoundation.org/konstantin/20211115>`.
  Then assert that `samples/openssh-signed.txt` (signed upstream,
  `s=20211115`, `samples/openssh-signed.txt:5-6`) validates RES_VALID
  with `keysrc` starting `vouch:`. Also assert that a stub with no
  matching selector falls through to `.keys` and triggers the warning.
- Upstream submission goes to tools@kernel.org with a `Signed-off-by:`
  per the DCO (`~/GIT/patatt/README.rst:54-58`).

## Blockers

None for the fork. Constraints that DESIGN.md should acknowledge:

- patatt cannot enforce sk user-presence (section 4) or key validity
  times (section 3).
- b4 can show a pass for up to 24 hours after a key leaves the registry
  (section 5).
- In b4, the non-vouch warning appears only on uncached checks
  (section 5).

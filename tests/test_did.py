"""Tests for did:key encoding and 'git vouch did', against externally sourced vectors.

Vectors come from the W3C CCG did:key test vectors, w3c-ccg/did-method-key
commit 1b4f72d577faef66d4ecb0103ce25472ed353f3a, test-vectors/ (removed
from the repository in the next commit). SSH key lines for them are built
here from the vector's own key material (seed via openssl, or JWK) and
checked with ssh-keygen and openssl, never with git-vouch.
"""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from conftest import Key, make_key, run_script

# test-vectors/ed25519-x25519.json: did -> 32-byte seed.
CCG_ED25519_SEEDS = {
    "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp": "00" * 32,
    "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG": "00" * 31 + "01",
    "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf": "00" * 31 + "02",
    "did:key:z6MkvqoYXQfDDJRv8L4wKzxYeuKyVZBfi9Qo6Ro8MiLH3kDQ": "00" * 31 + "03",
    "did:key:z6MkwYMhwTvsq376YBAcJHy3vyRWzBgn5vKfVqqDCgm7XVKU": "00" * 31 + "05",
}
# The seed-05 vector also gives its public key as a JWK.
CCG_ED25519_SEED5_JWK_X = "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"

# test-vectors/nist-curves.json: did -> JWK (x, y). Both have odd y.
CCG_P256_JWKS = {
    "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv": (
        "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
        "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM",
    ),
    "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169": (
        "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
        "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU",
    ),
}

# An even-y P-256 key, which the CCG vectors lack. Key from ssh-keygen; the
# compressed point (prefix 02) from `openssl ec -conv_form compressed`; the
# base58btc from python-bitcoinlib's bitcoin.base58, which reproduces the
# first CCG P-256 vector above.
EVEN_Y_P256_SSH = (
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI3V1l4YPV84"
    "V3HAJmHEMYj1l+NuB0tJNkOtVFT6lj5w3ei/r8HcDRqbLGG2AJapIvmxJ48AqIXaVtZEQXvbAZI="
)
EVEN_Y_P256_DID = "did:key:zDnaeZydegH3tmrALkCJ3hEhmYEgjivy6TxyzzprUZSfbHf7V"

# Key types DESIGN.md does not accept, as CCG did:keys (rsa.json, nist-curves.json P-384,
# secp256k1.json) and a real DSA public key made by ssh-keygen (OpenSSH 9.8+ no
# longer generates DSA, so it is hardcoded).
CCG_UNSUPPORTED_DIDS = [
    "did:key:z4MXj1wBzi9jUstyPMS4jQqB6KdJaiatPkAtVtGc6bQEQEEsKTic4G7Rou3iBf9vPmT5dbkm9qsZsuVNjq8HCuW1w24nhBFGkRE4cd2Uf2tfrB3N7h4mnyPp1BF3ZttHTYv3DLUPi1zMdkULiow3M1GfXkoC6DoxDUm1jmN6GBj22SjVsr6dxezRVQc7aj9TxE7JLbMH1wh5X3kA58H3DFW8rnYMakFGbca5CB2Jf6CnGQZmL7o5uJAdTwXfy2iiiyPxXEGerMhHwhjTA1mKYobyk2CpeEcmvynADfNZ5MBvcCS7m3XkFCMNUYBS9NQ3fze6vMSUPsNa6GVYmKx2x6JrdEjCk3qRMMmyjnjCMfR4pXbRMZa3i",  # noqa: E501 -- a vector is one token
    "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54",
    "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
]
DSA_SSH = (
    "ssh-dss AAAAB3NzaC1kc3MAAACBANyEsV3PSpUQ6owhKHPVljxvMwb9qnSUhmFA9m0nd/acaPd1rXMnW5a3RN+g"
    "wrOChHV70hlahyARIScJi7El70K+v6QMpmgiZMvrPU+BiadZ5ddCNZ8ZIGsGaA/ou26XwNw+leFApFVAEe0AmE"
    "daY/0fL0UOcBHVjzI3m7sjllOLAAAAFQDfkmoaLLXT8bKc+5HylUQ/X9L+PwAAAIAB/V6pPGLIvhRlYf5/50wy"
    "GfnsVDbs0lXNv6fIUNjIM33RldG0h+Zlt++hQsNmB/AIrcPPof8xcbZMSDm8OGUe0JDa2+V/03Qc7iuQcmwAIS"
    "RaAxWupIKtLQxGF7IzDlj7eb11ADnHJwv247dT61Xbng8sXHDYlccL8Huxd0ucbwAAAIEArrkPc6NUUV64ehaj"
    "QYnDYvPYwUQUq9Kcm5+gA29ATl5xsy/BZsz7sAAFiXa2fCMRkrG8a7ZS+1H8G9wz/U108FdNdr8gAiwDT2T5fz"
    "Dvb2DvnOw97/5IXFmtG2+RnAt+D0WOSih7E5BuJRzZtjOF8EuUyMjD5CplbEhBf08ayn8="
)


def b64url(text: str) -> bytes:
    """Decode unpadded base64url, as used in JWKs."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def ssh_line(*strings: bytes) -> str:
    """Build an OpenSSH public key line from its wire-format strings."""
    blob = b"".join(len(s).to_bytes(4, "big") + s for s in strings)
    return f"{strings[0].decode()} {base64.b64encode(blob).decode()}"


def ed25519_public_from_seed(seed_hex: str) -> bytes:
    """Return the ed25519 public key for a seed, derived by openssl."""
    pkcs8 = bytes.fromhex("302e020100300506032b657004220420" + seed_hex)
    der = subprocess.run(
        ["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=pkcs8,
        capture_output=True,
        check=True,
    ).stdout
    prefix = bytes.fromhex("302a300506032b6570032100")  # SubjectPublicKeyInfo, Ed25519
    assert der[: len(prefix)] == prefix and len(der) == len(prefix) + 32
    return der[len(prefix) :]


def p256_point(jwk: tuple[str, str]) -> bytes:
    """Return the uncompressed SEC1 point for a P-256 JWK (x, y)."""
    return b"\x04" + b64url(jwk[0]) + b64url(jwk[1])


def assert_ssh_keygen_accepts(line: str, tmp_path: Path) -> None:
    """Check that ssh-keygen parses ``line`` as a public key."""
    path = tmp_path / "check.pub"
    path.write_text(line + "\n")
    subprocess.run(
        ["ssh-keygen", "-l", "-f", str(path)], capture_output=True, check=True
    )


def assert_openssl_p256(line: str, tmp_path: Path) -> None:
    """Check that openssl accepts ``line``'s key as a point on P-256."""
    path = tmp_path / "check.pub"
    path.write_text(line + "\n")
    pkcs8 = subprocess.run(
        ["ssh-keygen", "-e", "-m", "PKCS8", "-f", str(path)],
        capture_output=True,
        check=True,
    ).stdout
    text = subprocess.run(
        ["openssl", "pkey", "-pubin", "-noout", "-text", "-check"],
        input=pkcs8,
        capture_output=True,
        check=True,
    ).stdout.decode()
    assert "prime256v1" in text


def ed25519_lines() -> list[tuple[str, str, str]]:
    """Return (did, ssh-ed25519 line, sk-ssh-ed25519 line) for each CCG vector."""
    out = []
    for did, seed in CCG_ED25519_SEEDS.items():
        public = ed25519_public_from_seed(seed)
        out.append(
            (
                did,
                ssh_line(b"ssh-ed25519", public),
                ssh_line(b"sk-ssh-ed25519@openssh.com", public, b"ssh:"),
            )
        )
    return out


def test_openssl_seed_derivation_matches_ccg_jwk() -> None:
    # Cross-checks the seed oracle against the vector's own public key.
    assert ed25519_public_from_seed("00" * 31 + "05") == b64url(CCG_ED25519_SEED5_JWK_X)


def test_ed25519_vectors(vouch: ModuleType, tmp_path: Path) -> None:
    for did, plain, sk in ed25519_lines():
        assert_ssh_keygen_accepts(plain, tmp_path)
        assert_ssh_keygen_accepts(sk, tmp_path)
        assert vouch.ssh_to_did(plain) == did
        assert vouch.ssh_to_did(plain + " a comment with spaces") == did
        assert vouch.ssh_to_did(sk) == did
        assert vouch.did_to_ssh(did) == plain


@pytest.mark.parametrize("did", CCG_P256_JWKS)
def test_p256_vectors(vouch: ModuleType, tmp_path: Path, did: str) -> None:
    point = p256_point(CCG_P256_JWKS[did])
    plain = ssh_line(b"ecdsa-sha2-nistp256", b"nistp256", point)
    sk = ssh_line(b"sk-ecdsa-sha2-nistp256@openssh.com", b"nistp256", point, b"ssh:")
    assert_openssl_p256(plain, tmp_path)
    assert_ssh_keygen_accepts(sk, tmp_path)
    assert vouch.ssh_to_did(plain) == did
    assert vouch.ssh_to_did(sk) == did
    assert vouch.did_to_ssh(did) == plain


def test_p256_even_y_vector(vouch: ModuleType, tmp_path: Path) -> None:
    assert_openssl_p256(EVEN_Y_P256_SSH, tmp_path)
    assert vouch.ssh_to_did(EVEN_Y_P256_SSH) == EVEN_Y_P256_DID
    assert vouch.did_to_ssh(EVEN_Y_P256_DID) == EVEN_Y_P256_SSH


def test_cli_prints_both_directions() -> None:
    did = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
    line = ssh_line(b"ecdsa-sha2-nistp256", b"nistp256", p256_point(CCG_P256_JWKS[did]))
    forward = run_script("did", line + " alice@example.org")
    assert (forward.returncode, forward.stdout, forward.stderr) == (0, did + "\n", "")
    reverse = run_script("did", did)
    assert (reverse.returncode, reverse.stdout, reverse.stderr) == (0, line + "\n", "")


def test_real_key_round_trips_through_ssh_keygen(any_key: Key, tmp_path: Path) -> None:
    # The reverse output must name the same key ssh-keygen made, by fingerprint.
    did = run_script("did", any_key.pubkey).stdout.strip()
    line = run_script("did", did).stdout.strip()
    path = tmp_path / "back.pub"
    path.write_text(line + "\n")

    def fingerprint(p: Path) -> str:
        out = subprocess.run(
            ["ssh-keygen", "-l", "-f", str(p)], capture_output=True, check=True
        )
        return out.stdout.split()[1].decode()

    assert fingerprint(path) == fingerprint(any_key.public)


@pytest.mark.parametrize(
    "keygen_args", [["-t", "rsa", "-b", "1024"], ["-t", "ecdsa", "-b", "384"]]
)
def test_cli_rejects_unsupported_real_keys(
    tmp_path: Path, keygen_args: list[str]
) -> None:
    key = make_key(tmp_path, "unsupported", keygen_args)
    result = run_script("did", key.pubkey)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("git-vouch: error: unsupported key type")


def test_cli_rejects_dsa() -> None:
    result = run_script("did", DSA_SSH)
    assert result.returncode == 1
    assert result.stderr.startswith("git-vouch: error: unsupported key type 'ssh-dss'")


@pytest.mark.parametrize("did", CCG_UNSUPPORTED_DIDS)
def test_cli_rejects_unsupported_dids(did: str) -> None:
    result = run_script("did", did)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("git-vouch: error:")


def _ed25519_vector_line() -> str:
    return ssh_line(b"ssh-ed25519", ed25519_public_from_seed("00" * 32))


@pytest.mark.parametrize(
    "line",
    [
        "",
        "ssh-ed25519",
        "ssh-ed25519 !!!notbase64",
        # Type field disagrees with the blob.
        "sk-ssh-ed25519@openssh.com " + _ed25519_vector_line().split()[1],
        ssh_line(b"ssh-ed25519", b"\x01" * 31),
        ssh_line(b"ssh-ed25519", b"\x01" * 32, b"extra"),
        "ssh-ed25519 "
        + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20").decode(),
        ssh_line(
            b"ecdsa-sha2-nistp256",
            b"nistp384",
            p256_point(next(iter(CCG_P256_JWKS.values()))),
        ),
        ssh_line(b"ecdsa-sha2-nistp256", b"nistp256", b"\x02" + b"\x01" * 32),
        # 65 bytes but a compressed-point prefix instead of 0x04.
        ssh_line(
            b"ecdsa-sha2-nistp256",
            b"nistp256",
            b"\x03" + p256_point(next(iter(CCG_P256_JWKS.values())))[1:],
        ),
    ],
)
def test_malformed_keys_rejected(vouch: ModuleType, line: str) -> None:
    with pytest.raises(vouch.VouchError):
        vouch.ssh_to_did(line)


def test_off_curve_point_rejected(vouch: ModuleType) -> None:
    point = bytearray(p256_point(next(iter(CCG_P256_JWKS.values()))))
    point[-1] ^= 1  # same x, wrong y: not on the curve
    with pytest.raises(vouch.VouchError, match="P-256"):
        vouch.ssh_to_did(ssh_line(b"ecdsa-sha2-nistp256", b"nistp256", bytes(point)))


@pytest.mark.parametrize(
    "did",
    [
        "did:web:example.org",
        "did:key:",
        "did:key:6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",  # no multibase prefix
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooW0",  # '0' is not base58
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWpp",  # 33-byte key
        "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp#frag",
        # p256-pub, prefix 0x04, x on the curve: only 0x02/0x03 are valid.
        "did:key:zDnafABTaPP8tosms2A8CK7jBEaD4tm4aprmssDjHUaWXjX5C",
    ],
)
def test_malformed_dids_rejected(vouch: ModuleType, did: str) -> None:
    with pytest.raises(vouch.VouchError):
        vouch.did_to_ssh(did)


def test_off_curve_did_rejected(vouch: ModuleType) -> None:
    # p256-pub, prefix 0x02, x = 1: 1 - 3 + b is not a square mod p.
    with pytest.raises(vouch.VouchError, match="P-256"):
        vouch.did_to_ssh("did:key:zDnaeQRy3dcKsKa1zmKtVKsTy3m2HYoQnFnfKuxD6HfSTQgYg")


def test_overlong_did_not_decoded(
    vouch: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_decode(text: str) -> bytes:
        raise AssertionError("b58decode called on over-long did")

    monkeypatch.setattr(vouch, "b58decode", no_decode)
    with pytest.raises(vouch.VouchError):
        vouch.did_to_ssh("did:key:zDnae" + "1" * 60)


# P-256 field prime, typed in from SEC 2 / `openssl ecparam -param_enc explicit`.
P256_P_HEX = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"


def test_p256_coordinate_not_below_p_rejected(vouch: ModuleType) -> None:
    # x = p reduces to x = 0, which is on the curve; accepting it would give
    # one key two encodings. b58encode only builds the input here; the CCG
    # vectors above check it.
    p = bytes.fromhex(P256_P_HEX)
    with pytest.raises(vouch.VouchError, match="out of range"):
        vouch.did_to_ssh("did:key:z" + vouch.b58encode(b"\x80\x24\x02" + p))
    with pytest.raises(vouch.VouchError, match="out of range"):
        vouch.ssh_to_did(ssh_line(b"ecdsa-sha2-nistp256", b"nistp256", b"\x04" + p + p))


# Bitcoin Core src/test/data/base58_encode_decode.json (confirmed with
# python-bitcoinlib); did:key payloads never start with a zero byte, so these
# are the only check of the leading-'1' rule.
@pytest.mark.parametrize(
    ("hex_data", "text"),
    [
        ("", ""),
        ("61", "2g"),
        ("0000287fb4cd", "11233QC4"),
        ("00000000000000000000", "1111111111"),
        (
            "00eb15231dfceb60925886b67d065299925915aeb172c06647",
            "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        ),
    ],
)
def test_base58_bitcoin_vectors(vouch: ModuleType, hex_data: str, text: str) -> None:
    assert vouch.b58encode(bytes.fromhex(hex_data)) == text
    assert vouch.b58decode(text) == bytes.fromhex(hex_data)


def test_leading_one_alias_rejected(vouch: ModuleType) -> None:
    # A '1' adds a zero byte, so it must not decode to the same key.
    with pytest.raises(vouch.VouchError):
        vouch.did_to_ssh("did:key:z16MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")

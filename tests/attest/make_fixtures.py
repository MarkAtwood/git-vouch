#!/usr/bin/env python3
"""Regenerate the git-vouch-attest test fixtures in tests/attest/fixtures/.

No hardware attestation is available yet, so this builds packed
attestations by hand: a throwaway root -> intermediate -> attestation
certificate chain made by openssl, and authenticator data for credential
keys made by openssl. It shares no code with git-vouch-attest. After
regenerating, cross-check every case with OpenSSH's
regress/misc/ssh-verify-attestation (see conftest.CASES).

Usage: python3 tests/attest/make_fixtures.py
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import subprocess
import tempfile
from pathlib import Path

OUT = Path(__file__).resolve().parent / "fixtures"
APPLICATION = b"ssh:"
AAGUID = bytes.fromhex("6a1f3c2e9b7d4e5fa0c1d2e3f4051627")
OTHER_AAGUID = bytes.fromhex("00112233445566778899aabbccddeeff")
AAGUID_EXT = "1.3.6.1.4.1.45724.1.1.4 = DER:04:"  # id-fido-gen-ce-aaguid
CNF = f"""\
[req]
distinguished_name = dn
prompt = no
[dn]
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[leaf]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
{AAGUID_EXT}10:{AAGUID.hex()}
[leaf_other]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
{AAGUID_EXT}10:{OTHER_AAGUID.hex()}
[leaf_bad]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
{AAGUID_EXT}0f:{AAGUID[:15].hex()}
"""


def run(*args: str) -> bytes:
    """Run a command, failing loudly, and return its stdout."""
    return subprocess.run(args, check=True, capture_output=True).stdout


def ssh_string(data: bytes) -> bytes:
    """Encode one SSH wire string."""
    return struct.pack(">I", len(data)) + data


def cbor_head(major: int, n: int) -> bytes:
    """Encode a CBOR initial byte and argument."""
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + struct.pack(">H", n)


def cbor_int(n: int) -> bytes:
    """Encode a CBOR integer."""
    return cbor_head(0, n) if n >= 0 else cbor_head(1, -1 - n)


def cbor_map(items: list[tuple[int, int | bytes]]) -> bytes:
    """Encode a CBOR map with integer keys and integer or byte-string values."""
    out = cbor_head(5, len(items))
    for key, value in items:
        out += cbor_int(key)
        out += (
            cbor_int(value)
            if isinstance(value, int)
            else cbor_head(2, len(value)) + value
        )
    return out


def make_cert(tmp: Path, name: str, subject: str, issuer: str | None, ext: str) -> None:
    """Make an EC P-256 key and a certificate for it, self-signed when issuer is None."""
    key, csr, pem = tmp / f"{name}.key", tmp / f"{name}.csr", tmp / f"{name}.pem"
    cnf = tmp / "openssl.cnf"
    run(
        "openssl",
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        str(key),
    )
    run(
        "openssl",
        "req",
        "-new",
        "-config",
        str(cnf),
        "-key",
        str(key),
        "-subj",
        subject,
        "-out",
        str(csr),
    )
    sign = (
        ["-signkey", str(key)]
        if issuer is None
        else ["-CA", str(tmp / f"{issuer}.pem"), "-CAkey", str(tmp / f"{issuer}.key")]
    )
    run(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(csr),
        *sign,
        "-days",
        "36500",
        "-sha256",
        "-set_serial",
        "0x" + os.urandom(8).hex(),
        "-extfile",
        str(cnf),
        "-extensions",
        ext,
        "-out",
        str(pem),
    )


def credential(
    tmp: Path, name: str, algorithm: list[str], raw_len: int
) -> tuple[Path, bytes]:
    """Make a credential key pair; return the private key path and the raw public key."""
    key = tmp / f"{name}.key"
    run("openssl", "genpkey", *algorithm, "-out", str(key))
    spki = run("openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER")
    return key, spki[-raw_len:]


def write_pub(
    name: str,
    key_type: str,
    fields: list[bytes],
    application: bytes = APPLICATION,
    wire_type: str | None = None,
) -> None:
    """Write an sk- SSH public key line and confirm ssh-keygen reads it.

    With wire_type, the encoded type differs from the line's, and ssh-keygen
    must refuse the line instead.
    """
    encoded = (wire_type or key_type).encode()
    wire = b"".join(ssh_string(f) for f in [encoded, *fields, application])
    path = OUT / f"{name}.pub"
    path.write_text(f"{key_type} {base64.b64encode(wire).decode()} {name}\n")
    check = subprocess.run(["ssh-keygen", "-l", "-f", str(path)], capture_output=True)
    if (check.returncode == 0) != (wire_type is None):
        raise SystemExit(f"ssh-keygen verdict on {path} is not the intended one")


def authdata(flags: int, cose: bytes) -> bytes:
    """Build raw authenticator data with attested credential data."""
    cred_id = os.urandom(64)
    return (
        hashlib.sha256(APPLICATION).digest()
        + bytes([flags])
        + struct.pack(">I", 0)
        + AAGUID
        + struct.pack(">H", len(cred_id))
        + cred_id
        + cose
    )


def blob(cert: bytes, sig: bytes, auth: bytes) -> bytes:
    """Pack an ssh-sk-attest-v01 blob; authData is wrapped as a CBOR byte string."""
    return (
        ssh_string(b"ssh-sk-attest-v01")
        + ssh_string(cert)
        + ssh_string(sig)
        + ssh_string(cbor_head(2, len(auth)) + auth)
        + struct.pack(">I", 0)
        + ssh_string(b"")
    )


def sign(tmp: Path, key: Path, data: bytes) -> bytes:
    """Sign data with ECDSA P-256 SHA-256 using openssl."""
    path = tmp / "tbs"
    path.write_bytes(data)
    return run("openssl", "dgst", "-sha256", "-sign", str(key), str(path))


def main() -> None:
    """Write every fixture file."""
    OUT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        (tmp / "openssl.cnf").write_text(CNF)
        make_cert(tmp, "root", "/O=Test Vendor/CN=Test Attestation Root", None, "ca")
        make_cert(tmp, "inter", "/O=Test Vendor/CN=Test Attestation CA 1", "root", "ca")
        make_cert(
            tmp,
            "leaf",
            "/O=Test Vendor/OU=Authenticator Attestation/CN=Test Key",
            "inter",
            "leaf",
        )
        for leaf in ("leaf_other", "leaf_bad"):
            make_cert(tmp, leaf, f"/O=Test Vendor/CN=Test Key {leaf}", "inter", leaf)
        make_cert(tmp, "other", "/O=Other Vendor/CN=Other Root", None, "ca")
        root, inter = (tmp / "root.pem").read_bytes(), (tmp / "inter.pem").read_bytes()
        (OUT / "root.pem").write_bytes(root)
        (OUT / "ca.pem").write_bytes(inter + root)
        (OUT / "other-ca.pem").write_bytes((tmp / "other.pem").read_bytes())
        leaf_der = run(
            "openssl", "x509", "-in", str(tmp / "leaf.pem"), "-outform", "DER"
        )
        leaf_key = tmp / "leaf.key"
        other_leaf, bad_leaf = (
            run("openssl", "x509", "-in", str(tmp / f"{n}.pem"), "-outform", "DER")
            for n in ("leaf_other", "leaf_bad")
        )

        ec_args = ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
        ec_key, ec_pub = credential(tmp, "ecdsa", ec_args, 65)
        _, ed_pub = credential(tmp, "ed25519", ["-algorithm", "ED25519"], 32)
        _, other_pub = credential(tmp, "other", ec_args, 65)
        write_pub(
            "ecdsa-sk", "sk-ecdsa-sha2-nistp256@openssh.com", [b"nistp256", ec_pub]
        )
        write_pub("ed25519-sk", "sk-ssh-ed25519@openssh.com", [ed_pub])
        write_pub(
            "other-app-sk",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            [b"nistp256", ec_pub],
            application=b"ssh:other",
        )
        write_pub(
            "type-mismatch-sk",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            [b"nistp256", ec_pub],
            wire_type="sk-ssh-ed25519@openssh.com",
        )
        write_pub(
            "other-sk", "sk-ecdsa-sha2-nistp256@openssh.com", [b"nistp256", other_pub]
        )
        ec_cose = cbor_map(
            [(1, 2), (3, -7), (-1, 1), (-2, ec_pub[1:33]), (-3, ec_pub[33:])]
        )
        ed_cose = cbor_map([(1, 1), (3, -8), (-1, 6), (-2, ed_pub)])

        def attest(
            name: str,
            auth: bytes,
            cert: bytes = leaf_der,
            key: Path = leaf_key,
            tamper_sig: bool = False,
            tamper_auth: bool = False,
        ) -> None:
            challenge = os.urandom(32)
            sig = sign(tmp, key, auth + hashlib.sha256(challenge).digest())
            if tamper_sig:
                sig = sig[:-1] + bytes([sig[-1] ^ 1])
            if tamper_auth:
                auth = (
                    auth[:37] + bytes([auth[37] ^ 1]) + auth[38:]
                )  # first AAGUID byte
            (OUT / f"{name}.challenge").write_bytes(challenge)
            (OUT / f"{name}.attest").write_bytes(blob(cert, sig, auth))

        attest("ecdsa-sk", authdata(0x41, ec_cose))
        attest("ed25519-sk", authdata(0x41, ed_cose))
        attest("bad-sig", authdata(0x41, ec_cose), tamper_sig=True)
        attest("bad-authdata", authdata(0x41, ec_cose), tamper_auth=True)
        attest("no-up", authdata(0x40, ec_cose))
        attest("self", authdata(0x41, ec_cose), cert=b"", key=ec_key)
        attest("no-at", authdata(0x01, ec_cose))
        attest(
            "aaguid-mismatch",
            authdata(0x41, ec_cose),
            cert=other_leaf,
            key=tmp / "leaf_other.key",
        )
        attest(
            "aaguid-malformed",
            authdata(0x41, ec_cose),
            cert=bad_leaf,
            key=tmp / "leaf_bad.key",
        )


if __name__ == "__main__":
    main()

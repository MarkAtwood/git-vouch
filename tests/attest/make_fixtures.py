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
[leaf_no_aaguid]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf_aaguid_critical]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.3.6.1.4.1.45724.1.1.4 = critical,DER:04:10:{AAGUID.hex()}
[leaf_ca_true]
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
{AAGUID_EXT}10:{AAGUID.hex()}
[leaf_no_basic_constraints]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
{AAGUID_EXT}10:{AAGUID.hex()}
[tls]
basicConstraints = critical,CA:FALSE
extendedKeyUsage = serverAuth
subjectAltName = DNS:www.example.com
"""
LEAF_SUBJECT = "/O=Test Vendor/OU=Authenticator Attestation/CN=Test Key"
# name -> (subject, openssl.cnf extension section or None for an X.509 v1 cert)
LEAVES = {
    "leaf": (LEAF_SUBJECT, "leaf"),
    "leaf_other": (LEAF_SUBJECT + " other", "leaf_other"),
    "leaf_bad": (LEAF_SUBJECT + " bad", "leaf_bad"),
    "leaf_no_aaguid": (LEAF_SUBJECT + " no aaguid", "leaf_no_aaguid"),
    "leaf_aaguid_critical": (LEAF_SUBJECT + " critical", "leaf_aaguid_critical"),
    "leaf_ca_true": (LEAF_SUBJECT + " ca", "leaf_ca_true"),
    "leaf_no_basic_constraints": (LEAF_SUBJECT + " no bc", "leaf_no_basic_constraints"),
    "leaf_no_ou": ("/O=Test Vendor/CN=Test Key no ou", "leaf"),
    "leaf_v1": (LEAF_SUBJECT + " v1", None),
    "leaf_v2": (LEAF_SUBJECT + " v2", "leaf"),  # version patched by as_v2()
    # A TLS server certificate under the same root (review vouch-xlha.11).
    "tls": ("/CN=www.example.com", "tls"),
}


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


def make_cert(
    tmp: Path, name: str, subject: str, issuer: str | None, ext: str | None
) -> None:
    """Make an EC P-256 key and a certificate for it, self-signed when issuer is None.

    With ext None the certificate has no extensions, so openssl makes it v1.
    """
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
        *([] if ext is None else ["-extfile", str(cnf), "-extensions", ext]),
        "-out",
        str(pem),
    )


def der_tlv(tag: int, value: bytes) -> bytes:
    """Encode one DER TLV (definite length)."""
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    size = (len(value).bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + len(value).to_bytes(size, "big") + value


def der_split(tlv: bytes) -> tuple[bytes, bytes]:
    """Split one DER TLV at the start of tlv into (header, contents)."""
    length, start = tlv[1], 2
    if length & 0x80:
        start += length & 0x7F
        length = int.from_bytes(tlv[2:start], "big")
    return tlv[:start], tlv[start : start + length]


def der_items(contents: bytes) -> list[bytes]:
    """Split the contents of a DER SEQUENCE into its encoded elements."""
    items = []
    while contents:
        header, value = der_split(contents)
        items.append(header + value)
        contents = contents[len(header) + len(value) :]
    return items


def as_v2(tmp: Path, cert: bytes, issuer_key: Path) -> bytes:
    """Return cert with its version field set to v2, re-signed by issuer_key.

    The result still chains, so only the version check can reject it.
    """
    tbs, algorithm, _ = der_items(der_split(cert)[1])
    header, fields = der_split(tbs)
    if not fields.startswith(b"\xa0\x03\x02\x01\x02"):  # [0] INTEGER 2
        raise SystemExit("leaf certificate is not v3")
    tbs = der_tlv(0x30, b"\xa0\x03\x02\x01\x01" + fields[5:])
    sig = sign(tmp, issuer_key, tbs)
    return der_tlv(0x30, tbs + algorithm + der_tlv(0x03, b"\x00" + sig))


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
        for leaf, (subject, ext) in LEAVES.items():
            make_cert(tmp, leaf, subject, "inter", ext)
        make_cert(tmp, "other", "/O=Other Vendor/CN=Other Root", None, "ca")
        root, inter = (tmp / "root.pem").read_bytes(), (tmp / "inter.pem").read_bytes()
        (OUT / "root.pem").write_bytes(root)
        (OUT / "ca.pem").write_bytes(inter + root)
        (OUT / "other-ca.pem").write_bytes((tmp / "other.pem").read_bytes())
        der = {
            leaf: run(
                "openssl", "x509", "-in", str(tmp / f"{leaf}.pem"), "-outform", "DER"
            )
            for leaf in LEAVES
        }
        der["leaf_v2"] = as_v2(tmp, der["leaf_v2"], tmp / "inter.key")
        leaf_der = der["leaf"]
        leaf_key = tmp / "leaf.key"

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
        for name, leaf in [
            ("aaguid-mismatch", "leaf_other"),
            ("aaguid-malformed", "leaf_bad"),
            ("no-aaguid", "leaf_no_aaguid"),
            ("aaguid-critical", "leaf_aaguid_critical"),
            ("ca-true", "leaf_ca_true"),
            ("no-basic-constraints", "leaf_no_basic_constraints"),
            ("no-ou", "leaf_no_ou"),
            ("v1", "leaf_v1"),
            ("v2", "leaf_v2"),
            ("tls-leaf", "tls"),
        ]:
            attest(
                name, authdata(0x41, ec_cose), cert=der[leaf], key=tmp / f"{leaf}.key"
            )


if __name__ == "__main__":
    main()

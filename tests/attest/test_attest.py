"""Tests for git-vouch-attest against hand-built packed attestations.

The fixtures in fixtures/ come from make_fixtures.py: a throwaway
openssl CA chain and hand-built packed attestations, not real hardware.
Each case's ``openssh_accepts`` is the expected verdict of OpenSSH's
regress/misc/ssh-verify-attestation (openssh-portable 26b1363, linked
against libfido2 1.14) on the same three files, predicted from reading its
source, not yet run (see vouch-ey47.15); set SSH_VERIFY_ATTESTATION to
that binary to check it. That program does not check certificate chains
or the certificate profile, so chain cases are separate.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "git-vouch-attest"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
AAGUID = "6a1f3c2e-9b7d-4e5f-a0c1-d2e3f4051627"  # set by make_fixtures.py


class Case(NamedTuple):
    """One (key, challenge, attestation) triple and the expected verdicts.

    reason is the stderr text the tool must give when it rejects, or "".
    """

    pub: str
    challenge: str
    attest: str
    openssh_accepts: bool
    tool_accepts: bool
    reason: str = ""


BAD_SIG = "attestation signature does not verify"
NO_MATCH = "attested credential does not match the SSH key"
CASES = {
    "ecdsa-sk": Case("ecdsa-sk", "ecdsa-sk", "ecdsa-sk", True, True),
    "ed25519-sk": Case("ed25519-sk", "ed25519-sk", "ed25519-sk", True, True),
    "tampered-signature": Case("ecdsa-sk", "bad-sig", "bad-sig", False, False, BAD_SIG),
    "tampered-authdata": Case(
        "ecdsa-sk", "bad-authdata", "bad-authdata", False, False, BAD_SIG
    ),
    "wrong-challenge": Case(
        "ecdsa-sk", "ed25519-sk", "ecdsa-sk", False, False, BAD_SIG
    ),
    "wrong-key": Case("other-sk", "ecdsa-sk", "ecdsa-sk", False, False, NO_MATCH),
    "wrong-key-type": Case(
        "ed25519-sk", "ecdsa-sk", "ecdsa-sk", False, False, NO_MATCH
    ),
    "wrong-application": Case(
        "other-app-sk", "ecdsa-sk", "ecdsa-sk", False, False, "for another application"
    ),
    "key-type-mismatch": Case(
        "type-mismatch-sk",
        "ecdsa-sk",
        "ecdsa-sk",
        False,
        False,
        "SSH key type does not match its encoding",
    ),
    "user-not-present": Case(
        "ecdsa-sk", "no-up", "no-up", False, False, "user-present flag not set"
    ),
    "no-attested-credential": Case(
        "ecdsa-sk", "no-at", "no-at", False, False, "no attested credential data"
    ),
    # The tool deliberately goes further than ssh-verify-attestation below.
    # Self attestation proves nothing about the device.
    "self-attestation": Case(
        "ecdsa-sk", "self", "self", True, False, "self attestation"
    ),
    # WebAuthn 8.2.1: the certificate's AAGUID extension must match authData.
    "aaguid-mismatch": Case(
        "ecdsa-sk", "aaguid-mismatch", "aaguid-mismatch", True, False, "AAGUID differs"
    ),
    "aaguid-malformed": Case(
        "ecdsa-sk",
        "aaguid-malformed",
        "aaguid-malformed",
        True,
        False,
        "malformed AAGUID extension",
    ),
    # WebAuthn 8.2.1 packed attestation certificate requirements.
    "no-aaguid-extension": Case(
        "ecdsa-sk", "no-aaguid", "no-aaguid", True, False, "no AAGUID extension"
    ),
    "aaguid-extension-critical": Case(
        "ecdsa-sk",
        "aaguid-critical",
        "aaguid-critical",
        True,
        False,
        "AAGUID extension in attestation certificate is critical",
    ),
    "ca-certificate": Case(
        "ecdsa-sk", "ca-true", "ca-true", True, False, "is a CA certificate"
    ),
    "no-basic-constraints": Case(
        "ecdsa-sk",
        "no-basic-constraints",
        "no-basic-constraints",
        True,
        False,
        "has no basicConstraints",
    ),
    "no-ou": Case(
        "ecdsa-sk",
        "no-ou",
        "no-ou",
        True,
        False,
        'lacks OU "Authenticator Attestation"',
    ),
    "x509-v1": Case("ecdsa-sk", "v1", "v1", True, False, "is not X.509 v3"),
    # Explicit version field v2, with extensions, re-signed so it still chains.
    "x509-v2": Case("ecdsa-sk", "v2", "v2", True, False, "is not X.509 v3"),
    # A TLS server certificate chaining to --ca signs for a software key.
    "tls-leaf": Case(
        "ecdsa-sk",
        "tls-leaf",
        "tls-leaf",
        True,
        False,
        'lacks OU "Authenticator Attestation"',
    ),
}


def case_files(case: Case) -> list[str]:
    """Return the PUBKEY CHALLENGE ATTESTATION paths for a case."""
    return [
        str(FIXTURES / f"{case.pub}.pub"),
        str(FIXTURES / f"{case.challenge}.challenge"),
        str(FIXTURES / f"{case.attest}.attest"),
    ]


def run_attest(
    *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """Run git-vouch-attest with the given arguments."""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env
    )


CA = str(FIXTURES / "ca.pem")


@pytest.mark.parametrize("case", CASES.values(), ids=CASES.keys())
def test_verdicts(case: Case) -> None:
    result = run_attest("--ca", CA, *case_files(case))
    assert (result.returncode == 0) == case.tool_accepts, result.stderr
    if case.tool_accepts:
        assert f"aaguid {AAGUID}" in result.stdout
        assert "CN = Test Key" in result.stdout
    else:
        assert result.returncode == 1
        assert case.reason in result.stderr


@pytest.mark.parametrize("case", CASES.values(), ids=CASES.keys())
def test_openssh_reference_verdicts(case: Case, openssh_verifier: str) -> None:
    """Check the predicted verdicts with ssh-verify-attestation."""
    result = subprocess.run([openssh_verifier, *case_files(case)], capture_output=True)
    assert (result.returncode == 0) == case.openssh_accepts


@pytest.mark.parametrize(
    ("ca", "reason"),
    [
        ("other-ca.pem", "unrelated vendor root"),
        ("root.pem", "root without the intermediate"),
    ],
)
def test_chain_to_ca_required(ca: str, reason: str) -> None:
    result = run_attest("--ca", str(FIXTURES / ca), *case_files(CASES["ecdsa-sk"]))
    assert result.returncode == 1, reason
    # openssl's own reason is passed through, so expiry is not reported as a wrong root.
    assert (
        "does not chain to --ca: unable to get local issuer certificate"
        in result.stderr
    )


@pytest.mark.parametrize("content", [None, "", "not a certificate\n"])
def test_unusable_ca_named(tmp_path: Path, content: str | None) -> None:
    """A missing or certificate-free --ca is reported as such, not as a bad chain."""
    ca = tmp_path / "ca.pem"
    if content is not None:
        ca.write_text(content)
    result = run_attest("--ca", str(ca), *case_files(CASES["ecdsa-sk"]))
    assert result.returncode == 1
    assert f"--ca {ca}: no readable PEM certificate" in result.stderr
    assert "does not chain" not in result.stderr


def test_corrupt_ca_block_named(tmp_path: Path) -> None:
    """A corrupt certificate after a good one in --ca is a --ca error."""
    ca = tmp_path / "ca.pem"
    ca.write_text(
        Path(CA).read_text()
        + "-----BEGIN CERTIFICATE-----\nMIIBzzzz\n-----END CERTIFICATE-----\n"
    )
    result = run_attest("--ca", str(ca), *case_files(CASES["ecdsa-sk"]))
    assert result.returncode == 1
    assert f"--ca {ca}: no readable PEM certificate" in result.stderr
    assert "openssl verify" not in result.stderr


def test_openssl_without_no_castore(tmp_path: Path) -> None:
    """An openssl that rejects -no-CAstore (before 3.0) is not blamed on the chain."""
    real = shutil.which("openssl")
    shim = tmp_path / "openssl"
    # ponytail: the shim's message is a stand-in; the tool must not depend on
    # its wording, only on the absence of an openssl "lookup:" verdict.
    shim.write_text(
        "#!/bin/sh\n"
        'for arg; do [ "$arg" = -no-CAstore ] && '
        "{ echo 'verify: Unknown option: -no-CAstore' >&2; exit 1; }; done\n"
        f'exec {real} "$@"\n'
    )
    shim.chmod(0o755)
    env = dict(os.environ, PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    result = run_attest("--ca", CA, *case_files(CASES["ecdsa-sk"]), env=env)
    assert result.returncode == 1
    assert "needs OpenSSL 3.0 or later" in result.stderr
    assert "-no-CAstore" in result.stderr
    assert "does not chain" not in result.stderr


def test_system_trust_store_ignored(tmp_path: Path) -> None:
    """A root in openssl's default store must not stand in for --ca."""
    pems = re.findall(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n",
        (FIXTURES / "ca.pem").read_text(),
        re.S,
    )
    for index, pem in enumerate(pems):
        (tmp_path / f"{index}.pem").write_text(pem)
    subprocess.run(["openssl", "rehash", str(tmp_path)], check=True)
    env = dict(os.environ, SSL_CERT_DIR=str(tmp_path), SSL_CERT_FILE=CA)
    args = ["--ca", str(FIXTURES / "other-ca.pem"), *case_files(CASES["ecdsa-sk"])]
    assert (
        run_attest("--ca", CA, *case_files(CASES["ecdsa-sk"]), env=env).returncode == 0
    )
    result = run_attest(*args, env=env)
    assert result.returncode == 1
    assert "does not chain to --ca" in result.stderr


@pytest.mark.parametrize(
    "damage",
    [
        lambda b: b + b"\0",
        lambda b: b[:-5],
        lambda b: b.replace(b"ssh-sk-attest-v01", b"ssh-sk-attest-v02"),
        lambda b: b"",
    ],
    ids=["trailing-byte", "truncated", "wrong-magic", "empty"],
)
def test_damaged_blob_rejected(tmp_path: Path, damage) -> None:
    pub, challenge, attest = case_files(CASES["ecdsa-sk"])
    damaged = tmp_path / "damaged.attest"
    damaged.write_bytes(damage(Path(attest).read_bytes()))
    result = run_attest("--ca", CA, pub, challenge, str(damaged))
    assert result.returncode == 1


def write_person(tmp_path: Path, keys: list[dict]) -> str:
    """Write a person file with the given keys entries."""
    path = tmp_path / "alice.json"
    path.write_text(json.dumps({"handle": "alice", "keys": keys}))
    return str(path)


def attestation(name: str, challenge: str) -> dict:
    """Return the {blob, challenge} field for fixture files, base64 as DESIGN.md says."""
    return {
        "blob": base64.b64encode((FIXTURES / f"{name}.attest").read_bytes()).decode(),
        "challenge": base64.b64encode(
            (FIXTURES / f"{challenge}.challenge").read_bytes()
        ).decode(),
    }


def pub_text(name: str) -> str:
    """Return a fixture public key line."""
    return (FIXTURES / f"{name}.pub").read_text().strip()


def test_person_file_checks_attested_keys(tmp_path: Path) -> None:
    person = write_person(
        tmp_path,
        [
            {"ssh": pub_text("other-sk"), "attestation": None},
            {
                "ssh": pub_text("ecdsa-sk"),
                "attestation": attestation("ecdsa-sk", "ecdsa-sk"),
            },
            {
                "ssh": pub_text("ed25519-sk"),
                "attestation": attestation("ed25519-sk", "ed25519-sk"),
            },
        ],
    )
    result = run_attest("--ca", CA, person)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert [line.split(": ")[1] for line in lines] == ["keys[1]", "keys[2]"]
    assert all(f"aaguid {AAGUID}" in line for line in lines)


def test_person_file_one_bad_attestation_fails(tmp_path: Path) -> None:
    person = write_person(
        tmp_path,
        [
            {
                "ssh": pub_text("ecdsa-sk"),
                "attestation": attestation("ecdsa-sk", "ecdsa-sk"),
            },
            {
                "ssh": pub_text("ed25519-sk"),
                "attestation": attestation("ed25519-sk", "ecdsa-sk"),
            },
        ],
    )
    result = run_attest("--ca", CA, person)
    assert result.returncode == 1
    assert "keys[0]: verified" in result.stdout
    assert "keys[1]: attestation signature does not verify" in result.stderr


NON_ASCII_KEY = "sk-ssh-ed25519@openssh.com AAAA\u00e9"


def test_person_file_non_ascii_key_reported(tmp_path: Path) -> None:
    """A non-ASCII key is reported and the keys after it are still checked."""
    person = write_person(
        tmp_path,
        [
            {"ssh": NON_ASCII_KEY, "attestation": attestation("ecdsa-sk", "ecdsa-sk")},
            {
                "ssh": pub_text("ecdsa-sk"),
                "attestation": attestation("ecdsa-sk", "ecdsa-sk"),
            },
        ],
    )
    result = run_attest("--ca", CA, person)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "keys[0]: SSH key is not valid base64" in result.stderr
    assert "keys[1]: verified" in result.stdout


def test_non_ascii_key_file_reported(tmp_path: Path) -> None:
    pub = tmp_path / "bad.pub"
    pub.write_bytes(NON_ASCII_KEY.encode() + b"\n")
    _, challenge, attest = case_files(CASES["ecdsa-sk"])
    result = run_attest("--ca", CA, str(pub), challenge, attest)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "SSH key is not valid base64" in result.stderr


def test_person_file_without_attestation_fails(tmp_path: Path) -> None:
    person = write_person(tmp_path, [{"ssh": pub_text("ecdsa-sk")}])
    result = run_attest("--ca", CA, person)
    assert result.returncode == 1
    assert "no key carries an attestation" in result.stderr


def test_person_file_bad_base64_fails(tmp_path: Path) -> None:
    person = write_person(
        tmp_path,
        [{"ssh": pub_text("ecdsa-sk"), "attestation": {"blob": "!!", "challenge": ""}}],
    )
    result = run_attest("--ca", CA, person)
    assert result.returncode == 1
    assert "not base64" in result.stderr


def test_two_files_is_a_usage_error() -> None:
    pub, challenge, _ = case_files(CASES["ecdsa-sk"])
    assert run_attest("--ca", CA, pub, challenge).returncode == 2


def test_non_sk_key_rejected(tmp_path: Path) -> None:
    key = tmp_path / "plain"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True
    )
    _, challenge, attest = case_files(CASES["ed25519-sk"])
    result = run_attest("--ca", CA, f"{key}.pub", challenge, attest)
    assert result.returncode == 1
    assert "not an sk-ssh-ed25519" in result.stderr

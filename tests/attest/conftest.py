"""Fixtures for git-vouch-attest tests."""

from __future__ import annotations

import os

import pytest


@pytest.fixture
def openssh_verifier() -> str:
    """Return OpenSSH's ssh-verify-attestation from SSH_VERIFY_ATTESTATION, or skip.

    It is built from openssh-portable regress/misc/ssh-verify-attestation and
    needs libfido2, so it is not assumed to be installed.
    """
    path = os.environ.get("SSH_VERIFY_ATTESTATION")
    if not path:
        pytest.skip("set SSH_VERIFY_ATTESTATION to OpenSSH's ssh-verify-attestation")
    return path

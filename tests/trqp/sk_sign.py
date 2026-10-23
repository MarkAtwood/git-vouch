"""A software sk-ssh-ed25519 signer for tests, run where ssh-keygen would be.

There is no FIDO token in a test run, so this stands in for one: it takes
``ssh-keygen``'s ``-Y sign -n NAMESPACE -f KEY FILE`` arguments, as git's
``gpg.ssh.program`` receives them, and writes ``FILE.sig``. KEY holds the
hex Ed25519 seed; the public key is ``KEY.pub``. The signature follows
OpenSSH PROTOCOL.sshsig and PROTOCOL.u2f (the authenticator signs
SHA-256(application) || flags || counter || SHA-256(message)); it is only
ever trusted after real ``ssh-keygen -Y verify`` accepts it.

    python sk_sign.py keygen KEY       # write KEY and KEY.pub
    python sk_sign.py -Y sign -n NAMESPACE -f KEY FILE
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import sys
import textwrap
from collections.abc import Sequence
from pathlib import Path

import nacl.signing

KEY_TYPE = b"sk-ssh-ed25519@openssh.com"
APPLICATION = b"ssh:"
USER_PRESENT = 0x01


def ssh_string(data: bytes) -> bytes:
    """Return ``data`` as an SSH wire-format string."""
    return struct.pack(">I", len(data)) + data


def public_blob(public: bytes) -> bytes:
    """Return the sk-ssh-ed25519 public key blob for raw key ``public``."""
    return ssh_string(KEY_TYPE) + ssh_string(public) + ssh_string(APPLICATION)


def keygen(key: Path) -> None:
    """Write a fresh seed to ``key`` and its public key line to ``key``.pub."""
    seed = os.urandom(32)
    key.write_text(seed.hex() + "\n")
    public = bytes(nacl.signing.SigningKey(seed).verify_key)
    line = f"{KEY_TYPE.decode()} {base64.b64encode(public_blob(public)).decode()}"
    Path(str(key) + ".pub").write_text(line + "\n")


def sign(key: Path, namespace: str, message: bytes) -> str:
    """Return the armored SSHSIG over ``message`` by the sk key in ``key``."""
    signer = nacl.signing.SigningKey(bytes.fromhex(key.read_text().strip()))
    preamble = ssh_string(namespace.encode()) + ssh_string(b"") + ssh_string(b"sha512")
    signed = b"SSHSIG" + preamble + ssh_string(hashlib.sha512(message).digest())
    counter = 1
    flags = struct.pack(">BI", USER_PRESENT, counter)
    raw = hashlib.sha256(APPLICATION).digest() + flags + hashlib.sha256(signed).digest()
    signature = ssh_string(KEY_TYPE) + ssh_string(signer.sign(raw).signature) + flags
    public = bytes(signer.verify_key)
    blob = (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + ssh_string(public_blob(public))
        + preamble
        + ssh_string(signature)
    )
    body = "\n".join(textwrap.wrap(base64.b64encode(blob).decode(), 70))
    return f"-----BEGIN SSH SIGNATURE-----\n{body}\n-----END SSH SIGNATURE-----\n"


def main(argv: Sequence[str]) -> int:
    """Run ``keygen KEY`` or ssh-keygen's ``-Y sign`` form."""
    if len(argv) == 2 and argv[0] == "keygen":
        keygen(Path(argv[1]))
        return 0
    args = list(argv)
    if args[:2] != ["-Y", "sign"] or "-n" not in args or "-f" not in args:
        print(f"sk_sign.py: unsupported arguments {args}", file=sys.stderr)
        return 2
    namespace = args[args.index("-n") + 1]
    key = Path(args[args.index("-f") + 1])
    target = Path(args[-1])
    Path(str(target) + ".sig").write_text(sign(key, namespace, target.read_bytes()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

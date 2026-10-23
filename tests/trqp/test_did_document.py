"""git-vouch-trqp did-document: the registry DID document verify-trust discovers.

Oracles: the document is verify-trust's own fixture (VGI
crates/verify-trust/src/registry.rs ``all_three``, commit 5d9b9b6) less its
TSP and DIDComm entries, with the service id made absolute because
affinidi-did-common 0.4.3 parses ``Service.id`` as a URL. That exact
document was fed once through affinidi's ``Document`` and verify-trust's
``choose_route(.., Auto, supported_transports())``, which picked HTTPS at
``https://registry.example/`` (the URL parse adds the slash; trql-client
trims it before appending ``/trust-tasks``). The same run's
``affinidi_did_web::build_url`` gave the URLs below. The did:web URLs are the examples of the did:web method
specification, section 3.2 (https://w3c-ccg.github.io/did-method-web/).
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from trqp.conftest import BRIDGE


def did_document(*args: str) -> subprocess.CompletedProcess[str]:
    """Run ``git-vouch-trqp did-document`` with ``args``."""
    return subprocess.run(
        [sys.executable, str(BRIDGE), "did-document", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_document_is_one_trqprest_service() -> None:
    proc = did_document(
        "--did", "did:web:registry.example", "--endpoint", "https://registry.example"
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:registry.example",
        "service": [
            {
                "id": "did:web:registry.example#rest",
                "type": "TRQPRest",
                "serviceEndpoint": "https://registry.example",
            }
        ],
    }


@pytest.mark.parametrize(
    ("did", "url"),
    [
        ("did:web:w3c-ccg.github.io", "https://w3c-ccg.github.io/.well-known/did.json"),
        (
            "did:web:w3c-ccg.github.io:user:alice",
            "https://w3c-ccg.github.io/user/alice/did.json",
        ),
        ("did:web:example.com%3A3000", "https://example.com:3000/.well-known/did.json"),
        (
            "did:web:example.com%3A3000:user:alice",
            "https://example.com:3000/user/alice/did.json",
        ),
    ],
)
def test_says_where_a_did_web_document_is_served(did: str, url: str) -> None:
    proc = did_document("--did", did, "--endpoint", "https://trqp.example")
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == f"git-vouch-trqp: serve it at {url}\n"
    assert json.loads(proc.stdout)["id"] == did


def test_did_webvh_is_left_to_a_webvh_tool() -> None:
    did = "did:webvh:QmSCID:registry.example"
    proc = did_document("--did", did, "--endpoint", "https://registry.example")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["service"][0]["id"] == did + "#rest"
    assert "webvh tool" in proc.stderr


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://registry.example",
        "HTTP://registry.example",
        "ftp://registry.example",
        "registry.example",
        "https://",
        "https:///trust",
        "https://registry.example?x=1",
        "https://registry.example#rest",
        "https://registry.example:99999",
        "https://registry.example/a b",
        "https://régistry.example",
        "https://user:pass@registry.example",
        "https://evil.example\\@registry.example/",
        "https://registry.example\\trust",
    ],
)
def test_endpoint_must_be_https(endpoint: str) -> None:
    proc = did_document("--did", "did:web:registry.example", "--endpoint", endpoint)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "--endpoint" in proc.stderr


@pytest.mark.parametrize(
    "bad",
    [
        "did:key:z6Mk",
        "https://registry.example",
        "did:web:",
        "did:web:registry.example:",
        "did:web:registry.example::x",
        "did:web:registry.example#rest",
        "did:web:registry.example?x=1",
        "did:web:registry.example/x",
        "did:web:registry.example:user:..",
        "did:web:evil.example%40registry.example",
        "did:web:registry.example:a%2Fb",
        "did:web:registry.example%3A",
        "did:webvh:registry.example",
        "did:webvh:QmSCID:registry.example#rest",
    ],
)
def test_did_document_wants_a_did_web(bad: str) -> None:
    proc = did_document("--did", bad, "--endpoint", "https://registry.example")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "did:web" in proc.stderr

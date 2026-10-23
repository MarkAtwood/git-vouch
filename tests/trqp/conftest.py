"""Fixtures for git-vouch-trqp tests: the bridge run as a real HTTP server.

The schemas under ``schemas/`` are the independent oracle. They are copied
verbatim, upstream paths kept, from the Trust Task spec repository
https://github.com/trustoverip/dtgwg-trust-tasks-tf at commit
9a48a4c67b75737b0226c175c34a6a60799c15e9 (2026-10-22):

- ``specs/_framework/0.5/trust-task.schema.json``: the envelope. The
  registry/authorization 0.1 spec declares targetFrameworkVersion 0.5.0.
- ``specs/registry/authorization/0.1/payload.schema.json``: the request
  payload, with the ``#response`` anchor for the response payload, and the
  two files its ``$ref``s name (``_shared/0.1/registry.schema.json`` and
  ``_framework/0.1/framework.schema.json``).
- ``specs/registry/authorization/0.1/payload.invalid-examples.json``.
- ``specs/trust-task-error/0.5/payload.schema.json``: the error payload,
  the version trust-tasks-rs 0.32.1 (verify-trust's) emits.

The schema oracle needs ``jsonschema`` and ``referencing`` (test-only; both
support 3.9). A missing oracle fails the run rather than skipping it, so
the gates are::

    python3 -m pytest -q tests/trqp
    uv run --python 3.9 --with pytest --with jsonschema --with referencing \
        python -m pytest -q tests/trqp
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import IO, NamedTuple, Union
from urllib.parse import urljoin

import pytest

BRIDGE = Path(__file__).resolve().parent.parent.parent / "git-vouch-trqp"
SCHEMAS = Path(__file__).resolve().parent / "schemas" / "specs"
DID = "did:web:registry.example"

Checker = Callable[[dict, str], None]


class Bridge(NamedTuple):
    """A running git-vouch-trqp serve."""

    port: int

    def call(
        self, body: Union[dict, bytes], method: str = "POST", path: str = "/trust-tasks"
    ) -> tuple[int, str, bytes]:
        """Send ``body`` and return the status, Content-Type and body of the answer."""
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            conn.request(method, path, data, {"Content-Type": "application/json"})
            resp = conn.getresponse()
            return resp.status, resp.getheader("Content-Type", ""), resp.read()
        finally:
            conn.close()

    def announce(self, length: str) -> tuple[int, dict]:
        """Send only headers with Content-Length ``length`` and return the reply.

        Sending no body keeps the server's unread input empty, so its close
        is a clean FIN rather than a reset that could lose the reply.
        """
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            conn.putrequest("POST", "/trust-tasks")
            conn.putheader("Content-Length", length)
            conn.endheaders()
            resp = conn.getresponse()
            assert resp.getheader("Content-Type") == "application/json"
            doc: dict = json.loads(resp.read())
            return resp.status, doc
        finally:
            conn.close()

    def post(self, body: Union[dict, bytes]) -> tuple[int, dict]:
        """POST ``body`` to /trust-tasks and return the status and JSON document."""
        status, content_type, data = self.call(body)
        assert content_type == "application/json", (status, data[:200])
        doc: dict = json.loads(data)
        return status, doc


@pytest.fixture
def serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[Path], Bridge]]:
    """Return a function that starts the bridge in a registry directory.

    The repository root goes first on PATH, so ``git vouch`` runs this
    tree's git-vouch.
    """
    repo = str(BRIDGE.parent)
    monkeypatch.setenv("PATH", repo + os.pathsep + os.environ["PATH"])
    procs: list[subprocess.Popen[str]] = []
    logs: list[IO[str]] = []

    def start(registry: Path, *extra: str) -> Bridge:
        log = (tmp_path / f"bridge-{len(procs)}.log").open("w")
        logs.append(log)
        proc = subprocess.Popen(
            [sys.executable, str(BRIDGE), "serve", "--did", DID, "--port", "0", *extra],
            cwd=registry,
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
        )
        procs.append(proc)
        assert proc.stdout is not None
        line = proc.stdout.readline()
        assert line.startswith("git-vouch-trqp: serving "), line
        return Bridge(int(line.rsplit(":", 1)[1].split("/")[0]))

    yield start
    for proc in procs:
        proc.terminate()
        proc.wait(timeout=10)
        assert proc.stdout is not None
        proc.stdout.close()
    for log in logs:
        log.close()


def schema_oracle() -> tuple[ModuleType, ModuleType]:
    """Return the ``jsonschema`` and ``referencing`` modules, or fail the test.

    Imported lazily so that collecting the other test directories never
    needs them.
    """
    try:
        import jsonschema
        import referencing
    except ImportError as e:
        pytest.fail(f"the schema oracle is missing: {e}; see tests/trqp/conftest.py")
    return jsonschema, referencing


def _load(rel: str) -> dict:
    data: dict = json.loads((SCHEMAS / rel).read_text())
    return data


@pytest.fixture(scope="session")
def check_schema() -> Checker:
    """Return ``check(doc, kind)``, which validates a Trust Task document.

    ``kind`` is "request", "response" or "error". The document must match
    the framework envelope and the payload schema for its kind.
    """
    jsonschema, referencing = schema_oracle()
    envelope = _load("_framework/0.5/trust-task.schema.json")
    payload = _load("registry/authorization/0.1/payload.schema.json")
    error = _load("trust-task-error/0.5/payload.schema.json")
    # The payload's $refs are file-relative upstream; register each file at
    # the URI the ref resolves to against the payload's $id.
    refs = {
        "../../_shared/0.1/registry.schema.json": "registry/_shared/0.1/registry.schema.json",
        "../../../_framework/0.1/framework.schema.json": "_framework/0.1/framework.schema.json",
    }
    resources = [(s["$id"], s) for s in (envelope, payload, error)] + [
        (urljoin(payload["$id"], ref), _load(rel)) for ref, rel in refs.items()
    ]
    registry = referencing.Registry().with_resources(
        (uri, referencing.Resource.from_contents(s)) for uri, s in resources
    )
    ids = {
        "request": payload["$id"],
        "response": payload["$id"] + "#response",
        "error": error["$id"],
    }

    def check(doc: dict, kind: str) -> None:
        jsonschema.Draft202012Validator(envelope).validate(doc)
        jsonschema.Draft202012Validator(
            {"$ref": ids[kind]}, registry=registry
        ).validate(doc["payload"])

    return check


@pytest.fixture(scope="session")
def invalid_payloads() -> list[dict]:
    """Return the spec's own invalid request payloads."""
    examples: list[dict] = json.loads(
        (
            SCHEMAS / "registry/authorization/0.1/payload.invalid-examples.json"
        ).read_text()
    )
    return [e["payload"] for e in examples]

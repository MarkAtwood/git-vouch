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

The schema oracle needs ``jsonschema`` and ``referencing``, and checks
``format`` with ``rfc3339-validator`` (date-time) and ``rfc3986-validator``
(uri) (test-only; all support 3.9). A missing oracle fails the run rather
than skipping it, so the gates are::

    python3 -m pytest -q tests/trqp
    uv run --python 3.9 --with pytest --with jsonschema --with referencing \
        --with rfc3339-validator --with rfc3986-validator \
        python -m pytest -q tests/trqp

Every document ``Bridge.post`` and ``Bridge.announce`` return has passed
the schema oracle for its type.
"""

from __future__ import annotations

import functools
import http.client
import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from typing import IO, NamedTuple, Optional, Union
from urllib.parse import urljoin, urlsplit

import pytest

BRIDGE = Path(__file__).resolve().parent.parent.parent / "git-vouch-trqp"
SCHEMAS = Path(__file__).resolve().parent / "schemas" / "specs"
DID = "did:web:registry.example"
REPLY_KINDS = {
    "https://trusttasks.org/spec/registry/authorization/0.1#response": "response",
    "https://trusttasks.org/spec/trust-task-error/0.5": "error",
}
# Runs the bridge at argv[1] with QUERY_TIMEOUT set to argv[2] seconds unless
# blank, and, unless argv[3] is blank, its monotonic clock ahead by the
# seconds written in the file argv[3] names.
LAUNCH = """import pathlib, sys, time, types
path, timeout, offset, *argv = sys.argv[1:]
bridge = types.ModuleType("bridge")
exec(compile(pathlib.Path(path).read_text(), path, "exec"), bridge.__dict__)
if timeout:
    bridge.QUERY_TIMEOUT = int(timeout)
if offset:
    ahead = pathlib.Path(offset)
    bridge.monotonic = lambda: time.monotonic() + float(ahead.read_text() or 0)
sys.exit(bridge.main(argv))
"""

Checker = Callable[[dict, str], None]


class Bridge(NamedTuple):
    """A running git-vouch-trqp serve."""

    port: int
    host: str = "127.0.0.1"

    def call(
        self, body: Union[dict, bytes], method: str = "POST", path: str = "/trust-tasks"
    ) -> tuple[int, str, bytes]:
        """Send ``body`` and return the status, Content-Type and body of the answer."""
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
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
        conn = http.client.HTTPConnection(self.host, self.port, timeout=60)
        try:
            conn.putrequest("POST", "/trust-tasks")
            conn.putheader("Content-Length", length)
            conn.endheaders()
            resp = conn.getresponse()
            assert resp.getheader("Content-Type") == "application/json"
            doc: dict = json.loads(resp.read())
            check_reply(doc)
            return resp.status, doc
        finally:
            conn.close()

    def post(self, body: Union[dict, bytes]) -> tuple[int, dict]:
        """POST ``body`` to /trust-tasks and return the status and JSON document."""
        status, content_type, data = self.call(body)
        assert content_type == "application/json", (status, data[:200])
        doc: dict = json.loads(data)
        check_reply(doc)
        return status, doc


def check_reply(doc: dict) -> None:
    """Check a reply document against the schema for its type."""
    assert doc.get("type") in REPLY_KINDS, doc
    schema_checker()(doc, REPLY_KINDS[doc["type"]])


@pytest.fixture
def serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[Path], Bridge]]:
    """Return a function that starts the bridge in a registry directory.

    The repository root goes first on PATH, so ``git vouch`` runs this
    tree's git-vouch. Unless ``stamp`` is false, the directory is made a
    git repository if it is not one (no commit, so check still reads it as
    a plain tree) and given the sync stamp ``git vouch sync`` writes,
    ``.git/vouch-fetched``, dated now. A ``query_timeout`` replaces the
    bridge's QUERY_TIMEOUT, in seconds. A ``clock`` file holds how many
    seconds ahead the bridge's monotonic clock reads (blank is none).
    """
    repo = str(BRIDGE.parent)
    monkeypatch.setenv("PATH", repo + os.pathsep + os.environ["PATH"])
    procs: list[subprocess.Popen[str]] = []
    logs: list[IO[str]] = []

    def start(
        registry: Path,
        *extra: str,
        stamp: bool = True,
        query_timeout: Optional[int] = None,
        clock: Optional[Path] = None,
    ) -> Bridge:
        if stamp:
            if not (registry / ".git").exists():
                subprocess.run(["git", "init", "-q", str(registry)], check=True)
            (registry / ".git" / "vouch-fetched").touch()
        log = (tmp_path / f"bridge-{len(procs)}.log").open("w")
        logs.append(log)
        command = [sys.executable, str(BRIDGE)]
        if query_timeout is not None or clock is not None:
            timeout = "" if query_timeout is None else str(query_timeout)
            offset = "" if clock is None else str(clock)
            command = [sys.executable, "-c", LAUNCH, str(BRIDGE), timeout, offset]
        proc = subprocess.Popen(
            [*command, "serve", "--did", DID, "--port", "0", *extra],
            cwd=registry,
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
        )
        procs.append(proc)
        assert proc.stdout is not None
        line = proc.stdout.readline()
        assert line.startswith("git-vouch-trqp: serving "), line
        url = urlsplit(line.split(" at ", 1)[1].strip())
        assert url.hostname is not None and url.port is not None, line
        return Bridge(url.port, url.hostname)

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


@functools.lru_cache(maxsize=None)
def schema_checker() -> Checker:
    """Return ``check(doc, kind)``, which validates a Trust Task document.

    ``kind`` is "request", "response" or "error". The document must match
    the framework envelope and the payload schema for its kind, formats
    included.
    """
    jsonschema, referencing = schema_oracle()
    formats = jsonschema.Draft202012Validator.FORMAT_CHECKER
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
        jsonschema.Draft202012Validator(envelope, format_checker=formats).validate(doc)
        jsonschema.Draft202012Validator(
            {"$ref": ids[kind]}, registry=registry, format_checker=formats
        ).validate(doc["payload"])

    return check


@pytest.fixture(scope="session")
def check_schema() -> Checker:
    """Return the schema oracle's ``check(doc, kind)`` (see ``schema_checker``)."""
    return schema_checker()


@pytest.fixture(scope="session")
def invalid_payloads() -> list[dict]:
    """Return the spec's own invalid request payloads."""
    examples: list[dict] = json.loads(
        (
            SCHEMAS / "registry/authorization/0.1/payload.invalid-examples.json"
        ).read_text()
    )
    return [e["payload"] for e in examples]

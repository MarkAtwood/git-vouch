"""git-vouch-trqp: Trust Task registry/authorization over HTTP (DESIGN.md, TRQP bridge).

Oracles: the upstream Trust Task JSON schemas (see conftest), the HTTPS
binding 0.3 status table, VGI vgi-core/src/resource.rs's own unit-test
vectors (commit 5d9b9b6), and fixture registries signed by real
``ssh-keygen`` whose dids come from test_check's ``did``, not git-vouch.
Every expected ``authorized`` is stated by hand from the fixture.
"""

from __future__ import annotations

import os
import json
import shutil
import socket
import subprocess
import sys
import time as clock
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pytest

from conftest import Key, run_script
from test_check import AFTER, BEFORE, Registry, did, keys  # noqa: F401 (keys is a fixture)
from test_export import reg  # noqa: F401 (reg is a fixture)
from test_query import T0, base, promoted_bot
from test_sync import commit_change, copy_head, data_dir, home, push, remote  # noqa: F401
from trqp.conftest import BRIDGE, DID, Bridge, Checker, schema_oracle

TYPE = "https://trusttasks.org/spec/registry/authorization/0.1"
RESPONSE_TYPE = TYPE + "#response"
ERROR_TYPE = "https://trusttasks.org/spec/trust-task-error/0.5"
ACTION = "git.commit.sign"
RESOURCE = "git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux"
ISSUED = "2026-10-22T12:00:00Z"


def request(
    entity: str,
    *,
    authority: str = DID,
    action: str = ACTION,
    resource: str = RESOURCE,
    time: Optional[str] = None,
) -> dict:
    """Return a request shaped as verify-trust sends it (docs/trqp-interop.md, section 1)."""
    payload: dict[str, object] = {
        "entity_id": entity,
        "authority_id": authority,
        "action": action,
        "resource": resource,
    }
    if time is not None:
        payload["context"] = {"time": time}
    return {
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": TYPE,
        "recipient": DID,
        "issuedAt": ISSUED,
        "payload": payload,
    }


@pytest.fixture
def bridge(reg: Registry, serve: Callable[[Path], Bridge]) -> Bridge:  # noqa: F811
    """Return the bridge serving test_export's registry."""
    return serve(reg.root)


def authorized(bridge: Bridge, req: dict) -> tuple[bool, dict]:
    """Return the answer's ``authorized`` and payload after checking the reply's framing.

    ``Bridge.post`` has checked the reply against the schemas.
    """
    status, doc = bridge.post(req)
    assert status == 200, doc
    assert doc["type"] == RESPONSE_TYPE
    assert doc["threadId"] == req["id"]
    assert doc["issuer"] == DID
    answer = doc["payload"]
    for name in ("entity_id", "authority_id", "action", "resource"):
        assert answer[name] == req["payload"][name]
    evaluated = datetime.strptime(answer["time_evaluated"], "%Y-%m-%dT%H:%M:%SZ")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((now - evaluated).total_seconds()) < 120
    result: bool = answer["authorized"]
    return result, answer


def error(bridge: Bridge, body: dict | bytes) -> tuple[int, dict]:
    """POST ``body`` and return the status and payload of the trust-task-error reply.

    ``Bridge.post`` has checked the reply against the schemas.
    """
    status, doc = bridge.post(body)
    assert doc["type"] == ERROR_TYPE, doc
    assert doc["issuer"] == DID
    return status, doc["payload"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("torvalds", True),  # anchor
        ("gregkh", True),  # maintainer
        ("alice", True),  # contributor
        ("alice2", False),  # revoked
        ("gregkh-old", False),  # retired 2026-06-01
        ("bot", False),  # automation never signs commits
        ("dave", False),  # registered, but no endorsed email
        ("mallory", False),  # not in the registry
    ],
)
def test_who_is_authorized(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    name: str,
    expected: bool,
) -> None:
    assert authorized(bridge, request(did(keys(name))))[0] is expected


@pytest.mark.parametrize(
    ("time", "expected"),
    [
        (BEFORE, True),
        ("2026-05-31T23:59:59.999Z", True),  # sub-second, just before retirement
        ("2026-05-31T19:59:59-04:00", True),
        ("2026-06-01T00:00:00Z", True),  # the retirement second, as check has it
        ("2026-05-31T20:00:00-04:00", True),
        ("2026-06-01T00:00:01Z", False),
        ("2026-05-31T20:00:01-04:00", False),
        (AFTER, False),
    ],
)
def test_context_time(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    time: str,
    expected: bool,
) -> None:
    got, answer = authorized(bridge, request(did(keys("gregkh-old")), time=time))
    assert (got, answer["time_requested"]) == (expected, time)


def test_bot_era_signature_of_since_promoted_handle(
    tmp_path: Path,
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """bot was automation until T1 and is a human contributor since (test_query)."""
    bridge = serve(promoted_bot(tmp_path, keys).root)
    got, answer = authorized(bridge, request(did(keys("bot")), time=T0))
    assert (got, answer["message"]) == (
        False,
        "automation identities do not sign commits",
    )
    assert authorized(bridge, request(did(keys("bot"))))[0] is True


def test_endorsed_after_time_is_not_authorized_then(
    tmp_path: Path,
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """carol, a contributor from the first commit, is endorsed in the second (T1)."""
    r = base(tmp_path, keys)
    r.person("carol", keys("carol"))
    r.tier("carol", "contributor", "gregkh", keys("gregkh"))
    r.commit()
    r.endorse("carol", keys("carol"), "gregkh", keys("gregkh"))
    r.commit()
    bridge = serve(r.root)
    assert authorized(bridge, request(did(keys("carol")), time=T0))[0] is False
    assert authorized(bridge, request(did(keys("carol"))))[0] is True


@pytest.mark.parametrize("time", ["0999-06-01T00:00:00Z", "0001-01-01T00:00:00Z"])
def test_time_before_any_key(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    time: str,
) -> None:
    """A valid early time is answered (no key existed then), not refused as an outage."""
    got, answer = authorized(bridge, request(did(keys("torvalds")), time=time))
    assert (got, answer["time_requested"]) == (False, time)


@pytest.mark.parametrize(
    ("name", "expected"), [("torvalds", True), ("gregkh-old", False)]
)
def test_blank_time_means_now(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    name: str,
    expected: bool,
) -> None:
    """registry.schema.json QueryContext.time: "Blank/absent uses current server time"."""
    got, answer = authorized(bridge, request(did(keys(name)), time=""))
    assert got is expected
    assert "time_requested" not in answer


def test_no_time_requested_without_context(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    _, doc = bridge.post(request(did(keys("torvalds"))))
    assert "time_requested" not in doc["payload"]


@pytest.mark.parametrize(
    "change",
    [
        {"authority": "did:web:other.example"},
        {"action": "git.tag.sign"},
        {"action": ""},
    ],
)
def test_other_authority_or_action_is_denied(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    change: dict[str, str],
) -> None:
    assert authorized(bridge, request(did(keys("torvalds")), **change))[0] is False


@pytest.mark.parametrize(
    "entity",
    [
        "did:web:torvalds.example",
        "--help",
        "did:key:z6Mk$(touch PWNED)",
        "did:key:z6Mk;touch PWNED",
        "",
    ],
)
def test_non_did_key_entity_is_denied(
    bridge: Bridge,
    reg: Registry,  # noqa: F811
    entity: str,
) -> None:
    assert authorized(bridge, request(entity))[0] is False
    assert not (reg.root / "PWNED").exists()


VALID_RESOURCES = [
    # vgi-core resource.rs canonical_resources_pass_through
    "github.com/acme",
    "github.com/acme/widgets",
    "codeberg.org/acme/widgets",
    "git.example.org/acme/.github",
    "ghe.corp.example/team-a/repo_1.x",
    "localhost/acme/widgets",
    # case_is_folded_and_nothing_else; depth_is_the_callers_bound at 21
    "GitHub.com/Acme/Widgets",
    "gitlab.com/Group/Sub/Project",
    # docs/trqp-interop.md section 6: .git is not refused; the kernel's 7 segments
    "git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
    RESOURCE,
    "gitlab.com/" + "/".join(["a"] * 21),  # MAX_PATH_SEGMENTS = 21
]
INVALID_RESOURCES = [
    # vgi-core resource.rs unit tests, each an Err at any depth
    "Acme/Widgets",
    "acme",
    "/acme/widgets",
    "https://github.com/Acme/widgets.git",
    "github.com//widgets",
    "github.com/acme/",
    "/github.com/acme",
    "github.com/acme/..",
    "github.com/./acme",
    "github.com//acme//x",
    "github.com",
    "github.com/",
    "github.com:443/acme",
    "-bad.example/acme",
    "bad..example/acme",
    "git_hub.com/acme",
    "GitHub.com:8443/acme/x",
    "github.com/ac me",
    " github.com/acme",
    "github.com/acmé",
    "github.com/acme/w%2e",
    "github.com/acme@x",
    "",
    "github.com/" + "a" * 600,  # MAX_RESOURCE_LEN = 512
    "é" * 400,
    "gitlab.com/" + "/".join(["a"] * 22),
]


@pytest.mark.parametrize("resource", VALID_RESOURCES)
def test_valid_resource_is_echoed(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    resource: str,
) -> None:
    assert authorized(bridge, request(did(keys("alice")), resource=resource))[0] is True


@pytest.mark.parametrize("resource", INVALID_RESOURCES)
def test_invalid_resource_is_malformed(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
    resource: str,
) -> None:
    req = request(did(keys("alice")), resource=resource)
    status, payload = error(bridge, req)
    assert (status, payload["code"], payload["retryable"]) == (
        400,
        "malformedRequest",
        False,
    )


def with_doc(**changes: object) -> dict:
    """Return a valid request for a random did:key with top-level members changed."""
    doc = request("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
    for name, value in changes.items():
        if value is None:
            del doc[name]
        else:
            doc[name] = value
    return doc


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        (b"", 400, "malformedRequest"),
        (b"not json", 400, "malformedRequest"),
        (b"[1, 2]", 400, "malformedRequest"),
        (b"[" * 60000, 400, "malformedRequest"),  # deep nesting
        (b'{"id": "x"', 400, "malformedRequest"),
        (with_doc(id=None), 400, "malformedRequest"),
        (with_doc(id=""), 400, "malformedRequest"),
        (with_doc(id=7), 400, "malformedRequest"),
        (with_doc(type=None), 400, "malformedRequest"),
        (with_doc(payload=None), 400, "malformedRequest"),
        (with_doc(payload="x"), 400, "malformedRequest"),
        (with_doc(issuer=""), 400, "malformedRequest"),
        (with_doc(issuedAt="yesterday"), 400, "malformedRequest"),
        (with_doc(issuedAt="2026-13-01T00:00:00Z"), 400, "malformedRequest"),
        (
            with_doc(issuedAt="\uff12\uff10\uff12\uff16-01-01T00:00:00Z"),
            400,
            "malformedRequest",
        ),
        (with_doc(recipient=None), 400, "malformedRequest"),  # the spec requires one
        (with_doc(recipient="did:web:elsewhere.example"), 422, "wrongRecipient"),
        (
            with_doc(type="https://trusttasks.org/spec/registry/recognition/0.1"),
            422,
            "unsupportedType",
        ),
        (
            with_doc(type="https://trusttasks.org/spec/registry/authorization/0.2"),
            422,
            "unsupportedVersion",
        ),
        (with_doc(issuedAt="2999-01-01T00:00:00Z"), 400, "malformedRequest"),  # future
        (
            with_doc(expiresAt="2026-01-01T00:00:00Z", issuedAt="2026-01-01T00:00:00Z"),
            400,
            "malformedRequest",
        ),
        (
            with_doc(expiresAt="2026-01-01T00:00:00Z", issuedAt="2025-12-01T00:00:00Z"),
            422,
            "expired",
        ),
        # SPEC.md 4.7 and 7.2 item 7: an unchecked proof is proofInvalid, not absent
        (with_doc(proof={"type": "DataIntegrityProof"}), 422, "proofInvalid"),
    ],
)
def test_refused_documents(
    bridge: Bridge, body: dict | bytes, status: int, code: str
) -> None:
    got_status, payload = error(bridge, body)
    assert (got_status, payload["code"], payload["retryable"]) == (status, code, False)


@pytest.mark.parametrize(
    "length",
    [
        str(64 * 1024 + 1),
        "\u00b2",
        "-1",
        "1e3",
        "1" * 5000,  # past int()'s 4300-digit limit
        "0" * 5000,
    ],
)
def test_bad_content_length_is_malformed(bridge: Bridge, length: str) -> None:
    status, doc = bridge.announce(length)
    assert (status, doc["type"], doc["payload"]["code"]) == (
        400,
        ERROR_TYPE,
        "malformedRequest",
    )


def test_spec_invalid_payloads_are_malformed(
    bridge: Bridge, invalid_payloads: list[dict]
) -> None:
    assert len(invalid_payloads) == 3
    for payload in invalid_payloads:
        status, answer = error(bridge, with_doc(payload=payload))
        assert (status, answer["code"]) == (400, "malformedRequest"), payload


@pytest.mark.parametrize(
    "context",
    [
        {"time": "now"},
        {"time": "2026-03-01"},
        {"time": 7},
        {"time": "\uff12\uff10\uff12\uff16-01-01T00:00:00Z"},  # full-width digits
        {"time": "0001-01-01T00:00:00+01:00"},  # before year 1 in UTC
        {"locator": 7},
        "2026-03-01T00:00:00Z",
    ],
)
def test_bad_context_is_malformed(bridge: Bridge, context: object) -> None:
    doc = with_doc()
    doc["payload"]["context"] = context
    status, payload = error(bridge, doc)
    assert (status, payload["code"]) == (400, "malformedRequest")


def test_ext_and_locator_are_accepted(
    bridge: Bridge,
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    req = request(did(keys("alice")))
    req["payload"]["context"] = {"locator": "anything"}
    req["payload"]["ext"] = {"org.example": {"x": 1}}
    assert authorized(bridge, req)[0] is True


def test_error_echoes_request(bridge: Bridge) -> None:
    doc = with_doc(
        issuer="did:web:client.example", recipient="did:web:elsewhere.example"
    )
    _, reply = bridge.post(doc)
    assert reply["threadId"] == doc["id"]
    assert reply["recipient"] == "did:web:client.example"
    assert reply["payload"]["inResponseTo"] == {"typeUri": TYPE, "id": doc["id"]}


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/trust-tasks", 405),
        ("PUT", "/trust-tasks", 405),
        ("POST", "/authorization", 404),
        ("POST", "/trust-tasks/", 404),
        ("POST", "/", 404),
        ("GET", "/", 404),
    ],
)
def test_other_methods_and_paths(
    bridge: Bridge, method: str, path: str, status: int
) -> None:
    got, content_type, _ = bridge.call(b"{}", method=method, path=path)
    assert got == status
    assert (
        content_type != "application/json"
    )  # not a framework document (binding section 2)


def test_registry_check_failure_is_unavailable(
    reg: Registry,  # noqa: F811
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    """The client gets a generic 503; the log says why, on one escaped line."""
    (reg.root / "people" / "zed.json").write_text('{"handle": "zed"')
    status, payload = error(serve(reg.root), request(did(keys("torvalds"))))
    assert (status, payload["code"], payload["retryable"]) == (503, "unavailable", True)
    assert "zed" not in payload["message"]
    logged = [
        line
        for line in (tmp_path / "bridge-0.log").read_text().splitlines()
        if line.startswith("git-vouch-trqp: git vouch query exited ")
    ]
    # git vouch query names no file; its error is what there is to log.
    assert logged == [
        "git-vouch-trqp: git vouch query exited 1: 'git-vouch: error: "
        "the registry check failed; run git vouch check .'"
    ]


def test_missing_git_vouch_is_unavailable(
    reg: Registry,  # noqa: F811
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = serve(reg.root)
    # the bridge already runs; a fresh one without git-vouch on PATH is what matters
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    bare = serve(reg.root)
    assert authorized(bridge, request(did(keys("torvalds"))))[0] is True
    status, payload = error(bare, request(did(keys("torvalds"))))
    assert (status, payload["code"], payload["retryable"]) == (503, "unavailable", True)


def stub_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str, other: str = ":"
) -> None:
    """Put a ``git`` first on PATH for bridges started next.

    ``git vouch`` runs the shell ``script``; any other git command runs the
    shell ``other`` and then real git.
    """
    real = shutil.which("git")
    stub = tmp_path / "stub"
    stub.mkdir()
    git = stub / "git"
    git.write_text(
        f'#!/bin/sh\nif [ "$1" != vouch ]; then\n{other}\nexec "{real}" "$@"\nfi\n'
        + script
        + "\n"
    )
    git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stub}{os.pathsep}{os.environ['PATH']}")


def test_unexpected_failure_is_a_bare_internal_error(
    reg: Registry,  # noqa: F811
    serve: Callable[[Path], Bridge],
    check_schema: Checker,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Output that is not UTF-8 is no TaskError: the trace goes to the log only."""
    stub_git(tmp_path, monkeypatch, "printf '\\377'")
    bridge = serve(reg.root)
    status, _, body = bridge.call(with_doc())
    doc = json.loads(body)
    assert (status, doc["payload"]["code"], doc["payload"]["retryable"]) == (
        500,
        "internalError",
        False,
    )
    assert b"Traceback" not in body
    assert "Traceback" in (tmp_path / "bridge-0.log").read_text()
    check_schema(doc, "error")


def test_concurrent_queries_are_capped(
    reg: Registry,  # noqa: F811
    serve: Callable[[Path], Bridge],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Six queries at once against a 3 s registry: four run, two get a retryable 503."""
    answer = (
        '{"handle": "x", "valid": true, "automation": false, "emails": ["x@x.org"]}'
    )
    stub_git(tmp_path, monkeypatch, f"sleep 3; printf '%s' '{answer}'")
    bridge = serve(reg.root)
    with ThreadPoolExecutor(6) as pool:
        replies = list(pool.map(lambda _: bridge.post(with_doc()), range(6)))
    assert sorted(status for status, _ in replies) == [200] * 4 + [503] * 2
    for status, doc in replies:
        if status == 503:
            assert (doc["payload"]["code"], doc["payload"]["retryable"]) == (
                "unavailable",
                True,
            )


def test_failure_log_is_bounded_and_escaped(
    reg: Registry,  # noqa: F811
    serve: Callable[[Path], Bridge],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only git-vouch's last stderr line is logged, escaped, at most 300 characters."""
    stub_git(
        tmp_path,
        monkeypatch,
        "echo early >&2; printf 'x\\033[2J%05000d\\n' 0 >&2; exit 3",
    )
    status, payload = error(serve(reg.root), with_doc())
    assert (status, payload["code"]) == (503, "unavailable")
    lines = (tmp_path / "bridge-0.log").read_text().splitlines()
    logged = [line for line in lines if "git vouch query exited 3: " in line]
    assert len(logged) == 1, lines
    assert logged[0].startswith(
        "git-vouch-trqp: git vouch query exited 3: 'x\\x1b[2J000"
    )
    assert "\033" not in logged[0] and "early" not in logged[0]
    assert len(logged[0]) == len("git-vouch-trqp: git vouch query exited 3: ") + 300


def test_query_timeout_kills_the_whole_query(
    reg: Registry,  # noqa: F811
    serve: Callable[..., Bridge],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timed-out query's children die with it before its slot is freed.

    git runs git-vouch as a child, so killing git alone left the registry
    check running. Here the stub git's background sleep stands in for it.
    """
    pid_file = tmp_path / "child.pid"
    stub_git(tmp_path, monkeypatch, f'sleep 60 & echo $! > "{pid_file}"; wait')
    bridge = serve(reg.root, query_timeout=2)
    started = clock.monotonic()
    status, payload = error(bridge, with_doc())
    assert (status, payload["code"], payload["retryable"]) == (503, "unavailable", True)
    assert clock.monotonic() - started < 30
    child = int(pid_file.read_text())
    deadline = clock.monotonic() + 5  # init reaps the killed child
    while clock.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        clock.sleep(0.05)
    else:
        os.kill(child, 9)
        pytest.fail("the timed-out query's child survived")
    log = (tmp_path / "bridge-0.log").read_text()
    assert "git-vouch-trqp: git vouch timed out after 2s" in log


def test_serve_on_a_port_in_use_fails_cleanly() -> None:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        port = str(taken.getsockname()[1])
        proc = subprocess.run(
            [sys.executable, str(BRIDGE), "serve", "--did", DID, "--port", port],
            capture_output=True,
            text=True,
            timeout=30,
        )
    assert proc.returncode == 1
    assert proc.stderr.startswith(
        f"git-vouch-trqp: cannot listen on 127.0.0.1:{port}: "
    )
    assert "Traceback" not in proc.stderr


@pytest.mark.parametrize(("port", "status"), [("70000", 2), ("-1", 2)])
def test_serve_wants_a_port(port: str, status: int) -> None:
    proc = subprocess.run(
        [sys.executable, str(BRIDGE), "serve", "--did", DID, "--port", port],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == status
    assert "--port" in proc.stderr and "Traceback" not in proc.stderr


def test_serve_binds_ipv6(
    reg: Registry,  # noqa: F811
    serve: Callable[..., Bridge],
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    v6 = serve(reg.root, "--bind", "::1")
    assert v6.host == "::1"
    assert authorized(v6, request(did(keys("torvalds"))))[0] is True


@pytest.mark.parametrize(
    ("bind", "host"), [("", "0.0.0.0"), ("localhost", "127.0.0.1")]
)
def test_serve_binds_names_and_all_on_ipv4(
    reg: Registry,  # noqa: F811
    serve: Callable[..., Bridge],
    keys: Callable[[str], Key],  # noqa: F811
    bind: str,
    host: str,
) -> None:
    """'' and 'localhost' listen on IPv4 as before, where a proxy expects them."""
    bridge = serve(reg.root, "--bind", bind)
    assert bridge.host == host
    assert authorized(bridge, request(did(keys("torvalds"))))[0] is True


@pytest.mark.parametrize(
    "bad", ["did:key:z6Mk", "https://registry.example", "did:web:"]
)
def test_serve_wants_a_did_web(bad: str, tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(BRIDGE), "serve", "--did", bad, "--port", "0"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 2
    assert "did:web" in proc.stderr


# Schema conformance of requests, and a guard on the oracle itself. Every
# reply is checked by Bridge.post and Bridge.announce.


def test_verify_trust_example_request_is_valid(check_schema: Checker) -> None:
    """The docs/trqp-interop.md section 1 example and this file's builder both conform."""
    example = {
        "id": "urn:uuid:7c0e0000-0000-4000-8000-000000000000",
        "type": TYPE,
        "recipient": "did:web:registry.example",
        "issuedAt": "2026-10-22T12:00:00Z",
        "payload": {
            "entity_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "authority_id": "did:web:vtc.example",
            "action": "git.commit.sign",
            "resource": RESOURCE,
        },
    }
    check_schema(example, "request")
    check_schema(request("did:key:z6Mk", time=BEFORE), "request")


def test_spec_invalid_payloads_fail_the_schema(
    check_schema: Checker, invalid_payloads: list[dict]
) -> None:
    """Guard the oracle: the schema validator really rejects the spec's bad payloads."""
    jsonschema = schema_oracle()[0]
    for payload in invalid_payloads:
        with pytest.raises(jsonschema.ValidationError):
            check_schema(with_doc(payload=payload), "request")


@pytest.mark.parametrize(
    "change",
    [
        {"issuedAt": "not a date"},  # needs rfc3339-validator
        {"issuedAt": "2026-10-22 12:00:00"},
        {"type": "not a uri"},  # needs rfc3986-validator
    ],
)
def test_oracle_checks_formats(check_schema: Checker, change: dict[str, str]) -> None:
    """Guard the oracle: a missing format package fails here, not silently."""
    jsonschema = schema_oracle()[0]
    check_schema(with_doc(), "request")
    with pytest.raises(jsonschema.ValidationError):
        check_schema(with_doc(**change), "request")


EXT = "org.kernel.git-vouch"


def age_stamp(registry: Path, hours: float) -> None:
    """Date the sync stamp ``git vouch sync`` writes (``.git/vouch-fetched``) ``hours`` ago."""
    then = clock.time() - hours * 3600
    os.utime(registry / ".git" / "vouch-fetched", (then, then))


def stamp_time(registry: Path) -> str:
    mtime = (registry / ".git" / "vouch-fetched").stat().st_mtime
    return datetime.fromtimestamp(mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def assert_stale(bridge: Bridge, req: dict) -> None:
    """Assert the bridge refuses ``req`` with the retryable error verify-trust fails closed on."""
    status, payload = error(bridge, req)
    assert (status, payload["code"], payload["retryable"]) == (503, "unavailable", True)
    assert "synced" in payload["message"]


@pytest.mark.parametrize(
    ("hours", "fresh"),
    [(23.9, True), (24.1, False), (720, False), (-0.05, True), (-1, False)],
)
def test_stale_registry_is_refused(
    bridge: Bridge,
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
    hours: float,
    fresh: bool,
) -> None:
    """Refused once 24 hours pass without a successful sync (DESIGN.md, Freshness).

    A stamp dated past the 5 minute clock skew ahead is refused too: a clock
    set back after a sync would otherwise keep it fresh indefinitely.
    """
    age_stamp(reg.root, hours)
    req = request(did(keys("torvalds")))
    if fresh:
        assert authorized(bridge, req)[0] is True
    else:
        assert_stale(bridge, req)
        assert stamp_time(reg.root) in error(bridge, req)[1]["message"]


def test_stale_registry_refuses_even_a_denial(
    bridge: Bridge,
    reg: Registry,  # noqa: F811
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    age_stamp(reg.root, 25)
    assert_stale(bridge, request(did(keys("torvalds")), authority="did:web:x.example"))


def test_stale_registry_still_reports_malformed_requests(
    bridge: Bridge,
    reg: Registry,  # noqa: F811
) -> None:
    age_stamp(reg.root, 25)
    status, payload = error(bridge, with_doc(recipient="did:web:elsewhere.example"))
    assert (status, payload["code"]) == (422, "wrongRecipient")


@pytest.mark.parametrize("is_repo", [False, True])
def test_never_synced_registry_is_refused(
    reg: Registry,  # noqa: F811
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
    is_repo: bool,
) -> None:
    """No vouch-fetched stamp, or no git directory to hold one: refused."""
    if is_repo:
        subprocess.run(["git", "init", "-q", str(reg.root)], check=True)
    status, payload = error(
        serve(reg.root, stamp=False), request(did(keys("torvalds")))
    )
    assert (status, payload["code"], payload["retryable"]) == (503, "unavailable", True)
    assert payload["message"] == (
        "the registry copy was never synced"
        if is_repo
        else "the registry is not a git repository"
    )


def test_answer_reports_commit_and_sync_time(
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
    check_schema: Checker,
) -> None:
    root = promoted_bot(tmp_path, keys).root
    bridge = serve(root)
    age_stamp(root, 2)
    status, doc = bridge.post(request(did(keys("gregkh"))))
    assert status == 200
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert doc["payload"]["ext"] == {EXT: {"commit": head, "synced": stamp_time(root)}}
    check_schema(doc, "response")


def test_answer_without_commit_reports_none(bridge: Bridge, reg: Registry) -> None:  # noqa: F811
    status, doc = bridge.post(with_doc())
    assert status == 200
    assert doc["payload"]["ext"] == {
        EXT: {"commit": None, "synced": stamp_time(reg.root)}
    }


def test_bridge_follows_git_vouch_sync(
    home: Path,  # noqa: F811
    reg: Registry,  # noqa: F811
    remote: Path,  # noqa: F811
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
    tmp_path: Path,
) -> None:
    """Deployed as DESIGN.md says: the bridge runs in the copy a sync timer keeps.

    A failed sync exits non-zero with a reason and leaves the stamp alone, so
    the bridge refuses once the last successful sync is 24 hours old; the
    next successful sync brings it back at the new commit.
    """
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    copy = data_dir(home) / "registry"
    bridge = serve(copy, stamp=False)
    req = request(did(keys("torvalds")))
    status, doc = bridge.post(req)
    assert (status, doc["payload"]["authorized"]) == (200, True)
    assert doc["payload"]["ext"][EXT]["commit"] == copy_head(home)
    age_stamp(copy, 25)
    gone = tmp_path / "gone.git"
    remote.rename(gone)
    proc = run_script("sync")
    assert proc.returncode == 1
    assert "cannot fetch the registry" in proc.stderr
    assert_stale(bridge, req)
    gone.rename(remote)
    new = commit_change(reg)
    push(reg, remote)
    proc = run_script("sync")
    assert proc.returncode == 0, proc.stderr
    status, doc = bridge.post(req)
    assert (status, doc["payload"]["authorized"]) == (200, True)
    assert doc["payload"]["ext"][EXT]["commit"] == new


def test_freshness_checks_the_copy_query_reads(
    home: Path,  # noqa: F811
    reg: Registry,  # noqa: F811
    remote: Path,  # noqa: F811
    serve: Callable[[Path], Bridge],
    keys: Callable[[str], Key],  # noqa: F811
) -> None:
    """Once setup has run, query reads the synced copy whatever the bridge's cwd.

    The bridge starts in another, freshly stamped repository, yet reports and
    gates on the synced copy, which is the one that answers.
    """
    assert run_script("setup", "--registry", str(remote)).returncode == 0
    copy = data_dir(home) / "registry"
    bridge = serve(reg.root)
    req = request(did(keys("torvalds")))
    status, doc = bridge.post(req)
    assert status == 200
    assert doc["payload"]["ext"] == {
        EXT: {"commit": copy_head(home), "synced": stamp_time(copy)}
    }
    age_stamp(copy, 25)
    assert_stale(bridge, req)


def test_freshness_check_waits_for_a_slot(
    reg: Registry,  # noqa: F811
    serve: Callable[[Path], Bridge],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past the cap of four, a request gets a retryable 503 before git rev-parse runs."""
    answer = (
        '{"handle": "x", "valid": true, "automation": false, "emails": ["x@x.org"]}'
    )
    log = tmp_path / "rev-parse.log"
    other = f'case " $* " in *" rev-parse "*) echo x >> "{log}"; sleep 3;; esac'
    stub_git(tmp_path, monkeypatch, f"printf '%s' '{answer}'", other)
    bridge = serve(reg.root)
    with ThreadPoolExecutor(6) as pool:
        replies = list(pool.map(lambda _: bridge.post(with_doc()), range(6)))
    assert sorted(status for status, _ in replies) == [200] * 4 + [503] * 2
    assert log.read_text().count("x") == 4

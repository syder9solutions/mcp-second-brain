"""Comprehensive tests for the MCP Second Brain server.

Coverage by layer (see fullstack-testing skill):
* Contract/schema: Poka-Yoke validation, pinned versions, strict schemas.
* Domain: sandbox containment, hybrid search, bi-directional links.
* Protocol: JSON-RPC dispatcher, initialize/ping/list/call/read.
* Transport: stdio newline JSON-RPC loop, HTTP JSON-RPC + REST + SSE.
* Assembled flow: REST call -> durable markdown persistence -> resource read.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src import api
from src.models import (
    PROTOCOL_VERSION,
    TOOL_VERSION,
    CreateNoteInput,
    GetNoteInput,
    LinkNotesInput,
    SearchNotesInput,
)
from src.server import MCPProtocolError, MCPServer
from src.stdio import run_stdio
from src.vault import SandboxedVaultEngine


@pytest.fixture
def vault_dir(tmp_path: Path) -> Path:
    """An isolated vault seeded from the project's core_vault.md."""
    seed = Path(__file__).resolve().parent.parent / "vault" / "core_vault.md"
    target = tmp_path / "vault"
    target.mkdir()
    target.mkdir(exist_ok=True)
    (target / "core_vault.md").write_text(seed.read_text(encoding="utf-8"), encoding="utf-8")
    return target


@pytest.fixture
def server(vault_dir: Path) -> MCPServer:
    return MCPServer(vault_dir=vault_dir)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, vault_dir: Path) -> TestClient:
    """An API client wired to an isolated server (no shared global state)."""
    isolated = MCPServer(vault_dir=vault_dir)
    monkeypatch.setattr(api, "server", isolated)
    return TestClient(api.app)


# -- tool discovery & pinned schemas ----------------------------------------

def test_tool_listing_has_four_pinned_tools(server: MCPServer) -> None:
    tools = server.list_tools()
    assert [t.name for t in tools] == ["search_notes", "get_note", "create_note", "link_notes"]
    assert all(t.version == TOOL_VERSION for t in tools)
    assert all(t.inputSchema.get("additionalProperties") is False for t in tools)


def test_resource_listing_uses_vault_uri_scheme(server: MCPServer) -> None:
    resources = server.list_resources()
    assert resources
    assert all(r.uri.startswith("vault://notes/") for r in resources)
    assert any(r.uri == "vault://notes/note-arch-001" for r in resources)


# -- schema validation (Poka-Yoke) ------------------------------------------

@pytest.mark.parametrize(
    "factory,kwargs",
    [
        (SearchNotesInput, {"query": "x"}),
        (SearchNotesInput, {"query": "valid", "top_k": 0}),
        (SearchNotesInput, {"query": "valid", "top_k": 99}),
        (GetNoteInput, {"note_id": "../../etc/passwd"}),
        (CreateNoteInput, {"note_id": "note-x/../evil", "title": "abc", "content": "valid content"}),
        (CreateNoteInput, {"note_id": "note-x", "title": "abc", "content": "valid content", "extra": 1}),
        (LinkNotesInput, {"source_note_id": "bad", "target_note_id": "note-sec-002"}),
    ],
)
def test_invalid_inputs_are_unrepresentable(factory: type, kwargs: dict) -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        factory(**kwargs)


# -- domain operations -------------------------------------------------------

def test_hybrid_search_returns_ranked_results(server: MCPServer) -> None:
    envelope = server.execute_tool("search_notes", {"query": "consensus WAL etcd", "top_k": 2})
    results = envelope["structuredContent"]["results"]
    assert results
    assert results[0]["note_id"] == "note-arch-001"
    assert 0.0 < results[0]["score"] < 1.0


def test_get_note_by_exact_id(server: MCPServer) -> None:
    envelope = server.execute_tool("get_note", {"note_id": "note-arch-001"})
    assert envelope["structuredContent"]["note"]["title"] == "Architecture Invariants"


def test_create_note_persists_to_vault(server: MCPServer, vault_dir: Path) -> None:
    envelope = server.execute_tool(
        "create_note",
        {"note_id": "note-new-001", "title": "New Note", "content": "Some durable content here."},
    )
    assert envelope["structuredContent"]["status"] == "created"
    on_disk = vault_dir / "note-new-001.md"
    assert on_disk.exists()
    assert "Some durable content here." in on_disk.read_text(encoding="utf-8")
    assert server.execute_tool("get_note", {"note_id": "note-new-001"})["structuredContent"]["note"]["note_id"] == "note-new-001"


def test_link_notes_is_bidirectional_and_durable(server: MCPServer, vault_dir: Path) -> None:
    server.execute_tool(
        "link_notes",
        {"source_note_id": "note-arch-001", "target_note_id": "note-sec-002", "relationship": "informs"},
    )
    source = server.engine.get_note("note-arch-001")
    target = server.engine.get_note("note-sec-002")
    assert any("note-sec-002" in link for link in source.outgoing_links)
    assert any("note-arch-001" in link for link in target.incoming_links)
    assert "[[note-sec-002 (informs)]]" in (vault_dir / "note-arch-001.md").read_text(encoding="utf-8")
    assert "[[note-arch-001 (informs)]]" in (vault_dir / "note-sec-002.md").read_text(encoding="utf-8")


def test_unknown_tool_raises_protocol_error(server: MCPServer) -> None:
    with pytest.raises(MCPProtocolError):
        server.execute_tool("drop_all_tables", {})


# -- sandbox red-team --------------------------------------------------------

@pytest.mark.parametrize(
    "attack_id",
    [
        "../../etc/passwd",
        "/etc/shadow",
        "..\\..\\windows\\system32",
        "note-x/../../secret",
        "note-x\x00../../etc/passwd",
        "....//....//etc/passwd",
    ],
)
def test_traversal_attacks_are_blocked(server: MCPServer, attack_id: str) -> None:
    with pytest.raises(MCPProtocolError):
        server.execute_tool(
            "create_note",
            {"note_id": attack_id, "title": "Malicious Note", "content": "payload injection"},
        )


def test_engine_direct_sandbox_check_blocks_traversal(server: MCPServer) -> None:
    with pytest.raises(PermissionError):
        server.engine._validate_path_sandbox("../../etc/passwd")


def test_symlink_escape_is_blocked(vault_dir: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.md"
    outside.write_text("secret", encoding="utf-8")
    link = vault_dir / "note-link.md"
    link.symlink_to(outside)
    engine = SandboxedVaultEngine(vault_dir)
    # A pre-planted symlink whose target is outside the vault must never be
    # written through: _write_atomic re-validates containment after resolve().
    with pytest.raises(PermissionError):
        engine._write_atomic(link, "overwrite")
    assert outside.read_text(encoding="utf-8") == "secret"  # unchanged
    # The public path validator also rejects the symlink's canonical escape.
    with pytest.raises(PermissionError):
        engine._validate_path_sandbox("note-link.md")


# -- JSON-RPC protocol dispatcher -------------------------------------------

def test_protocol_initialize_and_capabilities(server: MCPServer) -> None:
    resp = server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "test", "version": "1"}}}
    )
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert "tools" in resp["result"]["capabilities"]
    assert "resources" in resp["result"]["capabilities"]


def test_protocol_list_and_call_tools(server: MCPServer) -> None:
    listing = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert len(listing["result"]["tools"]) == 4
    called = server.handle_message(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "get_note", "arguments": {"note_id": "note-arch-001"}}}
    )
    assert "Architecture Invariants" in called["result"]["content"][0]["text"]


def test_protocol_resources_and_ping(server: MCPServer) -> None:
    resources = server.handle_message({"jsonrpc": "2.0", "id": 4, "method": "resources/list"})
    assert resources["result"]["resources"]
    read = server.handle_message(
        {"jsonrpc": "2.0", "id": 5, "method": "resources/read",
         "params": {"uri": "vault://notes/note-arch-001"}}
    )
    assert "Architecture Invariants" in read["result"]["contents"][0]["text"]
    assert server.handle_message({"jsonrpc": "2.0", "id": 6, "method": "ping"})["result"] == {}


def test_protocol_errors_and_notifications(server: MCPServer) -> None:
    unknown = server.handle_message({"jsonrpc": "2.0", "id": 7, "method": "does/not/exist"})
    assert unknown["error"]["code"] == -32601
    bad_version = server.handle_message({"jsonrpc": "1.0", "id": 8, "method": "ping"})
    assert bad_version["error"]["code"] == -32600
    assert server.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    ) is None


def test_json_rpc_batching(server: MCPServer) -> None:
    batch = [
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    responses = [server.handle_message(m) for m in batch]
    assert responses[0]["result"] == {}
    assert len(responses[1]["result"]["tools"]) == 4
    assert responses[2] is None


# -- stdio transport ---------------------------------------------------------

def test_stdio_transport_roundtrip(server: MCPServer) -> None:
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        "not valid json",
    ]
    out = io.StringIO()
    run_stdio(server, stdin=io.StringIO("\n".join(lines) + "\n"), stdout=out)
    responses = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    assert len(responses) == 3  # initialize, tools/list, parse error -- no notification reply
    assert responses[0]["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert len(responses[1]["result"]["tools"]) == 4
    assert responses[2]["error"]["code"] == -32700


# -- HTTP transport ----------------------------------------------------------

def test_rest_endpoints(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "healthy"
    tools = client.get("/mcp/v1/tools/list").json()["tools"]
    assert len(tools) == 4
    called = client.post(
        "/mcp/v1/tools/call",
        json={"name": "get_note", "arguments": {"note_id": "note-arch-001"}},
    )
    assert called.status_code == 200
    assert called.json()["raw_result"]["note"]["title"] == "Architecture Invariants"
    resources = client.get("/mcp/v1/resources/list").json()["resources"]
    assert resources
    read = client.post(
        "/mcp/v1/resources/read", json={"uri": "vault://notes/note-arch-001"}
    )
    assert read.status_code == 200
    assert "Architecture Invariants" in read.json()["contents"][0]["text"]


def test_http_json_rpc_endpoint(client: TestClient) -> None:
    resp = client.post(
        "/mcp/v1/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "search_notes", "arguments": {"query": "circuit breaker SRE"}}},
    )
    assert resp.status_code == 200
    assert "note-ops-003" in resp.json()["result"]["content"][0]["text"]


def test_sse_stream_emits_endpoint_event(client: TestClient) -> None:
    with client.stream("GET", "/sse") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        iterator = response.iter_lines()
        assert next(iterator) == "event: endpoint"
        assert next(iterator).startswith("data: /messages?session_id=")


def test_rest_rejects_path_traversal(client: TestClient) -> None:
    resp = client.post(
        "/mcp/v1/tools/call",
        json={"name": "create_note",
              "arguments": {"note_id": "../../etc/passwd", "title": "Hack", "content": "Malicious payload"}},
    )
    assert resp.status_code == 400
    assert resp.json()["isError"] is True


# -- assembled critical flow -------------------------------------------------

def test_assembled_create_link_read_flow(client: TestClient, vault_dir: Path) -> None:
    """REST create -> durable file -> REST link -> resource read proves the slice."""
    created = client.post(
        "/mcp/v1/tools/call",
        json={"name": "create_note",
              "arguments": {"note_id": "note-flow-001", "title": "Flow Note", "content": "Assembled flow content."}},
    )
    assert created.status_code == 200 and not created.json()["isError"]
    assert (vault_dir / "note-flow-001.md").exists()

    linked = client.post(
        "/mcp/v1/tools/call",
        json={"name": "link_notes",
              "arguments": {"source_note_id": "note-flow-001", "target_note_id": "note-arch-001"}},
    )
    assert linked.status_code == 200 and not linked.json()["isError"]

    resource = client.post(
        "/mcp/v1/resources/read", json={"uri": "vault://notes/note-flow-001"}
    )
    assert resource.status_code == 200
    assert "Flow Note" in resource.json()["contents"][0]["text"]

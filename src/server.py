"""Model Context Protocol (MCP) server core, compliant with spec revision 2024-11-05.

Responsibilities
----------------
* Expose the four vault tools with pinned, Poka-Yoke schemas.
* Expose notes as ``vault://notes/{note_id}`` resources.
* Answer JSON-RPC 2.0 protocol methods used by both transports:
  ``initialize``, ``notifications/initialized``, ``ping``, ``tools/list``,
  ``tools/call``, ``resources/list``, ``resources/read``, ``resources/templates/list``.

The same :class:`MCPServer` instance backs stdio and HTTP/SSE, so both
transports expose identical behavior.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.models import (
    PROTOCOL_VERSION,
    TOOL_VERSION,
    CreateNoteInput,
    GetNoteInput,
    LinkNotesInput,
    MCPResourceDefinition,
    MCPToolDefinition,
    Note,
    SearchNotesInput,
)
from src.vault import SandboxedVaultEngine


class MCPProtocolError(Exception):
    """A JSON-RPC error with a numeric code, raised by protocol handlers."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


# Standard JSON-RPC 2.0 error codes.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class MCPServer:
    """Protocol-agnostic MCP server over the sandboxed vault engine."""

    def __init__(self, vault_dir: Path | None = None, *, seed: bool = True):
        root = Path(__file__).resolve().parent.parent
        self.vault_dir = Path(vault_dir) if vault_dir is not None else (root / "vault")
        self.engine = SandboxedVaultEngine(self.vault_dir, seed=seed)
        self.server_info = {
            "name": "second-brain-mcp",
            "version": TOOL_VERSION,
        }
        self.protocol_version = PROTOCOL_VERSION

    # -- capability discovery ------------------------------------------------

    def capabilities(self) -> dict[str, Any]:
        return {
            "tools": {"listChanged": False},
            "resources": {"subscribe": False, "listChanged": False},
        }

    def initialize(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Negotiate the protocol version and advertise capabilities."""
        params = params or {}
        requested = params.get("protocolVersion")
        # We implement exactly one revision; echo it on a match, otherwise
        # return our version so the client can decide whether to continue.
        version = self.protocol_version if requested == self.protocol_version else self.protocol_version
        return {
            "protocolVersion": version,
            "capabilities": self.capabilities(),
            "serverInfo": self.server_info,
        }

    def list_tools(self) -> list[MCPToolDefinition]:
        return [
            MCPToolDefinition(
                name="search_notes",
                description=(
                    "Hybrid BM25 and dense-embedding search across the personal "
                    "knowledge vault, fused with reciprocal rank fusion."
                ),
                version=TOOL_VERSION,
                inputSchema=SearchNotesInput.model_json_schema(),
            ),
            MCPToolDefinition(
                name="get_note",
                description="Fetch the full content of one note by its exact note ID.",
                version=TOOL_VERSION,
                inputSchema=GetNoteInput.model_json_schema(),
            ),
            MCPToolDefinition(
                name="create_note",
                description=(
                    "Create a note inside the sandboxed vault directory. IDs must "
                    "match note-[A-Za-z0-9_-]+; paths are rejected."
                ),
                version=TOOL_VERSION,
                inputSchema=CreateNoteInput.model_json_schema(),
            ),
            MCPToolDefinition(
                name="link_notes",
                description="Create a bidirectional reference between two existing notes.",
                version=TOOL_VERSION,
                inputSchema=LinkNotesInput.model_json_schema(),
            ),
        ]

    def list_resources(self) -> list[MCPResourceDefinition]:
        return [
            MCPResourceDefinition(
                uri=f"vault://notes/{nid}",
                name=note.title,
                description=f"Vault note tagged: {', '.join(note.tags) or 'untagged'}",
                mimeType="text/markdown",
            )
            for nid, note in self.engine.notes.items()
        ]

    def list_resource_templates(self) -> list[dict[str, str]]:
        return [
            {
                "uriTemplate": "vault://notes/{note_id}",
                "name": "Vault note",
                "description": "A single note in the sandboxed vault.",
                "mimeType": "text/markdown",
            }
        ]

    def read_resource(self, uri: str) -> dict[str, Any]:
        prefix = "vault://notes/"
        if not uri.startswith(prefix):
            raise ValueError(f"Invalid resource URI '{uri}'; must start with '{prefix}'")
        nid = uri[len(prefix) :]
        if "/" in nid or ".." in nid:
            raise PermissionError(f"Security Sandbox Violation: unsafe resource ID '{nid}'")
        note = self.engine.get_note(nid)
        return {
            "uri": uri,
            "mimeType": "text/markdown",
            "text": f"# {note.title}\n\n{note.content}",
        }

    # -- tool execution ------------------------------------------------------

    @staticmethod
    def _as_text_result(payload: Any) -> dict[str, Any]:
        """Wrap a tool result in the MCP ``CallToolResult`` shape."""
        return {
            "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
            "isError": False,
            "structuredContent": payload,
        }

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Validate inputs with Poka-Yoke schemas, then dispatch the tool."""
        try:
            if name == "search_notes":
                inp = SearchNotesInput(**arguments)
                results = self.engine.search_notes(
                    inp.query, top_k=inp.top_k, tag_filter=inp.tag_filter
                )
                return self._as_text_result(
                    {
                        "results": [
                            {
                                "note_id": n.note_id,
                                "title": n.title,
                                "tags": n.tags,
                                "score": score,
                                "preview": n.content[:160] + ("..." if len(n.content) > 160 else ""),
                            }
                            for n, score in results
                        ]
                    }
                )

            if name == "get_note":
                inp = GetNoteInput(**arguments)
                note = self.engine.get_note(inp.note_id)
                return self._as_text_result({"note": note.model_dump()})

            if name == "create_note":
                inp = CreateNoteInput(**arguments)
                note = Note(
                    note_id=inp.note_id,
                    title=inp.title,
                    content=inp.content,
                    tags=inp.tags,
                    created_at=time.time(),
                )
                created = self.engine.create_note(note)
                return self._as_text_result(
                    {"status": "created", "note": created.model_dump()}
                )

            if name == "link_notes":
                inp = LinkNotesInput(**arguments)
                self.engine.link_notes(
                    inp.source_note_id, inp.target_note_id, inp.relationship
                )
                return self._as_text_result(
                    {
                        "status": "linked",
                        "source": inp.source_note_id,
                        "target": inp.target_note_id,
                        "relationship": inp.relationship,
                    }
                )

            raise MCPProtocolError(METHOD_NOT_FOUND, f"Unknown MCP tool '{name}'")
        except MCPProtocolError:
            raise
        except Exception as exc:  # validation / sandbox / storage errors
            raise MCPProtocolError(INVALID_PARAMS, f"Tool '{name}' failed: {exc}") from exc

    # -- JSON-RPC dispatcher --------------------------------------------------

    def handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one parsed JSON-RPC message; return None for notifications.

        Both transports call this, guaranteeing protocol parity.
        """
        request_id = message.get("id") if isinstance(message, dict) else None

        def result(value: Any) -> dict[str, Any]:
            return {"jsonrpc": "2.0", "id": request_id, "result": value}

        def error(code: int, msg: str, data: Any = None) -> dict[str, Any]:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": msg, "data": data},
            }

        if not isinstance(message, dict):
            return error(INVALID_REQUEST, "Request must be a JSON object")

        if message.get("jsonrpc") != "2.0":
            return error(INVALID_REQUEST, "jsonrpc must be '2.0'")

        method = message.get("method")
        if not isinstance(method, str) or not method:
            return error(INVALID_REQUEST, "Missing or invalid 'method'")

        params = message.get("params") or {}
        if not isinstance(params, dict):
            return error(INVALID_PARAMS, "'params' must be an object")

        # Notifications never receive a response.
        if request_id is None:
            if method in {"notifications/initialized", "notifications/cancelled"}:
                return None
            # Unknown notifications are ignored per JSON-RPC 2.0.
            return None

        try:
            if method == "initialize":
                return result(self.initialize(params))
            if method == "ping":
                return result({})
            if method == "tools/list":
                return result({"tools": [t.model_dump() for t in self.list_tools()]})
            if method == "tools/call":
                name = params.get("name")
                if not isinstance(name, str):
                    raise MCPProtocolError(INVALID_PARAMS, "'name' must be a string")
                args = params.get("arguments") or {}
                if not isinstance(args, dict):
                    raise MCPProtocolError(INVALID_PARAMS, "'arguments' must be an object")
                return result(self.execute_tool(name, args))
            if method == "resources/list":
                return result({"resources": [r.model_dump() for r in self.list_resources()]})
            if method == "resources/templates/list":
                return result({"resourceTemplates": self.list_resource_templates()})
            if method == "resources/read":
                uri = params.get("uri")
                if not isinstance(uri, str):
                    raise MCPProtocolError(INVALID_PARAMS, "'uri' must be a string")
                try:
                    contents = [self.read_resource(uri)]
                except (ValueError, KeyError, PermissionError) as exc:
                    raise MCPProtocolError(INVALID_PARAMS, str(exc)) from exc
                return result({"contents": contents})
            return error(METHOD_NOT_FOUND, f"Method not found: {method}")
        except MCPProtocolError as exc:
            return error(exc.code, exc.message, exc.data)

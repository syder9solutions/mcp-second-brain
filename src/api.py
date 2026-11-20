"""HTTP + SSE remote transport for the MCP Second Brain server.

Exposes three surfaces:

1. Official MCP 2024-11-05 HTTP+SSE transport:
   * ``GET  /sse``              -- SSE stream; first event is an ``endpoint`` event.
   * ``POST /messages``         -- JSON-RPC messages for that SSE session.
2. Convenience JSON-RPC + REST endpoints used by the Web UI explorer:
   * ``POST /mcp/v1/rpc``       -- single/batch JSON-RPC over plain HTTP.
   * ``GET/POST /mcp/v1/...``   -- tool/resource REST compatibility routes.
3. Ops endpoints: health, Web UI, eval report.

All routes delegate to :meth:`MCPServer.handle_message`, so stdio and HTTP
share exactly the same protocol behavior.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

from evals.mcp_eval import MCPEvalSuite
from src.server import MCPServer


def _allow_all_origins() -> bool:  # pragma: no cover - trivial env lookup
    return os.getenv("MCP_ALLOW_ALL_ORIGINS", "").lower() in {"1", "true", "yes"}


app = FastAPI(
    title="Second Brain MCP Server",
    description=(
        "MCP 2024-11-05 server with sandboxed vault, hybrid retrieval, pinned "
        "tool schemas, stdio and HTTP/SSE transports."
    ),
    version="1.0.0",
)

# Bind CORS to loopback/LAN origins by default. Open '*' only when the operator
# explicitly sets MCP_ALLOW_ALL_ORIGINS (documented in README).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _allow_all_origins() else [
        "http://localhost", "http://127.0.0.1", "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

server = MCPServer()
WEB_DIR = Path(__file__).resolve().parent.parent / "web"


# -- Web UI & ops -------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    html_file = WEB_DIR / "index.html"
    if not html_file.exists():
        return HTMLResponse("<h1>MCP Server Explorer loading...</h1>")
    return HTMLResponse(content=html_file.read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "mcp_server": "second-brain-mcp",
        "version": "1.0.0",
        "protocol_version": server.protocol_version,
        "total_vault_notes": len(server.engine.notes),
    }


@app.post("/api/eval/mcp")
def run_mcp_eval() -> dict[str, Any]:
    # Use an isolated throwaway vault: the red-team and link cases write notes,
    # and the live eval report must never mutate the operator's real vault.
    return MCPEvalSuite().run_full_suite()


# -- Official MCP JSON-RPC over POST -----------------------------------------

@app.post("/messages", response_model=None)
@app.post("/mcp/v1/rpc", response_model=None)
async def json_rpc(request: Request) -> JSONResponse | Response:
    """Handle a JSON-RPC request, batch, or notification over HTTP POST."""
    try:
        payload = await request.json()
    except Exception as exc:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            },
            status_code=400,
        )

    if isinstance(payload, list):
        responses = [r for msg in payload if (r := server.handle_message(msg)) is not None]
        return JSONResponse(responses if responses else None, status_code=200 if responses else 202)

    response = server.handle_message(payload)
    if response is None:  # notification -> 202 Accepted, no body
        return Response(status_code=202)
    return JSONResponse(response, status_code=200)


# -- Official MCP HTTP+SSE transport ----------------------------------------

@app.get("/sse")
async def sse() -> StreamingResponse:
    """Server-Sent Events stream; emits an initial ``endpoint`` event."""
    session_id = uuid.uuid4().hex
    queue: asyncio.Queue[str] = asyncio.Queue()
    # First event tells the client where to POST its JSON-RPC messages.
    await queue.put(f"event: endpoint\ndata: /messages?session_id={session_id}\n\n")

    async def event_stream():
        try:
            while True:
                event = await queue.get()
                yield event
        except asyncio.CancelledError:  # client disconnected
            return

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# -- REST compatibility endpoints (Web UI) ----------------------------------

@app.get("/mcp/v1/tools/list")
def list_tools() -> dict[str, Any]:
    return {
        "tools": [t.model_dump() for t in server.list_tools()],
        "protocolVersion": server.protocol_version,
    }


@app.post("/mcp/v1/tools/call")
async def call_tool(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception as exc:
        return JSONResponse(
            {"content": [{"type": "text", "text": f"Parse error: {exc}"}], "isError": True},
            status_code=400,
        )
    name = body.get("name") if isinstance(body, dict) else None
    arguments = body.get("arguments", {}) if isinstance(body, dict) else {}
    if not isinstance(name, str):
        return JSONResponse(
            {"content": [{"type": "text", "text": "'name' must be a string"}], "isError": True},
            status_code=400,
        )
    if not isinstance(arguments, dict):
        return JSONResponse(
            {"content": [{"type": "text", "text": "'arguments' must be an object"}], "isError": True},
            status_code=400,
        )
    try:
        envelope = server.execute_tool(name, arguments)
        return JSONResponse(
            {
                "content": envelope["content"],
                "raw_result": envelope["structuredContent"],
                "isError": False,
            }
        )
    except Exception as exc:
        return JSONResponse(
            {
                "content": [{"type": "text", "text": str(exc)}],
                "raw_result": None,
                "isError": True,
            },
            status_code=400,
        )


@app.get("/mcp/v1/resources/list")
def list_resources() -> dict[str, Any]:
    return {"resources": [r.model_dump() for r in server.list_resources()]}


@app.post("/mcp/v1/resources/read")
async def read_resource(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Parse error: {exc}")
    uri = body.get("uri") if isinstance(body, dict) else None
    if not isinstance(uri, str):
        raise HTTPException(status_code=400, detail="'uri' must be a string")
    try:
        return JSONResponse({"contents": [server.read_resource(uri)]})
    except (ValueError, KeyError, PermissionError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))

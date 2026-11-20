"""stdio transport for the MCP Second Brain server.

Local MCP clients (Claude Desktop, Cursor, Claude Code) launch this module as a
subprocess and speak newline-delimited JSON-RPC 2.0 over stdin/stdout. Per the
MCP stdio transport, logs/diagnostics MUST go to stderr so stdout stays a clean
protocol channel.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import TextIO

from src.server import MCPServer


def run_stdio(server: MCPServer | None = None, stdin: TextIO | None = None,
              stdout: TextIO | None = None) -> None:
    """Serve newline-delimited JSON-RPC until stdin reaches EOF.

    Args are injectable so the loop can be unit-tested with in-memory streams.
    """
    server = server or MCPServer()
    incoming = stdin if stdin is not None else sys.stdin
    outgoing = stdout if stdout is not None else sys.stdout

    print("second-brain-mcp: stdio transport ready (protocol 2024-11-05)", file=sys.stderr)
    for line in incoming:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc.msg}"},
            }
            outgoing.write(json.dumps(response, ensure_ascii=False) + "\n")
            outgoing.flush()
            continue

        # JSON-RPC batching is permitted by 2024-11-05.
        messages = message if isinstance(message, list) else [message]
        responses = []
        for msg in messages:
            response = server.handle_message(msg)
            if response is not None:  # notifications produce no response
                responses.append(response)
        if responses:
            payload = responses[0] if not isinstance(message, list) else responses
            outgoing.write(json.dumps(payload, ensure_ascii=False) + "\n")
            outgoing.flush()


def main() -> None:
    # Optional --vault-dir override for local clients that keep their vault elsewhere.
    vault_dir = None
    if len(sys.argv) > 2 and sys.argv[1] == "--vault-dir":
        vault_dir = Path(sys.argv[2])
    run_stdio(MCPServer(vault_dir=vault_dir) if vault_dir else MCPServer())


if __name__ == "__main__":
    main()

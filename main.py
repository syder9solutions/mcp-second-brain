"""ASGI/CLI entrypoints for the MCP Second Brain server."""
from __future__ import annotations

import sys
from pathlib import Path

# Make `src` importable when running `python -m main` or `python main.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def serve() -> None:  # pragma: no cover - exercised by container smoke test
    """Run the HTTP/SSE transport with uvicorn (read config from env)."""
    import os
    import uvicorn

    uvicorn.run(
        "src.api:app",
        host=os.getenv("MCP_HOST", "127.0.0.1"),
        port=int(os.getenv("MCP_PORT", "8000")),
        log_level=os.getenv("MCP_LOG_LEVEL", "info"),
    )


def stdio() -> None:  # pragma: no cover - exercised by stdio protocol test
    """Run the stdio transport for local MCP clients."""
    from src.stdio import main

    main()


def eval_suite() -> None:  # pragma: no cover - exercised by eval CLI test
    """Run the security red-team + retrieval eval suite."""
    from scripts.run_eval import main

    main()


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    {"serve": serve, "stdio": stdio, "eval": eval_suite}.get(command, serve)()

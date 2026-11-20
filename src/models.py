"""MCP data models, pinned tool contracts, and Poka-Yoke (unrepresentable-bad-input) schemas.

Security design
---------------
Every externally reachable input model uses ``extra="forbid"`` so that a client
cannot smuggle unexpected fields (a classic tool-poisoning / mass-assignment
vector). Identifiers use anchored regexes that make traversal payloads
*unrepresentable* before any filesystem code runs. The vault engine applies a
second, independent containment check (defense in depth).

All published tool contracts carry a pinned ``version``. A client that caches
the schema can detect a rug-pull (a silent description/schema change) because
the version must be bumped through review.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# --- Pinned protocol / contract versions ------------------------------------
PROTOCOL_VERSION = "2024-11-05"
TOOL_VERSION = "1.0.0"

# Anchored patterns: no separators, no dots, no leading dash. These make
# ``../../etc/passwd`` and its variants invalid at the schema boundary.
NOTE_ID_PATTERN = r"^note-[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
TAG_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$"
RELATIONSHIP_PATTERN = r"^[A-Za-z][A-Za-z0-9_-]{0,31}$"

StrictModel = ConfigDict(extra="forbid")

Tag = Annotated[str, Field(pattern=TAG_PATTERN)]


# --- MCP protocol envelopes --------------------------------------------------

class JSONRPCRequest(BaseModel):
    """A single JSON-RPC 2.0 request/notification as used by MCP transports."""

    model_config = ConfigDict(extra="allow")  # JSON-RPC permits extension members

    jsonrpc: Literal["2.0"]
    method: str = Field(..., min_length=1, max_length=128)
    id: str | int | None = None
    params: dict[str, Any] | None = None

    @property
    def is_notification(self) -> bool:
        """Notifications have no id and must not produce a response."""
        return self.id is None


# --- MCP discovery models ----------------------------------------------------

class MCPToolDefinition(BaseModel):
    model_config = StrictModel

    name: str
    description: str
    version: str = TOOL_VERSION  # pinned: block unreviewed rug-pull modifications
    inputSchema: dict[str, Any]


class MCPResourceDefinition(BaseModel):
    model_config = StrictModel

    uri: str
    name: str
    description: str
    mimeType: str = "text/markdown"


# --- Tool input contracts (Poka-Yoke schemas) --------------------------------

class SearchNotesInput(BaseModel):
    model_config = StrictModel

    query: str = Field(..., min_length=2, max_length=200, description="Search query string.")
    top_k: int = Field(default=5, ge=1, le=20, description="Maximum number of notes to return.")
    tag_filter: Tag | None = Field(default=None, description="Optional exact tag filter.")


class GetNoteInput(BaseModel):
    model_config = StrictModel

    note_id: str = Field(..., pattern=NOTE_ID_PATTERN, description="Exact ID of the note to fetch.")


class CreateNoteInput(BaseModel):
    model_config = StrictModel

    note_id: str = Field(..., pattern=NOTE_ID_PATTERN, description="Unique ID; must start with 'note-'.")
    title: str = Field(..., min_length=3, max_length=120)
    content: str = Field(..., min_length=5, max_length=5000)
    tags: list[Tag] = Field(default_factory=list, max_length=32)


class LinkNotesInput(BaseModel):
    model_config = StrictModel

    source_note_id: str = Field(..., pattern=NOTE_ID_PATTERN)
    target_note_id: str = Field(..., pattern=NOTE_ID_PATTERN)
    relationship: str = Field(default="references", pattern=RELATIONSHIP_PATTERN)


# --- Domain entity -----------------------------------------------------------

class Note(BaseModel):
    model_config = StrictModel

    note_id: str
    title: str
    content: str
    tags: list[str] = Field(default_factory=list)
    outgoing_links: list[str] = Field(default_factory=list)
    incoming_links: list[str] = Field(default_factory=list)
    created_at: float = 0.0

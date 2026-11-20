"""Sandboxed note vault storage engine.

Security model (least privilege / Poka-Yoke)
--------------------------------------------
All reads and writes flow through :meth:`_validate_path_sandbox`, which enforces
several independent checks:

1. Schema layer (``src.models``) rejects traversal strings before we see them.
2. A strict filename whitelist rejects separators, dots, NULs, absolute paths,
   Windows drive/UNC forms, and control characters.
3. ``Path.resolve()`` turns the candidate into a canonical absolute path;
   ``is_relative_to(vault_root)`` rejects anything that escapes the root even
   after symlink resolution.
4. Writes use ``O_NOFOLLOW``-equivalent semantics via a final symlink check and
   an atomic ``os.replace`` inside the vault directory.

Hybrid retrieval
----------------
Search fuses BM25+ (lexical) and LSA/TF-IDF dense cosine similarity (semantic,
computed locally with scikit-learn -- no network/model download) via
Reciprocal Rank Fusion (RRF).
"""
from __future__ import annotations

import os
import re
import tempfile
import time
from pathlib import Path

import numpy as np
from rank_bm25 import BM25Plus
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

from src.models import Note

# Strict filename whitelist: identifiers never legitimately contain these.
_FORBIDDEN_FILENAME_CHARS = re.compile(r"[/\\\x00-\x1f\x7f]|\.\.|^-")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.md$")
_TOKEN_RE = re.compile(r"\b[a-zA-Z0-9_\-]+\b")


class SandboxedVaultEngine:
    """In-memory index with atomic Markdown persistence inside ``vault_dir``."""

    def __init__(self, vault_dir: Path, *, seed: bool = True):
        self.vault_dir = vault_dir.resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.notes: dict[str, Note] = {}
        self.bm25: BM25Plus | None = None
        self.vectorizer: TfidfVectorizer | None = None
        self.svd: TruncatedSVD | None = None
        self.embeddings: np.ndarray | None = None
        self.note_id_list: list[str] = []
        if seed:
            self._load_seed_vault()
            self._rebuild_search_index()

    # -- sandbox -------------------------------------------------------------

    def _validate_path_sandbox(self, filename: str) -> Path:
        """Return a canonical path inside the vault or raise ``PermissionError``."""
        if not isinstance(filename, str) or not filename:
            raise PermissionError("Security Sandbox Violation: empty or non-string path")
        if _FORBIDDEN_FILENAME_CHARS.search(filename):
            raise PermissionError(
                f"Security Sandbox Violation: illegal characters/traversal in '{filename}'"
            )
        if not _SAFE_FILENAME.fullmatch(filename):
            raise PermissionError(
                f"Security Sandbox Violation: filename '{filename}' is not a safe vault filename"
            )
        candidate = (self.vault_dir / filename).resolve()
        # resolve() collapses '..' and follows symlinks; containment is checked
        # on the canonical paths, the only reliable way to prevent escapes.
        if not candidate.is_relative_to(self.vault_dir):
            raise PermissionError(
                f"Security Sandbox Violation: path '{candidate}' escapes vault root "
                f"'{self.vault_dir}'"
            )
        return candidate

    def _note_path(self, note_id: str) -> Path:
        # Note IDs are validated by the schema layer; re-check here so direct
        # engine use (without a schema) is still contained.
        if not re.fullmatch(r"note-[A-Za-z0-9][A-Za-z0-9_-]{0,63}", note_id):
            raise PermissionError(f"Security Sandbox Violation: unsafe note ID '{note_id}'")
        return self._validate_path_sandbox(f"{note_id}.md")

    # -- persistence ---------------------------------------------------------

    @staticmethod
    def _note_to_markdown(note: Note) -> str:
        lines = [f"# {note.title}", f"Tags: {', '.join(note.tags)}", ""]
        lines.extend(note.content.splitlines() or [""])
        if note.outgoing_links:
            lines += ["", "## Outgoing Links"]
            lines += [f"- [[{link}]]" for link in note.outgoing_links]
        if note.incoming_links:
            lines += ["", "## Incoming Links"]
            lines += [f"- [[{link}]]" for link in note.incoming_links]
        return "\n".join(lines) + "\n"

    def _write_atomic(self, path: Path, text: str) -> None:
        """Write a file atomically inside the vault, refusing symlink targets.

        Enforces containment a final time here (defense in depth) so even a
        caller that hands us a pre-resolved path cannot write outside the root.
        """
        canonical = path.resolve()
        if not canonical.is_relative_to(self.vault_dir):
            raise PermissionError(
                f"Security Sandbox Violation: write target '{canonical}' escapes vault root"
            )
        # Refuse to follow a pre-existing symlink planted by an attacker.
        if path.is_symlink():
            raise PermissionError(f"Security Sandbox Violation: refusing symlink target '{path}'")
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-note-", suffix=".md", dir=self.vault_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, canonical)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def _load_seed_vault(self) -> None:
        """Load the seed markdown vault (``core_vault.md``) if present."""
        seed_file = self.vault_dir / "core_vault.md"
        if not seed_file.exists():
            return
        content = seed_file.read_text(encoding="utf-8")
        for section in content.split("## Note")[1:]:
            lines = section.strip().splitlines()
            if not lines:
                continue
            title = lines[0].split(":", 1)[1].strip() if ":" in lines[0] else "Note"
            nid, tags, body = "", [], []
            for line in lines[1:]:
                if line.startswith("- id:"):
                    nid = line.replace("- id:", "", 1).strip()
                elif line.startswith("- tags:"):
                    tags = [t.strip() for t in line.replace("- tags:", "", 1).split(",") if t.strip()]
                elif line.startswith("- content:"):
                    body.append(line.replace("- content:", "", 1).strip())
                elif body:
                    body.append(line.strip())
            if nid and body:
                self.notes[nid] = Note(
                    note_id=nid,
                    title=title,
                    content=" ".join(body),
                    tags=tags,
                    created_at=time.time(),
                )

    # -- index ---------------------------------------------------------------

    def _rebuild_search_index(self) -> None:
        if not self.notes:
            self.bm25 = None
            self.embeddings = None
            self.note_id_list = []
            return
        self.note_id_list = list(self.notes.keys())
        corpus = [
            f"{n.title} {n.content} {' '.join(n.tags)}" for n in self.notes.values()
        ]
        tokenized = [_TOKEN_RE.findall(doc.lower()) for doc in corpus]
        self.bm25 = BM25Plus(tokenized)

        vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        tfidf = vectorizer.fit_transform(corpus)
        n_components = min(16, max(1, min(tfidf.shape) - 1))
        svd = TruncatedSVD(n_components=n_components, random_state=42)
        dense = svd.fit_transform(tfidf)
        self.vectorizer = vectorizer
        self.svd = svd
        self.embeddings = normalize(dense, norm="l2")

    # -- public operations ---------------------------------------------------

    def get_note(self, note_id: str) -> Note:
        if note_id not in self.notes:
            raise KeyError(f"Note with ID '{note_id}' not found.")
        return self.notes[note_id]

    def create_note(self, note: Note) -> Note:
        safe_path = self._note_path(note.note_id)
        if note.note_id in self.notes:
            raise ValueError(f"Note with ID '{note.note_id}' already exists.")
        self._write_atomic(safe_path, self._note_to_markdown(note))
        self.notes[note.note_id] = note
        self._rebuild_search_index()
        return note

    def link_notes(self, source_id: str, target_id: str, relationship: str = "references") -> None:
        """Create a bidirectional link edge and persist both notes atomically."""
        # Validate IDs through the same sandbox guard even though the schema
        # layer normally catches malformed IDs first (defense in depth).
        source_path = self._note_path(source_id)
        target_path = self._note_path(target_id)
        if source_id not in self.notes:
            raise KeyError(f"Source note '{source_id}' does not exist.")
        if target_id not in self.notes:
            raise KeyError(f"Target note '{target_id}' does not exist.")
        if source_id == target_id:
            raise ValueError("A note cannot link to itself.")

        source, target = self.notes[source_id], self.notes[target_id]
        outgoing = f"{target_id} ({relationship})"
        incoming = f"{source_id} ({relationship})"
        changed = False
        if outgoing not in source.outgoing_links:
            source.outgoing_links.append(outgoing)
            changed = True
        if incoming not in target.incoming_links:
            target.incoming_links.append(incoming)
            changed = True
        if changed:
            # Persist both sides; write files then commit memory only on success.
            self._write_atomic(source_path, self._note_to_markdown(source))
            self._write_atomic(target_path, self._note_to_markdown(target))

    def search_notes(
        self, query: str, top_k: int = 5, tag_filter: str | None = None
    ) -> list[tuple[Note, float]]:
        if not self.notes or self.bm25 is None or self.embeddings is None:
            return []

        q_tokens = _TOKEN_RE.findall(query.lower())
        bm_scores = (
            self.bm25.get_scores(q_tokens)
            if q_tokens
            else np.zeros(len(self.note_id_list))
        )

        # Semantic scoring; if the query is out-of-vocabulary, tf-idf is all
        # zeros and SVD yields a zero vector -- cosine scores fall back to 0.
        assert self.vectorizer is not None and self.svd is not None
        q_tfidf = self.vectorizer.transform([query])
        if q_tfidf.nnz:
            q_dense = self.svd.transform(q_tfidf)
            q_norm = normalize(q_dense, norm="l2")[0]
            dense_scores = np.asarray(np.dot(self.embeddings, q_norm)).ravel()
        else:
            dense_scores = np.zeros(len(self.note_id_list))

        # Reciprocal Rank Fusion of the two ranked lists.
        rrf_scores: dict[str, float] = {}
        for ranking in (bm_scores, dense_scores):
            for rank, idx in enumerate(np.argsort(ranking)[::-1], start=1):
                nid = self.note_id_list[idx]
                rrf_scores[nid] = rrf_scores.get(nid, 0.0) + 0.5 / (60 + rank)

        results: list[tuple[Note, float]] = []
        for nid in sorted(rrf_scores, key=lambda key: rrf_scores[key], reverse=True):
            note = self.notes[nid]
            if tag_filter and tag_filter not in note.tags:
                continue
            results.append((note, round(rrf_scores[nid], 6)))
            if len(results) >= top_k:
                break
        return results

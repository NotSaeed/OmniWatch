"""
RAG Retriever — Cosine Similarity + No-Grounding Gate

The sole public function retrieve() either returns relevant facility-manual
context chunks or returns (None, score) when the best match falls below the
hardcoded similarity threshold.

DESIGN CONSTRAINT (Sprint 2):
  SIMILARITY_THRESHOLD = 0.70 is hardcoded and must NOT be made configurable
  at runtime.  This enforces the deterministic "No Grounding" safety flag:
  any alert whose content has less than 70% cosine similarity to the facility
  corpus bypasses the LLM entirely and is returned to the frontend with
  grounding_available=False.  This prevents hallucination on out-of-scope events.
"""

import numpy as np

from ingestion.rag.embedder import embed_query
from ingestion.rag.index import get_index, get_it_index

# ── Safety thresholds — hardcoded, not env vars ────────────────────────────────
# OT/ICS corpus: high threshold — water-treatment facility manuals are precise
SIMILARITY_THRESHOLD:    float = 0.70
# IT security corpus: lower threshold — enterprise events are semantically broader
IT_SIMILARITY_THRESHOLD: float = 0.30


def retrieve(
    query_text: str,
    top_k: int = 3,
) -> tuple[list[str] | None, float]:
    """
    Retrieve from the OT/ICS facility-manual corpus (SWaT).
    Returns (None, score) when score < 0.70 — triggers No Grounding gate.
    """
    return _retrieve_from(get_index(), query_text, SIMILARITY_THRESHOLD, top_k)


def retrieve_it(
    query_text: str,
    top_k: int = 3,
) -> tuple[list[str] | None, float]:
    """
    Retrieve from the IT security corpus (BOTSv3 / enterprise events).
    Uses a lower threshold (0.30) appropriate for the broader IT security domain.
    Returns (None, score) when score < 0.30.
    """
    return _retrieve_from(get_it_index(), query_text, IT_SIMILARITY_THRESHOLD, top_k)


def _retrieve_from(
    index,
    query_text: str,
    threshold:  float,
    top_k:      int,
) -> tuple[list[str] | None, float]:
    if index.is_empty():
        return None, 0.0

    query_vec = embed_query(query_text)
    scores    = index.similarity(query_vec)

    if len(scores) == 0:
        return None, 0.0

    max_score = float(np.max(scores))

    if max_score < threshold:
        return None, max_score

    top_indices = np.argpartition(scores, -min(top_k, len(scores)))[-top_k:]
    top_indices = top_indices[np.argsort(scores[top_indices])[::-1]]

    top_chunks = [index.chunks[i] for i in top_indices]
    return top_chunks, max_score

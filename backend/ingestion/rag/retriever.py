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
from ingestion.rag.index import get_index

# ── Hardcoded safety threshold — do not make this an env var ──────────────────
SIMILARITY_THRESHOLD: float = 0.70


def retrieve(
    query_text: str,
    top_k: int = 3,
) -> tuple[list[str] | None, float]:
    """
    Retrieve the top-k most relevant facility-manual chunks for query_text.

    Returns:
        (chunks, max_score) where chunks is a list of text strings and
        max_score is the highest cosine similarity found.

        If max_score < SIMILARITY_THRESHOLD, returns (None, max_score) —
        the caller must treat this as "No Grounding Available" and skip
        LLM generation entirely.

    The (None, score) contract is the critical safety invariant of Sprint 2.
    """
    index = get_index()

    if index.is_empty():
        return None, 0.0

    query_vec = embed_query(query_text)
    scores    = index.similarity(query_vec)   # shape (N,)

    if len(scores) == 0:
        return None, 0.0

    max_score = float(np.max(scores))

    if max_score < SIMILARITY_THRESHOLD:
        return None, max_score

    # Select top-k indices (unsorted within top-k is fine for small corpora)
    top_indices = np.argpartition(scores, -min(top_k, len(scores)))[-top_k:]
    top_indices = top_indices[np.argsort(scores[top_indices])[::-1]]   # sort desc

    top_chunks = [index.chunks[i] for i in top_indices]
    return top_chunks, max_score

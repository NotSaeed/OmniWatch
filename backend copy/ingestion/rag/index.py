"""
In-Memory FP32 Vector Index
Stores chunk embeddings as a float32 numpy matrix.
Cosine similarity is a single matrix multiply (O(N·D)) — fast enough for
small ICS/SCADA corpora (< 10 000 chunks) without FAISS.
"""

import logging
from dataclasses import dataclass, field

import numpy as np

from ingestion.rag.embedder import embed_texts
from ingestion.rag.loader import load_chunks

logger = logging.getLogger(__name__)


@dataclass
class VectorIndex:
    chunks:     list[str]           = field(default_factory=list)
    embeddings: np.ndarray | None   = None   # shape (N, 384), dtype float32

    @property
    def size(self) -> int:
        return len(self.chunks)

    def is_empty(self) -> bool:
        return self.size == 0

    def similarity(self, query_vec: np.ndarray) -> np.ndarray:
        """
        Cosine similarity between query_vec (384,) and all stored embeddings (N, 384).
        Both sides are already L2-normalised by the embedder, so this is just a dot product.
        Returns shape (N,) float32.
        """
        if self.embeddings is None or self.is_empty():
            return np.array([], dtype=np.float32)
        return (self.embeddings @ query_vec).astype(np.float32)


# ── Module-level singleton ─────────────────────────────────────────────────────

_index: VectorIndex | None = None


def get_index() -> VectorIndex:
    """Return the built index, building it on first call."""
    global _index
    if _index is None:
        _index = _build()
    return _index


def _build() -> VectorIndex:
    chunks = load_chunks()
    if not chunks:
        logger.warning(
            "No facility manuals found in data/facility_manuals/. "
            "RAG retrieval will always return No Grounding Available."
        )
        return VectorIndex()

    logger.info("Building RAG index from %d chunks …", len(chunks))
    embeddings = embed_texts(chunks)
    logger.info("RAG index ready — %d chunks, shape %s, dtype %s",
                len(chunks), embeddings.shape, embeddings.dtype)
    return VectorIndex(chunks=chunks, embeddings=embeddings)


def rebuild_index() -> VectorIndex:
    """Force a fresh rebuild (call after new manuals are added)."""
    global _index
    _index = _build()
    return _index

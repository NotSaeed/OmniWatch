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
from ingestion.rag.loader import load_chunks, load_it_chunks

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


# ── Module-level singletons ────────────────────────────────────────────────────

_index:    VectorIndex | None = None   # OT/ICS (SWaT) corpus
_it_index: VectorIndex | None = None   # IT security corpus (BOTSv3 / enterprise)


def get_index() -> VectorIndex:
    """Return the OT corpus index, building it on first call."""
    global _index
    if _index is None:
        _index = _build(load_chunks, "data/facility_manuals/")
    return _index


def get_it_index() -> VectorIndex:
    """Return the IT security corpus index, building it on first call."""
    global _it_index
    if _it_index is None:
        _it_index = _build(load_it_chunks, "data/rag_corpus/it_security/")
    return _it_index


def _build(loader_fn, corpus_label: str) -> VectorIndex:
    chunks = loader_fn()
    if not chunks:
        logger.warning(
            "No corpus files found in %s. "
            "RAG retrieval will always return No Grounding Available.",
            corpus_label,
        )
        return VectorIndex()

    logger.info("Building RAG index for %s from %d chunks …", corpus_label, len(chunks))
    embeddings = embed_texts(chunks)
    logger.info("RAG index ready (%s) — %d chunks, shape %s, dtype %s",
                corpus_label, len(chunks), embeddings.shape, embeddings.dtype)
    return VectorIndex(chunks=chunks, embeddings=embeddings)


def rebuild_index() -> VectorIndex:
    """Force a fresh rebuild of the OT index (call after new manuals are added)."""
    global _index
    _index = _build(load_chunks, "data/facility_manuals/")
    return _index


def rebuild_it_index() -> VectorIndex:
    """Force a fresh rebuild of the IT index (call after new corpus files are added)."""
    global _it_index
    _it_index = _build(load_it_chunks, "data/rag_corpus/it_security/")
    return _it_index

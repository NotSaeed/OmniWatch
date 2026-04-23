"""
Local FP32 Sentence Embedder
Uses sentence-transformers/all-MiniLM-L6-v2 (22 MB, fully offline).

FPGA-lock policy: all tensors and output arrays are forced to float32.
No quantization, no BF16, no FP16 — embedding precision is deterministic
and reproducible across hardware.
"""

import logging
from functools import lru_cache

import numpy as np

logger = logging.getLogger(__name__)

_MODEL_NAME = "all-MiniLM-L6-v2"  # 384-dim, L2-normalized, 22 MB on disk


@lru_cache(maxsize=1)
def _get_model():
    """Load the sentence-transformer model exactly once (lazy, cached)."""
    from sentence_transformers import SentenceTransformer
    logger.info("Loading embedding model: %s", _MODEL_NAME)
    model = SentenceTransformer(_MODEL_NAME)
    return model


def embed_texts(texts: list[str]) -> np.ndarray:
    """
    Embed a list of text strings.

    Returns shape (N, 384) float32 numpy array.
    FPGA-lock: .astype(np.float32) is applied unconditionally — even if the
    model internally uses float16 on a GPU, output is always cast to FP32.
    """
    if not texts:
        return np.empty((0, 384), dtype=np.float32)

    model = _get_model()
    embeddings = model.encode(
        texts,
        batch_size=32,
        show_progress_bar=False,
        convert_to_numpy=True,
        normalize_embeddings=True,   # L2 normalise → cosine = dot product
    )
    return embeddings.astype(np.float32)   # FPGA-lock: enforce FP32


def embed_query(query: str) -> np.ndarray:
    """
    Embed a single query string.
    Returns shape (384,) float32 array.
    """
    return embed_texts([query])[0]

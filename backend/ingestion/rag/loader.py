"""
Facility Manual Loader
Reads all *.txt files from data/facility_manuals/ and splits them into
overlapping 512-character chunks for embedding.
"""

from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent.parent.parent

# Hardcoded corpus directories
_MANUALS_DIR    = _PROJECT_ROOT / "data" / "facility_manuals"
_IT_CORPUS_DIR  = _PROJECT_ROOT / "data" / "rag_corpus" / "it_security"

CHUNK_SIZE    = 512   # characters per chunk
CHUNK_OVERLAP = 64    # overlap between consecutive chunks


def load_chunks() -> list[str]:
    """Load OT/ICS facility manual chunks (SWaT corpus)."""
    return _load_from_dir(_MANUALS_DIR)


def load_it_chunks() -> list[str]:
    """Load IT security corpus chunks (BOTSv3 / enterprise IT path)."""
    return _load_from_dir(_IT_CORPUS_DIR)


def _load_from_dir(directory: Path) -> list[str]:
    chunks: list[str] = []
    if not directory.exists():
        return chunks

    for txt_file in sorted(directory.glob("*.txt")):
        try:
            text = txt_file.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        chunks.extend(_split(text))

    return chunks


def _split(text: str) -> list[str]:
    results = []
    start   = 0
    while start < len(text):
        end = start + CHUNK_SIZE
        results.append(text[start:end].strip())
        start += CHUNK_SIZE - CHUNK_OVERLAP
    return [c for c in results if len(c) > 20]   # drop near-empty tail chunks

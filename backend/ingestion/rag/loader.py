"""
Facility Manual Loader
Reads all *.txt files from data/facility_manuals/ and splits them into
overlapping 512-character chunks for embedding.
"""

from pathlib import Path

# Hardcoded corpus directory — one level above backend/
_MANUALS_DIR = Path(__file__).parent.parent.parent.parent / "data" / "facility_manuals"

CHUNK_SIZE    = 512   # characters per chunk
CHUNK_OVERLAP = 64    # overlap between consecutive chunks


def load_chunks() -> list[str]:
    """
    Load every *.txt file in data/facility_manuals/ and split into chunks.
    Returns a flat list of text chunks ready for embedding.
    """
    chunks: list[str] = []
    if not _MANUALS_DIR.exists():
        return chunks

    for txt_file in sorted(_MANUALS_DIR.glob("*.txt")):
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

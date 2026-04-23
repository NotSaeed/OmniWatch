"""
OmniWatch Triage Validator
Validates and normalises raw Claude tool_use output before it touches the database.
Any result that fails validation is rejected and written to errors.log — never shown in the UI.
"""

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from triage.models import FalsePositiveRisk, TriageResult

# ── Dead-letter log ────────────────────────────────────────────────────────────
_ERROR_LOG = Path(__file__).parent.parent / "logs" / "errors.log"
_ERROR_LOG.parent.mkdir(exist_ok=True)

logger = logging.getLogger(__name__)


def _write_dead_letter(raw: dict, reason: str) -> None:
    ts = datetime.now(tz=timezone.utc).isoformat()
    with _ERROR_LOG.open("a", encoding="utf-8") as f:
        f.write(f"[{ts}] REJECTED — {reason}\n  raw={raw}\n\n")


# ── Public API ────────────────────────────────────────────────────────────────

def validate(raw: dict, log_type: str = "unknown", source_type: str = "simulated") -> TriageResult | None:
    """
    Parse and validate a raw dict from Claude's tool_use response.
    Returns a validated TriageResult, or None if validation fails.
    """
    # Inject metadata fields not present in the Claude response
    raw.setdefault("alert_id",   str(uuid.uuid4()))
    raw.setdefault("timestamp",  datetime.now(tz=timezone.utc).isoformat())
    raw.setdefault("log_type",   log_type)
    raw.setdefault("source_type", source_type)

    try:
        result = TriageResult.model_validate(raw)
    except ValidationError as exc:
        reason = f"Pydantic validation failed: {exc.error_count()} error(s)"
        _write_dead_letter(raw, reason)
        logger.warning("Triage result rejected: %s", reason)
        return None

    return cap_confidence(result)


def cap_confidence(result: TriageResult) -> TriageResult:
    """
    Apply business-rule confidence caps:
    - Metadata-only sourcetypes cap at 0.50 (insufficient signal for higher)
    - BENIGN results from noisy sourcetypes get false_positive_risk=LOW
    """
    SPARSE_SOURCETYPES = {"osquery", "syslog", "simulated"}

    if result.source_type in SPARSE_SOURCETYPES and result.confidence > 0.50:
        result = result.model_copy(update={"confidence": 0.50})

    if result.category.value == "BENIGN":
        result = result.model_copy(update={"false_positive_risk": FalsePositiveRisk.LOW})

    return result


def validate_batch(
    raw_list: list[dict],
    log_type: str = "unknown",
    source_type: str = "simulated",
) -> list[TriageResult]:
    """Validate a list of raw Claude tool_use responses. Skips invalid entries."""
    results = []
    for raw in raw_list:
        result = validate(raw, log_type=log_type, source_type=source_type)
        if result is not None:
            results.append(result)
    return results

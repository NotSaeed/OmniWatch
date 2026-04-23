"""
OmniWatch AI Triage Engine — Sprint 2 (Air-Gapped Local Pipeline)
Orchestrates: RAG retrieval → Ollama/Phi-3-Mini → validation → MITRE enrichment.
Anthropic dependency removed; all inference is local.
"""

import logging
import uuid
from datetime import datetime, timezone

from llm.ollama_client import OllamaUnavailableError, get_client
from ingestion.rag.retriever import SIMILARITY_THRESHOLD, retrieve
from triage.mitre_map import get_techniques
from triage.models import (
    FalsePositiveRisk,
    SeverityLevel,
    ThreatCategory,
    TriageResult,
)
from triage.prompts import SYSTEM_PROMPT, build_triage_prompt
from triage.validator import validate_batch

logger = logging.getLogger(__name__)

CHUNK_SIZE = int(__import__("os").getenv("TRIAGE_CHUNK_SIZE", "50"))


# ── Core triage function ───────────────────────────────────────────────────────

async def triage_log_chunk(
    log_lines:   list[str],
    log_type:    str = "unknown",
    source_type: str = "simulated",
) -> list[TriageResult]:
    """
    Triage a chunk of log lines through the local RAG → Phi-3-Mini pipeline.

    Flow:
      1. RAG retrieval — cosine similarity against facility manuals
      2a. Score < 0.70 → return single BENIGN result with grounding_available=False
      2b. Score ≥ 0.70 → pass top-k context + logs to Phi-3-Mini (JSON mode)
      3. Parse + validate JSON output
      4. MITRE enrichment
      5. Threat intel enrichment (AbuseIPDB — if key configured)
    """
    if not log_lines:
        return []

    # ── Step 1: RAG retrieval ─────────────────────────────────────────────────
    query_text = "\n".join(log_lines[:10])   # use first 10 lines as query signal
    rag_chunks, rag_score = retrieve(query_text)

    if rag_chunks is None:
        # Below threshold — deterministic No Grounding path, skip LLM entirely
        logger.info(
            "No Grounding: RAG score %.3f < %.2f for %s chunk (%d lines)",
            rag_score, SIMILARITY_THRESHOLD, source_type, len(log_lines),
        )
        return [_no_grounding_result(log_lines, log_type, source_type, rag_score)]

    rag_context = "\n\n".join(rag_chunks)

    # ── Step 2: Build prompt ──────────────────────────────────────────────────
    prompt = build_triage_prompt(
        log_lines,
        log_type=log_type,
        source_type=source_type,
        rag_context=rag_context,
    )

    # ── Step 3: Local LLM call ────────────────────────────────────────────────
    client = get_client()
    try:
        raw_dict = await client.generate_triage(prompt, SYSTEM_PROMPT)
    except OllamaUnavailableError as exc:
        logger.error("Ollama unavailable during triage: %s", exc)
        return []

    if "_parse_error" in raw_dict:
        logger.warning("Phi-3-Mini returned non-JSON — rejecting chunk (%s)", source_type)
        return []

    # ── Step 4: Validate + attach grounding metadata ──────────────────────────
    raw_dict.setdefault("alert_id",   str(uuid.uuid4()))
    raw_dict.setdefault("timestamp",  datetime.now(tz=timezone.utc).isoformat())
    raw_dict.setdefault("log_type",   log_type)
    raw_dict.setdefault("source_type", source_type)
    raw_dict["grounding_available"] = True
    raw_dict["grounding_score"]     = round(rag_score, 4)

    validated = validate_batch([raw_dict], log_type=log_type, source_type=source_type)
    enriched  = [_enrich_mitre(r) for r in validated]

    # ── Step 5: Threat intelligence enrichment ────────────────────────────────
    enriched = await _enrich_threat_intel(enriched)
    return enriched


def _no_grounding_result(
    log_lines:   list[str],
    log_type:    str,
    source_type: str,
    rag_score:   float,
) -> TriageResult:
    """
    Deterministic safe result returned when RAG similarity < SIMILARITY_THRESHOLD.
    The LLM is never called — zero hallucination risk.
    """
    excerpt = log_lines[0][:200] if log_lines else "(empty chunk)"
    return TriageResult(
        alert_id            = str(uuid.uuid4()),
        timestamp           = datetime.now(tz=timezone.utc),
        severity            = SeverityLevel.INFO,
        category            = ThreatCategory.BENIGN,
        confidence          = 0.0,
        source_ip           = None,
        affected_asset      = None,
        mitre_techniques    = [],
        raw_log_excerpt     = excerpt,
        ai_reasoning        = (
            f"No Grounding Available — facility corpus similarity score {rag_score:.3f} "
            f"is below the required threshold of {SIMILARITY_THRESHOLD:.2f}. "
            "LLM analysis bypassed to prevent hallucination on out-of-scope events."
        ),
        recommendations     = [],
        false_positive_risk = FalsePositiveRisk.LOW,
        log_type            = log_type,
        source_type         = source_type,
        grounding_available = False,
        grounding_score     = round(rag_score, 4),
    )


def _enrich_mitre(result: TriageResult) -> TriageResult:
    static_techniques = get_techniques(result.category)
    merged = list(dict.fromkeys(result.mitre_techniques + static_techniques))
    return result.model_copy(update={"mitre_techniques": merged})


async def _enrich_threat_intel(results: list[TriageResult]) -> list[TriageResult]:
    try:
        from mcp_connectors.threat_intel_server import enrich_results_with_ti
    except ImportError:
        return results

    source_ips = [r.source_ip for r in results if r.source_ip]
    if not source_ips:
        return results

    ti_data = await enrich_results_with_ti(source_ips)
    if not ti_data:
        return results

    updated = []
    for result in results:
        ip  = result.source_ip
        rep = ti_data.get(ip) if ip else None
        if rep and rep.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            score   = rep.get("abuse_confidence_score", 0)
            reports = rep.get("total_reports", 0)
            ti_note = (
                f" [TI: AbuseIPDB confirms {ip} — {score}% abuse confidence, "
                f"{reports} reports, verdict={rep['verdict']}]"
            )
            new_conf = min(result.confidence + 0.10, 1.0) if rep["verdict"] == "MALICIOUS" else result.confidence
            result   = result.model_copy(update={
                "ai_reasoning": result.ai_reasoning + ti_note,
                "confidence":   round(new_conf, 4),
            })
        updated.append(result)
    return updated


# ── Full triage cycle ──────────────────────────────────────────────────────────

async def run_full_triage_cycle(dataset: str = "simulated") -> list[TriageResult]:
    all_results: list[TriageResult] = []
    if dataset == "simulated":
        all_results = await _triage_flat_logs()
    else:
        all_results = await _triage_db_events()
    return _sort_by_severity(all_results)


async def _triage_flat_logs() -> list[TriageResult]:
    from mcp_server import LOG_FILES, _tail

    all_results: list[TriageResult] = []
    for log_type, path in LOG_FILES.items():
        lines = _tail(path, CHUNK_SIZE)
        if lines:
            results = await triage_log_chunk(lines, log_type=log_type, source_type=log_type)
            all_results.extend(results)
    return all_results


async def _triage_db_events() -> list[TriageResult]:
    import sqlite3
    from pathlib import Path

    db_path = Path(__file__).parent.parent.parent / "omniwatch.db"
    if not db_path.exists():
        logger.warning("No database found — falling back to flat logs")
        return await _triage_flat_logs()

    sourcetypes: list[str] = []
    try:
        with sqlite3.connect(str(db_path)) as conn:
            cur = conn.cursor()
            cur.execute("SELECT DISTINCT sourcetype FROM raw_events")
            sourcetypes = [row[0] for row in cur.fetchall()]
    except Exception as exc:
        logger.error("Could not query sourcetypes: %s", exc)
        return []

    all_results: list[TriageResult] = []
    for st in sourcetypes:
        try:
            with sqlite3.connect(str(db_path)) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()
                cur.execute(
                    "SELECT raw_text FROM raw_events WHERE sourcetype = ? ORDER BY timestamp DESC LIMIT ?",
                    (st, CHUNK_SIZE),
                )
                lines = [row["raw_text"] for row in cur.fetchall()]
        except Exception as exc:
            logger.error("Error fetching %s events: %s", st, exc)
            continue
        if lines:
            results = await triage_log_chunk(lines, log_type="botsv3", source_type=st)
            all_results.extend(results)

    return all_results


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def _sort_by_severity(results: list[TriageResult]) -> list[TriageResult]:
    return sorted(results, key=lambda r: _SEVERITY_ORDER.get(r.severity.value, 5))

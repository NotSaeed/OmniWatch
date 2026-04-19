"""
OmniWatch AI Triage Engine
Orchestrates: MCP log retrieval → Claude tool_use call → validation → MITRE enrichment.
"""

import json
import logging
import os
from pathlib import Path

import anthropic

from triage.mitre_map import get_techniques
from triage.models import TriageResult
from triage.prompts import SYSTEM_PROMPT, build_triage_prompt
from triage.validator import validate_batch

logger = logging.getLogger(__name__)

# ── Claude client ─────────────────────────────────────────────────────────────
_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MODEL   = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

# Chunk size: how many log lines to send per Claude call
CHUNK_SIZE = int(os.getenv("TRIAGE_CHUNK_SIZE", "50"))


# ── Tool schema — forces Claude to produce structured TriageResult JSON ────────
TRIAGE_TOOL: dict = {
    "name": "triage_alert",
    "description": (
        "Record a triaged security alert. Call this once per distinct threat event found "
        "in the provided log lines. If no threats are found, call with category=BENIGN."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                "description": "Threat severity level.",
            },
            "category": {
                "type": "string",
                "enum": ["BRUTE_FORCE", "PORT_SCAN", "MALWARE", "EXFILTRATION", "ANOMALY", "BENIGN"],
                "description": "Primary threat category.",
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence score (0.0–1.0) based on evidence quality.",
            },
            "source_ip": {
                "type": "string",
                "description": "Attacker or source IP address as it appears in the logs. Null if not present.",
            },
            "affected_asset": {
                "type": "string",
                "description": "Target hostname, IP, or service as it appears in the logs. Null if not present.",
            },
            "raw_log_excerpt": {
                "type": "string",
                "description": "The exact log line(s) that triggered this alert (verbatim from the provided data).",
            },
            "ai_reasoning": {
                "type": "string",
                "description": "Concise explanation of your reasoning: what patterns you saw, why you chose this severity and category.",
            },
            "recommendations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "action":   {"type": "string"},
                        "priority": {"type": "integer", "minimum": 1, "maximum": 5},
                    },
                    "required": ["action", "priority"],
                },
                "description": "Ordered list of recommended analyst actions (priority 1 = most urgent).",
            },
            "false_positive_risk": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH"],
                "description": "Likelihood this alert is a false positive.",
            },
        },
        "required": [
            "severity", "category", "confidence",
            "raw_log_excerpt", "ai_reasoning",
            "false_positive_risk",
        ],
    },
}


# ── Core triage function ───────────────────────────────────────────────────────

async def triage_log_chunk(
    log_lines: list[str],
    log_type: str = "unknown",
    source_type: str = "simulated",
) -> list[TriageResult]:
    """
    Send a chunk of log lines to Claude for triage.
    Returns a list of validated, MITRE-enriched TriageResult objects.
    """
    if not log_lines:
        return []

    prompt = build_triage_prompt(log_lines, log_type=log_type, source_type=source_type)

    try:
        response = _client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=[TRIAGE_TOOL],
            tool_choice={"type": "any"},   # Force at least one tool call
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIError as exc:
        logger.error("Claude API error during triage: %s", exc)
        return []

    # Extract all triage_alert tool_use blocks from the response
    raw_results = [
        block.input
        for block in response.content
        if block.type == "tool_use" and block.name == "triage_alert"
    ]

    if not raw_results:
        logger.warning("Claude returned no tool calls for %s log chunk (%d lines)", log_type, len(log_lines))
        return []

    # Validate and enrich with MITRE mappings
    validated = validate_batch(raw_results, log_type=log_type, source_type=source_type)
    enriched  = [_enrich_mitre(r) for r in validated]

    # Parallel threat intelligence enrichment — AbuseIPDB lookups for all source IPs
    enriched = await _enrich_threat_intel(enriched)
    return enriched


def _enrich_mitre(result: TriageResult) -> TriageResult:
    """Merge Claude-provided MITRE IDs with static category mappings."""
    static_techniques = get_techniques(result.category)
    merged = list(dict.fromkeys(result.mitre_techniques + static_techniques))
    return result.model_copy(update={"mitre_techniques": merged})


async def _enrich_threat_intel(results: list[TriageResult]) -> list[TriageResult]:
    """
    Enrich results with AbuseIPDB data for all unique source IPs.
    Adjusts confidence and appends TI findings to ai_reasoning.
    Non-fatal — if TI lookup fails the original result is returned unchanged.
    """
    try:
        from mcp_connectors.threat_intel_server import enrich_results_with_ti
    except ImportError:
        return results   # TI connector not available — skip silently

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
                f"{reports} community reports, verdict={rep['verdict']}]"
            )
            # Boost confidence for corroborated IPs
            new_confidence = min(result.confidence + 0.10, 1.0) if rep["verdict"] == "MALICIOUS" else result.confidence
            result = result.model_copy(update={
                "ai_reasoning": result.ai_reasoning + ti_note,
                "confidence":   round(new_confidence, 4),
            })
        updated.append(result)
    return updated


# ── Full triage cycle ──────────────────────────────────────────────────────────

async def run_full_triage_cycle(dataset: str = "simulated") -> list[TriageResult]:
    """
    Run a complete triage cycle across all available log sources.
    Reads from flat log files (simulated) or BOTSv3 database events.
    Returns all results sorted by severity (CRITICAL first).
    """
    from pathlib import Path

    all_results: list[TriageResult] = []

    if dataset == "simulated":
        all_results = await _triage_flat_logs()
    else:
        all_results = await _triage_db_events()

    return _sort_by_severity(all_results)


async def _triage_flat_logs() -> list[TriageResult]:
    """Triage the three flat log files (syslog, network, auth)."""
    from mcp_server import LOG_FILES, _tail  # local import avoids circular

    all_results: list[TriageResult] = []
    for log_type, path in LOG_FILES.items():
        lines = _tail(path, CHUNK_SIZE)
        if lines:
            results = await triage_log_chunk(lines, log_type=log_type, source_type=log_type)
            all_results.extend(results)
    return all_results


async def _triage_db_events() -> list[TriageResult]:
    """Triage normalized events from the BOTSv3 database, grouped by sourcetype."""
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

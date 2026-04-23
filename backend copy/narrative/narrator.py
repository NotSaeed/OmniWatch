"""
OmniWatch Kill Chain Narrator
The competition's "wow" feature: takes all alerts from a scan cycle and has
Claude write a single, coherent threat intelligence narrative — the attack story.

This transforms a table of alerts into a boardroom-ready incident report that
even non-technical judges can immediately understand.

Endpoint: GET /api/scan/{scan_run_id}/narrative
"""

import json
import logging
import os
from datetime import datetime, timezone

import anthropic
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
MODEL   = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

# Kill chain stages in order — used for the progress bar in the dashboard
KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Exfiltration",
]

_CATEGORY_TO_KILL_CHAIN = {
    "PORT_SCAN":    "Reconnaissance",
    "BRUTE_FORCE":  "Delivery",
    "MALWARE":      "Installation",
    "EXFILTRATION": "Exfiltration",
    "ANOMALY":      "Exploitation",
    "BENIGN":       None,
}


class NarrativeReport(BaseModel):
    scan_run_id:         str
    generated_at:        datetime
    narrative_text:      str          # The prose threat intelligence report
    kill_chain_stage:    str          # Furthest stage reached in the kill chain
    kill_chain_index:    int          # 0-based index into KILL_CHAIN_STAGES
    total_alerts:        int
    critical_count:      int
    high_count:          int
    unique_attackers:    list[str]    # Unique source IPs involved
    mitre_techniques:    list[str]    # Unique MITRE techniques across all alerts
    recommended_priority:str          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    tlp_classification:  str = "TLP:WHITE"
    playbooks_fired:     list[str]    # Names of playbooks that executed


_NARRATIVE_SYSTEM_PROMPT = """You are a senior threat intelligence analyst writing an incident report.
Your audience includes both technical SOC analysts and non-technical management.

Write in clear, professional prose. Structure your narrative chronologically.
Be specific — cite the source IPs, hostnames, timestamps, and MITRE techniques from the data.
Do NOT invent any details not present in the provided alert data.
Keep the narrative between 200 and 400 words.

Your report should:
1. Open with a one-sentence executive summary of what happened.
2. Describe the attack chronologically — what the attacker did first, second, third.
3. Identify the furthest stage the attacker reached in the cyber kill chain.
4. Explain what evidence supports each conclusion.
5. Close with a one-sentence assessment of whether the attack succeeded or was contained.
"""


async def generate_kill_chain_narrative(
    scan_run_id: str,
    alerts: list,  # list of db.models.Alert ORM objects
) -> NarrativeReport:
    """
    Generate a prose threat intelligence narrative for a completed scan cycle.
    `alerts` should be pre-filtered to the scan_run_id by the caller.
    """
    if not alerts:
        return _empty_narrative(scan_run_id)

    # ── Summarise alerts for the prompt ───────────────────────────────────────
    alert_summaries = _build_alert_summaries(alerts)
    unique_ips       = list({a.source_ip for a in alerts if a.source_ip})
    all_techniques   = list({
        t
        for a in alerts
        for t in _safe_json(a.mitre_techniques)
    })
    playbooks_fired  = list({a.playbook_triggered for a in alerts if a.playbook_triggered})
    critical_count   = sum(1 for a in alerts if a.severity == "CRITICAL")
    high_count       = sum(1 for a in alerts if a.severity == "HIGH")
    furthest_stage   = _furthest_kill_chain_stage(alerts)
    kill_chain_index = KILL_CHAIN_STAGES.index(furthest_stage) if furthest_stage in KILL_CHAIN_STAGES else 0

    prompt = f"""Here are the triaged security alerts from scan run {scan_run_id}.
Write a threat intelligence narrative report based strictly on this data.

ALERT SUMMARY ({len(alerts)} total alerts):
{alert_summaries}

STATISTICS:
- Unique attacker IPs: {', '.join(unique_ips) or 'None identified'}
- MITRE techniques observed: {', '.join(all_techniques[:10]) or 'None'}
- Playbooks executed: {', '.join(playbooks_fired) or 'None'}
- Critical alerts: {critical_count} | High alerts: {high_count}
- Furthest kill chain stage reached: {furthest_stage}

Write the narrative now. Start directly with the executive summary sentence.
Do not include headers or bullet points — write in flowing prose paragraphs."""

    try:
        response = _client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=_NARRATIVE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        narrative_text = response.content[0].text.strip()
    except anthropic.APIError as exc:
        logger.error("Narrator API call failed: %s", exc)
        narrative_text = _fallback_narrative(alerts, furthest_stage)

    recommended_priority = (
        "CRITICAL" if critical_count > 0 else
        "HIGH"     if high_count > 0     else
        "MEDIUM"
    )

    return NarrativeReport(
        scan_run_id=scan_run_id,
        generated_at=datetime.now(tz=timezone.utc),
        narrative_text=narrative_text,
        kill_chain_stage=furthest_stage,
        kill_chain_index=kill_chain_index,
        total_alerts=len(alerts),
        critical_count=critical_count,
        high_count=high_count,
        unique_attackers=unique_ips,
        mitre_techniques=all_techniques[:15],
        recommended_priority=recommended_priority,
        playbooks_fired=playbooks_fired,
    )


def _build_alert_summaries(alerts: list) -> str:
    """Build a compact text block of alerts sorted chronologically."""
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp or datetime.min.replace(tzinfo=timezone.utc))
    lines = []
    for a in sorted_alerts:
        ts = a.timestamp.strftime("%H:%M:%S UTC") if a.timestamp else "unknown time"
        techniques = ", ".join(_safe_json(a.mitre_techniques)[:3])
        lines.append(
            f"[{ts}] {a.severity} {a.category} | src={a.source_ip or 'N/A'} "
            f"asset={a.affected_asset or 'N/A'} | techniques={techniques or 'N/A'} | "
            f"confidence={a.confidence:.0%} | {a.ai_reasoning[:120]}..."
        )
    return "\n".join(lines)


def _furthest_kill_chain_stage(alerts: list) -> str:
    """Return the furthest kill chain stage reached across all alerts."""
    stages_reached = set()
    for a in alerts:
        stage = _CATEGORY_TO_KILL_CHAIN.get(a.category)
        if stage:
            stages_reached.add(stage)

    if not stages_reached:
        return "Reconnaissance"

    # Return the stage with the highest index in the kill chain
    return max(stages_reached, key=lambda s: KILL_CHAIN_STAGES.index(s) if s in KILL_CHAIN_STAGES else -1)


def _fallback_narrative(alerts: list, furthest_stage: str) -> str:
    """Generate a basic narrative without Claude — used if API call fails."""
    ips = list({a.source_ip for a in alerts if a.source_ip})
    cats = list({a.category for a in alerts if a.category != "BENIGN"})
    return (
        f"OmniWatch detected {len(alerts)} security events during this scan cycle. "
        f"{'Suspicious activity was observed from ' + ', '.join(ips[:3]) + '. ' if ips else ''}"
        f"{'Threat categories identified: ' + ', '.join(cats) + '. ' if cats else ''}"
        f"The furthest kill chain stage reached was {furthest_stage}. "
        f"Analyst review is recommended for all HIGH and CRITICAL alerts."
    )


def _empty_narrative(scan_run_id: str) -> NarrativeReport:
    return NarrativeReport(
        scan_run_id=scan_run_id,
        generated_at=datetime.now(tz=timezone.utc),
        narrative_text="No alerts were generated in this scan cycle. The environment appears clean.",
        kill_chain_stage="Reconnaissance",
        kill_chain_index=0,
        total_alerts=0,
        critical_count=0,
        high_count=0,
        unique_attackers=[],
        mitre_techniques=[],
        recommended_priority="LOW",
        playbooks_fired=[],
    )


def _safe_json(value) -> list:
    if isinstance(value, list):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []

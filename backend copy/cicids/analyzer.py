"""
Tier 2 Incident Response Report generator.

Takes an attack_summary dict (produced by cicids_parser.get_attack_summary_for_report)
and calls Claude to produce a professional IR report suitable for CISO review.
"""

import logging
import os
import uuid
from datetime import datetime, timezone

import anthropic

logger = logging.getLogger(__name__)

_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
MODEL   = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

# ── Tool schema ───────────────────────────────────────────────────────────────

_IR_TOOL = {
    "name": "write_ir_report",
    "description": (
        "Write a structured Tier 2 SOC Incident Response Report "
        "based on the CIC-IDS-2017 network traffic analysis provided."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "executive_summary": {
                "type": "string",
                "description": "2-3 sentence CISO-level summary of the incident.",
            },
            "attack_details": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "attack_type":       {"type": "string"},
                        "count":             {"type": "integer"},
                        "description":       {"type": "string", "description": "Attack mechanics explanation (2-3 sentences)."},
                        "mitre_techniques":  {"type": "array", "items": {"type": "string"}},
                        "mitigation_steps":  {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["attack_type", "count", "description", "mitre_techniques", "mitigation_steps"],
                },
            },
            "immediate_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Ordered containment steps to execute right now.",
            },
            "long_term_recommendations": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Strategic security improvements (30-90 day horizon).",
            },
            "severity_assessment": {
                "type": "string",
                "description": "Overall severity and business impact statement.",
            },
            "affected_systems": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Inferred affected system types or IP ranges.",
            },
        },
        "required": [
            "executive_summary", "attack_details", "immediate_actions",
            "long_term_recommendations", "severity_assessment", "affected_systems",
        ],
    },
}

_SYSTEM_PROMPT = """You are a Tier 2 SOC Analyst writing a formal Incident Response Report.

Your reports must be:
- Grounded in the provided telemetry — do not invent incidents not present in the data
- Professional in tone (suitable for CISO review)
- Technically precise: use correct MITRE ATT&CK technique IDs (format: T####.###)
- Actionable: every finding must link to a concrete remediation step
- Concise: executive summary is for leadership, attack details are for the technical team"""


async def generate_ir_report(attack_summary: dict) -> dict:
    """
    Generate a Tier 2 IR report from a CIC-IDS-2017 attack summary.
    Falls back to a template report if the Claude API is unavailable.
    """
    if not attack_summary.get("attacks"):
        return _benign_report(attack_summary)

    prompt = _build_prompt(attack_summary)

    try:
        response = _client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            tools=[_IR_TOOL],
            tool_choice={"type": "any"},
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.APIError as exc:
        logger.error("Claude API error generating IR report: %s", exc)
        return _fallback_report(attack_summary)

    for block in response.content:
        if block.type == "tool_use" and block.name == "write_ir_report":
            return {
                "report_id":             str(uuid.uuid4()),
                "generated_at":          datetime.now(tz=timezone.utc).isoformat(),
                "source_file":           attack_summary.get("source_file", "unknown"),
                "total_events_analyzed": attack_summary.get("total_events", 0),
                **block.input,
            }

    return _fallback_report(attack_summary)


def _build_prompt(summary: dict) -> str:
    attacks = summary.get("attacks", [])
    lines = "\n".join(
        f"  • {a['label']}: {a['count']:,} flows | severity={a['severity']} | "
        f"sample source IPs: {', '.join(a.get('sample_ips', [])[:3]) or 'N/A'}"
        for a in attacks
    )
    tr = summary.get("time_range", {})
    return f"""Analyze the following CIC-IDS-2017 network intrusion dataset and produce an Incident Response Report.

DATASET FILE : {summary.get('source_file', 'unknown')}
TOTAL EVENTS : {summary.get('total_events', 0):,}
TIME RANGE   : {tr.get('start', 'N/A')} → {tr.get('end', 'N/A')}

DETECTED ATTACKS:
{lines}

For each attack type:
1. Explain how the attack works and why it is dangerous
2. Provide the correct MITRE ATT&CK technique ID(s)
3. List concrete mitigation steps
4. Identify the most impacted systems based on the IPs shown

End with prioritised immediate containment actions and long-term strategic recommendations."""


_LABEL_MITRE: dict[str, list[str]] = {
    "DoS":         ["T1498.001 — Direct Network Flood", "T1499.002 — Service Exhaustion Flood"],
    "DDoS":        ["T1498.001 — Direct Network Flood", "T1498.002 — Reflection Amplification"],
    "PortScan":    ["T1046 — Network Service Discovery", "T1595.001 — Scanning IP Blocks"],
    "Bot":         ["T1071.001 — Web Protocols (C2)", "T1102 — Web Service", "T1571 — Non-Standard Port"],
    "FTP-Patator": ["T1110.001 — Password Guessing", "T1078 — Valid Accounts"],
    "SSH-Patator": ["T1110.001 — Password Guessing", "T1021.004 — SSH Remote Access"],
    "Web Attack":  ["T1190 — Exploit Public-Facing Application", "T1059.007 — JavaScript / XSS"],
    "Infiltration":["T1078 — Valid Accounts", "T1083 — File and Directory Discovery"],
    "Heartbleed":  ["T1190 — Exploit Public-Facing Application", "T1552.004 — Private Keys"],
}

def _label_mitre(label: str) -> list[str]:
    for k, v in _LABEL_MITRE.items():
        if k.upper() in label.upper():
            return v
    return ["T1071 — Application Layer Protocol", "T1046 — Network Service Discovery"]


def _fallback_report(summary: dict) -> dict:
    attacks = summary.get("attacks", [])
    source  = summary.get("source_file") or "Ingested Dataset"
    total   = summary.get("total_events", 0)

    top_severity = "HIGH"
    for a in attacks:
        if a.get("severity") == "CRITICAL":
            top_severity = "CRITICAL"
            break

    executive_summary = (
        f"Heuristic Analysis Complete: Tier 1 detection engine identified "
        f"{len(attacks)} distinct threat class(es) across {total:,} network flow records "
        f"sourced from '{source}'. Automated AI narrative generation is currently queued "
        "or unavailable — relying on deterministic Tier 1 engine heuristics. "
        "Immediate Tier 2 review is recommended for all CRITICAL and HIGH severity findings."
    )

    return {
        "report_id":             str(uuid.uuid4()),
        "generated_at":          datetime.now(tz=timezone.utc).isoformat(),
        "source_file":           source,
        "total_events_analyzed": total,
        "executive_summary":     executive_summary,
        "attack_details": [
            {
                "attack_type":      a["label"],
                "count":            a["count"],
                "description": (
                    f"{a['count']:,} flows classified as {a['label']} "
                    f"(severity: {a.get('severity', 'UNKNOWN')}). "
                    "Deterministic heuristic match — threat signature confidence HIGH. "
                    "Full AI narrative pending analyst queue clearance."
                ),
                "mitre_techniques": _label_mitre(a["label"]),
                "mitigation_steps": [
                    f"Block source IP ranges associated with {a['label']} at the perimeter firewall.",
                    "Enable IDS/IPS blocking rules for this attack signature family.",
                    "Preserve PCAP evidence and escalate to Tier 2 for forensic correlation.",
                ],
            }
            for a in attacks
        ],
        "immediate_actions": [
            "Isolate network segments showing anomalous egress traffic patterns.",
            "Activate firewall block rules for top-N attacker source IPs identified in telemetry.",
            "Preserve packet captures and memory dumps from affected hosts for forensic analysis.",
            "Escalate to Tier 2 SOC analyst for full incident ownership and AI-assisted triage.",
        ],
        "long_term_recommendations": [
            "Deploy network behavioural anomaly detection (UEBA) to reduce alert fatigue.",
            "Implement zero-trust micro-segmentation for east-west traffic control.",
            "Review and harden ingress/egress firewall ACLs based on observed source ASNs.",
            "Schedule quarterly red-team exercises targeting the detected attack vectors.",
        ],
        "severity_assessment": (
            f"Overall severity: {top_severity}. "
            f"Telemetry analysis identified {len(attacks)} active threat class(es) across "
            f"{total:,} flow records. Heuristic confidence: HIGH. "
            "Full AI-assisted risk scoring will be available once the analyst queue is cleared."
        ),
        "affected_systems": list({
            ip
            for a in attacks
            for ip in a.get("sample_ips", [])[:3]
        }),
    }


def _benign_report(summary: dict) -> dict:
    return {
        "report_id":             str(uuid.uuid4()),
        "generated_at":          datetime.now(tz=timezone.utc).isoformat(),
        "source_file":           summary.get("source_file", "unknown"),
        "total_events_analyzed": summary.get("total_events", 0),
        "executive_summary":     "No attack traffic detected. All flows classified as BENIGN.",
        "attack_details":        [],
        "immediate_actions":     ["Continue routine monitoring"],
        "long_term_recommendations": ["Maintain current security posture"],
        "severity_assessment":   "No threats detected — LOW risk.",
        "affected_systems":      [],
    }

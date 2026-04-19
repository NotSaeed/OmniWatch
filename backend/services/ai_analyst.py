"""
Tier 2 AI Analyst — Sprint 2 (Air-Gapped Local Pipeline)
Generates professional Incident Response Reports using local Phi-3-Mini via Ollama.
Anthropic dependency removed; all inference is local and offline.
"""

import logging

from llm.ollama_client import OllamaUnavailableError, get_client

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a Senior Tier 2 SOC Analyst at a water treatment facility \
(SWaT — Secure Water Treatment) security operations centre.

A Tier 1 analyst has escalated a network intrusion alert. Write a complete, professional \
Incident Response Report in Markdown. This system is air-gapped — do not reference any \
cloud services, external URLs, or tools unavailable on-premise.

**Output format — follow this structure exactly:**

## Executive Summary
Two to three sentences. State the attack type, risk level, and the single most critical \
containment action. Be direct and authoritative.

## Technical Analysis
Precise technical explanation of how this attack operates in an ICS/SCADA context. \
Reference specific protocol behaviour (Modbus, DNP3, EtherNet/IP, OPC-UA) where relevant. \
3–5 sentences.

## Affected Assets
Characterise the attacker origin and victim system. Note service or PLC significance of \
the destination port. Assess blast radius if the attack reaches the OT network segment.

## MITRE ATT&CK Mapping
List 3–5 relevant techniques. Format: `- **T####.###** — Technique Name: one-sentence relevance.`
Include ICS-specific techniques from MITRE ATT&CK for ICS where applicable.

## Recommended Remediation Steps
Numbered list. First three steps are immediate containment (actionable within minutes). \
Remaining steps are short-term hardening (hours to days). Be specific.

## Risk Assessment
State overall risk: **CRITICAL / HIGH / MEDIUM / LOW**. \
One sentence on immediate operational impact and one on long-term exposure if unmitigated.

## Detection Engineering (Sigma / Splunk SPL)
Generate one ready-to-deploy detection rule based on the attack type and targeted port. \
Use a ```splunk``` or ```yaml``` fenced block. Add one sentence covering what the rule \
catches, false-positive rate, and one tuning recommendation.

---
**Absolute rules:**
- Analyse only the data provided. Never invent IPs, timestamps, or events.
- Use active voice and precise security terminology.
- Never use "simulated", "mock", "placeholder", or "TBD"."""


async def generate_incident_report(event: dict, cti: dict | None = None) -> str:
    """
    Generate a Markdown Incident Response Report for a single network event.
    Falls back to a deterministic local report if Ollama is unavailable.
    """
    prompt = _build_prompt(event, cti)
    client = get_client()

    try:
        text = await client.generate_report(prompt, _SYSTEM_PROMPT)
        return text or _fallback_report(event)
    except OllamaUnavailableError as exc:
        logger.warning("Ollama unavailable for IR report: %s — using local fallback", exc)
        return _fallback_report(event)


def _build_prompt(event: dict, cti: dict | None = None) -> str:
    def _fmt(v) -> str:
        return str(v) if v not in (None, "", "None") else "N/A"

    duration_s = None
    if event.get("flow_duration") is not None:
        try:
            duration_s = f"{float(event['flow_duration']) / 1_000_000:.3f}s"
        except (ValueError, TypeError):
            pass

    lines = [
        "A Tier 1 analyst has escalated the following network intrusion alert:",
        "",
        "| Field            | Value |",
        "|------------------|-------|",
        f"| Attack Label     | **{_fmt(event.get('label'))}** |",
        f"| Severity         | **{_fmt(event.get('severity'))}** |",
        f"| Category         | {_fmt(event.get('category'))} |",
        f"| Source IP        | `{_fmt(event.get('src_ip'))}` |",
        f"| Destination IP   | `{_fmt(event.get('dst_ip'))}` |",
        f"| Destination Port | `{_fmt(event.get('dst_port'))}` |",
        f"| Protocol         | {_fmt(event.get('protocol'))} |",
        f"| Flow Duration    | {duration_s or _fmt(event.get('flow_duration'))} |",
        f"| Flow Bytes/s     | {_fmt(event.get('flow_bytes_s'))} |",
        f"| Source File      | {_fmt(event.get('source_file'))} |",
        f"| Ingested At      | {_fmt(event.get('ingested_at'))} |",
    ]

    if cti:
        lines += ["", "---", "**Cyber Threat Intelligence (pre-fetched):**", ""]
        abuse = cti.get("abuseipdb", {})
        if not abuse.get("skipped") and not abuse.get("error"):
            lines.append(
                f"- **AbuseIPDB** — Confidence Score: **{abuse.get('abuse_confidence_score', 0)}%** "
                f"| Country: {abuse.get('country_code', 'N/A')} "
                f"| ISP: {abuse.get('isp', 'N/A')} "
                f"| Total Reports: {abuse.get('total_reports', 0)}"
            )
        vt = cti.get("virustotal", {})
        if not vt.get("skipped"):
            lines.append(
                f"- **VirusTotal** — {vt.get('malicious', 0)}/{vt.get('total_engines', 94)} "
                f"engines flagged | Threat label: {vt.get('threat_label', 'clean')}"
            )
        mitre = cti.get("mitre", [])
        if mitre:
            tech_str = ", ".join(f"{t['id']} ({t['tactic']})" for t in mitre)
            lines.append(f"- **MITRE ATT&CK** — {tech_str}")

    lines += ["", "Write the full Incident Response Report following the structure in your instructions."]
    return "\n".join(lines)


def _fallback_report(event: dict) -> str:
    """Deterministic local report — called when Ollama is unreachable."""
    label    = event.get("label") or "Anomalous Network Activity"
    severity = event.get("severity") or "HIGH"
    src      = event.get("src_ip") or "Unknown-Source"
    dst      = event.get("dst_ip") or "Internal Asset"
    port     = event.get("dst_port") or "N/A"
    proto    = event.get("protocol") or "TCP"

    try:
        dur_s = f"{float(event['flow_duration']) / 1_000_000:.3f}s"
    except (TypeError, ValueError, KeyError):
        dur_s = "< 1s"

    try:
        bps = f"{float(event['flow_bytes_s']):,.1f} B/s"
    except (TypeError, ValueError, KeyError):
        bps = "elevated"

    return f"""## Executive Summary

**{severity}** — Anomalous network activity classified as **{label}** detected from \
`{src}` targeting `{dst}:{port}`. Immediate investigation and containment are required \
to prevent escalation to the OT/SCADA network segment.

## Technical Analysis

A {proto} flow from `{src}` to `{dst}:{port}` spanning {dur_s} at {bps} deviates from \
established facility baselines. The traffic pattern is consistent with threat category \
**{label}**. Further correlation with endpoint telemetry and PLC audit logs is recommended \
to determine whether lateral movement toward the OT segment has occurred.

## Affected Assets

- **Attacker origin:** `{src}` — assess whether external or a compromised internal node.
- **Target:** `{dst}:{port}` — verify asset classification in CMDB (IT vs OT network).
- **Protocol:** `{proto}` | **Duration:** {dur_s} | **Throughput:** {bps}

## MITRE ATT&CK Mapping

- **T1071** — Application Layer Protocol: Traffic using standard protocols for obfuscation.
- **T1041** — Exfiltration Over C2 Channel: Potential data loss via established communications.
- **T0885** — Commonly Used Port (ICS): Use of standard ICS ports to blend with normal traffic.

## Recommended Remediation Steps

1. Block `{src}` at the perimeter firewall and add to the threat intelligence blocklist.
2. Inspect all traffic between `{src}` and `{dst}:{port}` for the past 24 hours via SIEM.
3. Alert the asset owner of `{dst}` and initiate standard incident response procedures.
4. Review and tighten egress firewall rules for the affected network segment.
5. Verify no lateral movement has reached the OT DMZ — review Modbus/DNP3 logs.

## Risk Assessment

**{severity}** — Treat as active threat until investigation confirms otherwise. \
Unmitigated, this could provide an attacker with a pathway to the SCADA historian or PLCs.

## Detection Engineering (Sigma / Splunk SPL)

```splunk
index=network sourcetype=netflow
| where src_ip="{src}" AND dest_ip="{dst}" AND dest_port={port}
| bucket _time span=5m
| stats count AS connections, sum(bytes_in) AS total_bytes BY _time, src_ip, dest_ip, dest_port
| where connections > 50
| table _time, src_ip, dest_ip, dest_port, connections, total_bytes
```

*Generic anomaly rule for `{label}` traffic; tune the connection-count threshold \
to 3× your facility baseline for this source/destination pair. Expected false-positive \
rate: low if threshold is correctly calibrated to operational traffic.*"""

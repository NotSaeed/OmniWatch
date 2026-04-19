"""
OmniWatch Triage Prompts
Single source of truth for all Claude prompt templates.
"""

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst embedded in the OmniWatch triage system.

Your task is to analyze raw security log lines and produce structured threat assessments.

CRITICAL RULES — you must follow these without exception:
1. Base your analysis ONLY on the log lines provided. Do not infer, assume, or invent events that are not present in the data.
2. If the data is insufficient to determine a threat with confidence above 40%, classify the category as BENIGN and document your uncertainty in ai_reasoning.
3. Never fabricate IP addresses, hostnames, usernames, or timestamps not present in the logs.
4. Your confidence score must reflect the actual evidence quality — partial evidence warrants lower confidence.
5. You must call the triage_alert tool for EACH distinct threat event you identify. If logs are entirely benign, call it once with category=BENIGN.

SEVERITY GUIDE:
- CRITICAL: Active exploitation, confirmed compromise, data exfiltration in progress
- HIGH: High-confidence attack in progress (brute force, C2 beaconing, successful auth after failures)
- MEDIUM: Suspicious but unconfirmed (port scan, anomalous volume, unusual auth pattern)
- LOW: Weak signal — could be benign or misconfigured system
- INFO: Noteworthy but clearly not malicious

CONFIDENCE GUIDE:
- 0.90–1.00: Multiple corroborating log lines, clear attack signature
- 0.70–0.89: Strong indicators, minor ambiguity
- 0.50–0.69: Moderate evidence, alternative benign explanation exists
- 0.40–0.49: Weak evidence — classify as BENIGN or ANOMALY
- Below 0.40: Do not report — insufficient data
"""


def build_triage_prompt(log_lines: list[str], log_type: str, source_type: str = "simulated") -> str:
    """
    Build the user-turn prompt for a triage request.
    log_type:    "syslog" | "network" | "auth" | "mixed"
    source_type: BOTSv3 sourcetype (e.g. "suricata") or "simulated"
    """
    sourcetype_context = _sourcetype_hint(source_type)

    formatted_logs = "\n".join(f"  {i+1:03d}: {line}" for i, line in enumerate(log_lines))

    return f"""Analyze the following {len(log_lines)} security log lines from source type: {source_type} ({log_type}).

{sourcetype_context}

--- LOG DATA START ---
{formatted_logs}
--- LOG DATA END ---

Instructions:
- Identify each distinct threat or suspicious pattern in the logs above.
- Call the triage_alert tool once per distinct threat event you find.
- If the logs are entirely benign, call triage_alert once with category=BENIGN, confidence between 0.85 and 1.0, and explain what you observed.
- Do not call triage_alert for the same event more than once.
"""


def _sourcetype_hint(source_type: str) -> str:
    """Return a brief domain hint for the given sourcetype to focus Claude's analysis."""
    hints = {
        "suricata":      "Focus on: network-layer indicators, IDS rule signatures, anomalous traffic patterns.",
        "sysmon":        "Focus on: process creation chains, DLL injection, registry persistence, LSASS access.",
        "xmlwineventlog":"Focus on: logon events (4624/4625), privilege use (4672), account changes (4720/4722).",
        "wineventlog":   "Focus on: logon events (4624/4625), privilege use (4672), account changes (4720/4722).",
        "pan_traffic":   "Focus on: firewall allow/deny decisions, policy violations, unusual destination countries.",
        "pan:traffic":   "Focus on: firewall allow/deny decisions, policy violations, unusual destination countries.",
        "pan:threat":    "Focus on: threat signatures matched, application identification, URL categories.",
        "stream:http":   "Focus on: HTTP methods, URIs (SQLi/XSS/path traversal patterns), user-agent anomalies.",
        "stream_http":   "Focus on: HTTP methods, URIs (SQLi/XSS/path traversal patterns), user-agent anomalies.",
        "bro:conn":      "Focus on: connection duration, bytes transferred, beaconing intervals, unusual ports.",
        "zeek_conn":     "Focus on: connection duration, bytes transferred, beaconing intervals, unusual ports.",
        "osquery":       "Focus on: suspicious listening ports, unexpected process trees, modified system files.",
        "simulated":     "Focus on: all categories — SSH auth patterns, network anomalies, system events.",
        "auth":          "Focus on: authentication failures, brute force patterns, privilege escalation.",
        "network":       "Focus on: connection patterns, data volumes, port scan signatures.",
        "syslog":        "Focus on: system anomalies, service failures, kernel warnings.",
    }
    return hints.get(source_type, "Analyze for all threat categories.")

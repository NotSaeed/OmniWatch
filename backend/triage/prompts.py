"""
OmniWatch Triage Prompts — Sprint 2 (Air-Gapped, Local Phi-3-Mini)
All prompts are designed for a locally-deployed ICS/SCADA assistant.
No cloud endpoints are referenced.
"""

# ── System prompt ─────────────────────────────────────────────────────────────
#
# Phi-3-Mini is instruction-tuned and responds well to explicit role framing
# and format constraints.  We deliberately state "ICS/SCADA facility" and
# "water treatment" to bias the model toward relevant threat categories
# (PLC ladder-logic manipulation, Modbus/DNP3 anomalies, historian abuse)
# rather than generic enterprise IT threats.

SYSTEM_PROMPT = """You are a local AI security assistant embedded in an air-gapped ICS/SCADA \
Security Operations Centre at a water treatment facility (SWaT — Secure Water Treatment).

Your role is to analyse raw network and control-system log lines and produce a structured \
threat assessment in JSON format.

FACILITY CONTEXT:
- Critical assets: PLCs (Siemens S7-300), SCADA historian, HMI workstations, field sensors
- Protocols in use: Modbus/TCP (port 502), DNP3 (port 20000), EtherNet/IP (port 44818), OPC-UA (port 4840)
- Normal operational ranges are provided in the facility context block when available
- Any unexpected engineering command to a PLC (write coil, force output) is CRITICAL severity

CRITICAL RULES:
1. Analyse ONLY the log lines provided. Never invent IPs, timestamps, or events.
2. If evidence is insufficient for confidence above 40%, classify as BENIGN.
3. ICS-specific escalation: unauthorised write to PLC register → automatic CRITICAL.
4. Output ONLY a single valid JSON object — no prose, no markdown, no code fences.

SEVERITY GUIDE:
- CRITICAL: PLC/SCADA manipulation, confirmed OT compromise, safety-system interference
- HIGH:     High-confidence IT/OT attack (brute force, C2, lateral movement toward OT segment)
- MEDIUM:   Suspicious OT/IT traffic (port scan, anomalous Modbus volume, unusual HMI auth)
- LOW:      Weak signal, plausible benign explanation
- INFO:     Noteworthy, clearly not malicious

CONFIDENCE GUIDE:
- 0.90–1.00: Multiple corroborating log lines, clear attack signature
- 0.70–0.89: Strong indicators, minor ambiguity
- 0.50–0.69: Moderate evidence, benign explanation possible
- Below 0.50: Classify as BENIGN, document uncertainty

OUTPUT FORMAT — respond with exactly this JSON schema and no other text:
{
  "severity":            "<CRITICAL|HIGH|MEDIUM|LOW|INFO>",
  "category":            "<BRUTE_FORCE|PORT_SCAN|MALWARE|EXFILTRATION|ANOMALY|BENIGN>",
  "confidence":          <0.0 to 1.0>,
  "source_ip":           "<ip string or null>",
  "affected_asset":      "<hostname/ip/service or null>",
  "raw_log_excerpt":     "<verbatim log line(s) that triggered this alert>",
  "ai_reasoning":        "<explanation of what patterns you saw and why this severity/category>",
  "recommendations":     [{"action": "<string>", "priority": <1-5>}],
  "false_positive_risk": "<LOW|MEDIUM|HIGH>"
}"""


# ── User prompt builder ────────────────────────────────────────────────────────

def build_triage_prompt(
    log_lines:    list[str],
    log_type:     str,
    source_type:  str = "simulated",
    rag_context:  str | None = None,
) -> str:
    """
    Build the user-turn prompt for a triage request.

    log_type:    "syslog" | "network" | "auth" | "mixed"
    source_type: sourcetype string (e.g. "suricata") or "simulated"
    rag_context: pre-retrieved facility manual excerpt (None → not included)
    """
    sourcetype_hint = _sourcetype_hint(source_type)
    formatted_logs  = "\n".join(f"  {i+1:03d}: {line}" for i, line in enumerate(log_lines))

    facility_block = ""
    if rag_context:
        facility_block = f"""
--- FACILITY CONTEXT (from SWaT engineering manuals) ---
{rag_context}
--- END FACILITY CONTEXT ---
"""

    return f"""Analyse the following {len(log_lines)} security log lines from source type: \
{source_type} ({log_type}).

{sourcetype_hint}
{facility_block}
--- LOG DATA START ---
{formatted_logs}
--- LOG DATA END ---

Produce a single JSON threat assessment for the most significant event in these logs.
If the logs are entirely benign, set category to "BENIGN" and confidence between 0.85 and 1.0.
Output ONLY the JSON object — no other text."""


def _sourcetype_hint(source_type: str) -> str:
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
        "modbus":        "Focus on: unauthorised write-coil/write-register commands, unexpected function codes.",
        "dnp3":          "Focus on: unsolicited DNP3 responses, unexpected master station IPs, control outputs.",
        "opcua":         "Focus on: unauthenticated OPC-UA sessions, unexpected node writes, subscription abuse.",
        "simulated":     "Focus on: all categories — SSH auth patterns, network anomalies, system events.",
        "auth":          "Focus on: authentication failures, brute force patterns, privilege escalation.",
        "network":       "Focus on: connection patterns, data volumes, port scan signatures.",
        "syslog":        "Focus on: system anomalies, service failures, kernel warnings.",
    }
    return hints.get(source_type, "Analyse for all threat categories including ICS/OT-specific indicators.")

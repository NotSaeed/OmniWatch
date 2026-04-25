"""
MITRE ATT&CK Technique Mapping — OmniWatch v2
==============================================
Two mapping modes:

1. Category-based (static) — `get_techniques(category)`:
   Returns known technique IDs for a broad ThreatCategory enum value.
   Used by the AI-triage engine and playbook trigger system.

2. Signal-based (dynamic) — `derive_from_signals(...)`:
   Derives the most specific technique from runtime signals:
   label keyword > Z-score magnitude > destination port > volume > protocol.
   Used by analysis_engine.py's Tier 2 enrichment.

Source: https://attack.mitre.org/
"""

from __future__ import annotations

from triage.models import ThreatCategory

# ── Category-based mapping (static) ──────────────────────────────────────────

MITRE_MAP: dict[ThreatCategory, list[str]] = {
    ThreatCategory.BRUTE_FORCE: [
        "T1110",        # Brute Force
        "T1110.001",    # Password Guessing
        "T1110.003",    # Password Spraying
        "T1078",        # Valid Accounts (if credentials succeed)
    ],
    ThreatCategory.PORT_SCAN: [
        "T1046",        # Network Service Discovery
        "T1595",        # Active Scanning
        "T1595.001",    # Scanning IP Blocks
        "T1595.002",    # Vulnerability Scanning
    ],
    ThreatCategory.MALWARE: [
        "T1059",        # Command and Scripting Interpreter
        "T1071",        # Application Layer Protocol (C2)
        "T1071.001",    # Web Protocols
        "T1543",        # Create or Modify System Process
        "T1547",        # Boot or Logon Autostart Execution
        "T1498",        # Network Denial of Service (DoS family)
        "T1499",        # Endpoint Denial of Service
    ],
    ThreatCategory.EXFILTRATION: [
        "T1041",        # Exfiltration Over C2 Channel
        "T1048",        # Exfiltration Over Alternative Protocol
        "T1048.002",    # Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
        "T1567",        # Exfiltration Over Web Service
    ],
    ThreatCategory.ANOMALY: [
        "T1078",        # Valid Accounts
        "T1136",        # Create Account
        "T1098",        # Account Manipulation
        "T1571",        # Non-Standard Port (statistical outlier on port usage)
    ],
    ThreatCategory.BENIGN: [],
}

# Human-readable descriptions for dashboard tooltips
MITRE_DESCRIPTIONS: dict[str, str] = {
    "T1110":     "Brute Force — repeated authentication attempts",
    "T1110.001": "Password Guessing — systematic credential attempts",
    "T1110.003": "Password Spraying — one password across many accounts",
    "T1078":     "Valid Accounts — use of legitimate credentials",
    "T1046":     "Network Service Discovery — port and service enumeration",
    "T1595":     "Active Scanning — probing target infrastructure",
    "T1595.001": "Scanning IP Blocks — systematic IP range probing",
    "T1595.002": "Vulnerability Scanning — probing for known weaknesses",
    "T1059":     "Command and Scripting Interpreter — malicious script execution",
    "T1071":     "Application Layer Protocol — C2 over standard protocols",
    "T1071.001": "Web Protocols — C2 using HTTP/HTTPS",
    "T1071.004": "Application Layer Protocol: DNS — DNS tunneling / C2",
    "T1543":     "Create/Modify System Process — persistence via services",
    "T1547":     "Boot/Logon Autostart — persistence at startup",
    "T1041":     "Exfiltration Over C2 Channel — data theft via C2",
    "T1048":     "Exfiltration Over Alternative Protocol — non-C2 exfil",
    "T1048.002": "Exfiltration via Asymmetric Encrypted Protocol",
    "T1567":     "Exfiltration Over Web Service — cloud/storage abuse",
    "T1136":     "Create Account — unauthorized account creation",
    "T1098":     "Account Manipulation — privilege or credential changes",
    "T1498":     "Network Denial of Service — volumetric flood attack",
    "T1499":     "Endpoint Denial of Service — resource exhaustion attack",
    "T1571":     "Non-Standard Port — traffic on unusual/ephemeral port",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB / Windows Admin Shares",
    "T1021.004": "Remote Services: SSH",
    "T1190":     "Exploit Public-Facing Application",
    "T1110.001": "Brute Force: Password Guessing",
    "T1486":     "Data Encrypted for Impact — ransomware",
    "T1090":     "Proxy",
    "T1090.003": "Proxy: Multi-hop Proxy (Tor / anonymizer)",
}

# ── Signal-based dynamic derivation ──────────────────────────────────────────

# Ordered most-specific to least-specific — first match wins.
_LABEL_RULES: list[tuple[str, str, str]] = [
    ("ftp-patator",   "T1110.001", "Brute Force: Password Guessing"),
    ("ssh-patator",   "T1110.001", "Brute Force: Password Guessing"),
    ("heartbleed",    "T1190",     "Exploit Public-Facing Application"),
    ("shellshock",    "T1190",     "Exploit Public-Facing Application"),
    ("sql injection", "T1190",     "Exploit Public-Facing Application"),
    ("web attack",    "T1190",     "Exploit Public-Facing Application"),
    ("infiltration",  "T1190",     "Exploit Public-Facing Application"),
    ("ransomware",    "T1486",     "Data Encrypted for Impact"),
    ("ddos",          "T1498",     "Network Denial of Service"),
    ("dos",           "T1499",     "Endpoint Denial of Service"),
    ("port scan",     "T1046",     "Network Service Discovery"),
    ("portscan",      "T1046",     "Network Service Discovery"),
    ("network scan",  "T1046",     "Network Service Discovery"),
    ("brute force",   "T1110",     "Brute Force"),
    ("bruteforce",    "T1110",     "Brute Force"),
    ("bot",           "T1583",     "Acquire Infrastructure"),
    ("xss",           "T1189",     "Drive-by Compromise"),
    ("lateral",       "T1021",     "Remote Services"),
    ("exfil",         "T1041",     "Exfiltration Over C2 Channel"),
    ("c&c",           "T1071",     "Application Layer Protocol"),
    ("command",       "T1059",     "Command and Scripting Interpreter"),
    ("privilege",     "T1548",     "Abuse Elevation Control Mechanism"),
    ("credential",    "T1555",     "Credentials from Password Stores"),
    ("phishing",      "T1566",     "Phishing"),
    ("malware",       "T1204",     "User Execution"),
]

_PORT_RULES: dict[int, tuple[str, str]] = {
    21:    ("T1021.002", "Remote Services: FTP"),
    22:    ("T1021.004", "Remote Services: SSH"),
    23:    ("T1021.001", "Remote Services: Telnet"),
    53:    ("T1071.004", "Application Layer Protocol: DNS"),
    80:    ("T1071.001", "Application Layer Protocol: Web Protocols"),
    443:   ("T1071.001", "Application Layer Protocol: Web Protocols"),
    445:   ("T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    1433:  ("T1190",     "Exploit Public-Facing Application"),
    3306:  ("T1190",     "Exploit Public-Facing Application"),
    3389:  ("T1021.001", "Remote Services: Remote Desktop Protocol"),
    4444:  ("T1059",     "Command and Scripting Interpreter"),
    5900:  ("T1021.005", "Remote Services: VNC"),
    6667:  ("T1071",     "Application Layer Protocol"),
    9001:  ("T1090.003", "Proxy: Multi-hop Proxy"),
}


def derive_from_signals(
    label:         str | None = None,
    dst_port:      int | None = None,
    bytes_out:     float | None = None,
    protocol:      str | None = None,
    *,
    z_score_bytes: float | None = None,
    z_score_pkts:  float | None = None,
) -> tuple[str, str]:
    """
    Dynamically derive the most specific MITRE ATT&CK technique from
    available runtime signals.

    Priority (most specific → most general):
      1. Label keyword match
      2. Volumetric Z-score > 6.0 on bytes/s → T1498 (severe DoS flood)
      3. Volumetric Z-score > 3.0 on bytes/s → T1499 (moderate endpoint DoS)
      4. Packet-rate Z-score > 3.0            → T1046 (potential sweep/scan)
      5. Known destination port               → port-specific technique
      6. Absolute byte volume heuristic       → T1041 or T1048
      7. ICMP protocol                        → T1498
      8. Default                              → T1046

    Parameters
    ----------
    z_score_bytes : float | None
        |Z| of the flow's bytes/s against the session baseline.
        Populated by analysis_engine.zscore_baseline_filter().
    z_score_pkts : float | None
        |Z| of the flow's packet count against the session baseline.
    """
    # 1. Label keyword
    if label:
        lc = label.strip().lower()
        for keyword, tid, tname in _LABEL_RULES:
            if keyword in lc:
                return tid, tname

    # 2–3. Bytes Z-score
    if z_score_bytes is not None:
        if z_score_bytes > 6.0:
            return "T1498", "Network Denial of Service"
        if z_score_bytes > 3.0:
            return "T1499", "Endpoint Denial of Service"

    # 4. Packet-rate Z-score — sweep / connection flood
    if z_score_pkts is not None and z_score_pkts > 3.0:
        return "T1046", "Network Service Discovery"

    # 5. Port lookup
    if dst_port is not None:
        try:
            p = int(dst_port)
            if p in _PORT_RULES:
                return _PORT_RULES[p]
            if 49152 <= p <= 65535:
                return "T1571", "Non-Standard Port"
        except (ValueError, TypeError):
            pass

    # 6. Absolute volume heuristic
    if bytes_out is not None:
        try:
            b = float(bytes_out)
            if b > 50_000_000:
                return "T1041", "Exfiltration Over C2 Channel"
            if b > 10_000_000:
                return "T1048", "Exfiltration Over Alternative Protocol"
        except (ValueError, TypeError):
            pass

    # 7. Protocol
    if protocol and protocol.strip().lower() == "icmp":
        return "T1498", "Network Denial of Service"

    return "T1046", "Network Service Discovery"


# ── Public API ────────────────────────────────────────────────────────────────

def get_techniques(category: ThreatCategory) -> list[str]:
    """Return MITRE technique IDs for the given threat category."""
    return MITRE_MAP.get(category, [])


def describe(technique_id: str) -> str:
    """Return a human-readable description for a MITRE technique ID."""
    return MITRE_DESCRIPTIONS.get(technique_id, technique_id)

"""
Static mapping from ThreatCategory → MITRE ATT&CK technique IDs.
Source: https://attack.mitre.org/
"""

from triage.models import ThreatCategory

MITRE_MAP: dict[ThreatCategory, list[str]] = {
    ThreatCategory.BRUTE_FORCE: [
        "T1110",        # Brute Force
        "T1110.001",    # Password Guessing
        "T1110.003",    # Password Spraying
        "T1078",        # Valid Accounts (if successful)
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
    "T1543":     "Create/Modify System Process — persistence via services",
    "T1547":     "Boot/Logon Autostart — persistence at startup",
    "T1041":     "Exfiltration Over C2 Channel — data theft via C2",
    "T1048":     "Exfiltration Over Alternative Protocol — non-C2 exfil",
    "T1048.002": "Exfiltration via Asymmetric Encrypted Protocol",
    "T1567":     "Exfiltration Over Web Service — cloud/storage abuse",
    "T1136":     "Create Account — unauthorized account creation",
    "T1098":     "Account Manipulation — privilege or credential changes",
}


def get_techniques(category: ThreatCategory) -> list[str]:
    """Return MITRE technique IDs for the given threat category."""
    return MITRE_MAP.get(category, [])


def describe(technique_id: str) -> str:
    """Return a human-readable description for a MITRE technique ID."""
    return MITRE_DESCRIPTIONS.get(technique_id, technique_id)

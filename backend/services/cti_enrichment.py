"""
CTI Enrichment Service

Enriches CIC-IDS-2017 events with:
  1. AbuseIPDB  — real async API (ABUSEIPDB_API_KEY required)
  2. VirusTotal — real async API (VIRUSTOTAL_API_KEY required)
  3. MITRE ATT&CK — static offline label → technique mapping

All functions are safe to call without keys: they return structured dicts with
a "skipped": True field and a human-readable "reason" instead of raising or
returning fake scores. The UI should render these as "CTI Unavailable" badges.
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)

_ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
_VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
_ABUSEIPDB_URL  = "https://api.abuseipdb.com/api/v2/check"
_VT_URL         = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
_TIMEOUT        = 8.0


# ── MITRE ATT&CK static map ───────────────────────────────────────────────────

_MITRE_MAP: dict[str, list[dict]] = {
    "DoS Hulk": [
        {"id": "T1498",     "name": "Network Denial of Service",         "tactic": "Impact"},
        {"id": "T1498.001", "name": "Direct Network Flood",              "tactic": "Impact"},
    ],
    "DoS GoldenEye": [
        {"id": "T1498",     "name": "Network Denial of Service",         "tactic": "Impact"},
        {"id": "T1498.001", "name": "Direct Network Flood",              "tactic": "Impact"},
    ],
    "DoS slowloris": [
        {"id": "T1499",     "name": "Endpoint Denial of Service",        "tactic": "Impact"},
        {"id": "T1499.001", "name": "OS Exhaustion Flood",               "tactic": "Impact"},
    ],
    "DoS Slowhttptest": [
        {"id": "T1499",     "name": "Endpoint Denial of Service",        "tactic": "Impact"},
        {"id": "T1499.002", "name": "Service Exhaustion Flood",          "tactic": "Impact"},
    ],
    "DDoS": [
        {"id": "T1498",     "name": "Network Denial of Service",         "tactic": "Impact"},
        {"id": "T1498.002", "name": "Reflection Amplification",          "tactic": "Impact"},
    ],
    "Heartbleed": [
        {"id": "T1203",     "name": "Exploitation for Client Execution", "tactic": "Execution"},
        {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "Web Attack \u2013 Brute Force": [
        {"id": "T1110",     "name": "Brute Force",                       "tactic": "Credential Access"},
        {"id": "T1110.001", "name": "Password Guessing",                 "tactic": "Credential Access"},
    ],
    "Web Attack – Brute Force": [
        {"id": "T1110",     "name": "Brute Force",                       "tactic": "Credential Access"},
        {"id": "T1110.001", "name": "Password Guessing",                 "tactic": "Credential Access"},
    ],
    "Web Attack \u2013 XSS": [
        {"id": "T1059.007", "name": "JavaScript",                        "tactic": "Execution"},
        {"id": "T1189",     "name": "Drive-by Compromise",               "tactic": "Initial Access"},
    ],
    "Web Attack – XSS": [
        {"id": "T1059.007", "name": "JavaScript",                        "tactic": "Execution"},
        {"id": "T1189",     "name": "Drive-by Compromise",               "tactic": "Initial Access"},
    ],
    "Web Attack \u2013 Sql Injection": [
        {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505.003", "name": "Web Shell",                         "tactic": "Persistence"},
    ],
    "Web Attack – Sql Injection": [
        {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505.003", "name": "Web Shell",                         "tactic": "Persistence"},
    ],
    "Infiltration": [
        {"id": "T1078",     "name": "Valid Accounts",                    "tactic": "Defense Evasion"},
        {"id": "T1071",     "name": "Application Layer Protocol",        "tactic": "Command and Control"},
        {"id": "T1083",     "name": "File and Directory Discovery",      "tactic": "Discovery"},
    ],
    "Bot": [
        {"id": "T1071.001", "name": "Web Protocols (C2 beacon)",        "tactic": "Command and Control"},
        {"id": "T1102",     "name": "Web Service",                       "tactic": "Command and Control"},
        {"id": "T1571",     "name": "Non-Standard Port",                 "tactic": "Command and Control"},
    ],
    "PortScan": [
        {"id": "T1046",     "name": "Network Service Discovery",         "tactic": "Discovery"},
        {"id": "T1595.001", "name": "Scanning IP Blocks",                "tactic": "Reconnaissance"},
    ],
    "FTP-Patator": [
        {"id": "T1110",     "name": "Brute Force",                       "tactic": "Credential Access"},
        {"id": "T1110.001", "name": "Password Guessing",                 "tactic": "Credential Access"},
        {"id": "T1021.002", "name": "SMB/Windows Admin Shares",          "tactic": "Lateral Movement"},
    ],
    "SSH-Patator": [
        {"id": "T1110",     "name": "Brute Force",                       "tactic": "Credential Access"},
        {"id": "T1110.004", "name": "Credential Stuffing",               "tactic": "Credential Access"},
        {"id": "T1021.004", "name": "SSH",                               "tactic": "Lateral Movement"},
    ],
}

_ALIASES: dict[str, str] = {
    k.replace("\u2013", "-"): k
    for k in _MITRE_MAP
    if "\u2013" in k
}


def get_mitre_techniques(label: str) -> list[dict]:
    if label in _MITRE_MAP:
        return _MITRE_MAP[label]
    normalised = label.replace("\u2013", "-").replace(" - ", " – ")
    if normalised in _MITRE_MAP:
        return _MITRE_MAP[normalised]
    if normalised in _ALIASES:
        return _MITRE_MAP[_ALIASES[normalised]]
    for key, techs in _MITRE_MAP.items():
        if label.strip().lower() == key.strip().lower():
            return techs
    return []


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async def check_abuseipdb(ip: str | None) -> dict:
    if not ip or ip in ("N/A", "0.0.0.0"):
        return {"skipped": True, "reason": "no_ip"}
    if not _ABUSEIPDB_KEY:
        # Return a mock result so the UI always has something to render
        return _mock_abuseipdb(ip)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _ABUSEIPDB_URL,
                headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code":           data.get("countryCode", ""),
                "isp":                    data.get("isp", ""),
                "domain":                 data.get("domain", ""),
                "total_reports":          data.get("totalReports", 0),
                "last_reported_at":       data.get("lastReportedAt", ""),
                "is_tor":                 data.get("isTor", False),
                "usage_type":             data.get("usageType", ""),
            }
    except httpx.TimeoutException:
        logger.warning("AbuseIPDB timeout for %s — using mock", ip)
        return _mock_abuseipdb(ip)
    except httpx.HTTPStatusError as exc:
        logger.warning("AbuseIPDB HTTP %s for %s — using mock", exc.response.status_code, ip)
        return _mock_abuseipdb(ip)
    except Exception as exc:
        logger.warning("AbuseIPDB error for %s: %s — using mock", ip, exc)
        return _mock_abuseipdb(ip)


_REAL_ISPS = [
    "Chinanet",
    "PJSC Rostelecom",
    "Amazon Technologies",
    "DigitalOcean, LLC",
    "Hetzner Online GmbH",
    "OVH SAS",
    "Linode, LLC",
    "Vultr Holdings, LLC",
    "Zayo Bandwidth",
    "Leaseweb USA",
    "Alibaba Cloud Computing",
    "Microsoft Corporation",
    "Google LLC",
    "Contabo GmbH",
    "ServerMania Inc.",
]
_REAL_DOMAINS = [
    "chinanet.cn", "rt.ru", "aws.amazon.com", "digitalocean.com",
    "hetzner.com", "ovh.net", "linode.com", "vultr.com",
    "zayo.com", "leaseweb.com", "alibaba.com", "microsoft.com",
    "google.com", "contabo.com", "servermania.com",
]

def _mock_abuseipdb(_ip: str) -> dict:
    return {
        "skipped": True,
        "reason":  "API key not configured — configure ABUSEIPDB_API_KEY in .env",
        "abuse_confidence_score": None,
        "country_code":           None,
        "isp":                    None,
        "domain":                 None,
        "total_reports":          None,
        "last_reported_at":       None,
        "is_tor":                 None,
        "usage_type":             None,
    }


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def check_virustotal(ip: str | None) -> dict:
    """
    Query the real VirusTotal API v3 for IP reputation.
    Falls back to deterministic mock when key is absent or request fails.
    """
    if not ip or ip in ("N/A", "0.0.0.0"):
        return {"skipped": True, "reason": "no_ip"}

    if _VIRUSTOTAL_KEY:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    _VT_URL.format(ip=ip),
                    headers={"x-apikey": _VIRUSTOTAL_KEY},
                )
                resp.raise_for_status()
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "malicious":     stats.get("malicious", 0),
                    "suspicious":    stats.get("suspicious", 0),
                    "harmless":      stats.get("harmless", 0),
                    "undetected":    stats.get("undetected", 0),
                    "total_engines": sum(stats.values()) or 80,
                    "threat_label":  attrs.get("reputation", "unknown"),
                    "last_analysis": attrs.get("last_analysis_date", ""),
                    "country":       attrs.get("country", ""),
                    "asn":           attrs.get("asn", ""),
                    "as_owner":      attrs.get("as_owner", ""),
                }
        except httpx.TimeoutException:
            logger.warning("VirusTotal timeout for %s — using mock", ip)
        except httpx.HTTPStatusError as exc:
            logger.warning("VirusTotal HTTP %s for %s — using mock", exc.response.status_code, ip)
        except Exception as exc:
            logger.warning("VirusTotal error for %s: %s — using mock", ip, exc)

    return check_virustotal_mock(ip)


def check_virustotal_mock(ip: str | None) -> dict:
    """Returned when VirusTotal API key is absent or the request fails."""
    if not ip or ip in ("N/A", "0.0.0.0"):
        return {"skipped": True, "reason": "no_ip"}

    return {
        "skipped":       True,
        "reason":        "API key not configured — configure VIRUSTOTAL_API_KEY in .env",
        "malicious":     None,
        "suspicious":    None,
        "harmless":      None,
        "undetected":    None,
        "total_engines": None,
        "threat_label":  None,
        "last_analysis": None,
        "is_mocked":     True,
    }


# ── Public API ────────────────────────────────────────────────────────────────

async def enrich_event(event: dict) -> dict:
    """Full CTI enrichment for one event dict. Always returns structured data."""
    ip    = event.get("src_ip") or event.get("source_ip")
    label = (event.get("label") or "").strip()

    abuse_result = await check_abuseipdb(ip)
    vt_result    = await check_virustotal(ip)
    mitre_result = get_mitre_techniques(label)

    return {
        "ip":         ip,
        "abuseipdb":  abuse_result,
        "virustotal": vt_result,
        "mitre":      mitre_result,
    }


async def enrich_ip_batch(ips: list[str]) -> dict[str, dict]:
    """
    Enrich a batch of unique IPs with CTI. Used after CSV ingestion.
    Returns a dict keyed by IP address.
    """
    import asyncio
    results: dict[str, dict] = {}
    for ip in ips[:20]:   # cap at 20 to respect rate limits during demo
        try:
            abuse = await check_abuseipdb(ip)
            vt    = await check_virustotal(ip)
            results[ip] = {"abuseipdb": abuse, "virustotal": vt}
        except Exception as exc:
            logger.warning("Batch CTI failed for %s: %s", ip, exc)
            results[ip] = {"error": str(exc)}
        # small delay to avoid hammering APIs in demo mode
        await asyncio.sleep(0.1)
    return results

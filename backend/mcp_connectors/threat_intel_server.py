"""
OmniWatch Threat Intelligence MCP Server
Exposes IP reputation and file hash lookup tools to Claude during the triage phase.

Providers:
  - AbuseIPDB  : IP reputation (reports, confidence score, country, ISP)
  - VirusTotal : File hash / URL analysis (engine detection counts, threat labels)
  - MITRE ATT&CK: Technique context (description, threat groups, sub-techniques)

Run standalone: python backend/mcp_connectors/threat_intel_server.py
Or import functions directly: from mcp_connectors.threat_intel_server import check_ip_reputation_direct

Design notes:
  - All external calls use httpx with a 10-second timeout — never blocks indefinitely.
  - An in-process LRU cache prevents duplicate API calls within the same scan cycle.
  - Cache TTL = 1 hour (enough for a competition demo session).
  - API keys are read from environment variables — never hardcoded.
  - Graceful degradation: if an API key is missing, the tool returns a clear
    "not_configured" response instead of crashing, so triage continues unaffected.
"""

import hashlib
import os
import time
from functools import lru_cache

import httpx
from fastmcp import FastMCP

# ── FastMCP server ─────────────────────────────────────────────────────────────
mcp = FastMCP(
    name="omniwatch-threat-intel",
    instructions=(
        "You are connected to the OmniWatch Threat Intelligence server. "
        "Use check_ip_reputation() to validate suspicious IPs against AbuseIPDB before "
        "finalising a severity score. Use lookup_file_hash() to check file hashes against "
        "VirusTotal. Always cite the data source in your ai_reasoning field."
    ),
)

# ── Config ─────────────────────────────────────────────────────────────────────
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
HTTP_TIMEOUT    = 10.0  # seconds — never let a single API call stall triage

# ── Simple time-based cache (avoids hammering free-tier rate limits) ───────────
_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 3600  # 1 hour


def _cached(key: str, value: dict | None = None) -> dict | None:
    """Get or set a cache entry. Returns None on miss."""
    now = time.monotonic()
    if value is not None:
        _cache[key] = (value, now)
        return value
    entry = _cache.get(key)
    if entry and (now - entry[1]) < _CACHE_TTL:
        return entry[0]
    return None


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

@mcp.tool()
def check_ip_reputation(ip: str) -> dict:
    """
    Check an IP address against AbuseIPDB.

    Returns:
      - abuse_confidence_score (0–100): how likely this IP is malicious
      - total_reports: number of community abuse reports
      - country_code, isp, domain: geolocation and ownership
      - last_reported_at: timestamp of most recent report
      - is_whitelisted: whether the IP is on AbuseIPDB's whitelist
      - verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "NOT_CONFIGURED"

    Use the verdict and abuse_confidence_score to adjust your confidence score:
      - score > 80 → increase your severity; cite AbuseIPDB in reasoning
      - score 30–80 → note as suspicious; keep existing severity
      - score < 30 → note as clean; consider reducing severity if evidence is weak
    """
    cached = _cached(f"abuseipdb:{ip}")
    if cached:
        return {**cached, "source": "cache"}

    if not ABUSEIPDB_KEY:
        return {
            "verdict": "NOT_CONFIGURED",
            "message": "ABUSEIPDB_API_KEY not set. Add it to .env to enable TI enrichment.",
            "ip": ip,
        }

    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except httpx.TimeoutException:
        return {"verdict": "TIMEOUT", "ip": ip, "message": "AbuseIPDB request timed out."}
    except httpx.HTTPStatusError as exc:
        return {"verdict": "API_ERROR", "ip": ip, "status_code": exc.response.status_code}
    except Exception as exc:
        return {"verdict": "ERROR", "ip": ip, "message": str(exc)}

    score = data.get("abuseConfidenceScore", 0)
    verdict = "MALICIOUS" if score >= 80 else ("SUSPICIOUS" if score >= 30 else "CLEAN")

    result = {
        "ip":                    ip,
        "verdict":               verdict,
        "abuse_confidence_score":score,
        "total_reports":         data.get("totalReports", 0),
        "country_code":          data.get("countryCode"),
        "isp":                   data.get("isp"),
        "domain":                data.get("domain"),
        "last_reported_at":      data.get("lastReportedAt"),
        "is_whitelisted":        data.get("isWhitelisted", False),
        "source":                "abuseipdb_live",
    }
    _cached(f"abuseipdb:{ip}", result)
    return result


# ── VirusTotal ─────────────────────────────────────────────────────────────────

@mcp.tool()
def lookup_file_hash(file_hash: str) -> dict:
    """
    Check a file hash (MD5, SHA1, or SHA256) against VirusTotal.

    Returns:
      - malicious_engines: count of AV engines that flagged this hash
      - total_engines: total engines that scanned it
      - detection_ratio: e.g. "58/72"
      - threat_labels: list of threat family names from top engines
      - verdict: "MALICIOUS" | "SUSPICIOUS" | "CLEAN" | "NOT_FOUND" | "NOT_CONFIGURED"

    Use detection_ratio to adjust confidence:
      - ratio > 10/72 → HIGH severity, cite VirusTotal detections in reasoning
      - ratio 1–10/72 → MEDIUM, note as potentially unwanted
      - ratio 0/72    → lower confidence on malware classification
    """
    cached = _cached(f"vt:{file_hash}")
    if cached:
        return {**cached, "source": "cache"}

    if not VIRUSTOTAL_KEY:
        return {
            "verdict": "NOT_CONFIGURED",
            "message": "VIRUSTOTAL_API_KEY not set. Add it to .env to enable hash lookup.",
            "hash": file_hash,
        }

    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"verdict": "NOT_FOUND", "hash": file_hash, "source": "virustotal_live"}
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
    except httpx.TimeoutException:
        return {"verdict": "TIMEOUT", "hash": file_hash, "message": "VirusTotal request timed out."}
    except httpx.HTTPStatusError as exc:
        return {"verdict": "API_ERROR", "hash": file_hash, "status_code": exc.response.status_code}
    except Exception as exc:
        return {"verdict": "ERROR", "hash": file_hash, "message": str(exc)}

    stats       = attrs.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    total       = sum(stats.values()) or 1

    # Collect threat names from engines that flagged it
    results_map = attrs.get("last_analysis_results", {})
    threat_labels = list({
        v.get("result")
        for v in results_map.values()
        if v.get("category") == "malicious" and v.get("result")
    })[:10]

    verdict = (
        "MALICIOUS"  if malicious > 10 else
        "SUSPICIOUS" if malicious > 0 or suspicious > 3 else
        "CLEAN"
    )

    result = {
        "hash":              file_hash,
        "verdict":           verdict,
        "malicious_engines": malicious,
        "suspicious_engines":suspicious,
        "total_engines":     total,
        "detection_ratio":   f"{malicious}/{total}",
        "threat_labels":     threat_labels,
        "file_name":         attrs.get("meaningful_name"),
        "file_type":         attrs.get("type_description"),
        "source":            "virustotal_live",
    }
    _cached(f"vt:{file_hash}", result)
    return result


# ── MITRE ATT&CK context (public, no API key required) ────────────────────────

@mcp.tool()
def get_attack_context(mitre_technique_id: str) -> dict:
    """
    Return a brief description of a MITRE ATT&CK technique and its typical next steps.
    Uses the local mitre_map — no external API call required.

    mitre_technique_id: e.g. "T1110", "T1110.001"
    """
    from triage.mitre_map import MITRE_DESCRIPTIONS, MITRE_MAP
    from triage.models import ThreatCategory

    # Build reverse map: technique → category
    technique_to_category: dict[str, str] = {}
    for cat, techniques in MITRE_MAP.items():
        for t in techniques:
            technique_to_category[t] = cat.value

    description = MITRE_DESCRIPTIONS.get(mitre_technique_id, "No description available.")
    category    = technique_to_category.get(mitre_technique_id, "UNKNOWN")

    # Suggest next techniques in the same category (simulates kill-chain prediction)
    all_in_category = MITRE_MAP.get(ThreatCategory(category), []) if category != "UNKNOWN" else []
    next_steps = [t for t in all_in_category if t != mitre_technique_id][:3]

    return {
        "technique_id":    mitre_technique_id,
        "description":     description,
        "threat_category": category,
        "likely_next_techniques": next_steps,
        "source": "local_mitre_map",
    }


# ── Direct async wrappers (used by triage/engine.py without MCP overhead) ─────

async def check_ip_reputation_direct(ip: str) -> dict:
    """Async wrapper — called from triage engine without going through MCP transport."""
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, check_ip_reputation, ip)


async def enrich_results_with_ti(ips: list[str]) -> dict[str, dict]:
    """
    Parallel AbuseIPDB lookups for a list of IPs.
    Returns a dict mapping ip → reputation result.
    Used by triage/engine.py after initial Claude scoring.
    """
    import asyncio
    unique_ips = list(set(filter(None, ips)))
    if not unique_ips:
        return {}
    tasks   = [check_ip_reputation_direct(ip) for ip in unique_ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return {
        ip: (r if not isinstance(r, Exception) else {"verdict": "ERROR", "ip": ip})
        for ip, r in zip(unique_ips, results)
    }


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting OmniWatch Threat Intelligence MCP Server...")
    configured = []
    if ABUSEIPDB_KEY:
        configured.append("AbuseIPDB ✓")
    if VIRUSTOTAL_KEY:
        configured.append("VirusTotal ✓")
    print(f"APIs configured: {', '.join(configured) or 'none — add keys to .env'}")
    mcp.run()

"""
OmniWatch Threat Intelligence Module
IP reputation and file hash lookups — AbuseIPDB, VirusTotal, MITRE ATT&CK.
FastMCP dependency removed — Sprint 2 (air-gapped local pipeline).
"""

import os
import time

import httpx

# ── Config ─────────────────────────────────────────────────────────────────────
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
HTTP_TIMEOUT   = 10.0

# ── Simple time-based cache ────────────────────────────────────────────────────
_cache: dict[str, tuple[dict, float]] = {}
_CACHE_TTL = 3600


def _cached(key: str, value: dict | None = None) -> dict | None:
    now = time.monotonic()
    if value is not None:
        _cache[key] = (value, now)
        return value
    entry = _cache.get(key)
    if entry and (now - entry[1]) < _CACHE_TTL:
        return entry[0]
    return None


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

def check_ip_reputation(ip: str) -> dict:
    cached = _cached(f"abuseipdb:{ip}")
    if cached:
        return {**cached, "source": "cache"}

    if not ABUSEIPDB_KEY:
        return {
            "verdict": "NOT_CONFIGURED",
            "message": "ABUSEIPDB_API_KEY not set.",
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

    score   = data.get("abuseConfidenceScore", 0)
    verdict = "MALICIOUS" if score >= 80 else ("SUSPICIOUS" if score >= 30 else "CLEAN")
    result  = {
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

def lookup_file_hash(file_hash: str) -> dict:
    cached = _cached(f"vt:{file_hash}")
    if cached:
        return {**cached, "source": "cache"}

    if not VIRUSTOTAL_KEY:
        return {
            "verdict": "NOT_CONFIGURED",
            "message": "VIRUSTOTAL_API_KEY not set.",
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

    stats      = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) or 1

    results_map  = attrs.get("last_analysis_results", {})
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
        "hash":               file_hash,
        "verdict":            verdict,
        "malicious_engines":  malicious,
        "suspicious_engines": suspicious,
        "total_engines":      total,
        "detection_ratio":    f"{malicious}/{total}",
        "threat_labels":      threat_labels,
        "file_name":          attrs.get("meaningful_name"),
        "file_type":          attrs.get("type_description"),
        "source":             "virustotal_live",
    }
    _cached(f"vt:{file_hash}", result)
    return result


# ── MITRE ATT&CK (local, no API key) ──────────────────────────────────────────

def get_attack_context(mitre_technique_id: str) -> dict:
    from triage.mitre_map import MITRE_DESCRIPTIONS, MITRE_MAP
    from triage.models import ThreatCategory

    technique_to_category: dict[str, str] = {}
    for cat, techniques in MITRE_MAP.items():
        for t in techniques:
            technique_to_category[t] = cat.value

    description = MITRE_DESCRIPTIONS.get(mitre_technique_id, "No description available.")
    category    = technique_to_category.get(mitre_technique_id, "UNKNOWN")
    all_in_cat  = MITRE_MAP.get(ThreatCategory(category), []) if category != "UNKNOWN" else []
    next_steps  = [t for t in all_in_cat if t != mitre_technique_id][:3]

    return {
        "technique_id":           mitre_technique_id,
        "description":            description,
        "threat_category":        category,
        "likely_next_techniques": next_steps,
        "source":                 "local_mitre_map",
    }


# ── Async wrappers (used by triage/engine.py) ──────────────────────────────────

async def check_ip_reputation_direct(ip: str) -> dict:
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, check_ip_reputation, ip)


async def enrich_results_with_ti(ips: list[str]) -> dict[str, dict]:
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

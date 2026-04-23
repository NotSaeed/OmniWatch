"""
OmniWatch Notification Module
Discord and Slack webhook senders — called by soar/engine.py.
FastMCP dependency removed — Sprint 2 (air-gapped local pipeline).
"""

import os
from datetime import datetime, timezone

import httpx

# ── Config ─────────────────────────────────────────────────────────────────────
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
SLACK_WEBHOOK_URL   = os.getenv("SLACK_WEBHOOK_URL", "")
HTTP_TIMEOUT        = 8.0

_SEVERITY_COLOURS = {
    "CRITICAL": 0xEF4444,
    "HIGH":     0xF97316,
    "MEDIUM":   0xEAB308,
    "LOW":      0x3B82F6,
    "INFO":     0x6B7280,
}

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


# ── Discord ────────────────────────────────────────────────────────────────────

def send_discord_alert(
    title:            str,
    description:      str,
    severity:         str,
    alert_id:         str,
    source_ip:        str       = "N/A",
    affected_asset:   str       = "N/A",
    mitre_techniques: list[str] = None,
    playbook_action:  str       = "None",
    confidence:       float     = 0.0,
) -> dict:
    if not DISCORD_WEBHOOK_URL:
        return {"status": "not_configured", "message": "DISCORD_WEBHOOK_URL not set."}

    emoji  = _SEVERITY_EMOJI.get(severity.upper(), "⚪")
    colour = _SEVERITY_COLOURS.get(severity.upper(), 0x6B7280)
    techs  = ", ".join((mitre_techniques or [])[:5]) or "N/A"
    ts     = datetime.now(tz=timezone.utc).isoformat()

    payload = {
        "username":   "OmniWatch SOC",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/2092/2092757.png",
        "embeds": [{
            "title":       f"{emoji} {severity} Alert — {title}",
            "description": description,
            "color":       colour,
            "fields": [
                {"name": "🆔 Alert ID",        "value": f"`{alert_id}`",      "inline": True},
                {"name": "📊 Confidence",       "value": f"{confidence:.0%}", "inline": True},
                {"name": "🌐 Source IP",        "value": source_ip,           "inline": True},
                {"name": "🖥️ Affected Asset",  "value": affected_asset,      "inline": True},
                {"name": "🎯 MITRE Techniques", "value": techs,               "inline": False},
                {"name": "🤖 Playbook Action",  "value": f"`{playbook_action}`", "inline": False},
            ],
            "footer":    {"text": "OmniWatch AI-SOC • CITREX 2026"},
            "timestamp": ts,
        }],
    }

    try:
        resp = httpx.post(DISCORD_WEBHOOK_URL, json=payload, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return {"status": "sent", "http_status": resp.status_code}
    except httpx.TimeoutException:
        return {"status": "error", "reason": "Discord webhook timed out"}
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "reason": f"HTTP {exc.response.status_code}"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


# ── Slack ──────────────────────────────────────────────────────────────────────

def send_slack_alert(
    title:           str,
    severity:        str,
    alert_id:        str,
    source_ip:       str   = "N/A",
    affected_asset:  str   = "N/A",
    playbook_action: str   = "None",
    confidence:      float = 0.0,
) -> dict:
    if not SLACK_WEBHOOK_URL:
        return {"status": "not_configured", "message": "SLACK_WEBHOOK_URL not set."}

    emoji = _SEVERITY_EMOJI.get(severity.upper(), "⚪")

    payload = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {severity} — {title}"}},
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID:*\n`{alert_id}`"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence:.0%}"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{source_ip}"},
                    {"type": "mrkdwn", "text": f"*Affected Asset:*\n{affected_asset}"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Playbook Action:*\n`{playbook_action}`"}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": "OmniWatch AI-SOC • CITREX 2026"}]},
        ]
    }

    try:
        resp = httpx.post(SLACK_WEBHOOK_URL, json=payload, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        return {"status": "sent", "http_status": resp.status_code}
    except httpx.TimeoutException:
        return {"status": "error", "reason": "Slack webhook timed out"}
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "reason": f"HTTP {exc.response.status_code}"}
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


# ── Async wrapper (soar/engine.py) ─────────────────────────────────────────────

async def send_discord_alert_direct(alert, playbook_result) -> dict:
    import asyncio

    def _call():
        return send_discord_alert(
            title=f"{alert.category.value.replace('_', ' ').title()} Detected",
            description=alert.ai_reasoning[:200] + ("..." if len(alert.ai_reasoning) > 200 else ""),
            severity=alert.severity.value,
            alert_id=alert.alert_id,
            source_ip=alert.source_ip or "N/A",
            affected_asset=alert.affected_asset or "N/A",
            mitre_techniques=alert.mitre_techniques,
            playbook_action=playbook_result.simulated_action,
            confidence=alert.confidence,
        )

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _call)

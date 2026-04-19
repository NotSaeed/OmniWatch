"""
Micro-SOAR Orchestrator
Evaluates each TriageResult against the registered playbook list.
First matching playbook (ordered by confidence threshold descending) wins.
Dispatches Discord notifications for CRITICAL and HIGH severity alerts.
"""

import asyncio
import logging

from soar.models import PlaybookResult
from soar.playbooks.anomaly import playbook as anomaly_pb
from soar.playbooks.brute_force import playbook as brute_force_pb
from soar.playbooks.exfiltration import playbook as exfiltration_pb
from soar.playbooks.malware import playbook as malware_pb
from soar.playbooks.port_scan import playbook as port_scan_pb
from triage.models import TriageResult

logger = logging.getLogger(__name__)

# Registry ordered by min_confidence descending — most specific match wins
PLAYBOOK_REGISTRY = [
    malware_pb,        # 0.80
    exfiltration_pb,   # 0.80
    brute_force_pb,    # 0.75
    port_scan_pb,      # 0.70
    anomaly_pb,        # 0.65
]

_NOTIFY_SEVERITIES = {"CRITICAL", "HIGH"}


async def evaluate_alert(alert: TriageResult) -> PlaybookResult | None:
    """
    Find and execute the first matching playbook for this alert.
    Returns PlaybookResult or None if no playbook matched.
    """
    for pb in PLAYBOOK_REGISTRY:
        if pb.should_trigger(alert):
            result = await asyncio.get_event_loop().run_in_executor(None, pb.execute, alert)
            logger.info("Playbook '%s' fired for alert %s (%.0f%% confidence)",
                        pb.name, alert.alert_id, alert.confidence * 100)

            # Non-blocking Discord notification for high-severity alerts
            if alert.severity.value in _NOTIFY_SEVERITIES:
                asyncio.create_task(_notify_discord(alert, result))

            return result

    return None


async def evaluate_batch(alerts: list[TriageResult]) -> list[PlaybookResult]:
    """Run evaluate_alert for every alert in the batch. Skips None results."""
    tasks = [evaluate_alert(a) for a in alerts]
    raw   = await asyncio.gather(*tasks, return_exceptions=True)
    results = []
    for r in raw:
        if isinstance(r, Exception):
            logger.error("SOAR evaluate_alert failed: %s", r)
        elif r is not None:
            results.append(r)
    return results


async def _notify_discord(alert: TriageResult, result: PlaybookResult) -> None:
    """Fire-and-forget Discord notification. Failure is logged, never raises."""
    try:
        from mcp_connectors.notification_server import send_discord_alert_direct
        await send_discord_alert_direct(alert, result)
    except Exception as exc:
        logger.warning("Discord notification failed (non-fatal): %s", exc)

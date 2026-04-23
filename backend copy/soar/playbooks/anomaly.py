"""
Playbook: Anomaly escalation — no automated action, human-in-the-loop.
Demonstrates that OmniWatch respects uncertainty and doesn't over-automate.
"""

from soar.models import PlaybookResult
from soar.playbooks.base import BasePlaybook
from triage.models import ThreatCategory, TriageResult


class AnomalyPlaybook(BasePlaybook):
    name             = "Anomaly Escalation"
    trigger_category = ThreatCategory.ANOMALY
    min_confidence   = 0.65
    description      = "Escalates ambiguous anomalies to Tier-2 analyst. No automated containment."

    def simulate(self, alert: TriageResult) -> PlaybookResult:
        asset = alert.affected_asset or alert.source_ip or "unknown asset"
        return PlaybookResult(
            playbook_name=self.name,
            alert_id=alert.alert_id,
            trigger_category=alert.category.value,
            confidence=alert.confidence,
            status="ESCALATED",
            simulated_action=f"Escalate {asset} to Tier-2 SOC analyst — human review required",
            action_detail=(
                f"# PagerDuty alert sent to on-call analyst  [SIMULATED]\n"
                f"# Ticket INC-{alert.alert_id[:8]} created: priority=P2  [SIMULATED]\n"
                f"# Confidence {alert.confidence:.0%} insufficient for automated response\n"
                f"# Analyst must review: {alert.ai_reasoning[:120]}..."
            ),
            affected_asset=asset,
            notes=(
                "Anomaly confidence below automated-action threshold. "
                "Human judgment required before any containment action."
            ),
        )


playbook = AnomalyPlaybook()

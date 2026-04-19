"""Playbook: SSH / credential brute-force response — simulate IP block."""

from soar.models import PlaybookResult
from soar.playbooks.base import BasePlaybook
from triage.models import ThreatCategory, TriageResult


class BruteForcePlaybook(BasePlaybook):
    name             = "SSH Brute Force Response"
    trigger_category = ThreatCategory.BRUTE_FORCE
    min_confidence   = 0.75
    description      = "Blocks the attacker IP at the firewall when brute-force is detected."

    def simulate(self, alert: TriageResult) -> PlaybookResult:
        ip = alert.source_ip or "UNKNOWN_IP"
        return PlaybookResult(
            playbook_name=self.name,
            alert_id=alert.alert_id,
            trigger_category=alert.category.value,
            confidence=alert.confidence,
            status="SIMULATED",
            simulated_action=f"Block attacker IP {ip} — ingress firewall rule",
            action_detail=(
                f"iptables -A INPUT -s {ip} -j DROP  [SIMULATED]\n"
                f"fail2ban-client set sshd banip {ip}  [SIMULATED]"
            ),
            affected_asset=alert.affected_asset,
            notes=f"Triggered by {len(alert.mitre_techniques)} MITRE techniques: {', '.join(alert.mitre_techniques[:3])}",
        )


playbook = BruteForcePlaybook()

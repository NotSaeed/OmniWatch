"""Playbook: Port scan response — simulate rate-limiting the scanner."""

from soar.models import PlaybookResult
from soar.playbooks.base import BasePlaybook
from triage.models import ThreatCategory, TriageResult


class PortScanPlaybook(BasePlaybook):
    name             = "Port Scan Mitigation"
    trigger_category = ThreatCategory.PORT_SCAN
    min_confidence   = 0.70
    description      = "Rate-limits the scanning IP to 10 packets/second and alerts the network team."

    def simulate(self, alert: TriageResult) -> PlaybookResult:
        ip = alert.source_ip or "UNKNOWN_IP"
        return PlaybookResult(
            playbook_name=self.name,
            alert_id=alert.alert_id,
            trigger_category=alert.category.value,
            confidence=alert.confidence,
            status="SIMULATED",
            simulated_action=f"Rate-limit scanner {ip} to 10 pps — scan suppression",
            action_detail=(
                f"tc qdisc add dev eth0 root handle 1: htb default 10  [SIMULATED]\n"
                f"iptables -A INPUT -s {ip} -m limit --limit 10/sec -j ACCEPT  [SIMULATED]\n"
                f"iptables -A INPUT -s {ip} -j DROP  [SIMULATED]"
            ),
            affected_asset=alert.affected_asset,
            notes="Network team notified via alert channel.",
        )


playbook = PortScanPlaybook()

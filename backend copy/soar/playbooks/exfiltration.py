"""Playbook: Data exfiltration response — simulate outbound block + evidence preservation."""

from soar.models import PlaybookResult
from soar.playbooks.base import BasePlaybook
from triage.models import ThreatCategory, TriageResult


class ExfiltrationPlaybook(BasePlaybook):
    name             = "Data Exfiltration Containment"
    trigger_category = ThreatCategory.EXFILTRATION
    min_confidence   = 0.80
    description      = "Blocks outbound traffic from the source asset and captures a packet snapshot."

    def simulate(self, alert: TriageResult) -> PlaybookResult:
        ip    = alert.source_ip    or "UNKNOWN_IP"
        asset = alert.affected_asset or ip
        return PlaybookResult(
            playbook_name=self.name,
            alert_id=alert.alert_id,
            trigger_category=alert.category.value,
            confidence=alert.confidence,
            status="SIMULATED",
            simulated_action=f"Block outbound from {ip} + preserve evidence snapshot",
            action_detail=(
                f"iptables -A OUTPUT -s {ip} -j DROP  [SIMULATED]\n"
                f"tcpdump -i eth0 -w /evidence/{alert.alert_id}.pcap host {ip} -c 10000  [SIMULATED]\n"
                f"# DLP system notified — data classification scan queued  [SIMULATED]\n"
                f"# Ticket INC-{alert.alert_id[:8]} created in ITSM  [SIMULATED]"
            ),
            affected_asset=asset,
            notes="Evidence pcap preserved. Legal/compliance team notified.",
        )


playbook = ExfiltrationPlaybook()

"""
BasePlaybook — abstract contract every playbook must implement.

Safety invariant: execute() calls simulate() by default.
Live execution requires SOAR_LIVE_MODE=true AND _live_execute() to be implemented.
_live_execute() raises NotImplementedError in all built-in playbooks, so nothing
dangerous can run even if the env flag is accidentally set.
"""

import os
import time
from abc import ABC, abstractmethod

from soar.models import PlaybookResult
from triage.models import ThreatCategory, TriageResult


class BasePlaybook(ABC):
    name:             str
    trigger_category: ThreatCategory
    min_confidence:   float
    description:      str

    def should_trigger(self, alert: TriageResult) -> bool:
        return (
            alert.category == self.trigger_category
            and alert.confidence >= self.min_confidence
        )

    def execute(self, alert: TriageResult) -> PlaybookResult:
        if os.getenv("SOAR_LIVE_MODE") == "true":
            return self._live_execute(alert)
        start = time.monotonic()
        result = self.simulate(alert)
        elapsed = int((time.monotonic() - start) * 1000)
        return result.model_copy(update={"execution_time_ms": elapsed})

    @abstractmethod
    def simulate(self, alert: TriageResult) -> PlaybookResult:
        """Build a PlaybookResult describing what WOULD happen. No real commands."""

    def _live_execute(self, alert: TriageResult) -> PlaybookResult:
        # Intentionally not implemented — competition build is simulation-only
        raise NotImplementedError("Live execution not implemented in this build.")

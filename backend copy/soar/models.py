"""Micro-SOAR result model."""

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


class PlaybookResult(BaseModel):
    playbook_name:    str
    alert_id:         str
    trigger_category: str
    confidence:       float
    status:           Literal["SIMULATED", "SKIPPED", "ESCALATED"]
    simulated_action: str
    action_detail:    str
    affected_asset:   Optional[str] = None
    executed_at:      datetime      = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    execution_time_ms:int           = 0
    notes:            str           = ""

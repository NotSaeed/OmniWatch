"""Normalized event model — common schema for all BOTSv3 sourcetypes."""

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    event_id:      str      = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:     datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))
    sourcetype:    str
    source_family: str      # "network_ids" | "endpoint" | "firewall" | "web" | "auth" | "unknown"
    src_ip:        Optional[str] = None
    dst_ip:        Optional[str] = None
    dst_port:      Optional[int] = None
    hostname:      Optional[str] = None
    username:      Optional[str] = None
    process_name:  Optional[str] = None
    action:        Optional[str] = None
    severity_hint: Optional[str] = None
    raw_text:      str
    extra:         dict[str, Any] = Field(default_factory=dict)


class IngestSummary(BaseModel):
    total_parsed:   int
    total_stored:   int
    by_sourcetype:  dict[str, int]
    skipped:        int
    dataset_name:   str = "botsv3"

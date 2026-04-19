"""
OmniWatch Triage Models
Pydantic models for structured AI output — the contract between Claude and the rest of the system.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ThreatCategory(str, Enum):
    BRUTE_FORCE   = "BRUTE_FORCE"
    PORT_SCAN     = "PORT_SCAN"
    MALWARE       = "MALWARE"
    EXFILTRATION  = "EXFILTRATION"
    ANOMALY       = "ANOMALY"
    BENIGN        = "BENIGN"


class FalsePositiveRisk(str, Enum):
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


class Recommendation(BaseModel):
    action:   str = Field(..., min_length=5)
    priority: int = Field(..., ge=1, le=5)


class TriageResult(BaseModel):
    alert_id:            str
    timestamp:           datetime
    severity:            SeverityLevel
    category:            ThreatCategory
    confidence:          float = Field(..., ge=0.0, le=1.0)
    source_ip:           Optional[str]  = None
    affected_asset:      Optional[str]  = None
    mitre_techniques:    list[str]      = Field(default_factory=list)
    raw_log_excerpt:     str            = Field(..., min_length=1)
    ai_reasoning:        str            = Field(..., min_length=10)
    recommendations:     list[Recommendation] = Field(default_factory=list)
    false_positive_risk: FalsePositiveRisk = FalsePositiveRisk.MEDIUM
    log_type:            str            = "unknown"
    source_type:         str            = "simulated"
    playbook_triggered:  Optional[str]  = None

    @field_validator("confidence")
    @classmethod
    def confidence_precision(cls, v: float) -> float:
        return round(v, 4)

    @field_validator("mitre_techniques")
    @classmethod
    def validate_mitre_format(cls, v: list[str]) -> list[str]:
        """Ensure technique IDs look like T followed by digits (loose check)."""
        return [t for t in v if t.startswith("T") and len(t) >= 4]

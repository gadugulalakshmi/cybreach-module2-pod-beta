"""
Pydantic models for the Validation Engine (Pod Beta).

EvidenceEvent  -> the frozen contract Module 2 CONSUMES from Module 1
                  (Technical Doc, Section 2 & 3.3)
Verdict        -> the raw output Module 2 PRODUCES for each EvidenceEvent
                  before it is passed to the Outcome Classifier
                  (Technical Doc, Section 3.3)
"""
from typing import List, Optional

from pydantic import BaseModel, Field


class EvidenceEvent(BaseModel):
    """
    One simulated adversarial action, as published by Module 1 (The Strike
    Engine). During build, this is never fetched live -- it is loaded from
    the frozen JSON fixture in tests/fixtures/mock_evidence_events.json.
    """

    action_id: str = Field(..., description="Unique ID of the simulated attack action")
    correlation_key: str = Field(..., description="Key linking related evidence within a campaign")
    technique_ref: str = Field(..., description="MITRE ATT&CK technique ID, e.g. T1486")
    target_asset_ref: str = Field(..., description="Reference to the targeted asset or host")
    expected_observable: str = Field(..., description="The observable the defensive stack should have produced")
    timestamp: str = Field(..., description="ISO 8601 timestamp of the simulated action")


class Verdict(BaseModel):
    """
    Raw output of the Validation Engine for a single EvidenceEvent.
    """

    action_id: str
    verdict: str = Field(..., description="One of: Detected, Missed, Partial, NoData")
    confidence: float = Field(..., ge=0.0, le=1.0)
    mttd_seconds: Optional[float] = Field(default=None)
    matched_evidence_ref: Optional[str] = Field(default=None)
    causal_chain: List[str] = Field(default_factory=list)
    rule_id: str
    technique_ref: str

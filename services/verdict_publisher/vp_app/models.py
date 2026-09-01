from typing import Optional, List

from pydantic import BaseModel, Field


class PublishedVerdict(BaseModel):
    action_id: str
    verdict: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    rule_id: str
    technique_ref: str
    mttd_seconds: Optional[float] = None
    matched_evidence_ref: Optional[str] = None
    causal_chain: List[str] = Field(default_factory=list)

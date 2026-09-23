"""
Pydantic models for the Outcome Classifier (Pod Beta).
"""
from typing import List, Optional

from pydantic import BaseModel


class CausalStep(BaseModel):
    step_number: int
    description: str
    evidence_ref: Optional[str] = None


class OutcomeVerdict(BaseModel):
    action_id: str
    verdict: str  # Detected, Missed, Partial, NoData
    confidence: float
    causal_chain: List[CausalStep]
    mttd_seconds: Optional[float] = None
    alert_fidelity: Optional[str] = None  # high, medium, low

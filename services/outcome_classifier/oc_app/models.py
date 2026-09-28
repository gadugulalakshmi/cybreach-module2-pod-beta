"""
Pydantic models for the Outcome Classifier (Pod Beta).
"""
from typing import List, Optional

from pydantic import BaseModel, Field


class CausalStep(BaseModel):
    step_number: int
    description: str
    evidence_ref: Optional[str] = None

    def as_contract_entry(self) -> str:
        """Render as the single string the v2.0 contract expects.

        M11: the plan's `causal_chain` is `array of string` (Alpha's schema and
        Delta's frozen schema both say so). Beta emitted a list of objects, so
        the same logical field had two incompatible shapes across pods. The
        object form is kept for the rich UI view and flattened at the boundary.
        """

        if self.evidence_ref:
            return f"{self.step_number}. {self.description} [{self.evidence_ref}]"

        return f"{self.step_number}. {self.description}"


class OutcomeVerdict(BaseModel):
    action_id: str
    verdict: str  # Detected, Missed, Partial, NoData

    # B5: the Validation Engine and Verdict Publisher already constrained
    # confidence to 0.0-1.0; this one accepted any float. An unconstrained
    # field here meant the same evidence could score 95 on this path and 0.95
    # on the others, and no threshold comparison behaved predictably.
    confidence: float = Field(..., ge=0.0, le=1.0)

    causal_chain: List[CausalStep]
    mttd_seconds: Optional[float] = None
    alert_fidelity: Optional[str] = None  # high, medium, low

    @property
    def causal_chain_strings(self) -> List[str]:
        """The v2.0 wire form of the causal chain."""

        return [step.as_contract_entry() for step in self.causal_chain]

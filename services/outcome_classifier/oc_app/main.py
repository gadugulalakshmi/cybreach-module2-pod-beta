"""
Outcome Classifier -- Pod Beta, Service 2 of 2.

Run locally with:
    uvicorn oc_app.main:app --reload --port 8003
"""
from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from oc_app.causal_chain import build_causal_chain
from oc_app.fidelity import assess_fidelity
from oc_app.models import OutcomeVerdict
from oc_app.mttd import compute_mttd

app = FastAPI(title="Outcome Classifier", version="0.2.0")

THRESHOLDS = {"detected": 0.7, "partial": 0.3}


class RawValidationResult(BaseModel):
    """
    Input to /classify. The core fields (action_id, confidence, rule_id,
    no_data) are all that's needed for the Week 1-3 flat scoring path.
    The Week 4/5 fields below are optional so nothing that worked before
    breaks -- they simply unlock richer fidelity assessment, a fuller
    causal chain, and MTTD computation when the Validation Engine
    supplies them.
    """

    action_id: str
    confidence: float
    rule_id: str
    no_data: bool = False
    matched_evidence_ref: Optional[str] = None
    mttd_seconds: Optional[float] = None

    # Week 5 additions
    evidence_timestamp: Optional[str] = None   # when the simulated attack actually happened
    alert_timestamp: Optional[str] = None      # when the matching SIEM result was raised
    match_specificity: Optional[str] = None    # "exact" | "substring" | "partial" | "flat_technique"
    keywords_checked: Optional[List[str]] = None


@app.post("/classify", response_model=OutcomeVerdict)
async def classify(result: RawValidationResult) -> OutcomeVerdict:
    # Task 1: Outcome Classifier Implementation -- raw validation result -> classified verdict
    if result.no_data:
        verdict = "NoData"
        fidelity = None
    elif result.confidence >= THRESHOLDS["detected"]:
        verdict = "Detected"
        fidelity = assess_fidelity(result.confidence, result.match_specificity)
    elif result.confidence >= THRESHOLDS["partial"]:
        verdict = "Partial"
        fidelity = "medium"
    else:
        verdict = "Missed"
        fidelity = None

    # Task 4: MTTD computation -- prefer an explicitly supplied value,
    # otherwise derive it from evidence/alert timestamps when both are present.
    mttd = result.mttd_seconds
    if mttd is None:
        mttd = compute_mttd(result.evidence_timestamp, result.alert_timestamp)

    # Task 2: Causal chain analysis
    chain = build_causal_chain(result, verdict, mttd_seconds=mttd)

    return OutcomeVerdict(
        action_id=result.action_id,
        verdict=verdict,
        confidence=result.confidence,
        causal_chain=chain,
        mttd_seconds=mttd,
        alert_fidelity=fidelity,
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "outcome_classifier"}

"""
Outcome Classifier -- Pod Beta, Service 2 of 2.

Run locally with:
    uvicorn oc_app.main:app --reload --port 8003
"""
from typing import List, Optional

import logging

from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from oc_app.causal_chain import build_causal_chain
from oc_app.fidelity import assess_fidelity
from oc_app.models import OutcomeVerdict, OutcomeVerdictResponse
from oc_app.mttd import compute_mttd
from oc_app.security import get_current_claims, get_current_tenant

app = FastAPI(title="Outcome Classifier", version="0.2.0")

THRESHOLDS = {"detected": 0.7, "partial": 0.3}

logger = logging.getLogger(__name__)


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
    # B5: bounded here as well as on `OutcomeVerdict`. Without it an
    # out-of-range score reached the classifier, was compared against the
    # thresholds, and then raised inside the response model -- a 500 rather
    # than a 422 for what is a client error.
    confidence: float = Field(..., ge=0.0, le=1.0)
    rule_id: str
    no_data: bool = False
    matched_evidence_ref: Optional[str] = None
    mttd_seconds: Optional[float] = None

    # Week 5 additions
    evidence_timestamp: Optional[str] = None   # when the simulated attack actually happened
    alert_timestamp: Optional[str] = None      # when the matching SIEM result was raised
    match_specificity: Optional[str] = None    # "exact" | "substring" | "partial" | "flat_technique"
    keywords_checked: Optional[List[str]] = None


# B11: /api/v2 is gated on the module's shared JWT. Per-route rather than
# app-level so /health stays reachable without a token for the run plan's
# cross-pod health check.
@app.post(
    "/api/v2/classify",
    response_model=OutcomeVerdictResponse,
    dependencies=[Depends(get_current_claims)],
)
async def classify(
    result: RawValidationResult,
    tenant_id: str = Depends(get_current_tenant),
) -> OutcomeVerdictResponse:
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

    # M11: the chain is built as rich `CausalStep` objects and then flattened
    # through `causal_chain_strings` on the way out, so the wire shape matches
    # the `array of string` every other pod publishes.
    #
    # B11: the tenant is resolved and enforced here but deliberately not added
    # to the response -- `OutcomeVerdictResponse` is the frozen v2.0 contract
    # shape that Delta's schema validates, so echoing a tenant field onto it
    # would break every downstream consumer for no gain.
    logger.debug(
        "Classified action %s for tenant %s as %s",
        result.action_id,
        tenant_id,
        verdict,
    )
    return OutcomeVerdictResponse.from_verdict(
        OutcomeVerdict(
            action_id=result.action_id,
            verdict=verdict,
            confidence=result.confidence,
            causal_chain=chain,
            mttd_seconds=mttd,
            alert_fidelity=fidelity,
        )
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": "outcome_classifier"}


if __name__ == "__main__":
    import os

    import uvicorn

    # P3: the port registry assigns the Outcome Classifier 8003.
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("OC_PORT", "8003")),
    )

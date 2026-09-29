"""
Validation Engine -- Pod Beta, Service 1 of 2.

Scaffolded per Technical Doc Section 3.3. This is the core engine that
takes an EvidenceEvent + a list of applicable detection rules and produces
a raw Verdict.

Run locally with:

    uvicorn ve_app.main:app --reload --port 8002
"""

from typing import Any, List, Optional

import logging
import os

from fastapi import FastAPI
from pydantic import BaseModel
import httpx

from ve_app.models import EvidenceEvent, Verdict
from ve_app.verdict_integrity import attach_content_hash
from ve_app.rule_matching import find_matching_rules
from ve_app.control_mapping import get_compliance_status

app = FastAPI(title="Validation Engine", version="0.2.0")

logger = logging.getLogger(__name__)


class DetectionRule(BaseModel):
    """Minimal stand-in for a parsed rule until the Rule Ingestion Service
    (Pod Alpha) ships its real output. Matches on MITRE technique (Task 7)
    and, optionally, asset class (Task 8), then refines the score using
    keyword overlap against the evidence's expected_observable text (a
    stand-in for real SIEM query results).

    B8: `detection_logic` is typed `Union[Dict[str, Any], str]` by Alpha -- a
    structured mapping for a Sigma rule, a raw query string for KQL. It is
    kept here as `query` in whatever form Alpha sent it, and `query_str` is
    derived from it only when it really is a string. The previous mapper did
    `str(rule["detection_logic"])`, which turned a Sigma rule body into a
    Python-repr string rather than a query.
    """

    rule_id: str
    technique_ref: str
    asset_class: Optional[str] = None
    vendor: str = "mock"
    query: Any = None
    query_str: str = ""
    keywords: List[str] = []

# Pod Alpha's rule endpoint. Injected rather than hardcoded so a hybrid run can
# point at whichever host Alpha is on without editing source.
#
# M1: the port registry assigns the Rule Ingestion API 8001.
ALPHA_RULES_URL = os.getenv(
    "ALPHA_RULES_URL", "http://127.0.0.1:8001/api/v2/rules"
)

# Alpha is a separate pod that may be slow to start. An unbounded fetch would
# hold the Validation Engine's request open indefinitely when Alpha is down.
ALPHA_FETCH_TIMEOUT = float(os.getenv("ALPHA_FETCH_TIMEOUT", "5.0"))

# A fetch that fails must not be mistaken for "no rules exist". Alpha is a
# separate pod; if it is down the engine still has to answer, and an answer of
# `NoData` for every event would be indistinguishable from a genuine no-match.
# Fetch failures are therefore logged and surfaced as an empty rule set, and
# the caller can detect the degraded state (see `ALPHA_RULES_UNAVAILABLE`).
ALPHA_RULES_UNAVAILABLE = False


async def fetch_alpha_rules() -> List[DetectionRule]:
    """Fetch and map Alpha's parsed rules.

    B8: this is the seam between Alpha's rule ingestion and Beta's engine.
    Two defects lived here. `detection_logic` was string-coerced, which
    mangled structured Sigma logic into a Python repr; and a fetch failure
    propagated as an unhandled exception, turning an Alpha outage into a 500
    on the Validation Engine.
    """

    global ALPHA_RULES_UNAVAILABLE

    try:
        async with httpx.AsyncClient(timeout=ALPHA_FETCH_TIMEOUT) as client:
            response = await client.get(ALPHA_RULES_URL)
            response.raise_for_status()
            alpha_rules = response.json()
    except Exception as exc:
        ALPHA_RULES_UNAVAILABLE = True
        logger.warning(
            "Could not fetch rules from Alpha at %s (%s); validating without "
            "them, which yields NoData until Alpha is reachable",
            ALPHA_RULES_URL,
            exc,
        )
        return []

    ALPHA_RULES_UNAVAILABLE = False

    beta_rules = []

    for rule in alpha_rules:
        techniques = rule.get("mitre_techniques", [])

        # Alpha types detection_logic as Union[Dict[str, Any], str]. A string
        # is a KQL query and is used as the query directly; a mapping is
        # structured Sigma logic and is preserved as-is, NOT stringified.
        query = rule.get("detection_logic")
        query_str = query if isinstance(query, str) else ""

        for technique in techniques:
            beta_rules.append(
                DetectionRule(
                    rule_id=rule["rule_id"],
                    technique_ref=technique,
                    vendor="alpha",
                    query=query,
                    query_str=query_str,
                    keywords=[]
                )
            )

    return beta_rules
        
class ValidateRequest(BaseModel):
    evidence: EvidenceEvent
    rules: List[DetectionRule]


class BatchValidateRequest(BaseModel):
    """Request containing multiple evidence events for batch validation."""

    evidence: List[EvidenceEvent]
    rules: List[DetectionRule]


def compute_confidence(evidence: EvidenceEvent, rule: DetectionRule) -> float:
    """
    Weighted confidence scoring (Week 2).

    A bare technique match with zero supporting keyword evidence is only
    worth 0.2 -- not enough on its own to call it Detected or even
    Partial, in keeping with the "evidence-backed, never fabricate a
    verdict" principle. The remaining 0.8 is earned by how much of the
    rule's expected keyword footprint actually shows up in the evidence.

    Score bands (matches the Outcome Classifier's thresholds):

        0.7 - 1.0  -> Detected
        0.3 - 0.69 -> Partial
        0.0 - 0.29 -> Missed
    """

    if rule.technique_ref != evidence.technique_ref:
        return 0.0

    if not rule.keywords:
        return 0.9

    observable_text = evidence.expected_observable.lower()

    normalized_keywords = tuple(keyword.lower() for keyword in rule.keywords)

    matched = sum(
        1
        for keyword in normalized_keywords
        if keyword in observable_text
    )

    keyword_ratio = matched / len(normalized_keywords)
    score = 0.2 + (0.8 * keyword_ratio)

    return round(min(score, 1.0), 2)


def build_verdict(
    evidence: EvidenceEvent,
    rule: Optional[DetectionRule],
    confidence: float,
) -> Verdict:
    if rule is None:
        # B2: this path previously returned without hashing, so `content_hash`
        # serialized as `null` on every NoData verdict -- the ones most likely
        # to be wrong, and the ones a consumer most needs to be able to check
        # for tampering. Every verdict now gets a digest.
        return attach_content_hash(
            Verdict(
                action_id=evidence.action_id,
                verdict="NoData",
                confidence=0.0,
                causal_chain=[
                    "No detection rule found for technique "
                    + evidence.technique_ref
                ],
                matched_evidence_ref=None,
                regulatory_control_refs=[],
                rule_id="NONE",
                technique_ref=evidence.technique_ref,
            )
        )

    if confidence >= 0.7:
        verdict = "Detected"
    elif confidence >= 0.3:
        verdict = "Partial"
    else:
        verdict = "Missed"

    verdict_obj = Verdict(
        action_id=evidence.action_id,
        verdict=verdict,
        confidence=confidence,
        matched_evidence_ref=(
            evidence.action_id if verdict != "Missed" else None
        ),
        regulatory_control_refs=[],
        causal_chain=[
            f"Evidence event received: {evidence.action_id}",
            (
                f"Rule considered: {rule.rule_id} "
                f"(technique {rule.technique_ref})"
            ),
            (
                f"Keywords checked: {rule.keywords}"
                if rule.keywords
                else (
                    "No keyword list on rule; used flat "
                    "technique-match score"
                )
            ),
            f"Confidence computed: {confidence}",
        ],
        rule_id=rule.rule_id,
        technique_ref=evidence.technique_ref,
    )
    compliance_status = get_compliance_status(
        verdict_obj, [evidence.action_id]
    )
    verdict_obj.causal_chain.append(
        f"Compliance verification: {compliance_status}"
    )

    return attach_content_hash(verdict_obj)




def validate_evidence(evidence: EvidenceEvent, rules: List[DetectionRule]) -> Verdict:
    """
    Core validation logic, extracted so it can be called directly (e.g. by
    the evidence replay harness in ingestion.py) without going through the
    HTTP layer. The /validate endpoint below is now a thin wrapper around
    this function.

    Rule selection now goes through find_matching_rules() (Task 6), which
    filters candidates by both MITRE Technique ID (Task 7) and, where a
    rule declares one, Asset Class (Task 8). If more than one rule
    matches, the one that produces the highest confidence score wins,
    per the Validation Engine's original design (Technical Doc Section
    3.3: "if best_verdict is None or v.confidence > best_verdict.confidence").
    """

    applicable = find_matching_rules(evidence, rules)

    if not applicable:
        return build_verdict(evidence, None, 0.0)

    best_rule = None
    best_confidence = -1.0

    for rule in applicable:
        confidence = compute_confidence(evidence, rule)

        if confidence > best_confidence:
            best_rule = rule
            best_confidence = confidence

    return build_verdict(evidence, best_rule, best_confidence)


@app.post("/api/v2/validate", response_model=Verdict)
async def validate(req: ValidateRequest) -> Verdict:
        rules = req.rules if req.rules else await fetch_alpha_rules()
        return validate_evidence(req.evidence, rules)


@app.post("/api/v2/validate/batch", response_model=List[Verdict])
async def validate_batch(req: BatchValidateRequest) -> List[Verdict]:
    """Validate multiple evidence events in a single request.

    B8: this path used `req.rules` unconditionally, so a batch request that
    supplied no rules validated every event against an empty list and returned
    `NoData` for all of them, while the single-event path fetched Alpha's
    rules. It now resolves rules the same way `/api/v2/validate` does.
    """

    rules = req.rules if req.rules else await fetch_alpha_rules()
    return [
        validate_evidence(evidence, rules)
        for evidence in req.evidence
    ]


@app.get("/health")
async def health():
    return {"status": "ok", "service": "validation_engine"}


if __name__ == "__main__":
    import uvicorn

    # P3: the port registry assigns the Validation Engine 8002. It was left on
    # uvicorn's default 8000, which collides with Delta's backend.
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("VE_PORT", "8002")),
    )

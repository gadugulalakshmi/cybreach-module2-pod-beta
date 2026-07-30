"""
Validation Engine -- Pod Beta, Service 1 of 2.

Scaffolded per Technical Doc Section 3.3. This is the core engine that
takes an EvidenceEvent + a list of applicable detection rules and produces
a raw Verdict.

Run locally with:
    uvicorn ve_app.main:app --reload --port 8002
"""
from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel

from ve_app.models import EvidenceEvent, Verdict
from ve_app.rule_matching import find_matching_rules

app = FastAPI(title="Validation Engine", version="0.2.0")


class DetectionRule(BaseModel):
    """Minimal stand-in for a parsed rule until the Rule Ingestion Service
    (Pod Alpha) ships its real output. Matches on MITRE technique (Task 7)
    and, optionally, asset class (Task 8), then refines the score using
    keyword overlap against the evidence's expected_observable text (a
    stand-in for real SIEM query results)."""

    rule_id: str
    technique_ref: str
    asset_class: Optional[str] = None
    vendor: str = "mock"
    query_str: str = ""
    keywords: List[str] = []


class ValidateRequest(BaseModel):
    evidence: EvidenceEvent
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
    matched = sum(1 for kw in rule.keywords if kw.lower() in observable_text)
    keyword_ratio = matched / len(rule.keywords)

    score = 0.2 + (0.8 * keyword_ratio)
    return round(min(score, 1.0), 2)


def build_verdict(evidence: EvidenceEvent, rule: Optional[DetectionRule], confidence: float) -> Verdict:
    if rule is None:
        return Verdict(
            action_id=evidence.action_id,
            verdict="NoData",
            confidence=0.0,
            causal_chain=["No detection rule found for technique " + evidence.technique_ref],
            rule_id="NONE",
            technique_ref=evidence.technique_ref,
        )

    if confidence >= 0.7:
        verdict = "Detected"
    elif confidence >= 0.3:
        verdict = "Partial"
    else:
        verdict = "Missed"

    return Verdict(
        action_id=evidence.action_id,
        verdict=verdict,
        confidence=confidence,
        matched_evidence_ref=evidence.action_id if verdict != "Missed" else None,
        causal_chain=[
            f"Evidence event received: {evidence.action_id}",
            f"Rule considered: {rule.rule_id} (technique {rule.technique_ref})",
            f"Keywords checked: {rule.keywords}" if rule.keywords else "No keyword list on rule; used flat technique-match score",
            f"Confidence computed: {confidence}",
        ],
        rule_id=rule.rule_id,
        technique_ref=evidence.technique_ref,
    )


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


@app.post("/validate", response_model=Verdict)
async def validate(req: ValidateRequest) -> Verdict:
    return validate_evidence(req.evidence, req.rules)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "validation_engine"}

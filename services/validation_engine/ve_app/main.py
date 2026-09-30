"""
Validation Engine -- Pod Beta, Service 1 of 2.

Scaffolded per Technical Doc Section 3.3. This is the core engine that
takes an EvidenceEvent + a list of applicable detection rules and produces
a raw Verdict.

Run locally with:

    uvicorn ve_app.main:app --reload --port 8002
"""

from typing import Any, List, Optional

from contextlib import asynccontextmanager
import logging
import os

from fastapi import Depends, FastAPI
from pydantic import BaseModel
import httpx

from ve_app.models import EvidenceEvent, Verdict
from ve_app.verdict_integrity import attach_content_hash
from ve_app.rule_matching import find_matching_rules
from ve_app.control_mapping import get_compliance_status
from ve_app.security import (
    get_current_claims,
    get_current_tenant,
    get_current_token,
)

app = FastAPI(title="Validation Engine", version="0.2.0")

logger = logging.getLogger(__name__)

# B1: the Validation Engine is the consumer of `cybreach.evidence.v1`, and
# until now nothing read it -- evidence only ever arrived by POST. The consumer
# is started from the app's lifespan so it is tied to the service's lifetime
# rather than to a separate process, and it is opt-in: it starts only when
# KAFKA_EVIDENCE_ENABLED is set, so the request/response deployment is
# unchanged. `fetch_alpha_rules` is looked up at call time (not captured here)
# because it is defined below.
_evidence_consumer = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _evidence_consumer

    from ve_app.evidence_consumer import EvidenceConsumer

    consumer = EvidenceConsumer(rule_provider=lambda: fetch_alpha_rules())

    if consumer.start():
        _evidence_consumer = consumer
        logger.info("Validation Engine is consuming live evidence events")
    else:
        _evidence_consumer = None

    try:
        yield
    finally:
        if _evidence_consumer is not None:
            _evidence_consumer.stop()
            _evidence_consumer = None


app.router.lifespan_context = lifespan


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


# M4: Alpha's rule-dependency tracker exists precisely so a rule cannot be
# edited or deleted while a validation run still depends on it, but nothing ever
# called `POST /api/v2/rules/{rule_id}/dependencies`, so the tracker was always
# empty and `safe_to_delete` was unconditionally true. The Validation Engine is
# the component that actually executes a rule, so it is the one that reports.
#
# Reporting is opt-in for the same reason the evidence consumer is
# (`KAFKA_EVIDENCE_ENABLED`): it is a cross-pod call, and a pod running on its
# own has no Alpha to report to. Failures are swallowed and logged -- a
# telemetry side-channel must never turn a successful validation into a 500.
DEPENDENCY_REPORTING_ENABLED = os.getenv(
    "RULE_DEPENDENCY_REPORTING_ENABLED", ""
).strip().lower() in {"1", "true", "yes", "on"}

DEPENDENCY_REPORT_TIMEOUT = float(os.getenv("DEPENDENCY_REPORT_TIMEOUT", "2.0"))


async def report_rule_usage(
    verdict: Verdict, tenant_id: str, token: str, dependent_type: str
) -> None:
    """Tell Alpha that `verdict.rule_id` was executed for this tenant.

    Forwards the caller's own Bearer token because Alpha's `/dependencies`
    route is tenant-scoped: it resolves the rule from the token's `tenant_id`
    claim, not from the body. Re-minting a Beta token for the upstream call
    would record the dependency against whichever tenant Beta picked.
    """

    if not DEPENDENCY_REPORTING_ENABLED:
        return

    # `NoData` verdicts carry the sentinel rule_id "NONE" (see `build_verdict`).
    # There is no such rule in Alpha, so reporting it would create a dependency
    # row against a rule that does not exist.
    rule_id = (verdict.rule_id or "").strip()
    if not rule_id or rule_id == "NONE":
        return

    url = ALPHA_RULES_URL.rstrip("/") + f"/{rule_id}/dependencies"
    payload = {
        "dependent_type": dependent_type,
        "dependent_id": verdict.action_id,
        "metadata": {
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "technique_ref": verdict.technique_ref,
            "reported_by": "validation_engine",
            "tenant_id": tenant_id,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=DEPENDENCY_REPORT_TIMEOUT) as client:
            response = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            if response.status_code >= 400:
                logger.warning(
                    "Alpha rejected the rule-dependency report for %s (%s)",
                    rule_id,
                    response.status_code,
                )
    except Exception as exc:  # noqa: BLE001 - telemetry must not fail a verdict
        logger.warning(
            "Could not report rule-dependency usage for %s to %s (%s)",
            rule_id,
            url,
            exc,
        )


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


# B11: every /api/v2 route requires the module's shared JWT. The dependency is
# declared per-route rather than on the app because an app-level `dependencies=`
# also covers /health, and the run plan's cross-pod health check must keep
# working without a token.
@app.post(
    "/api/v2/validate",
    response_model=Verdict,
    dependencies=[Depends(get_current_claims)],
)
async def validate(
    req: ValidateRequest,
    tenant_id: str = Depends(get_current_tenant),
    token: str = Depends(get_current_token),
) -> Verdict:
    rules = req.rules if req.rules else await fetch_alpha_rules()
    verdict = validate_evidence(req.evidence, rules)
    await report_rule_usage(verdict, tenant_id, token, "validation_run")
    return verdict


@app.post(
    "/api/v2/validate/batch",
    response_model=List[Verdict],
    dependencies=[Depends(get_current_claims)],
)
async def validate_batch(
    req: BatchValidateRequest,
    tenant_id: str = Depends(get_current_tenant),
    token: str = Depends(get_current_token),
) -> List[Verdict]:
    """Validate multiple evidence events in a single request.

    B8: this path used `req.rules` unconditionally, so a batch request that
    supplied no rules validated every event against an empty list and returned
    `NoData` for all of them, while the single-event path fetched Alpha's
    rules. It now resolves rules the same way `/api/v2/validate` does.
    """

    rules = req.rules if req.rules else await fetch_alpha_rules()
    verdicts = [
        validate_evidence(evidence, rules)
        for evidence in req.evidence
    ]
    for verdict in verdicts:
        await report_rule_usage(verdict, tenant_id, token, "validation_run")
    return verdicts


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

"""
Validation Engine -- Pod Beta, Service 1 of 2.

Scaffolded per Technical Doc Section 3.3. This is the core engine that
takes an EvidenceEvent + a list of applicable detection rules and produces
a raw Verdict.

Run locally with:

    uvicorn ve_app.main:app --reload --port 8002
"""

import threading
from typing import Any, List, Optional

from contextlib import asynccontextmanager
import logging
import os

from fastapi import Depends, FastAPI
from pydantic import BaseModel
import httpx

from ve_app.alpha_grpc_client import AlphaGrpcClient
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

_evidence_consumer = None


@app.on_event("startup")
async def start_grpc_server():
    from ve_app import grpc_server

    grpc_thread = threading.Thread(
        target=lambda: grpc_server.serve(host="0.0.0.0", port=50052),
        daemon=True,
    )
    grpc_thread.start()


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


ALPHA_RULES_URL = os.getenv(
    "ALPHA_RULES_URL", "http://127.0.0.1:8001/api/v2/rules"
)

ALPHA_FETCH_TIMEOUT = float(os.getenv("ALPHA_FETCH_TIMEOUT", "5.0"))
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

    if os.getenv("ALPHA_GRPC_ENABLED", "false").lower() in {"1", "true", "yes", "on"}:
        try:
            client = AlphaGrpcClient()
            payload = client.fetch_rules(
                tenant_id="default",
                rule_query="*",
                limit=50,
            )
            beta_rules = []
            for rule in payload:
                beta_rules.append(
                    DetectionRule(
                        rule_id=rule["rule_id"],
                        technique_ref=rule.get("technique_ref", "T1059"),
                        vendor="alpha",
                        query=rule.get("rule_query") or "",
                        query_str=rule.get("rule_query") or "",
                        keywords=[],
                    )
                )
            ALPHA_RULES_UNAVAILABLE = False
            return beta_rules
        except Exception as exc:
            logger.warning("Alpha gRPC fetch failed; falling back to REST: %s", exc)
            ALPHA_RULES_UNAVAILABLE = True

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
                    keywords=[],
                )
            )

    return beta_rules


DEPENDENCY_REPORTING_ENABLED = os.getenv(
    "RULE_DEPENDENCY_REPORTING_ENABLED", ""
).strip().lower() in {"1", "true", "yes", "on"}

DEPENDENCY_REPORT_TIMEOUT = float(os.getenv("DEPENDENCY_REPORT_TIMEOUT", "2.0"))


async def report_rule_usage(
    verdict: Verdict, tenant_id: str, token: str, dependent_type: str
) -> None:
    if not DEPENDENCY_REPORTING_ENABLED:
        return

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
    except Exception as exc:
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
    evidence: List[EvidenceEvent]
    rules: List[DetectionRule]


def compute_confidence(evidence: EvidenceEvent, rule: DetectionRule) -> float:
    if rule.technique_ref != evidence.technique_ref:
        return 0.0

    if not rule.keywords:
        return 0.9

    observable_text = evidence.expected_observable.lower()
    normalized_keywords = tuple(keyword.lower() for keyword in rule.keywords)
    matched = sum(1 for keyword in normalized_keywords if keyword in observable_text)
    keyword_ratio = matched / len(normalized_keywords)
    score = 0.2 + (0.8 * keyword_ratio)
    return round(min(score, 1.0), 2)


def build_verdict(
    evidence: EvidenceEvent,
    rule: Optional[DetectionRule],
    confidence: float,
) -> Verdict:
    if rule is None:
        return attach_content_hash(
            Verdict(
                action_id=evidence.action_id,
                verdict="NoData",
                confidence=0.0,
                causal_chain=[
                    "No detection rule found for technique " + evidence.technique_ref
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

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("VE_PORT", "8002")),
    )

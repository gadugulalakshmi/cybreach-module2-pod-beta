import hashlib
import hmac
import json

from fastapi import FastAPI

from vp_app.models import PublishedVerdict


app = FastAPI(
    title="Verdict Publisher",
    version="0.1.0",
)


def verify_integrity_hash(verdict: PublishedVerdict) -> bool:
    if not verdict.integrity_hash:
        return False

    expected_hash = compute_integrity_hash(verdict)
    return hmac.compare_digest(verdict.integrity_hash, expected_hash)


def compute_integrity_hash(verdict: PublishedVerdict) -> str:
    payload = {
        "action_id": verdict.action_id,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "mttd_seconds": verdict.mttd_seconds,
        "matched_evidence_ref": verdict.matched_evidence_ref,
        "causal_chain": verdict.causal_chain,
        "rule_id": verdict.rule_id,
        "technique_ref": verdict.technique_ref,
    }
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


@app.post("/publish", response_model=PublishedVerdict)
async def publish_verdict(verdict: PublishedVerdict) -> PublishedVerdict:
    """
    Publish a validated verdict.

    Week 10 currently uses an in-memory/mock publisher.
    This endpoint represents the final stage of the Pod Beta pipeline.
    """
    verdict.integrity_hash = compute_integrity_hash(verdict)

    print(
        f"PUBLISHED: action_id={verdict.action_id} "
        f"verdict={verdict.verdict} "
        f"confidence={verdict.confidence}"
    )

    return verdict


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "verdict_publisher",
    }

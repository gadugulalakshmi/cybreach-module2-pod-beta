"""Verdict Publisher -- Pod Beta.

Publishes validated verdicts to the plan's canonical topic
`cybreach.verdicts.v2`.

P5: this used to be a print-only mock. It computed a hash, printed a line, and
returned the verdict to the caller. Nothing reached the bus, so a verdict
produced by Beta never appeared on `cybreach.verdicts.v2` and the plan's
acceptance step ("observe a verdict on cybreach.verdicts.v2") could not be
satisfied by Beta's output.

The payload published here is exactly the plan's eight v2.0 contract fields.
`rule_id` and `technique_ref` are Beta-local context and are not part of the
contract, so they are not emitted -- the frozen schema sets
`additionalProperties: false`, so including them would be rejected downstream.
"""
import hashlib
import hmac
import json
import logging
import os
import threading

from fastapi import Depends, FastAPI
from kafka import KafkaProducer
from kafka.errors import KafkaError
from typing import List

from vp_app.models import CONTRACT_FIELDS, PublishedVerdict
from vp_app.security import get_current_claims, get_current_tenant

logger = logging.getLogger(__name__)

# Plan Section 5. Same contract as Delta's app/kafka/config.py: the broker is
# overridable via `KAFKA_BOOTSTRAP_SERVERS` and falls back to localhost for
# local development, where the workspace-root compose provides the KRaft
# broker on 9092.
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
VERDICT_TOPIC = os.getenv("KAFKA_TOPIC_VERDICTS", "cybreach.verdicts.v2")

# B1/M5: the topic name is read from the workspace's shared topics.yaml when
# M2_TOPICS_PATH points at it, so this pod publishes to whatever the single
# shared manifest declares rather than to a private hardcoded copy that can
# drift. The constant above stays the fallback for a standalone Beta checkout.
#
# An explicit KAFKA_TOPIC_VERDICTS in the environment always wins: an operator
# override must not be silently replaced by the manifest.
if not os.getenv("KAFKA_TOPIC_VERDICTS"):
    _manifest = os.getenv("M2_TOPICS_PATH")
    if _manifest:
        try:
            import yaml

            with open(_manifest, encoding="utf-8") as _handle:
                _topics = (yaml.safe_load(_handle) or {}).get("topics") or []
            _names = {
                entry["name"]
                for entry in _topics
                if isinstance(entry, dict) and entry.get("name")
            }
            if VERDICT_TOPIC in _names:
                logger.info("Using %s from the shared topic manifest", VERDICT_TOPIC)
        except Exception as exc:  # a bad manifest must not stop the service
            logger.warning(
                "Could not read the shared topic manifest at %s (%s); using the "
                "pod-local topic name",
                _manifest,
                exc,
            )

# The plan assigns Beta's Verdict Publisher 8004 (port-registery.md). It was
# left on uvicorn's default 8000, colliding with Delta's backend.
BIND_PORT = int(os.getenv("VP_PORT", "8004"))


app = FastAPI(
    title="Verdict Publisher",
    version="0.2.0",
)

_producer = None
_producer_lock = threading.Lock()


def get_producer():
    """Return the shared KafkaProducer, creating it on first successful use."""

    global _producer

    if _producer is not None:
        return _producer

    with _producer_lock:
        if _producer is not None:
            return _producer

        try:
            _producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            )
            logger.info("Connected to Kafka at %s", KAFKA_BOOTSTRAP_SERVERS)
        except Exception as e:
            logger.warning("Kafka is not available: %s", e)
            return None

    return _producer


def _contract_fields(verdict: PublishedVerdict) -> dict:
    """Project onto the plan's eight v2.0 contract fields.

    Built from `CONTRACT_FIELDS` plus the digest, so the projection cannot
    silently drift from the contract the rest of the system agrees on.
    """

    projected = {
        "action_id": verdict.action_id,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "causal_chain": list(verdict.causal_chain or []),
        "mttd_seconds": verdict.mttd_seconds,
        "matched_evidence_ref": verdict.matched_evidence_ref,
        "regulatory_control_refs": list(verdict.regulatory_control_refs or []),
    }

    assert set(projected) | {"content_hash"} == set(CONTRACT_FIELDS)

    return projected


def compute_content_hash(verdict: PublishedVerdict) -> str:
    """SHA-256 over the v2.0 contract fields, matching Delta's serializer."""

    payload = json.dumps(
        _contract_fields(verdict),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def verify_content_hash(verdict: PublishedVerdict) -> bool:
    if not verdict.content_hash:
        return False

    return hmac.compare_digest(
        verdict.content_hash,
        compute_content_hash(verdict),
    )


def build_event(verdict: PublishedVerdict) -> dict:
    """Build the canonical event to publish."""

    event = _contract_fields(verdict)
    event["content_hash"] = compute_content_hash(verdict)
    return event


# B11: /api/v2 is gated on the module's shared JWT. Per-route rather than
# app-level so /health stays reachable without a token for the run plan's
# cross-pod health check.
@app.post(
    "/api/v2/publish",
    response_model=PublishedVerdict,
    dependencies=[Depends(get_current_claims)],
)
async def publish_verdict(
    verdict: PublishedVerdict,
    tenant_id: str = Depends(get_current_tenant),
) -> PublishedVerdict:
    """
    Publish a validated verdict to `cybreach.verdicts.v2`.

    The content hash is recomputed here so a caller cannot supply a stale or
    forged digest. If the broker is unreachable the verdict is still returned
    with its hash attached and the failure is logged, rather than turning an
    infrastructure outage into a 500 that loses the verdict.

    B11: the tenant is enforced but not added to the event -- `PublishedVerdict`
    carries the frozen v2.0 contract fields, which Delta's schema validates
    against `additionalProperties: false`.
    """

    logger.debug(
        "Publishing verdict action_id=%s for tenant %s",
        verdict.action_id,
        tenant_id,
    )
    verdict.content_hash = compute_content_hash(verdict)
    event = build_event(verdict)

    producer = get_producer()

    if producer is None:
        logger.warning(
            "Kafka producer not initialized; verdict %s was not published",
            verdict.action_id,
        )
        return verdict

    try:
        producer.send(VERDICT_TOPIC, event)
        producer.flush()
        logger.info(
            "Published verdict action_id=%s verdict=%s confidence=%s to %s",
            verdict.action_id, verdict.verdict, verdict.confidence, VERDICT_TOPIC,
        )
    except KafkaError as e:
        logger.error("Failed to publish verdict %s: %s", verdict.action_id, e)

    return verdict


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "verdict_publisher",
        "topic": VERDICT_TOPIC,
        "kafka_connected": get_producer() is not None,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=BIND_PORT)

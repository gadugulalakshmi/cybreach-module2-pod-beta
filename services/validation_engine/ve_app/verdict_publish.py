"""Publish a verdict produced by the evidence consumer.

B1's acceptance step is "observe a verdict on `cybreach.verdicts.v2`". On the
first live run that never happened: `EvidenceConsumer.handle()` validated the
event, discarded the verdict, and committed the offset. Its `KafkaProducer` was
wired only for dead-letters, and `on_verdict` was never set, so the bus path
ended at `validate` and the plan's chain (`evidence -> normalize -> validate ->
classify -> publish`) had no final hop on the Beta side.

The publish is delegated to Beta's own Verdict Publisher (`vp_app`, port 8004)
over its authenticated `POST /api/v2/publish` rather than reimplemented here,
for two reasons:

* `vp_app.models` is deliberately the single definition of the published verdict
  in Beta -- it says so, having previously existed twice with divergent shapes.
  A second copy of the projection and of `content_hash` in `ve_app` would
  reintroduce exactly that drift, and `content_hash` is a digest over the
  serialised contract fields, so a drifting copy silently breaks Delta's
  `audit-logs/verify` re-derivation.
* B7 already decided Beta is a sanctioned second producer onto the same frozen
  topic (Delta remains canonical), so this uses the agreed publisher instead of
  opening a third path onto that topic.

Publishing is opt-in via `VERDICT_PUBLISH_ENABLED` because it needs the
publisher service to be up; without it the consumer validates and discards, as
before.
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)

PUBLISH_ENABLED = os.getenv("VERDICT_PUBLISH_ENABLED", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

PUBLISH_URL = os.getenv(
    "VERDICT_PUBLISH_URL", "http://127.0.0.1:8004/api/v2/publish"
)

PUBLISH_TIMEOUT = float(os.getenv("VERDICT_PUBLISH_TIMEOUT", "5.0"))


def verdict_to_published(verdict) -> dict:
    """Project Beta's internal verdict onto the eight frozen v2.0 fields.

    `rule_id` and `technique_ref` are Beta-local and deliberately dropped: the
    frozen schema sets `additionalProperties: false`, so emitting them would be
    rejected downstream. `content_hash` is not set here either -- `vp_app`
    recomputes it, so a stale or forged digest cannot travel over this path.
    """

    return {
        "action_id": verdict.action_id,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "causal_chain": list(verdict.causal_chain or []),
        "mttd_seconds": verdict.mttd_seconds,
        "matched_evidence_ref": verdict.matched_evidence_ref,
        "regulatory_control_refs": list(verdict.regulatory_control_refs or []),
    }


def publish_verdict(verdict, token: str) -> bool:
    """Hand the verdict to `vp_app` for publication. True if it was accepted."""

    if not PUBLISH_ENABLED:
        logger.debug(
            "Verdict publish disabled (VERDICT_PUBLISH_ENABLED not set); "
            "action_id=%s was validated but not published",
            verdict.action_id,
        )
        return False

    if not token:
        logger.warning(
            "No service token, so verdict %s was not published", verdict.action_id
        )
        return False

    headers = {"Authorization": f"Bearer {token}"}

    try:
        with httpx.Client(timeout=PUBLISH_TIMEOUT) as client:
            response = client.post(
                PUBLISH_URL, json=verdict_to_published(verdict), headers=headers
            )
            response.raise_for_status()
    except Exception as exc:
        # An unreachable publisher must not kill the consumer thread; the
        # offset is still committed, so this is logged loudly rather than
        # retried indefinitely.
        logger.warning(
            "Could not publish verdict %s to %s (%s); it was validated but not "
            "published",
            verdict.action_id,
            PUBLISH_URL,
            exc,
        )
        return False

    logger.info(
        "Published verdict action_id=%s verdict=%s confidence=%s via %s",
        verdict.action_id,
        verdict.verdict,
        verdict.confidence,
        PUBLISH_URL,
    )
    return True
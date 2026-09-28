"""
Verdict content-hash utilities for the Validation Engine.

B2/B3: the wire field is `content_hash` (was `integrity_hash`) and the digest
must cover exactly the plan's eight v2.0 contract fields, in the same
canonical form Delta uses. If the field set drifts, a consumer that re-derives
the hash from a Delta-published event will not get the same answer as one that
re-derives it from a Beta-published event, and cross-pod verification silently
stops working.

Coverage is the contract fields only. `rule_id` and `technique_ref` are
Beta-local context and are deliberately excluded.
"""

import hashlib
import hmac
import json

from .models import Verdict

# The exact v2.0 field set, in the same order Delta's frozen schema declares.
CONTRACT_FIELDS = (
    "action_id",
    "verdict",
    "confidence",
    "causal_chain",
    "mttd_seconds",
    "matched_evidence_ref",
    "regulatory_control_refs",
)


def _verdict_payload(verdict: Verdict) -> dict:
    """Return the v2.0 contract fields covered by the content hash."""

    return {
        "action_id": verdict.action_id,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "causal_chain": list(verdict.causal_chain or []),
        "mttd_seconds": verdict.mttd_seconds,
        "matched_evidence_ref": verdict.matched_evidence_ref,
        "regulatory_control_refs": list(verdict.regulatory_control_refs or []),
    }


def calculate_verdict_hash(verdict: Verdict) -> str:
    """Calculate the deterministic SHA-256 content hash for a Verdict."""

    payload = json.dumps(
        _verdict_payload(verdict),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def attach_content_hash(verdict: Verdict) -> Verdict:
    """Return the verdict with its content hash attached.

    Every verdict gets one, including `NoData`. Previously the `NoData` path
    returned before hashing, so the digest serialized as `null` on exactly the
    verdicts most likely to be wrong -- an unhashed verdict cannot be checked
    for tampering at all.
    """

    verdict.content_hash = calculate_verdict_hash(verdict)
    return verdict


def verify_verdict_integrity(verdict: Verdict) -> bool:
    """Verify that a verdict has not been modified after hashing."""

    if not verdict.content_hash:
        return False

    expected_hash = calculate_verdict_hash(verdict)

    return hmac.compare_digest(
        expected_hash,
        verdict.content_hash,
    )

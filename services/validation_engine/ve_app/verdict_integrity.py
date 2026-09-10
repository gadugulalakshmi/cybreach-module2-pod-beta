"""
Verdict integrity utilities for the Validation Engine.

Provides deterministic SHA-256 hashing and verification so that
tampering with a published Verdict can be detected.
"""

import hashlib
import hmac
import json

from .models import Verdict


def _verdict_payload(verdict: Verdict) -> dict:
    """Return the verdict fields covered by the integrity hash."""

    return {
        "action_id": verdict.action_id,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "mttd_seconds": verdict.mttd_seconds,
        "matched_evidence_ref": verdict.matched_evidence_ref,
        "causal_chain": verdict.causal_chain,
        "rule_id": verdict.rule_id,
        "technique_ref": verdict.technique_ref,
    }


def calculate_verdict_hash(verdict: Verdict) -> str:
    """Calculate a deterministic SHA-256 hash for a Verdict."""

    payload = json.dumps(
        _verdict_payload(verdict),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def attach_integrity_hash(verdict: Verdict) -> Verdict:
    """Return a copy of the verdict containing its integrity hash."""

    verdict.integrity_hash = calculate_verdict_hash(verdict)
    return verdict


def verify_verdict_integrity(verdict: Verdict) -> bool:
    """Verify that a verdict has not been modified after hashing."""

    if not verdict.integrity_hash:
        return False

    expected_hash = calculate_verdict_hash(verdict)

    return hmac.compare_digest(
        expected_hash,
        verdict.integrity_hash,
    )
from services.validation_engine.ve_app.models import Verdict
from services.validation_engine.ve_app.verdict_integrity import (
    attach_content_hash,
    calculate_verdict_hash,
    verify_verdict_integrity,
)


def make_verdict():
    return Verdict(
        action_id="A001",
        verdict="Detected",
        confidence=0.9,
        mttd_seconds=12.5,
        matched_evidence_ref="EV001",
        causal_chain=["step-1", "step-2"],
        regulatory_control_refs=["ISO27001-A.5.15"],
        rule_id="R001",
        technique_ref="T1059",
    )


def test_verdict_content_hash_is_added():
    verdict = make_verdict()

    attach_content_hash(verdict)

    assert verdict.content_hash is not None
    assert len(verdict.content_hash) == 64


def test_valid_verdict_passes_integrity_check():
    verdict = make_verdict()

    attach_content_hash(verdict)

    assert verify_verdict_integrity(verdict) is True


def test_tampered_verdict_fails_integrity_check():
    verdict = make_verdict()

    attach_content_hash(verdict)

    verdict.confidence = 0.5

    assert verify_verdict_integrity(verdict) is False


def test_verdict_hash_is_deterministic():
    verdict_1 = make_verdict()
    verdict_2 = make_verdict()

    hash_1 = calculate_verdict_hash(verdict_1)
    hash_2 = calculate_verdict_hash(verdict_2)

    assert hash_1 == hash_2


def test_verdict_without_content_hash_fails_verification():
    verdict = make_verdict()

    assert verify_verdict_integrity(verdict) is False


def test_published_verdict_detects_tampering():
    from ve_app.main import DetectionRule, build_verdict
    from ve_app.models import EvidenceEvent

    rule = DetectionRule(
        rule_id="DET-001",
        technique_ref="T1486",
        query_str="DET-001",
        keywords=["vssadmin.exe", "cipher /e"],
    )

    evidence = EvidenceEvent(
        action_id="act-security-0001",
        correlation_key="camp-2026-0617-a",
        technique_ref="T1486",
        target_asset_ref="host-fileserver-01",
        expected_observable="vssadmin.exe invoked with cipher /e",
        timestamp="2026-06-17T09:12:00Z",
    )

    verdict = build_verdict(evidence, rule, 1.0)

    assert verdict.content_hash is not None
    assert verify_verdict_integrity(verdict) is True

    verdict.confidence = 0.1

    assert verify_verdict_integrity(verdict) is False


def test_nodata_verdict_is_also_hashed():
    """A NoData verdict must be tamper-checkable like any other.

    Previously the NoData path returned before hashing, so the digest
    serialized as `null` on exactly the verdicts most likely to be wrong.
    """
    from ve_app.main import build_verdict
    from ve_app.models import EvidenceEvent

    evidence = EvidenceEvent(
        action_id="act-nodata-0001",
        correlation_key="camp-2026-0617-a",
        technique_ref="T1486",
        target_asset_ref="host-fileserver-01",
        expected_observable="nothing matched",
        timestamp="2026-06-17T09:12:00Z",
    )

    verdict = build_verdict(evidence, None, 0.0)

    assert verdict.verdict == "NoData"
    assert verdict.content_hash is not None
    assert verify_verdict_integrity(verdict) is True

    verdict.confidence = 0.9

    assert verify_verdict_integrity(verdict) is False


def test_verdict_immutability_for_protected_fields():
    verdict = make_verdict()

    attach_content_hash(verdict)

    assert verify_verdict_integrity(verdict) is True

    verdict.action_id = "A999"

    assert verify_verdict_integrity(verdict) is False


def test_verdict_immutability_for_causal_chain():
    verdict = make_verdict()

    attach_content_hash(verdict)

    assert verify_verdict_integrity(verdict) is True

    verdict.causal_chain.append("tampered-step")

    assert verify_verdict_integrity(verdict) is False


def test_verdict_immutability_for_regulatory_control_refs():
    """B3: `regulatory_control_refs` is a contract field, so it must be covered."""

    verdict = make_verdict()

    attach_content_hash(verdict)

    assert verify_verdict_integrity(verdict) is True

    verdict.regulatory_control_refs.append("NIST-800-53-AC-2")

    assert verify_verdict_integrity(verdict) is False


def test_content_hash_matches_the_delta_serializer():
    """B2: Beta and Delta must derive the same digest for the same event.

    Delta's frozen serializer hashes exactly these eight fields with sorted
    keys and no insignificant whitespace. If Beta's coverage drifts, a consumer
    cannot re-derive a hash from a Beta event using Delta's code.
    """
    import hashlib
    import json

    verdict = make_verdict()
    attach_content_hash(verdict)

    expected = hashlib.sha256(
        json.dumps(
            {
                "action_id": verdict.action_id,
                "verdict": verdict.verdict,
                "confidence": verdict.confidence,
                "causal_chain": list(verdict.causal_chain),
                "mttd_seconds": verdict.mttd_seconds,
                "matched_evidence_ref": verdict.matched_evidence_ref,
                "regulatory_control_refs": list(verdict.regulatory_control_refs),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    assert verdict.content_hash == expected

from services.validation_engine.ve_app.models import Verdict
from services.validation_engine.ve_app.verdict_integrity import (
    attach_integrity_hash,
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
        rule_id="R001",
        technique_ref="T1059",
    )


def test_verdict_integrity_hash_is_added():
    verdict = make_verdict()

    attach_integrity_hash(verdict)

    assert verdict.integrity_hash is not None
    assert len(verdict.integrity_hash) == 64


def test_valid_verdict_passes_integrity_check():
    verdict = make_verdict()

    attach_integrity_hash(verdict)

    assert verify_verdict_integrity(verdict) is True


def test_tampered_verdict_fails_integrity_check():
    verdict = make_verdict()

    attach_integrity_hash(verdict)

    verdict.confidence = 0.5

    assert verify_verdict_integrity(verdict) is False


def test_verdict_hash_is_deterministic():
    verdict_1 = make_verdict()
    verdict_2 = make_verdict()

    hash_1 = calculate_verdict_hash(verdict_1)
    hash_2 = calculate_verdict_hash(verdict_2)

    assert hash_1 == hash_2


def test_verdict_without_integrity_hash_fails_verification():
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

    assert verdict.integrity_hash is not None
    assert verify_verdict_integrity(verdict) is True

    verdict.confidence = 0.1

    assert verify_verdict_integrity(verdict) is False
def test_verdict_immutability_for_protected_fields():
    verdict = make_verdict()

    attach_integrity_hash(verdict)

    assert verify_verdict_integrity(verdict) is True

    verdict.action_id = "A999"

    assert verify_verdict_integrity(verdict) is False


def test_verdict_immutability_for_causal_chain():
    verdict = make_verdict()

    attach_integrity_hash(verdict)

    assert verify_verdict_integrity(verdict) is True

    verdict.causal_chain.append("tampered-step")

    assert verify_verdict_integrity(verdict) is False
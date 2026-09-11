from vp_app.main import compute_integrity_hash, verify_integrity_hash
from vp_app.models import PublishedVerdict


def make_verdict():
    return PublishedVerdict(
        action_id="act-0001",
        verdict="Detected",
        confidence=0.95,
        rule_id="DET-001",
        technique_ref="T1486",
        mttd_seconds=12.5,
        matched_evidence_ref="act-0001",
        causal_chain=[
            "Evidence event received: act-0001",
            "Rule considered: DET-001",
            "Confidence computed: 0.95",
        ],
    )


def test_valid_hash_passes():
    verdict = make_verdict()
    verdict.integrity_hash = compute_integrity_hash(verdict)

    assert verify_integrity_hash(verdict) is True


def test_missing_hash_fails():
    verdict = make_verdict()

    assert verify_integrity_hash(verdict) is False


def test_confidence_tampering_is_detected():
    verdict = make_verdict()
    verdict.integrity_hash = compute_integrity_hash(verdict)

    verdict.confidence = 0.50

    assert verify_integrity_hash(verdict) is False


def test_action_id_tampering_is_detected():
    verdict = make_verdict()
    verdict.integrity_hash = compute_integrity_hash(verdict)

    verdict.action_id = "act-9999"

    assert verify_integrity_hash(verdict) is False


def test_causal_chain_tampering_is_detected():
    verdict = make_verdict()
    verdict.integrity_hash = compute_integrity_hash(verdict)

    verdict.causal_chain.append("Tampered event")

    assert verify_integrity_hash(verdict) is False


def test_identical_verdicts_produce_same_hash():
    first = make_verdict()
    second = make_verdict()

    assert compute_integrity_hash(first) == compute_integrity_hash(second)


def test_published_verdict_tampering_is_detected():
    verdict = make_verdict()
    original_hash = compute_integrity_hash(verdict)
    verdict.integrity_hash = original_hash

    verdict.rule_id = "DET-TAMPERED"

    assert verify_integrity_hash(verdict) is False


def test_integrity_hash_is_sha256():
    verdict = make_verdict()

    integrity_hash = compute_integrity_hash(verdict)

    assert len(integrity_hash) == 64
    assert all(
        character in "0123456789abcdef"
        for character in integrity_hash
    )

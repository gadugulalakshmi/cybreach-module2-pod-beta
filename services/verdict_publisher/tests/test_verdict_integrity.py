from vp_app.main import (
    build_event,
    compute_content_hash,
    verify_content_hash,
)
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
        regulatory_control_refs=["ISO27001-A.5.15"],
        causal_chain=[
            "Evidence event received: act-0001",
            "Rule considered: DET-001",
            "Confidence computed: 0.95",
        ],
    )


def test_valid_hash_passes():
    verdict = make_verdict()
    verdict.content_hash = compute_content_hash(verdict)

    assert verify_content_hash(verdict) is True


def test_missing_hash_fails():
    verdict = make_verdict()

    assert verify_content_hash(verdict) is False


def test_confidence_tampering_is_detected():
    verdict = make_verdict()
    verdict.content_hash = compute_content_hash(verdict)

    verdict.confidence = 0.50

    assert verify_content_hash(verdict) is False


def test_action_id_tampering_is_detected():
    verdict = make_verdict()
    verdict.content_hash = compute_content_hash(verdict)

    verdict.action_id = "act-9999"

    assert verify_content_hash(verdict) is False


def test_causal_chain_tampering_is_detected():
    verdict = make_verdict()
    verdict.content_hash = compute_content_hash(verdict)

    verdict.causal_chain.append("Tampered event")

    assert verify_content_hash(verdict) is False


def test_regulatory_control_refs_tampering_is_detected():
    """B3: `regulatory_control_refs` is a v2.0 contract field, so it is covered."""

    verdict = make_verdict()
    verdict.content_hash = compute_content_hash(verdict)

    verdict.regulatory_control_refs = ["ISO27001-A.9.2"]

    assert verify_content_hash(verdict) is False


def test_identical_verdicts_produce_same_hash():
    first = make_verdict()
    second = make_verdict()

    assert compute_content_hash(first) == compute_content_hash(second)


def test_content_hash_is_sha256():
    verdict = make_verdict()

    content_hash = compute_content_hash(verdict)

    assert len(content_hash) == 64
    assert all(
        character in "0123456789abcdef"
        for character in content_hash
    )


def test_hash_covers_exactly_the_contract_fields():
    """B2: Beta's digest must be derivable by Delta's serializer.

    Coverage is the plan's eight v2.0 fields. `rule_id` and `technique_ref`
    are Beta-local context: they are not in the contract, they are not
    published, and including them made the digest differ from Delta's for the
    same event. This asserts the contract fields are the ones that count.
    """
    verdict = make_verdict()
    event = build_event(verdict)

    assert set(event) == {
        "action_id",
        "verdict",
        "confidence",
        "causal_chain",
        "mttd_seconds",
        "matched_evidence_ref",
        "regulatory_control_refs",
        "content_hash",
    }

    # Beta-local context is accepted on input but absent from the event.
    assert "rule_id" not in event
    assert "technique_ref" not in event


def test_tampering_with_beta_local_context_does_not_change_the_event():
    """`rule_id` is not published, so changing it cannot change the payload."""

    verdict = make_verdict()
    before = build_event(verdict)

    verdict.rule_id = "DET-TAMPERED"
    verdict.technique_ref = "T0000"

    assert build_event(verdict) == before

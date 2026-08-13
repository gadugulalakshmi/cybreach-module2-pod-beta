import pytest

from services.validation_engine.ve_app.models import Verdict
from services.validation_engine.ve_app.verdict_aggregation import (
    aggregate_verdicts,
)


def make_verdict(
    action_id="A001",
    verdict="Detected",
    confidence=0.8,
    mttd_seconds=None,
    matched_evidence_ref=None,
    causal_chain=None,
    rule_id="R001",
    technique_ref="T1059",
):
    return Verdict(
        action_id=action_id,
        verdict=verdict,
        confidence=confidence,
        mttd_seconds=mttd_seconds,
        matched_evidence_ref=matched_evidence_ref,
        causal_chain=causal_chain or [],
        rule_id=rule_id,
        technique_ref=technique_ref,
    )


def test_aggregate_selects_highest_priority_verdict():
    results = [
        make_verdict(verdict="Missed", confidence=0.2, rule_id="R001"),
        make_verdict(verdict="Partial", confidence=0.5, rule_id="R002"),
        make_verdict(
            verdict="Detected",
            confidence=0.9,
            matched_evidence_ref="EV001",
            rule_id="R003",
        ),
    ]

    result = aggregate_verdicts(results)

    assert result.action_id == "A001"
    assert result.verdict == "Detected"
    assert result.confidence == 0.9
    assert result.matched_evidence_ref == "EV001"


def test_aggregate_uses_highest_confidence_when_priority_is_same():
    results = [
        make_verdict(verdict="Detected", confidence=0.75, rule_id="R001"),
        make_verdict(verdict="Detected", confidence=0.95, rule_id="R002"),
    ]

    result = aggregate_verdicts(results)

    assert result.verdict == "Detected"
    assert result.confidence == 0.95


def test_aggregate_uses_fastest_available_mttd():
    results = [
        make_verdict(verdict="Detected", confidence=0.8, mttd_seconds=30),
        make_verdict(verdict="Detected", confidence=0.9, mttd_seconds=12),
        make_verdict(verdict="Detected", confidence=0.85),
    ]

    result = aggregate_verdicts(results)

    assert result.mttd_seconds == 12


def test_aggregate_merges_unique_causal_chain():
    results = [
        make_verdict(
            causal_chain=["step-1", "step-2"],
            rule_id="R001",
        ),
        make_verdict(
            causal_chain=["step-2", "step-3"],
            rule_id="R002",
        ),
    ]

    result = aggregate_verdicts(results)

    assert result.causal_chain == ["step-1", "step-2", "step-3"]


def test_aggregate_rejects_empty_results():
    with pytest.raises(ValueError, match="At least one verdict"):
        aggregate_verdicts([])


def test_aggregate_rejects_different_action_ids():
    results = [
        make_verdict(action_id="A001"),
        make_verdict(action_id="A002"),
    ]

    with pytest.raises(ValueError, match="same action_id"):
        aggregate_verdicts(results)
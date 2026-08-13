from services.validation_engine.ve_app.models import Verdict
from services.validation_engine.ve_app.validation_diff import (
    diff_validation_results,
)


def make_verdict(
    action_id="A001",
    verdict="Detected",
    confidence=0.9,
):
    return Verdict(
        action_id=action_id,
        verdict=verdict,
        confidence=confidence,
        rule_id="R001",
        technique_ref="T1059",
    )


def test_detects_verdict_change():
    old_results = [
        make_verdict(
            action_id="A001",
            verdict="Missed",
            confidence=0.2,
        )
    ]

    new_results = [
        make_verdict(
            action_id="A001",
            verdict="Detected",
            confidence=0.9,
        )
    ]

    differences = diff_validation_results(
        old_results,
        new_results,
    )

    assert len(differences) == 1
    assert differences[0]["action_id"] == "A001"
    assert differences[0]["old_verdict"] == "Missed"
    assert differences[0]["new_verdict"] == "Detected"
    assert differences[0]["old_confidence"] == 0.2
    assert differences[0]["new_confidence"] == 0.9


def test_ignores_unchanged_verdicts():
    old_results = [
        make_verdict(
            action_id="A001",
            verdict="Detected",
            confidence=0.9,
        )
    ]

    new_results = [
        make_verdict(
            action_id="A001",
            verdict="Detected",
            confidence=0.95,
        )
    ]

    differences = diff_validation_results(
        old_results,
        new_results,
    )

    assert differences == []


def test_detects_multiple_changed_results():
    old_results = [
        make_verdict(
            action_id="A001",
            verdict="Missed",
            confidence=0.2,
        ),
        make_verdict(
            action_id="A002",
            verdict="Partial",
            confidence=0.5,
        ),
    ]

    new_results = [
        make_verdict(
            action_id="A001",
            verdict="Detected",
            confidence=0.9,
        ),
        make_verdict(
            action_id="A002",
            verdict="Detected",
            confidence=0.8,
        ),
    ]

    differences = diff_validation_results(
        old_results,
        new_results,
    )

    assert len(differences) == 2
    assert differences[0]["action_id"] == "A001"
    assert differences[1]["action_id"] == "A002"


def test_detects_new_validation_result():
    old_results = []

    new_results = [
        make_verdict(
            action_id="A001",
            verdict="Detected",
            confidence=0.9,
        )
    ]

    differences = diff_validation_results(
        old_results,
        new_results,
    )

    assert len(differences) == 1
    assert differences[0]["old_verdict"] is None
    assert differences[0]["new_verdict"] == "Detected"
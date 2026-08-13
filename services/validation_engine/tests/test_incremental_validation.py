from services.validation_engine.ve_app.main import DetectionRule
from services.validation_engine.ve_app.models import EvidenceEvent
from services.validation_engine.ve_app.incremental_validation import (
    get_affected_evidence,
    incremental_validate,
)


def make_evidence(
    action_id="A001",
    technique_ref="T1059",
    target_asset_ref="host-server-01",
):
    return EvidenceEvent(
        action_id=action_id,
        correlation_key="C001",
        technique_ref=technique_ref,
        target_asset_ref=target_asset_ref,
        expected_observable="powershell command execution",
        timestamp="2026-01-01T10:00:00Z",
    )


def make_rule(
    rule_id="R001",
    technique_ref="T1059",
    asset_class=None,
):
    return DetectionRule(
        rule_id=rule_id,
        technique_ref=technique_ref,
        asset_class=asset_class,
        keywords=["powershell"],
    )


def test_get_affected_evidence_matches_changed_rule():
    evidence = [
        make_evidence(action_id="A001", technique_ref="T1059"),
        make_evidence(action_id="A002", technique_ref="T1486"),
    ]

    changed_rules = [
        make_rule(rule_id="R001", technique_ref="T1059"),
    ]

    affected = get_affected_evidence(
        evidence,
        changed_rules,
    )

    assert [item.action_id for item in affected] == ["A001"]


def test_get_affected_evidence_respects_asset_class():
    evidence = [
        make_evidence(
            action_id="A001",
            technique_ref="T1059",
            target_asset_ref="host-server-01",
        ),
        make_evidence(
            action_id="A002",
            technique_ref="T1059",
            target_asset_ref="cloud-account-01",
        ),
    ]

    changed_rules = [
        make_rule(
            rule_id="R001",
            technique_ref="T1059",
            asset_class="host",
        ),
    ]

    affected = get_affected_evidence(
        evidence,
        changed_rules,
    )

    assert [item.action_id for item in affected] == ["A001"]


def test_incremental_validation_returns_only_affected_results():
    evidence = [
        make_evidence(action_id="A001", technique_ref="T1059"),
        make_evidence(action_id="A002", technique_ref="T1486"),
    ]

    rules = [
        make_rule(rule_id="R001", technique_ref="T1059"),
        make_rule(rule_id="R002", technique_ref="T1486"),
    ]

    results = incremental_validate(
        evidence_events=evidence,
        all_rules=rules,
        changed_rule_ids={"R001"},
    )

    assert len(results) == 1
    assert results[0].action_id == "A001"


def test_incremental_validation_returns_empty_for_unknown_rule():
    evidence = [
        make_evidence(action_id="A001"),
    ]

    rules = [
        make_rule(rule_id="R001"),
    ]

    results = incremental_validate(
        evidence_events=evidence,
        all_rules=rules,
        changed_rule_ids={"UNKNOWN"},
    )

    assert results == []
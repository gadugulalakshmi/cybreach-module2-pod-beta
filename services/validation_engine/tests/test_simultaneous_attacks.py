from ve_app.connectors import MockConnector
from ve_app.main import DetectionRule
from ve_app.models import EvidenceEvent
from ve_app.rule_execution import execute_rules_parallel


def test_simultaneous_attacks_are_validated_independently():
    evidence_events = [
        EvidenceEvent(
            action_id="attack-001",
            correlation_key="campaign-001",
            technique_ref="T1486",
            target_asset_ref="host-01",
            expected_observable="vssadmin.exe invoked with cipher /e",
            timestamp="2026-06-17T09:12:00Z",
        ),
        EvidenceEvent(
            action_id="attack-002",
            correlation_key="campaign-002",
            technique_ref="T1059",
            target_asset_ref="host-02",
            expected_observable="powershell.exe encoded command",
            timestamp="2026-06-17T09:12:00Z",
        ),
    ]

    rules = [
        DetectionRule(
            rule_id="DET-001",
            technique_ref="T1486",
            query_str="DET-001",
        ),
        DetectionRule(
            rule_id="DET-002",
            technique_ref="T1059",
            query_str="DET-002",
        ),
    ]

    connector = MockConnector(
        config={
            "seeded_results": {
                "DET-001": [
                    {
                        "observable": "vssadmin.exe invoked with cipher /e",
                        "timestamp": "2026-06-17T09:12:00Z",
                    }
                ],
                "DET-002": [
                    {
                        "observable": "powershell.exe encoded command",
                        "timestamp": "2026-06-17T09:12:00Z",
                    }
                ],
            }
        }
    )

    results = []

    for evidence in evidence_events:
        results.extend(
            execute_rules_parallel(
                evidence,
                rules,
                [connector],
            )
        )

    assert len(results) == 4

    attack_001_results = [
        result for result in results
        if result.action_id == "attack-001"
    ]

    attack_002_results = [
        result for result in results
        if result.action_id == "attack-002"
    ]

    assert len(attack_001_results) == 2
    assert len(attack_002_results) == 2

    assert any(
        result.rule_id == "DET-001" and result.matched
        for result in attack_001_results
    )

    assert any(
        result.rule_id == "DET-002" and result.matched
        for result in attack_002_results
    )
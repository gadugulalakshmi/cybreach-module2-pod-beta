from ve_app.connectors import MockConnector
from ve_app.main import DetectionRule
from ve_app.models import EvidenceEvent
from ve_app.rule_execution import execute_rules_parallel


def test_multi_connector_validation_collects_results_from_all_connectors():
    evidence = EvidenceEvent(
        action_id="multi-connector-001",
        correlation_key="campaign-multi-001",
        technique_ref="T1486",
        target_asset_ref="host-fileserver-01",
        expected_observable="vssadmin.exe invoked with cipher /e",
        timestamp="2026-06-17T09:12:00Z",
    )

    rules = [
        DetectionRule(
            rule_id="DET-001",
            technique_ref="T1486",
            query_str="DET-001",
        )
    ]

    connector_1 = MockConnector(
        config={
            "seeded_results": {
                "DET-001": [
                    {
                        "observable": "vssadmin.exe invoked with cipher /e",
                        "timestamp": "2026-06-17T09:12:00Z",
                    }
                ]
            }
        }
    )

    connector_2 = MockConnector(
        config={
            "seeded_results": {
                "DET-001": [
                    {
                        "observable": "vssadmin.exe invoked",
                        "timestamp": "2026-06-17T09:12:30Z",
                    }
                ]
            }
        }
    )

    connector_3 = MockConnector(
        config={
            "seeded_results": {
                "DET-001": []
            }
        }
    )

    results = execute_rules_parallel(
        evidence,
        rules,
        [connector_1, connector_2, connector_3],
    )

    assert len(results) == 3

    assert results[0].matched is True
    assert results[0].confidence == 1.0

    assert results[1].matched is True
    assert results[1].confidence > 0.0

    assert results[2].no_data is True
    assert results[2].matched is False
    assert results[2].confidence == 0.0


def test_multi_connector_validation_preserves_results_from_each_connector():
    evidence = EvidenceEvent(
        action_id="multi-connector-002",
        correlation_key="campaign-multi-002",
        technique_ref="T1059",
        target_asset_ref="host-workstation-01",
        expected_observable="powershell.exe encoded command",
        timestamp="2026-06-17T09:12:00Z",
    )

    rule = DetectionRule(
        rule_id="DET-002",
        technique_ref="T1059",
        query_str="DET-002",
    )

    connectors = [
        MockConnector(
            config={
                "seeded_results": {
                    "DET-002": [
                        {
                            "observable": "powershell.exe encoded command",
                            "timestamp": "2026-06-17T09:12:00Z",
                        }
                    ]
                }
            }
        ),
        MockConnector(
            config={
                "seeded_results": {
                    "DET-002": [
                        {
                            "observable": "unrelated event",
                            "timestamp": "2026-06-17T09:12:00Z",
                        }
                    ]
                }
            }
        ),
    ]

    results = execute_rules_parallel(
        evidence,
        [rule],
        connectors,
    )

    assert len(results) == 2
    assert results[0].confidence == 1.0
    assert results[0].matched is True
    assert results[1].confidence == 0.0
    assert results[1].matched is False
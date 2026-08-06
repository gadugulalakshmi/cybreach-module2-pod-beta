import time

from ve_app.connectors import MockConnector
from ve_app.main import DetectionRule
from ve_app.models import EvidenceEvent
from ve_app.rule_execution import execute_rules_parallel


class SlowMockConnector(MockConnector):
    def query(self, query_str, time_range):
        time.sleep(0.2)
        return [
            {
                "observable": "vssadmin.exe invoked with cipher /e",
                "timestamp": "2026-06-17T09:12:00Z",
            }
        ]


def test_execute_rules_parallel_runs_connectors_concurrently():
    evidence = EvidenceEvent(
        action_id="act-0001",
        correlation_key="camp-2026-0617-a",
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

    connectors = [
        SlowMockConnector(),
        SlowMockConnector(),
        SlowMockConnector(),
    ]

    start = time.perf_counter()

    results = execute_rules_parallel(
        evidence,
        rules,
        connectors,
    )

    elapsed = time.perf_counter() - start

    assert len(results) == 3
    assert all(result.matched for result in results)
    assert elapsed < 0.5
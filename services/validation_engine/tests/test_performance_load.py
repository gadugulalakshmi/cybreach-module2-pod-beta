import time

from ve_app.main import DetectionRule, validate_evidence
from ve_app.models import EvidenceEvent


def test_validation_engine_handles_1000_events():
    rule = DetectionRule(
        rule_id="DET-001",
        technique_ref="T1486",
        query_str="DET-001",
        keywords=["vssadmin.exe", "cipher /e"],
    )

    events = [
        EvidenceEvent(
            action_id=f"act-{i:04d}",
            correlation_key="camp-2026-0617-a",
            technique_ref="T1486",
            target_asset_ref="host-fileserver-01",
            expected_observable="vssadmin.exe invoked with cipher /e",
            timestamp="2026-06-17T09:12:00Z",
        )
        for i in range(1000)
    ]

    start = time.perf_counter()

    results = [
        validate_evidence(event, [rule])
        for event in events
    ]

    elapsed = time.perf_counter() - start

    assert len(results) == 1000
    assert all(result.verdict == "Detected" for result in results)

    print(f"\nProcessed 1000 events in {elapsed:.4f} seconds")
    print(f"Average time per event: {(elapsed / 1000) * 1000:.4f} ms")
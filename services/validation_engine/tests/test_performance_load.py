import time

from ve_app.main import DetectionRule, validate_evidence, compute_confidence
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

def test_validation_engine_handles_10000_events():
    rule = DetectionRule(
        rule_id="DET-001",
        technique_ref="T1486",
        query_str="DET-001",
        keywords=["vssadmin.exe", "cipher /e"],
    )

    events = [
        EvidenceEvent(
            action_id=f"act-{i:05d}",
            correlation_key="camp-2026-0617-a",
            technique_ref="T1486",
            target_asset_ref="host-fileserver-01",
            expected_observable="vssadmin.exe invoked with cipher /e",
            timestamp="2026-06-17T09:12:00Z",
        )
        for i in range(10000)
    ]

    start = time.perf_counter()

    results = [
        validate_evidence(event, [rule])
        for event in events
    ]

    elapsed = time.perf_counter() - start

    assert len(results) == 10000
    assert all(result.verdict == "Detected" for result in results)

    print(f"\nProcessed 10000 events in {elapsed:.4f} seconds")
    print(f"Average time per event: {(elapsed / 10000) * 1000:.4f} ms")  
def test_end_to_end_latency_10000_events():
    from ve_app.ingestion import run_replay

    rule = DetectionRule(
        rule_id="DET-001",
        technique_ref="T1486",
        query_str="DET-001",
        keywords=["vssadmin.exe", "cipher /e"],
    )

    events = [
        EvidenceEvent(
            action_id=f"act-e2e-{i:05d}",
            correlation_key="camp-2026-0617-a",
            technique_ref="T1486",
            target_asset_ref="host-fileserver-01",
            expected_observable="vssadmin.exe invoked with cipher /e",
            timestamp="2026-06-17T09:12:00Z",
        )
        for i in range(10000)
    ]

    start = time.perf_counter()

    results = run_replay(events, [rule])

    elapsed = time.perf_counter() - start

    assert len(results) == 10000
    assert all(result.verdict == "Detected" for result in results)

    print(f"\nEnd-to-end processing time for 10000 events: {elapsed:.4f} seconds")
    print(f"Average end-to-end latency per event: {(elapsed / 10000) * 1000:.4f} ms")
def test_profile_confidence_score_computation():
    rule = DetectionRule(
        rule_id="DET-001",
        technique_ref="T1486",
        query_str="DET-001",
        keywords=["vssadmin.exe", "cipher /e"],
    )

    event = EvidenceEvent(
        action_id="act-profile-00001",
        correlation_key="camp-2026-0617-a",
        technique_ref="T1486",
        target_asset_ref="host-fileserver-01",
        expected_observable="vssadmin.exe invoked with cipher /e",
        timestamp="2026-06-17T09:12:00Z",
    )

    start = time.perf_counter()

    scores = [
        compute_confidence(event, rule)
        for _ in range(10000)
    ]

    elapsed = time.perf_counter() - start

    assert len(scores) == 10000
    assert all(0 <= score <= 1 for score in scores)

    print(f"\nConfidence-score computation for 10000 runs: {elapsed:.4f} seconds")
    print(f"Average confidence computation time: {(elapsed / 10000) * 1000:.4f} ms")  
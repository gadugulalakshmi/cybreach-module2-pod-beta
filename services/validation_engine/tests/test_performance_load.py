import time

from ve_app.ingestion import run_replay
from ve_app.main import DetectionRule, validate_evidence
from ve_app.models import EvidenceEvent


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

    verdicts = run_replay(events, [rule])

    elapsed = time.perf_counter() - start

    assert len(verdicts) == 10000
    assert all(verdict.verdict == "Detected" for verdict in verdicts)

    print(f"\nE2E processed 10000 events in {elapsed:.4f} seconds")
    print(
        f"E2E average latency per event: "
        f"{(elapsed / 10000) * 1000:.4f} ms"
    )


def test_confidence_profiling_10000_calculations():
    from ve_app.observable_matching import match_observable

    expected = "vssadmin.exe invoked with cipher /e"
    actual = "vssadmin.exe invoked with cipher /e"

    start = time.perf_counter()

    scores = [
        match_observable(expected, actual)
        for _ in range(10000)
    ]

    elapsed = time.perf_counter() - start

    assert len(scores) == 10000
    assert all(0.0 <= score <= 1.0 for score in scores)
    assert all(score == 1.0 for score in scores)

    print(f"\nComputed 10000 confidence scores in {elapsed:.4f} seconds")
    print(
        f"Average confidence computation time: "
        f"{(elapsed / 10000) * 1000:.4f} ms"
    )

"""
Tests for the evidence event ingestion pipeline and replay harness.
Run from the validation_engine folder with: pytest -v
"""
from ve_app.ingestion import DEFAULT_FIXTURE_PATH, load_evidence_fixtures, replay_stream, run_replay
from ve_app.main import DetectionRule
from ve_app.models import EvidenceEvent


def test_load_evidence_fixtures_reads_all_records():
    """Task 1 + 2: the ingestion pipeline reads every record in the fixture file."""
    events = load_evidence_fixtures()
    assert len(events) == 6
    assert all(isinstance(e, EvidenceEvent) for e in events)


def test_load_evidence_fixtures_default_path_exists():
    assert DEFAULT_FIXTURE_PATH.exists()


def test_replay_stream_yields_events_in_timestamp_order():
    """Task 4 + 5: the mock replay harness simulates Module 1's stream in
    the order the actions actually happened, not file order."""
    events = load_evidence_fixtures()
    # Shuffle input order to prove the stream re-sorts by timestamp
    shuffled = list(reversed(events))
    replayed = list(replay_stream(shuffled))
    timestamps = [e.timestamp for e in replayed]
    assert timestamps == sorted(timestamps)


def test_replay_stream_is_a_generator_not_a_list():
    """Confirms events are yielded one at a time (streamed), matching how
    a real Kafka consumer would deliver them, rather than materialised
    all at once."""
    events = load_evidence_fixtures()
    stream = replay_stream(events)
    first = next(stream)
    assert isinstance(first, EvidenceEvent)


def test_run_replay_feeds_every_event_into_the_validation_engine():
    """Task 3: every event pulled off the stream reaches
    validate_evidence() and produces exactly one verdict."""
    events = load_evidence_fixtures()
    rules = [DetectionRule(rule_id="DET-001", technique_ref="T1486", keywords=["vssadmin.exe", "cipher /e"])]

    verdicts = run_replay(events, rules)

    assert len(verdicts) == len(events)
    action_ids = {v.action_id for v in verdicts}
    assert action_ids == {e.action_id for e in events}


def test_run_replay_produces_detected_for_full_keyword_match():
    events = [e for e in load_evidence_fixtures() if e.action_id == "act-0001"]
    rules = [DetectionRule(rule_id="DET-001", technique_ref="T1486", keywords=["vssadmin.exe", "cipher /e"])]

    verdicts = run_replay(events, rules)

    assert verdicts[0].verdict == "Detected"


def test_run_replay_produces_no_data_when_no_rule_covers_the_technique():
    events = [e for e in load_evidence_fixtures() if e.action_id == "act-0006"]  # T1499, no rule
    rules = [DetectionRule(rule_id="DET-001", technique_ref="T1486")]

    verdicts = run_replay(events, rules)

    assert verdicts[0].verdict == "NoData"


def test_run_replay_on_verdict_callback_fires_once_per_event():
    events = load_evidence_fixtures()
    rules = [DetectionRule(rule_id="DET-001", technique_ref="T1486")]
    seen = []

    run_replay(events, rules, on_verdict=lambda evidence, verdict: seen.append(evidence.action_id))

    assert len(seen) == len(events)
    assert len(seen) == len(set(seen))  # no duplicates

"""
Evidence Event Ingestion Pipeline -- Pod Beta, Week 3 (Person A).

Covers:
    1. Implement evidence event ingestion pipeline
    2. Read frozen evidence fixtures from the local repository
    3. Feed evidence into the Validation Engine
    4. Develop the mock evidence replay harness
    5. Simulate Module 1 evidence event stream

Until Module 1's real evidence event feed exists, this module reads the
frozen JSON fixture committed in tests/fixtures/mock_evidence_events.json
(per the Zero Interdependency build model, Technical Doc Section 2) and
replays it through the Validation Engine one event at a time, in
timestamp order -- exactly the shape a live Kafka consumer of
`cybreach.evidence.v1` will eventually have, so swapping the fixture
loader for a real consumer later should not require changing any of the
replay or validation logic below.
"""
import json
from pathlib import Path
from typing import Callable, Iterator, List, Optional

from ve_app.main import DetectionRule, validate_evidence
from ve_app.models import EvidenceEvent, Verdict

DEFAULT_FIXTURE_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "mock_evidence_events.json"


def load_evidence_fixtures(path: Path = DEFAULT_FIXTURE_PATH) -> List[EvidenceEvent]:
    """
    Task 1 + 2: Ingestion pipeline entry point. Reads the frozen evidence
    fixture file from the local repository and parses every record into
    an EvidenceEvent, raising immediately (via Pydantic) if any record
    does not conform to the contract.
    """
    with open(path) as f:
        raw_events = json.load(f)
    return [EvidenceEvent(**e) for e in raw_events]


def replay_stream(events: List[EvidenceEvent]) -> Iterator[EvidenceEvent]:
    """
    Task 4 + 5: Mock evidence replay harness / Module 1 stream simulator.

    Module 1 publishes evidence events onto the `cybreach.evidence.v1`
    Kafka topic as a campaign runs, so consumers see them arrive one at a
    time, in the order the simulated actions occurred. This generator
    reproduces that shape locally: it yields events strictly in
    timestamp order, one at a time, so any code written against this
    stream (like run_replay below) will work unchanged once it is pointed
    at a real Kafka consumer instead of a fixture file.
    """
    for event in sorted(events, key=lambda e: e.timestamp):
        yield event


def run_replay(
    events: List[EvidenceEvent],
    rules: List[DetectionRule],
    on_verdict: Optional[Callable[[EvidenceEvent, Verdict], None]] = None,
) -> List[Verdict]:
    """
    Task 3: Feed evidence into the Validation Engine.

    Pulls each evidence event off the replay stream (Task 4/5) and feeds
    it directly into the Validation Engine's core validate_evidence()
    function (Task 3), exactly as the real engine will do when it
    consumes live evidence events. An optional on_verdict callback lets
    callers (e.g. a CLI demo, or later the Verdict Publisher) react to
    each verdict as it is produced rather than waiting for the whole
    batch.
    """
    results: List[Verdict] = []
    for evidence in replay_stream(events):
        verdict = validate_evidence(evidence, rules)
        results.append(verdict)
        if on_verdict:
            on_verdict(evidence, verdict)
    return results


if __name__ == "__main__":
    # Small end-to-end demo: load the fixtures, replay them through the
    # engine against a couple of sample rules (one asset-class-scoped,
    # one wildcard), and print each verdict as it is produced.
    # Run with:  python -m ve_app.ingestion
    demo_rules = [
        DetectionRule(rule_id="DET-001", technique_ref="T1486", asset_class="host", keywords=["vssadmin.exe", "cipher /e"]),
        DetectionRule(rule_id="DET-005", technique_ref="T1098", keywords=["attachuserpolicy"]),
    ]
    fixture_events = load_evidence_fixtures()

    def _print_verdict(evidence: EvidenceEvent, verdict: Verdict) -> None:
        print(f"{evidence.action_id} ({evidence.technique_ref}, {evidence.target_asset_ref}) -> {verdict.verdict} (confidence={verdict.confidence})")

    run_replay(fixture_events, demo_rules, on_verdict=_print_verdict)

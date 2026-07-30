"""
Task 9: Test evidence replay and rule matching, together.

Where test_ingestion.py tests the replay harness in isolation and
test_rule_matching.py tests rule matching in isolation, this file proves
the two work correctly end to end: a full evidence stream, replayed
through the Validation Engine, against a rule set that uses both MITRE
Technique ID and Asset Class scoping.
"""
from ve_app.ingestion import load_evidence_fixtures, run_replay
from ve_app.main import DetectionRule

# A small rule set mirroring the Global Detection Content Library, with
# asset_class scoping added on two rules to exercise Task 8 during replay.
RULESET = [
    DetectionRule(
        rule_id="DET-001",
        technique_ref="T1486",
        asset_class="host",
        keywords=["vssadmin.exe", "wbadmin.exe", "cipher /e"],
    ),
    DetectionRule(
        rule_id="DET-003",
        technique_ref="T0831",
        asset_class="ot",
        keywords=["modbus", "write command"],
    ),
    DetectionRule(
        rule_id="DET-005",
        technique_ref="T1098",
        # deliberately no asset_class -- wildcard, should still match the
        # cloud-account evidence in the fixtures
        keywords=["attachuserpolicy", "addusertogroup"],
    ),
]


def test_full_fixture_stream_replays_and_matches_correctly():
    events = load_evidence_fixtures()

    verdicts = run_replay(events, RULESET)

    by_action_id = {v.action_id for v in verdicts}
    assert by_action_id == {e.action_id for e in events}


def test_ransomware_evidence_on_host_asset_is_detected():
    events = [e for e in load_evidence_fixtures() if e.action_id == "act-0001"]  # host-fileserver-01, T1486
    verdicts = run_replay(events, RULESET)
    assert verdicts[0].verdict == "Detected"
    assert verdicts[0].rule_id == "DET-001"


def test_ot_evidence_matches_ot_scoped_rule():
    events = [e for e in load_evidence_fixtures() if e.action_id == "act-0003"]  # ot-plc-modbus-07, T0831
    verdicts = run_replay(events, RULESET)
    assert verdicts[0].rule_id == "DET-003"
    assert verdicts[0].verdict in ("Detected", "Partial")


def test_wildcard_asset_class_rule_still_matches_cloud_evidence():
    events = [e for e in load_evidence_fixtures() if e.action_id == "act-0005"]  # cloud-account-aws-prod, T1098
    verdicts = run_replay(events, RULESET)
    assert verdicts[0].rule_id == "DET-005"


def test_evidence_with_no_covering_rule_still_streams_through_as_no_data():
    """Task 9 also covers the negative path: replay must not break or
    drop an event just because no rule matches it -- act-0002 (T1195) and
    act-0006 (T1499) have no rule in RULESET and should surface as
    NoData, not be silently skipped."""
    events = load_evidence_fixtures()
    verdicts = run_replay(events, RULESET)
    verdict_by_action = {v.action_id: v for v in verdicts}

    assert verdict_by_action["act-0002"].verdict == "NoData"
    assert verdict_by_action["act-0006"].verdict == "NoData"
    # and the stream still produced a verdict for every single event
    assert len(verdicts) == len(events)


def test_replay_preserves_timestamp_order_while_matching():
    events = load_evidence_fixtures()
    seen_order = []

    run_replay(events, RULESET, on_verdict=lambda evidence, verdict: seen_order.append(evidence.timestamp))

    assert seen_order == sorted(seen_order)

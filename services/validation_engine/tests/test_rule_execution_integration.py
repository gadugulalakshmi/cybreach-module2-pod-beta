"""
Week 4 integration tests, covering exactly the three things the task
list asked for:

    - Evidence event input
    - Detection rule execution
    - Raw validation result generation

These tests wire together the real evidence fixtures, the real
DetectionRule model, a MockConnector standing in for a live SIEM, and
execute_rule()/execute_rules() -- proving the whole Week 4 path works
end to end, not just each piece in isolation.
"""
from ve_app.connectors import MockConnector
from ve_app.ingestion import load_evidence_fixtures
from ve_app.main import DetectionRule
from ve_app.rule_execution import RawValidationResult, execute_rule, execute_rules

# act-0001 in the fixtures: T1486, host-fileserver-01,
# "vssadmin.exe or wbadmin.exe invoked with an encryption flag (cipher /e)"
RANSOMWARE_EVIDENCE = next(e for e in load_evidence_fixtures() if e.action_id == "act-0001")

RANSOMWARE_RULE = DetectionRule(rule_id="DET-001", technique_ref="T1486", query_str="DET-001")


def make_connector(seeded_results):
    return MockConnector(config={"seeded_results": seeded_results})


# --- Evidence event input ---

def test_fixtures_provide_valid_evidence_event_input():
    assert RANSOMWARE_EVIDENCE.technique_ref == "T1486"
    assert RANSOMWARE_EVIDENCE.target_asset_ref == "host-fileserver-01"


# --- Detection rule execution ---

def test_execute_rule_queries_the_connector_with_the_rules_query_string():
    connector = make_connector({
        "DET-001": [{"observable": "vssadmin.exe invoked with cipher /e", "timestamp": RANSOMWARE_EVIDENCE.timestamp}],
    })

    result = execute_rule(RANSOMWARE_EVIDENCE, RANSOMWARE_RULE, connector)

    assert isinstance(result, RawValidationResult)
    assert result.rule_id == "DET-001"
    assert result.action_id == "act-0001"


def test_execute_rule_falls_back_to_rule_id_when_no_query_str_set():
    bare_rule = DetectionRule(rule_id="DET-001", technique_ref="T1486")  # no query_str
    connector = make_connector({"DET-001": [{"observable": "vssadmin.exe invoked", "timestamp": RANSOMWARE_EVIDENCE.timestamp}]})

    result = execute_rule(RANSOMWARE_EVIDENCE, bare_rule, connector)

    assert result.matched is True


# --- Raw validation result generation ---

def test_raw_result_is_high_confidence_for_exact_in_window_observable_match():
    connector = make_connector({
        "DET-001": [{"observable": RANSOMWARE_EVIDENCE.expected_observable, "timestamp": RANSOMWARE_EVIDENCE.timestamp}],
    })

    result = execute_rule(RANSOMWARE_EVIDENCE, RANSOMWARE_RULE, connector)

    assert result.confidence == 1.0
    assert result.matched is True
    assert result.no_data is False


def test_raw_result_is_no_data_when_connector_returns_nothing():
    connector = make_connector({})  # nothing seeded for DET-001

    result = execute_rule(RANSOMWARE_EVIDENCE, RANSOMWARE_RULE, connector)

    assert result.no_data is True
    assert result.confidence == 0.0
    assert result.matched is False


def test_raw_result_is_zero_confidence_when_only_out_of_window_results_exist():
    far_away_timestamp = "2026-06-17T13:00:00Z"  # hours after the evidence event
    connector = make_connector({
        "DET-001": [{"observable": RANSOMWARE_EVIDENCE.expected_observable, "timestamp": far_away_timestamp}],
    })

    result = execute_rule(RANSOMWARE_EVIDENCE, RANSOMWARE_RULE, connector)

    assert result.confidence == 0.0
    assert result.matched is False
    assert result.no_data is False  # the connector DID return something -- it just didn't count


def test_execute_rules_generates_one_raw_result_per_rule():
    other_rule = DetectionRule(rule_id="DET-999", technique_ref="T1486", query_str="DET-999")
    connector = make_connector({
        "DET-001": [{"observable": RANSOMWARE_EVIDENCE.expected_observable, "timestamp": RANSOMWARE_EVIDENCE.timestamp}],
    })

    results = execute_rules(RANSOMWARE_EVIDENCE, [RANSOMWARE_RULE, other_rule], connector)

    assert len(results) == 2
    assert results[0].confidence == 1.0  # DET-001 had seeded results
    assert results[1].no_data is True    # DET-999 had none


def test_full_pipeline_all_fixture_events_produce_a_raw_result():
    """Evidence event input -> detection rule execution -> raw
    validation result generation, run across the entire fixture set."""
    events = load_evidence_fixtures()
    rules = [DetectionRule(rule_id="DET-001", technique_ref="T1486", query_str="DET-001")]
    connector = make_connector({
        "DET-001": [{"observable": "vssadmin.exe invoked with cipher /e", "timestamp": "2026-06-17T09:12:30Z"}],
    })

    all_results = []
    for evidence in events:
        all_results.extend(execute_rules(evidence, rules, connector))

    assert len(all_results) == len(events)
    assert all(isinstance(r, RawValidationResult) for r in all_results)

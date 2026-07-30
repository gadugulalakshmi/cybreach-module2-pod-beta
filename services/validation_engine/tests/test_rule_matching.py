"""
Tests for rule matching logic: MITRE Technique ID matching (Task 7) and
Asset Class matching (Task 8), combined via find_matching_rules (Task 6).
"""
from ve_app.main import DetectionRule
from ve_app.models import EvidenceEvent
from ve_app.rule_matching import find_matching_rules, infer_asset_class, matches_asset_class, matches_technique

EVIDENCE_HOST = EvidenceEvent(
    action_id="act-0001",
    correlation_key="camp-1",
    technique_ref="T1486",
    target_asset_ref="host-fileserver-01",
    expected_observable="vssadmin.exe invoked with cipher /e",
    timestamp="2026-06-17T09:12:00Z",
)

EVIDENCE_CLOUD = EvidenceEvent(
    action_id="act-0005",
    correlation_key="camp-1",
    technique_ref="T1098",
    target_asset_ref="cloud-account-aws-prod",
    expected_observable="AttachUserPolicy by a non-admin principal",
    timestamp="2026-06-17T11:00:00Z",
)


# --- infer_asset_class (Task 8 helper) ---

def test_infer_asset_class_host():
    assert infer_asset_class("host-fileserver-01") == "host"


def test_infer_asset_class_cloud():
    assert infer_asset_class("cloud-account-aws-prod") == "cloud"


def test_infer_asset_class_ot():
    assert infer_asset_class("ot-plc-modbus-07") == "ot"


def test_infer_asset_class_identity():
    assert infer_asset_class("identity-tenant-azure-eu") == "identity"


# --- matches_technique (Task 7) ---

def test_matches_technique_true_on_exact_match():
    assert matches_technique("T1486", EVIDENCE_HOST) is True


def test_matches_technique_false_on_different_technique():
    assert matches_technique("T1098", EVIDENCE_HOST) is False


# --- matches_asset_class (Task 8) ---

def test_matches_asset_class_wildcard_when_rule_has_no_asset_class():
    assert matches_asset_class(None, EVIDENCE_HOST) is True
    assert matches_asset_class(None, EVIDENCE_CLOUD) is True


def test_matches_asset_class_true_when_classes_match():
    assert matches_asset_class("host", EVIDENCE_HOST) is True


def test_matches_asset_class_false_when_classes_differ():
    assert matches_asset_class("cloud", EVIDENCE_HOST) is False


def test_matches_asset_class_case_insensitive():
    assert matches_asset_class("HOST", EVIDENCE_HOST) is True


# --- find_matching_rules (Task 6: combined logic) ---

def test_find_matching_rules_wildcard_rule_matches_any_asset():
    rule = DetectionRule(rule_id="DET-001", technique_ref="T1486")  # no asset_class set
    assert find_matching_rules(EVIDENCE_HOST, [rule]) == [rule]


def test_find_matching_rules_scoped_rule_matches_correct_asset_class():
    rule = DetectionRule(rule_id="DET-001", technique_ref="T1486", asset_class="host")
    assert find_matching_rules(EVIDENCE_HOST, [rule]) == [rule]


def test_find_matching_rules_scoped_rule_excludes_wrong_asset_class():
    """A rule scoped to 'cloud' must not fire on a 'host' asset, even
    though the technique matches -- this is the case Task 8 exists for."""
    rule = DetectionRule(rule_id="DET-CLOUD-ONLY", technique_ref="T1486", asset_class="cloud")
    assert find_matching_rules(EVIDENCE_HOST, [rule]) == []


def test_find_matching_rules_rejects_wrong_technique_even_with_matching_asset_class():
    rule = DetectionRule(rule_id="DET-WRONG-TECH", technique_ref="T1098", asset_class="host")
    assert find_matching_rules(EVIDENCE_HOST, [rule]) == []


def test_find_matching_rules_returns_multiple_when_several_rules_apply():
    rule_a = DetectionRule(rule_id="DET-A", technique_ref="T1486")
    rule_b = DetectionRule(rule_id="DET-B", technique_ref="T1486", asset_class="host")
    rule_c = DetectionRule(rule_id="DET-C", technique_ref="T1098")  # different technique
    matches = find_matching_rules(EVIDENCE_HOST, [rule_a, rule_b, rule_c])
    assert matches == [rule_a, rule_b]


# --- validate_evidence: asset-class-aware end-to-end behaviour ---

def test_validate_evidence_prefers_best_confidence_among_matching_rules():
    from ve_app.main import validate_evidence

    weak_rule = DetectionRule(rule_id="DET-WEAK", technique_ref="T1486", keywords=["unrelated-term"])
    strong_rule = DetectionRule(rule_id="DET-STRONG", technique_ref="T1486", keywords=["vssadmin.exe", "cipher /e"])

    verdict = validate_evidence(EVIDENCE_HOST, [weak_rule, strong_rule])

    assert verdict.rule_id == "DET-STRONG"
    assert verdict.verdict == "Detected"


def test_validate_evidence_ignores_asset_scoped_rule_for_wrong_asset():
    from ve_app.main import validate_evidence

    cloud_only_rule = DetectionRule(rule_id="DET-CLOUD-ONLY", technique_ref="T1486", asset_class="cloud")

    verdict = validate_evidence(EVIDENCE_HOST, [cloud_only_rule])

    assert verdict.verdict == "NoData"
    assert verdict.rule_id == "NONE"

"""
Pytest suite for the Validation Engine's /validate endpoint.
"""
from fastapi.testclient import TestClient

from ve_app.main import app

client = TestClient(app)

EVIDENCE = {
    "action_id": "act-0001",
    "correlation_key": "camp-2026-0617-a",
    "technique_ref": "T1486",
    "target_asset_ref": "host-fileserver-01",
    "expected_observable": "vssadmin.exe invoked with cipher /e encryption flag",
    "timestamp": "2026-06-17T09:12:00Z",
}


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200


def test_validate_detected_with_flat_technique_match_no_keywords():
    resp = client.post("/validate", json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}]})
    body = resp.json()
    assert body["verdict"] == "Detected"
    assert body["confidence"] == 0.9


def test_validate_detected_with_full_keyword_match():
    resp = client.post("/validate", json={
        "evidence": EVIDENCE,
        "rules": [{"rule_id": "DET-001", "technique_ref": "T1486", "keywords": ["vssadmin.exe", "cipher /e"]}],
    })
    body = resp.json()
    assert body["verdict"] == "Detected"
    assert body["confidence"] == 1.0


def test_validate_partial_with_some_keyword_match():
    resp = client.post("/validate", json={
        "evidence": EVIDENCE,
        "rules": [{"rule_id": "DET-001", "technique_ref": "T1486", "keywords": ["vssadmin.exe", "wbadmin.exe", "--encrypt", "cipher /e"]}],
    })
    body = resp.json()
    assert body["confidence"] == 0.6
    assert body["verdict"] == "Partial"


def test_validate_missed_with_no_keyword_match():
    resp = client.post("/validate", json={
        "evidence": EVIDENCE,
        "rules": [{"rule_id": "DET-001", "technique_ref": "T1486", "keywords": ["totally-unrelated-string"]}],
    })
    body = resp.json()
    assert body["confidence"] == 0.2
    assert body["verdict"] == "Missed"


def test_validate_no_data_when_no_rule_matches_technique():
    resp = client.post("/validate", json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-099", "technique_ref": "T1499"}]})
    assert resp.json()["verdict"] == "NoData"


def test_validate_no_data_when_no_rules_at_all():
    resp = client.post("/validate", json={"evidence": EVIDENCE, "rules": []})
    assert resp.json()["verdict"] == "NoData"
def test_validate_batch_processes_multiple_evidence_events():
    evidence_2 = {
        **EVIDENCE,
        "action_id": "act-0002",
    }

    evidence_3 = {
        **EVIDENCE,
        "action_id": "act-0003",
    }

    resp = client.post(
        "/validate/batch",
        json={
            "evidence": [EVIDENCE, evidence_2, evidence_3],
            "rules": [
                {
                    "rule_id": "DET-001",
                    "technique_ref": "T1486",
                }
            ],
        },
    )

    assert resp.status_code == 200

    body = resp.json()

    assert len(body) == 3
    assert body[0]["action_id"] == "act-0001"
    assert body[1]["action_id"] == "act-0002"
    assert body[2]["action_id"] == "act-0003"

    assert all(result["verdict"] == "Detected" for result in body)
def test_validate_evidence_integrates_with_compliance_verification():
    from ve_app.main import validate_evidence
    from ve_app.control_mapping import get_compliance_status

    from ve_app.main import DetectionRule
    from ve_app.models import EvidenceEvent

    evidence = EvidenceEvent(**EVIDENCE)
    rules = [
        DetectionRule(
            rule_id="DET-001",
            technique_ref="T1486",
        )
    ]

    verdict = validate_evidence(evidence, rules)

    assert verdict.verdict == "Detected"
    assert verdict.matched_evidence_ref == "act-0001"

    compliance_status = get_compliance_status(
        verdict,
        [evidence.action_id],
    )

    assert compliance_status == "Met"

from fastapi.testclient import TestClient

from ve_app.main import DetectionRule, validate_evidence
from ve_app.models import EvidenceEvent
from oc_app.main import app as classifier_app
from vp_app.main import app as publisher_app


classifier_client = TestClient(classifier_app)
publisher_client = TestClient(publisher_app)


def test_cross_pod_pipeline_detected():
    # 1. Validation Engine
    evidence = EvidenceEvent(
        action_id="act-pipeline-001",
        correlation_key="campaign-001",
        technique_ref="T1486",
        target_asset_ref="host-fileserver-01",
        expected_observable="vssadmin.exe invoked with cipher /e",
        timestamp="2026-09-01T10:00:00Z",
    )

    rule = DetectionRule(
        rule_id="DET-001",
        technique_ref="T1486",
        asset_class="host",
        keywords=["vssadmin.exe", "cipher /e"],
    )

    validation_result = validate_evidence(evidence, [rule])

    assert validation_result.verdict == "Detected"
    assert validation_result.confidence >= 0.7

    # 2. Outcome Classifier
    classifier_payload = {
        "action_id": validation_result.action_id,
        "confidence": validation_result.confidence,
        "rule_id": validation_result.rule_id,
        "no_data": validation_result.verdict == "NoData",
        "matched_evidence_ref": validation_result.matched_evidence_ref,
        "mttd_seconds": validation_result.mttd_seconds,
        "evidence_timestamp": evidence.timestamp,
        "alert_timestamp": "2026-09-01T10:00:12Z",
        "match_specificity": "exact",
        "keywords_checked": rule.keywords,
    }

    classifier_response = classifier_client.post(
        "/classify",
        json=classifier_payload,
    )

    assert classifier_response.status_code == 200

    classified = classifier_response.json()

    assert classified["verdict"] == "Detected"
    assert classified["confidence"] >= 0.7
    assert classified["causal_chain"]

    # 3. Verdict Publisher
    publisher_payload = {
        "action_id": classified["action_id"],
        "verdict": classified["verdict"],
        "confidence": classified["confidence"],
        "rule_id": validation_result.rule_id,
        "technique_ref": evidence.technique_ref,
        "mttd_seconds": classified["mttd_seconds"],
        "matched_evidence_ref": validation_result.matched_evidence_ref,
        "causal_chain": [
            step["description"]
            if isinstance(step, dict)
            else str(step)
            for step in classified["causal_chain"]
        ],
    }

    publisher_response = publisher_client.post(
        "/publish",
        json=publisher_payload,
    )

    assert publisher_response.status_code == 200

    published = publisher_response.json()

    assert published["action_id"] == "act-pipeline-001"
    assert published["verdict"] == "Detected"
    assert published["confidence"] >= 0.7

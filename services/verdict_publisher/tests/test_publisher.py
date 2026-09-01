from fastapi.testclient import TestClient

from vp_app.main import app


client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "verdict_publisher",
    }


def test_publish_detected_verdict():
    payload = {
        "action_id": "act-0001",
        "verdict": "Detected",
        "confidence": 0.95,
        "rule_id": "DET-001",
        "technique_ref": "T1486",
        "mttd_seconds": 12.5,
        "matched_evidence_ref": "act-0001",
        "causal_chain": [
            "Evidence event received: act-0001",
            "Rule considered: DET-001",
            "Confidence computed: 0.95",
        ],
    }

    response = client.post("/publish", json=payload)

    assert response.status_code == 200
    assert response.json() == payload


def test_publish_missed_verdict():
    payload = {
        "action_id": "act-0002",
        "verdict": "Missed",
        "confidence": 0.1,
        "rule_id": "DET-002",
        "technique_ref": "T1059",
        "mttd_seconds": None,
        "matched_evidence_ref": None,
        "causal_chain": [
            "Evidence event received: act-0002",
        ],
    }

    response = client.post("/publish", json=payload)

    assert response.status_code == 200
    assert response.json()["verdict"] == "Missed"
    assert response.json()["confidence"] == 0.1


def test_publish_partial_verdict():
    payload = {
        "action_id": "act-0003",
        "verdict": "Partial",
        "confidence": 0.5,
        "rule_id": "DET-003",
        "technique_ref": "T1003",
        "mttd_seconds": 30.0,
        "matched_evidence_ref": "act-0003",
        "causal_chain": [],
    }

    response = client.post("/publish", json=payload)

    assert response.status_code == 200
    assert response.json()["verdict"] == "Partial"


def test_publish_nodata_verdict():
    payload = {
        "action_id": "act-0004",
        "verdict": "NoData",
        "confidence": 0.0,
        "rule_id": "NONE",
        "technique_ref": "T1047",
        "mttd_seconds": None,
        "matched_evidence_ref": None,
        "causal_chain": [
            "No detection rule found for technique T1047",
        ],
    }

    response = client.post("/publish", json=payload)

    assert response.status_code == 200
    assert response.json()["verdict"] == "NoData"
    assert response.json()["confidence"] == 0.0


def test_publish_rejects_invalid_confidence():
    payload = {
        "action_id": "act-0005",
        "verdict": "Detected",
        "confidence": 1.5,
        "rule_id": "DET-005",
        "technique_ref": "T1486",
    }

    response = client.post("/publish", json=payload)

    assert response.status_code == 422

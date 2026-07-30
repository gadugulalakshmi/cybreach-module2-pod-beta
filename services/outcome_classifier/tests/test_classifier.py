"""
Pytest suite for the Outcome Classifier.
"""
from fastapi.testclient import TestClient

from oc_app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_classify_detected():
    resp = client.post("/classify", json={"action_id": "act-0001", "confidence": 0.95, "rule_id": "DET-001"})
    body = resp.json()
    assert body["verdict"] == "Detected"
    assert body["alert_fidelity"] == "high"


def test_classify_partial():
    resp = client.post("/classify", json={"action_id": "act-0002", "confidence": 0.45, "rule_id": "DET-002"})
    assert resp.json()["verdict"] == "Partial"


def test_classify_missed():
    resp = client.post("/classify", json={"action_id": "act-0003", "confidence": 0.05, "rule_id": "DET-003"})
    assert resp.json()["verdict"] == "Missed"


def test_classify_no_data():
    resp = client.post("/classify", json={"action_id": "act-0004", "confidence": 0.0, "rule_id": "NONE", "no_data": True})
    assert resp.json()["verdict"] == "NoData"
    assert resp.json()["alert_fidelity"] is None

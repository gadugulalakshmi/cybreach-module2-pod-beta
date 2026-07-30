"""
Integration tests for the Week 5 additions to POST /classify:
MTTD auto-computation from timestamps, and specificity-aware fidelity.
"""
from fastapi.testclient import TestClient

from oc_app.main import app

client = TestClient(app)


def test_classify_computes_mttd_from_evidence_and_alert_timestamps():
    resp = client.post("/classify", json={
        "action_id": "act-0001",
        "confidence": 0.95,
        "rule_id": "DET-001",
        "evidence_timestamp": "2026-06-17T09:12:00Z",
        "alert_timestamp": "2026-06-17T09:13:30Z",
    })
    body = resp.json()
    assert body["mttd_seconds"] == 90.0


def test_classify_explicit_mttd_seconds_takes_priority_over_timestamps():
    resp = client.post("/classify", json={
        "action_id": "act-0001",
        "confidence": 0.95,
        "rule_id": "DET-001",
        "mttd_seconds": 12.5,
        "evidence_timestamp": "2026-06-17T09:12:00Z",
        "alert_timestamp": "2026-06-17T09:13:30Z",
    })
    body = resp.json()
    assert body["mttd_seconds"] == 12.5


def test_classify_mttd_is_null_when_no_timestamps_given():
    resp = client.post("/classify", json={"action_id": "act-0001", "confidence": 0.95, "rule_id": "DET-001"})
    assert resp.json()["mttd_seconds"] is None


def test_classify_uses_match_specificity_for_fidelity():
    resp = client.post("/classify", json={
        "action_id": "act-0001",
        "confidence": 0.75,  # would be "medium" under the old confidence-only logic
        "rule_id": "DET-001",
        "match_specificity": "exact",
    })
    assert resp.json()["alert_fidelity"] == "high"


def test_classify_causal_chain_includes_week5_detail_when_supplied():
    resp = client.post("/classify", json={
        "action_id": "act-0001",
        "confidence": 0.95,
        "rule_id": "DET-001",
        "match_specificity": "exact",
        "keywords_checked": ["vssadmin.exe", "cipher /e"],
        "evidence_timestamp": "2026-06-17T09:12:00Z",
        "alert_timestamp": "2026-06-17T09:12:45Z",
    })
    chain_text = " | ".join(step["description"] for step in resp.json()["causal_chain"])
    assert "Match specificity: exact" in chain_text
    assert "vssadmin.exe" in chain_text
    assert "MTTD computed: 45.0 seconds" in chain_text


def test_classify_backward_compatible_with_week1_style_request():
    """A bare-minimum Week 1/2/3 style request must still work exactly as before."""
    resp = client.post("/classify", json={"action_id": "act-0001", "confidence": 0.95, "rule_id": "DET-001"})
    body = resp.json()
    assert body["verdict"] == "Detected"
    assert body["alert_fidelity"] == "high"
    assert body["mttd_seconds"] is None

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from auth_helpers import auth_headers
from vp_app.main import app


client = TestClient(app)
# B11: /api/v2 is JWT-gated, so the suite's client presents a valid token by
# default. The unauthenticated-rejection cases build their own client.
client.headers.update(auth_headers())


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "ok"
    assert body["service"] == "verdict_publisher"
    # P5: the publisher must report which canonical topic it uses.
    assert body["topic"] == "cybreach.verdicts.v2"


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

    response = client.post("/api/v2/publish", json=payload)

    assert response.status_code == 200
    response_data = response.json()

    # B2: the wire field is `content_hash`, not `integrity_hash`.
    assert response_data["content_hash"]
    assert "integrity_hash" not in response_data

    # B3: `regulatory_control_refs` is part of the v2.0 contract.
    assert response_data["regulatory_control_refs"] == []


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

    response = client.post("/api/v2/publish", json=payload)

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

    response = client.post("/api/v2/publish", json=payload)

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

    response = client.post("/api/v2/publish", json=payload)

    assert response.status_code == 200
    assert response.json()["verdict"] == "NoData"
    assert response.json()["confidence"] == 0.0
    # A NoData verdict is still hashable and tamper-checkable.
    assert response.json()["content_hash"]


def test_publish_rejects_invalid_confidence():
    payload = {
        "action_id": "act-0005",
        "verdict": "Detected",
        "confidence": 1.5,
        "rule_id": "DET-005",
        "technique_ref": "T1486",
    }

    response = client.post("/api/v2/publish", json=payload)

    assert response.status_code == 422


class TestVerdictVocabulary:
    """Delta's frozen schema allows exactly `Detected|Missed|Partial|NoData`.

    Beta previously typed `verdict` as a bare `str`, so a legacy spelling was
    accepted, published to the bus, and then rejected by every consumer --
    while hashing different bytes than Delta would, because Delta normalises
    aliases before hashing. Normalising here keeps both sides in agreement.
    """

    @pytest.mark.parametrize(
        "sent,expected",
        [
            ("No Data", "NoData"),
            ("no data", "NoData"),
            ("NODATA", "NoData"),
            ("no_data", "NoData"),
            ("detected", "Detected"),
            ("DETECTED", "Detected"),
            ("missed", "Missed"),
            ("partial", "Partial"),
            ("PartialDetection", "Partial"),
        ],
    )
    def test_legacy_spelling_is_normalised(self, sent, expected):
        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-alias",
                "verdict": sent,
                "confidence": 0.5,
            },
        )

        assert response.status_code == 200
        assert response.json()["verdict"] == expected

    def test_normalisation_changes_the_digest(self):
        """The digest must cover the canonical token, not the raw input."""

        from vp_app.main import compute_content_hash
        from vp_app.models import PublishedVerdict

        canonical = PublishedVerdict(
            action_id="a", verdict="NoData", confidence=0.0
        )
        alias = PublishedVerdict(
            action_id="a", verdict="No Data", confidence=0.0
        )

        assert canonical.verdict == alias.verdict
        assert compute_content_hash(canonical) == compute_content_hash(alias)

        # ...and the event is emitted with the canonical token.
        response = client.post(
            "/api/v2/publish",
            json={"action_id": "a", "verdict": "No Data", "confidence": 0.0},
        )

        assert response.json()["verdict"] == "NoData"

    def test_unrecognised_verdict_is_rejected_at_the_edge(self):
        """An unknown token must not reach the bus."""

        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-bogus",
                "verdict": "Probably",
                "confidence": 0.5,
            },
        )

        assert response.status_code == 422

    def test_malformed_content_hash_is_rejected(self):
        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-badhash",
                "verdict": "Detected",
                "confidence": 0.5,
                "content_hash": "not-a-sha256",
            },
        )

        assert response.status_code == 422

    def test_empty_action_id_is_rejected(self):
        response = client.post(
            "/api/v2/publish",
            json={"action_id": "", "verdict": "Detected", "confidence": 0.5},
        )

        assert response.status_code == 422


class TestPublishesToKafka:
    """P5: the publisher used to be a print-only stub."""

    def test_event_is_sent_to_the_canonical_topic(self, fake_producer):
        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-kafka-1",
                "verdict": "Detected",
                "confidence": 0.9,
                "rule_id": "DET-001",
                "technique_ref": "T1486",
                "mttd_seconds": 1.5,
                "matched_evidence_ref": "act-kafka-1",
                "regulatory_control_refs": ["ISO27001-A.5.15"],
                "causal_chain": ["step"],
            },
        )

        assert response.status_code == 200
        assert fake_producer.topics == ["cybreach.verdicts.v2"]
        assert fake_producer.flushed is True

        event = fake_producer.last_event

        # The published event is exactly the v2.0 contract -- eight fields, no
        # Beta-local extras. Delta's frozen schema sets
        # `additionalProperties: false`, so `rule_id`/`technique_ref` would be
        # rejected downstream.
        assert set(event) == {
            "action_id",
            "verdict",
            "confidence",
            "causal_chain",
            "mttd_seconds",
            "matched_evidence_ref",
            "regulatory_control_refs",
            "content_hash",
        }

        assert event["regulatory_control_refs"] == ["ISO27001-A.5.15"]

    def test_beta_local_context_is_not_published(self, fake_producer):
        """`rule_id`/`technique_ref` are caller context, not contract fields."""

        client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-kafka-2",
                "verdict": "Detected",
                "confidence": 0.9,
                "rule_id": "DET-001",
                "technique_ref": "T1486",
            },
        )

        event = fake_producer.last_event

        assert "rule_id" not in event
        assert "technique_ref" not in event

    def test_a_legacy_verdict_token_is_published_in_canonical_form(
        self, fake_producer
    ):
        client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-kafka-3",
                "verdict": "No Data",
                "confidence": 0.0,
            },
        )

        assert fake_producer.last_event["verdict"] == "NoData"

    def test_verdict_survives_a_broker_outage(self, monkeypatch):
        """A Kafka outage must not turn into a 500 that loses the verdict."""

        monkeypatch.setattr("vp_app.main.get_producer", lambda: None)

        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-kafka-down",
                "verdict": "Detected",
                "confidence": 0.8,
                "rule_id": "DET-001",
                "technique_ref": "T1486",
            },
        )

        assert response.status_code == 200
        assert response.json()["content_hash"]

    def test_a_broker_error_does_not_fail_the_request(self, monkeypatch):
        """A mid-send KafkaError is logged, not raised into a 500."""

        from kafka.errors import KafkaError

        class FailingProducer:
            def send(self, topic, event):
                raise KafkaError("broker unavailable")

            def flush(self):
                pass

        monkeypatch.setattr(
            "vp_app.main.get_producer", lambda: FailingProducer()
        )

        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-kafka-error",
                "verdict": "Detected",
                "confidence": 0.8,
            },
        )

        assert response.status_code == 200
        assert response.json()["content_hash"]


class TestContentHash:
    def test_published_hash_is_recomputable(self):
        from vp_app.main import (
            PublishedVerdict,
            build_event,
            compute_content_hash,
        )

        verdict = PublishedVerdict(
            action_id="act-hash-1",
            verdict="Detected",
            confidence=0.75,
            mttd_seconds=2.0,
            matched_evidence_ref="act-hash-1",
            regulatory_control_refs=["NIST-800-53-AC-2"],
            causal_chain=["a", "b"],
        )

        assert compute_content_hash(verdict) == build_event(verdict)["content_hash"]

    def test_stale_hash_from_the_caller_is_replaced(self):
        """A caller cannot supply a forged or stale digest."""

        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": "act-hash-2",
                "verdict": "Detected",
                "confidence": 0.75,
                "content_hash": "0" * 64,
            },
        )

        assert response.status_code == 200
        assert response.json()["content_hash"] != "0" * 64

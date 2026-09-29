"""Tests for the live evidence consumer (B1).

The consumer is off by default and only starts when KAFKA_EVIDENCE_ENABLED is
set, so these tests never touch a broker: they exercise `handle`, which holds
the decisions (validation, malformed rejection, dead-lettering, callback
isolation, stale-rule behaviour) and the enable gate itself.
"""

import pytest

from ve_app.evidence_consumer import EvidenceConsumer, _enabled
from ve_app.models import EvidenceEvent

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

EVIDENCE = {
    "action_id": "act-consumer-1",
    "correlation_key": "campaign-1",
    "technique_ref": "T1486",
    "target_asset_ref": "host-fileserver-01",
    "expected_observable": "vssadmin.exe invoked with cipher /e",
    "timestamp": "2026-09-28T10:00:00Z",
}


def _rule(technique_ref="T1486", keywords=("vssadmin.exe",)):
    from ve_app.main import DetectionRule

    return DetectionRule(
        rule_id="DET-001",
        technique_ref=technique_ref,
        keywords=list(keywords),
    )


class _RecordingProducer:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, topic, value):
        if self.fail:
            raise RuntimeError("broker down")
        self.sent.append((topic, value))


def _consumer(**kwargs):
    producer = kwargs.pop("producer", None) or _RecordingProducer()
    rule_provider = kwargs.pop("rule_provider", lambda: [_rule()])
    consumer = EvidenceConsumer(rule_provider=rule_provider, **kwargs)
    consumer._producer = producer
    return consumer


class TestEnableGate:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("KAFKA_EVIDENCE_ENABLED", raising=False)
        assert _enabled() is False

    def test_start_is_a_noop_when_disabled(self, monkeypatch):
        monkeypatch.delenv("KAFKA_EVIDENCE_ENABLED", raising=False)
        consumer = _consumer()
        assert consumer.start() is False
        assert consumer._thread is None

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_truthy_values_enable(self, monkeypatch, value):
        monkeypatch.setenv("KAFKA_EVIDENCE_ENABLED", value)
        assert _enabled() is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
    def test_falsy_values_stay_off(self, monkeypatch, value):
        monkeypatch.setenv("KAFKA_EVIDENCE_ENABLED", value)
        assert _enabled() is False


class TestHandle:
    def test_validates_a_well_formed_event(self):
        consumer = _consumer()
        verdict = consumer.handle(dict(EVIDENCE))

        assert verdict is not None
        assert verdict.action_id == "act-consumer-1"
        assert verdict.technique_ref == "T1486"

    def test_malformed_event_is_rejected_and_dead_lettered(self):
        producer = _RecordingProducer()
        consumer = _consumer(producer=producer)

        broken = dict(EVIDENCE)
        del broken["target_asset_ref"]  # required by the frozen contract

        assert consumer.handle(broken) is None
        assert len(producer.sent) == 1
        topic, value = producer.sent[0]
        assert topic == consumer._dead_letter_topic
        assert "malformed" in value["error"]

    def test_dead_letter_failure_does_not_raise(self):
        producer = _RecordingProducer(fail=True)
        consumer = _consumer(producer=producer)

        broken = dict(EVIDENCE)
        del broken["expected_observable"]

        # A dead-letter send failure must not propagate into the poll loop.
        assert consumer.handle(broken) is None

    def test_on_verdict_is_called(self):
        seen = []
        consumer = _consumer(on_verdict=lambda e, v: seen.append((e.action_id, v.verdict)))

        consumer.handle(dict(EVIDENCE))

        assert len(seen) == 1
        assert seen[0][0] == "act-consumer-1"

    def test_callback_failure_does_not_lose_the_verdict(self):
        def explode(event, verdict):
            raise RuntimeError("downstream is down")

        consumer = _consumer(on_verdict=explode)

        verdict = consumer.handle(dict(EVIDENCE))

        assert verdict is not None, "a broken callback must not discard the verdict"

    def test_no_callback_is_fine(self):
        consumer = _consumer()
        assert consumer.handle(dict(EVIDENCE)) is not None


class TestRuleCaching:
    def test_rules_are_fetched_once_and_cached(self):
        calls = []

        def provider():
            calls.append(1)
            return [_rule()]

        consumer = _consumer(rule_provider=provider)

        consumer.handle(dict(EVIDENCE))
        consumer.handle(dict(EVIDENCE))
        consumer.handle(dict(EVIDENCE))

        assert len(calls) == 1, "a network fetch per event is not acceptable"

    def test_a_failed_refresh_keeps_the_previous_rules(self):
        state = {"n": 0}

        def provider():
            state["n"] += 1
            if state["n"] == 1:
                return [_rule()]
            raise RuntimeError("alpha is down")

        consumer = _consumer(rule_provider=provider)

        first = consumer.handle(dict(EVIDENCE))
        assert first is not None

        # Force a refresh that fails.
        consumer._rules_loaded_at = 0.0
        second = consumer.handle(dict(EVIDENCE))

        assert second is not None
        # Stale rules beat an empty set: an empty set yields NoData for
        # everything, which is indistinguishable from a genuine no-match.
        assert second.verdict == first.verdict

    def test_provider_returning_nothing_is_tolerated(self):
        consumer = _consumer(rule_provider=lambda: None)
        assert consumer.handle(dict(EVIDENCE)) is not None


class TestStop:
    def test_stop_without_start_is_safe(self):
        EvidenceConsumer(rule_provider=lambda: []).stop()

    def test_stop_closes_the_consumer(self, monkeypatch):
        monkeypatch.setenv("KAFKA_EVIDENCE_ENABLED", "false")
        consumer = _consumer()

        class _Closable:
            closed = False

            def close(self):
                _Closable.closed = True

        consumer._consumer = _Closable()
        consumer.stop()

        assert _Closable.closed is True
        assert consumer._consumer is None


class TestEventShape:
    def test_handles_a_real_evidence_event_object(self):
        consumer = _consumer()
        event = EvidenceEvent(**EVIDENCE)
        verdict = consumer.handle(event.model_dump())
        assert verdict.action_id == event.action_id

"""Shared fixtures for the Verdict Publisher suite.

The publisher is the one Beta service that talks to Kafka. Without stubbing the
producer here, every request in the default test run attempts a real connection
to `localhost:9092` and burns kafka-python's full retry budget first -- the
suite went from 19s to 8m19s purely on connection timeouts, and passed or
failed depending on whether a broker happened to be running.

Stubbing by default keeps the suite hermetic and fast. Tests that care about
publishing behaviour still assert on the recorded event, and the one test that
asserts broker-outage behaviour overrides this with a `None` producer.
"""
import pytest


class FakeProducer:
    """Records everything the publisher sends instead of contacting a broker."""

    def __init__(self):
        self.sent = []
        self.flushed = False

    def send(self, topic, event):
        self.sent.append((topic, event))

    def flush(self):
        self.flushed = True

    @property
    def topics(self):
        return [topic for topic, _ in self.sent]

    @property
    def events(self):
        return [event for _, event in self.sent]

    @property
    def last_event(self):
        return self.sent[-1][1]


@pytest.fixture
def fake_producer(monkeypatch):
    """Install a `FakeProducer` in place of the real lazy singleton."""

    producer = FakeProducer()

    monkeypatch.setattr("vp_app.main.get_producer", lambda: producer)

    return producer


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Guarantee no test in this suite reaches a broker.

    Autouse and fail-safe: even a test that forgets the fixture above cannot
    hang the suite on a connection timeout.
    """

    monkeypatch.setattr("vp_app.main.get_producer", lambda: FakeProducer())

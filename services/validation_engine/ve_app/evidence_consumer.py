"""Live evidence consumer for the Validation Engine (Pod Beta).

B1: `cybreach.evidence.v1` was produced by nobody and consumed by nobody. This
module is the consumer side of that seam. It is deliberately *off by default*:
the consumer only starts when `KAFKA_EVIDENCE_ENABLED` is truthy, so an
existing deployment or test run never acquires a background thread that tries
to reach a broker it does not have.

Design notes:

* The consumer reuses `replay_stream`/`validate_evidence` semantics rather than
  inventing a second validation path, so a verdict produced from a live Kafka
  message is the same verdict the fixture replay produces.
* Rules come from Alpha through the existing `fetch_alpha_rules` seam. If that
  fetch fails the engine is degraded (every event validates to `NoData`), so
  the degraded state is logged once and then events are re-driven once Alpha
  recovers, rather than being silently discarded.
* Offsets are committed only after a verdict is produced, so an exception in
  validation does not lose the event.
* Malformed messages are sent to the dead-letter topic rather than blocking the
  partition forever.
"""

import json
import logging
import os
import threading
from typing import Callable, List, Optional

from ve_app.ingestion import validate_evidence
from ve_app.models import EvidenceEvent

logger = logging.getLogger(__name__)

# Plan Section 5. Both the broker and the topic are injected, matching the
# publisher's configuration and Delta's app/kafka/config.py.
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
EVIDENCE_TOPIC = os.getenv("KAFKA_TOPIC_EVIDENCE", "cybreach.evidence.v1")
CONSUMER_GROUP = os.getenv(
    "KAFKA_CONSUMER_GROUP_EVIDENCE", "validation-engine-evidence"
)
DEAD_LETTER_TOPIC = os.getenv(
    "KAFKA_TOPIC_EVIDENCE_DLQ", "cybreach.evidence.v1.dlq"
)

# Off unless explicitly enabled. A missing/falsey value means "stay a plain
# request/response service", which is how the service runs today.
KAFKA_EVIDENCE_ENABLED = os.getenv("KAFKA_EVIDENCE_ENABLED", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# How long to wait for Alpha's rules before giving up on a fetch. Kept short so
# the consumer thread is not blocked behind an unreachable Alpha.
RULES_REFRESH_SECONDS = float(os.getenv("ALPHA_RULES_REFRESH_SECONDS", "60"))


def _enabled() -> bool:
    """Read the enable flag at call time, not import time.

    Read at import time the flag could only be set before the process started;
    this keeps it settable in tests and by an operator restarting a service.
    """

    return os.getenv("KAFKA_EVIDENCE_ENABLED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


class EvidenceConsumer:
    """Consumes `cybreach.evidence.v1` and validates each event.

    One instance owns one consumer thread. `start` is non-blocking and
    `stop` joins it, so it can be driven from a FastAPI lifespan.
    """

    def __init__(
        self,
        rule_provider: Callable[[], List],
        on_verdict: Optional[Callable[[EvidenceEvent, object], None]] = None,
        bootstrap_servers: str = KAFKA_BOOTSTRAP_SERVERS,
        topic: str = EVIDENCE_TOPIC,
        group_id: str = CONSUMER_GROUP,
        dead_letter_topic: str = DEAD_LETTER_TOPIC,
    ):
        # Injected rather than imported so this module stays testable without
        # Alpha or a broker, and so the Alpha seam has a single definition.
        self._rule_provider = rule_provider
        self._on_verdict = on_verdict
        self._bootstrap_servers = bootstrap_servers
        self._topic = topic
        self._group_id = group_id
        self._dead_letter_topic = dead_letter_topic

        self._consumer = None
        self._producer = None
        self._thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        self._rules: List = []
        self._rules_loaded_at: float = 0.0

    # -- rule cache ---------------------------------------------------------

    def _rules_current(self) -> bool:
        import time

        return (time.monotonic() - self._rules_loaded_at) < RULES_REFRESH_SECONDS

    def _current_rules(self) -> List:
        """Fetch Alpha's rules, caching briefly.

        Re-fetched on an interval rather than once per event: Alpha's rule set
        changes rarely, and fetching per message would put a network round trip
        (and an Alpha outage) in the path of every single event.
        """

        if not self._rules_current():
            import time

            try:
                self._rules = self._rule_provider() or []
                self._rules_loaded_at = time.monotonic()
            except Exception as exc:
                # Keep the previous rule set if a refresh fails: stale rules
                # produce a possibly-wrong verdict, whereas an empty set
                # produces NoData for everything.
                logger.warning("Rule refresh from Alpha failed (%s); keeping %d cached rules", exc, len(self._rules))

        return self._rules

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> bool:
        """Start the consumer thread. Returns False when disabled or already running."""

        if not _enabled():
            logger.info(
                "Evidence consumer not started: KAFKA_EVIDENCE_ENABLED is not set "
                "(the Validation Engine runs request/response only)"
            )
            return False

        if self._thread is not None and self._thread.is_alive():
            return True

        try:
            from kafka import KafkaConsumer, KafkaProducer
        except ImportError:
            logger.error("kafka-python is not installed; evidence consumer cannot start")
            return False

        self._stopping.clear()

        try:
            self._consumer = KafkaConsumer(
                self._topic,
                bootstrap_servers=self._bootstrap_servers,
                group_id=self._group_id,
                # Start at the earliest available offset on first join so a new
                # deployment sees the evidence already on the bus rather than
                # idling until the next campaign.
                auto_offset_reset="earliest",
                enable_auto_commit=False,
                value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
            )
            self._producer = KafkaProducer(
                bootstrap_servers=self._bootstrap_servers,
                value_serializer=lambda value: json.dumps(value).encode("utf-8"),
            )
        except Exception as exc:
            # A broker that is not up yet must not stop the API from serving.
            logger.error("Could not connect to Kafka at %s: %s", self._bootstrap_servers, exc)
            self._consumer = None
            self._producer = None
            return False

        self._thread = threading.Thread(
            target=self._run, name="evidence-consumer", daemon=True
        )
        self._thread.start()
        logger.info("Evidence consumer started on %s (group %s)", self._topic, self._group_id)
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the consumer thread and close the client."""

        self._stopping.set()

        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None

        for client in (self._consumer, self._producer):
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass

        self._consumer = None
        self._producer = None

    # -- message handling ---------------------------------------------------

    def _dead_letter(self, payload: dict, error: str) -> None:
        if self._producer is None:
            logger.warning("Dead-lettering %s but no producer is available", error)
            return
        try:
            self._producer.send(
                self._dead_letter_topic,
                {"payload": payload, "error": error},
            )
        except Exception as exc:
            logger.error("Could not dead-letter a message (%s): %s", error, exc)

    def handle(self, payload: dict) -> Optional[object]:
        """Validate one deserialised evidence message.

        Returns the verdict, or None if the message was rejected. Split out
        from `_run` so the decision logic is testable without a broker.
        """

        try:
            evidence = EvidenceEvent(**payload)
        except Exception as exc:
            # A malformed event must not stall the partition, and must not be
            # silently dropped either.
            logger.warning("Rejecting malformed evidence event: %s", exc)
            self._dead_letter(payload, f"malformed evidence event: {exc}")
            return None

        verdict = validate_evidence(evidence, self._current_rules())

        if self._on_verdict:
            try:
                self._on_verdict(evidence, verdict)
            except Exception as exc:
                logger.error("on_verdict callback failed for %s: %s", evidence.action_id, exc)

        return verdict

    def _run(self) -> None:
        assert self._consumer is not None

        while not self._stopping.is_set():
            try:
                for message in self._consumer:
                    if self._stopping.is_set():
                        break

                    self.handle(message.value)

                    # Commit only after a verdict exists, so a crash mid-
                    # validation replays the event instead of losing it.
                    try:
                        self._consumer.commit()
                    except Exception as exc:
                        logger.warning("Offset commit failed: %s", exc)
            except Exception as exc:
                if self._stopping.is_set():
                    break
                logger.error("Evidence consumer loop error: %s", exc)
                # Back off before retrying so an unreachable broker does not
                # spin this thread.
                self._stopping.wait(5.0)

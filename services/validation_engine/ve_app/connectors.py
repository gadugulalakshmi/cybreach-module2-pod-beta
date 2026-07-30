"""
Connector Framework -- Pod Beta, Week 4.

Covers "Connector Framework Integration": integrating the Validation
Engine with a BaseConnector interface and using mock connectors for
testing, so the engine's rule-execution logic never has to change once
real SIEM connectors (Splunk, Sentinel, Elastic, QRadar, CrowdStrike --
Technical Doc Section 3.2) are dropped in later.

The read-only guarantee from the technical doc is enforced here at the
interface level: BaseConnector only exposes query(), poll(), and
validate_connection(). There is no update(), create(), or delete()
method, and subclasses cannot add one without breaking the abstract
contract other code relies on.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple


class BaseConnector(ABC):
    """Every SIEM connector (real or mock) implements this interface."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def query(self, query_str: str, time_range: Tuple[str, str]) -> List[Dict[str, Any]]:
        """Execute a read-only query. Returns raw results in vendor-native shape."""
        raise NotImplementedError

    @abstractmethod
    def poll(self) -> List[Dict[str, Any]]:
        """Pull new events since the last poll. READ-ONLY."""
        raise NotImplementedError

    @abstractmethod
    def validate_connection(self) -> bool:
        """Verify credentials/connectivity work. READ-ONLY."""
        raise NotImplementedError


class MockConnector(BaseConnector):
    """
    Testing stand-in for a real SIEM connector. Results are seeded ahead
    of time via config["seeded_results"], a dict keyed by query string
    (by convention, the rule_id) mapping to a list of result records,
    each shaped like:

        {"observable": "vssadmin.exe invoked with cipher /e", "timestamp": "2026-06-17T09:12:30Z"}

    This lets tests simulate "the SIEM did/did not see this" without a
    real Splunk/Sentinel/Elastic instance, per the technical doc's
    connector-testing pattern (Section 2: connectors run against
    recorded telemetry fixtures during build).
    """

    def query(self, query_str: str, time_range: Tuple[str, str]) -> List[Dict[str, Any]]:
        seeded_results: Dict[str, List[Dict[str, Any]]] = self.config.get("seeded_results", {})
        return list(seeded_results.get(query_str, []))

    def poll(self) -> List[Dict[str, Any]]:
        return []

    def validate_connection(self) -> bool:
        return True

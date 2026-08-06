from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ve_app.connectors import BaseConnector
from ve_app.models import EvidenceEvent
from ve_app.observable_matching import best_observable_match
from ve_app.time_window import DEFAULT_WINDOW_SECONDS, filter_results_in_window


class RawValidationResult(BaseModel):
    action_id: str
    rule_id: str
    confidence: float
    matched: bool
    raw_results: List[Dict[str, Any]] = []
    no_data: bool = False


def execute_rule(
    evidence: EvidenceEvent,
    rule,
    connector: BaseConnector,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> RawValidationResult:

    query_str = rule.query_str or rule.rule_id
    time_range = (evidence.timestamp, evidence.timestamp)

    raw_results = connector.query(query_str, time_range)

    if not raw_results:
        return RawValidationResult(
            action_id=evidence.action_id,
            rule_id=rule.rule_id,
            confidence=0.0,
            matched=False,
            raw_results=[],
            no_data=True,
        )

    in_window = filter_results_in_window(
        evidence.timestamp,
        raw_results,
        window_seconds,
    )

    if not in_window:
        return RawValidationResult(
            action_id=evidence.action_id,
            rule_id=rule.rule_id,
            confidence=0.0,
            matched=False,
            raw_results=raw_results,
        )

    confidence = best_observable_match(
        evidence.expected_observable,
        in_window,
    )

    return RawValidationResult(
        action_id=evidence.action_id,
        rule_id=rule.rule_id,
        confidence=confidence,
        matched=confidence > 0.0,
        raw_results=in_window,
    )


def execute_rules(
    evidence: EvidenceEvent,
    rules: list,
    connector: BaseConnector,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> List[RawValidationResult]:

    return [
        execute_rule(evidence, rule, connector, window_seconds)
        for rule in rules
    ]


def execute_rules_parallel(
    evidence: EvidenceEvent,
    rules: list,
    connectors: List[BaseConnector],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> List[RawValidationResult]:

    def run_connector(connector: BaseConnector):
        return execute_rules(
            evidence,
            rules,
            connector,
            window_seconds,
        )

    with ThreadPoolExecutor(max_workers=len(connectors)) as executor:
        results = executor.map(run_connector, connectors)

    return [
        result
        for connector_results in results
        for result in connector_results
    ]
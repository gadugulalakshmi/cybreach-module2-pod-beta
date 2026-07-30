"""
Detection Rule Execution -- Pod Beta, Week 4.

Covers:
    - Implement detection rule execution
    - Execute rules against mock evidence events
    - Compute confidence scores
    - Generate raw validation results
    - Connector Framework Integration (BaseConnector, mock connectors)
    - Time-window bounding logic / configurable time range validation
    - Confidence Score Logic: weighted matching (exact vs partial)
    - Observable Matching: compare evidence events with SIEM query results

This is the connector-integrated sibling of compute_confidence() in
main.py. Where compute_confidence() scores a rule against evidence using
only the rule's own keyword list (no SIEM involved -- useful before any
connector exists), execute_rule() below is the fuller Week 4 path: it
actually queries a BaseConnector, keeps only results inside the
configurable time window, and scores confidence from how well those
real query results match the evidence's expected observable.
"""
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from ve_app.connectors import BaseConnector
from ve_app.models import EvidenceEvent
from ve_app.observable_matching import best_observable_match
from ve_app.time_window import DEFAULT_WINDOW_SECONDS, filter_results_in_window


class RawValidationResult(BaseModel):
    """
    Output of execute_rule(): the raw, pre-classification result for one
    (evidence, rule) pair. The Outcome Classifier (or, before Week 6,
    build_verdict() in main.py) turns this into a final Detected/Missed/
    Partial/NoData verdict.
    """

    action_id: str
    rule_id: str
    confidence: float
    matched: bool
    raw_results: List[Dict[str, Any]] = []
    no_data: bool = False


def execute_rule(
    evidence: EvidenceEvent,
    rule,  # main.DetectionRule -- avoided as a type import to prevent a circular import
    connector: BaseConnector,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> RawValidationResult:
    """
    Executes a single detection rule against a single evidence event via
    a connector, and returns a raw validation result.

    Steps:
        1. Query the connector (Connector Framework Integration) using
           the rule's query string (falls back to rule_id if the mock
           rule has no query_str set).
        2. Time-window bounding: drop any returned result whose
           timestamp falls outside the configurable window around the
           evidence's timestamp.
        3. Observable matching: score the best remaining result against
           the evidence's expected_observable using weighted field
           matching (exact match scores higher than partial overlap).
    """
    query_str = rule.query_str or rule.rule_id
    raw_results = connector.query(query_str, (evidence.timestamp, evidence.timestamp))

    if not raw_results:
        return RawValidationResult(
            action_id=evidence.action_id,
            rule_id=rule.rule_id,
            confidence=0.0,
            matched=False,
            raw_results=[],
            no_data=True,
        )

    in_window = filter_results_in_window(evidence.timestamp, raw_results, window_seconds)
    if not in_window:
        # The connector returned something, but nothing close enough in
        # time to credibly correspond to this evidence event.
        return RawValidationResult(
            action_id=evidence.action_id,
            rule_id=rule.rule_id,
            confidence=0.0,
            matched=False,
            raw_results=raw_results,
        )

    confidence = best_observable_match(evidence.expected_observable, in_window)
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
    """Executes every rule in `rules` against a single evidence event and
    returns one RawValidationResult per rule (Task: "Generate raw
    validation results")."""
    return [execute_rule(evidence, rule, connector, window_seconds) for rule in rules]

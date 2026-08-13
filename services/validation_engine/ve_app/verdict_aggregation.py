"""
Verdict aggregation for the Validation Engine.

Combines multiple validation results belonging to the same action
into one overall verdict.
"""

from typing import List

from .models import Verdict


VERDICT_PRIORITY = {
    "NoData": 0,
    "Missed": 1,
    "Partial": 2,
    "Detected": 3,
}


def aggregate_verdicts(results: List[Verdict]) -> Verdict:
    """
    Aggregate multiple Verdict records for the same action into one Verdict.

    Rules:
    - All results must belong to the same action_id.
    - The highest-severity verdict represents the overall outcome.
    - Confidence is the highest confidence among the results.
    - MTTD uses the fastest available detection time.
    - Matched evidence is taken from the selected strongest result.
    - Causal chains are merged without duplicates.
    """

    if not results:
        raise ValueError("At least one verdict is required for aggregation")

    action_ids = {result.action_id for result in results}

    if len(action_ids) != 1:
        raise ValueError("All verdicts must belong to the same action_id")

    selected = max(
        results,
        key=lambda result: (
            VERDICT_PRIORITY.get(result.verdict, -1),
            result.confidence,
        ),
    )

    mttd_values = [
        result.mttd_seconds
        for result in results
        if result.mttd_seconds is not None
    ]

    causal_chain = []
    for result in results:
        for step in result.causal_chain:
            if step not in causal_chain:
                causal_chain.append(step)

    matched_evidence_ref = selected.matched_evidence_ref

    return Verdict(
        action_id=selected.action_id,
        verdict=selected.verdict,
        confidence=max(result.confidence for result in results),
        mttd_seconds=min(mttd_values) if mttd_values else None,
        matched_evidence_ref=matched_evidence_ref,
        causal_chain=causal_chain,
        rule_id=",".join(sorted({result.rule_id for result in results})),
        technique_ref=selected.technique_ref,
    )
"""
Validation result diffing for the Validation Engine.

Compares old and new validation results and identifies verdict changes.
"""

from typing import List

from ve_app.models import Verdict


def diff_validation_results(
    old_results: List[Verdict],
    new_results: List[Verdict],
) -> List[dict]:
    """
    Compare old and new validation results.

    Only results whose verdict changed are returned.

    Results are matched using action_id.
    """

    old_by_action = {
        result.action_id: result
        for result in old_results
    }

    new_by_action = {
        result.action_id: result
        for result in new_results
    }

    differences = []

    for action_id, new_result in new_by_action.items():
        old_result = old_by_action.get(action_id)

        if old_result is None:
            differences.append(
                {
                    "action_id": action_id,
                    "old_verdict": None,
                    "new_verdict": new_result.verdict,
                    "old_confidence": None,
                    "new_confidence": new_result.confidence,
                }
            )
            continue

        if old_result.verdict != new_result.verdict:
            differences.append(
                {
                    "action_id": action_id,
                    "old_verdict": old_result.verdict,
                    "new_verdict": new_result.verdict,
                    "old_confidence": old_result.confidence,
                    "new_confidence": new_result.confidence,
                }
            )

    return differences
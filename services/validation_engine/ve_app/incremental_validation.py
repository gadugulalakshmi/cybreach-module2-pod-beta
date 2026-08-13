"""
Incremental validation for the Validation Engine.

When detection rules change, only evidence events affected by those
changed rules are re-validated. Unaffected evidence is left untouched.
"""

from typing import List, Set

from ve_app.models import EvidenceEvent, Verdict
from ve_app.main import DetectionRule, validate_evidence


def get_affected_evidence(
    evidence_events: List[EvidenceEvent],
    changed_rules: List[DetectionRule],
) -> List[EvidenceEvent]:
    """
    Return only evidence events that may be affected by changed rules.

    A rule affects an evidence event when:
    1. The MITRE technique matches.
    2. If the rule has an asset_class, the evidence belongs to that class.
    """

    affected = []

    for evidence in evidence_events:
        for rule in changed_rules:
            if rule.technique_ref != evidence.technique_ref:
                continue

            if rule.asset_class is not None:
                asset_class = evidence.target_asset_ref.split("-")[0].lower()

                if asset_class != rule.asset_class.lower():
                    continue

            affected.append(evidence)
            break

    return affected


def incremental_validate(
    evidence_events: List[EvidenceEvent],
    all_rules: List[DetectionRule],
    changed_rule_ids: Set[str],
) -> List[Verdict]:
    """
    Re-validate only evidence events affected by changed detection rules.

    Returns validation results only for affected evidence events.
    """

    changed_rules = [
        rule
        for rule in all_rules
        if rule.rule_id in changed_rule_ids
    ]

    if not changed_rules:
        return []

    affected_evidence = get_affected_evidence(
        evidence_events,
        changed_rules,
    )

    return [
        validate_evidence(evidence, all_rules)
        for evidence in affected_evidence
    ]
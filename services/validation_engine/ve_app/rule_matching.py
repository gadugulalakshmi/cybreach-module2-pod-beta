"""
Rule Matching Logic -- Pod Beta, Week 3 (Person B).

Covers:
    6. Implement rule matching logic
    7. Match rules using MITRE Technique ID
    8. Match rules using Asset Class

Given an EvidenceEvent and the full list of currently loaded detection
rules, this module finds every rule that is actually applicable to that
event, using two independent filters that must BOTH pass:

  - Technique match (Task 7): the rule's technique_ref must equal the
    evidence's technique_ref. This is a hard requirement -- a rule for
    ransomware (T1486) should never be allowed to "detect" a privilege
    escalation event (T1098), no matter how it scores.

  - Asset class match (Task 8): a rule can optionally be scoped to a
    class of asset (e.g. "host", "cloud", "ot", "identity"). If the rule
    does not specify an asset_class, it is treated as a wildcard that
    applies to any asset (this keeps the simple Week 1/2 rules, which
    never set asset_class, working unchanged). If it does specify one,
    the evidence's target_asset_ref must belong to that same class.

Asset class is inferred from target_asset_ref by convention: fixtures and
the Global Detection Content Library both name assets as
"<class>-<descriptor>-<id>", e.g. "host-fileserver-01",
"cloud-account-aws-prod", "ot-plc-modbus-07", "identity-tenant-azure-eu".
"""
from typing import List, Optional

from pydantic import BaseModel

from ve_app.models import EvidenceEvent


def infer_asset_class(target_asset_ref: str) -> str:
    """
    Extracts the asset class token from an asset reference.

    "host-fileserver-01"          -> "host"
    "cloud-account-aws-prod"      -> "cloud"
    "ot-plc-modbus-07"            -> "ot"
    "identity-tenant-azure-eu"    -> "identity"
    """
    return target_asset_ref.split("-")[0].lower()


def matches_technique(rule_technique_ref: str, evidence: EvidenceEvent) -> bool:
    """Task 7: MITRE Technique ID match. Exact match only -- no partial
    or prefix matching, since a rule for one technique must never be
    allowed to silently cover a different one."""
    return rule_technique_ref == evidence.technique_ref


def matches_asset_class(rule_asset_class: Optional[str], evidence: EvidenceEvent) -> bool:
    """Task 8: Asset Class match. A rule with no asset_class set is a
    wildcard and matches any asset. Otherwise the evidence's inferred
    asset class must equal the rule's declared asset_class."""
    if rule_asset_class is None:
        return True
    return infer_asset_class(evidence.target_asset_ref) == rule_asset_class.lower()


class MatchableRule(BaseModel):
    """
    Protocol-ish shape used by find_matching_rules: anything with these
    three fields can be matched, whether it's the DetectionRule defined
    in main.py or a future richer rule object from the Rule Ingestion
    Service (Pod Alpha).
    """

    rule_id: str
    technique_ref: str
    asset_class: Optional[str] = None


def find_matching_rules(evidence: EvidenceEvent, rules: List) -> List:
    """
    Task 6: Rule matching logic. Returns every rule from `rules` that
    passes BOTH the technique match (Task 7) and the asset class match
    (Task 8) for the given evidence event. Order is preserved from the
    input rule list so callers can still prefer earlier rules when
    multiple match.
    """
    return [
        rule
        for rule in rules
        if matches_technique(rule.technique_ref, evidence)
        and matches_asset_class(getattr(rule, "asset_class", None), evidence)
    ]

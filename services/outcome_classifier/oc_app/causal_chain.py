"""
Causal Chain Builder -- Pod Beta, Week 5 (extended from the Week 1/2
skeleton).

Produces the step-by-step reasoning trail explaining how a verdict was
derived. The chain always includes the basic evidence-received and
rule-executed steps; when richer detail is available from the Week 4
rule execution path (match specificity, which keywords were checked,
computed MTTD), those are appended too, so an auditor can trace exactly
why a verdict was assigned without guessing.
"""
from typing import List, Optional

from oc_app.models import CausalStep


def build_causal_chain(
    result,
    verdict: str,
    mttd_seconds: Optional[float] = None,
) -> List[CausalStep]:
    steps: List[CausalStep] = [
        CausalStep(step_number=1, description=f"Evidence event received: {result.action_id}"),
        CausalStep(step_number=2, description=f"Rule executed: {result.rule_id}"),
    ]

    match_specificity = getattr(result, "match_specificity", None)
    if match_specificity:
        steps.append(CausalStep(step_number=len(steps) + 1, description=f"Match specificity: {match_specificity}"))

    keywords_checked = getattr(result, "keywords_checked", None)
    if keywords_checked:
        steps.append(CausalStep(step_number=len(steps) + 1, description=f"Keywords checked: {keywords_checked}"))

    steps.append(CausalStep(step_number=len(steps) + 1, description=f"Confidence {result.confidence} -> verdict {verdict}"))

    if mttd_seconds is not None:
        steps.append(
            CausalStep(
                step_number=len(steps) + 1,
                description=f"MTTD computed: {mttd_seconds} seconds between attack execution and first matching alert",
            )
        )

    return steps

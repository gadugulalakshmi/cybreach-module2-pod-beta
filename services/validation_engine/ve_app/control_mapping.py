"""
Regulatory control mapping and evidence-backed compliance verification
for the Validation Engine.
"""

from typing import Dict, List, Protocol

from ve_app.models import Verdict


class ControlRegistry(Protocol):
    """
    Frozen control registry interface.

    Implementations return controls applicable to a given
    regulatory framework and validation verdict.
    """

    def get_controls(self, framework: str, verdict: str) -> List[str]:
        ...


SUPPORTED_FRAMEWORKS = {
    "NIST CSF 2.0",
    "ISO 27001:2022",
    "PCI-DSS 4.0",
    "GDPR",
}


def map_verdict_to_controls(
    verdict: Verdict,
    framework: str,
    registry: ControlRegistry,
) -> List[str]:
    """
    Map a validation verdict to controls in the requested framework.
    """

    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(
            f"Unsupported regulatory framework: {framework}"
        )

    controls = registry.get_controls(
        framework=framework,
        verdict=verdict.verdict,
    )

    return list(controls)


def map_verdict_to_all_frameworks(
    verdict: Verdict,
    registry: ControlRegistry,
) -> Dict[str, List[str]]:
    """
    Return regulatory control mappings for all supported frameworks.
    """

    return {
        framework: map_verdict_to_controls(
            verdict,
            framework,
            registry,
        )
        for framework in SUPPORTED_FRAMEWORKS
    }


def verify_compliance_evidence(
    verdict: Verdict,
    evidence_refs: List[str],
) -> bool:
    """
    Evidence-backed compliance verification.

    A control can be considered compliant only when:
      1. The validation verdict is Detected.
      2. The verdict contains an explicit evidence reference.
      3. That evidence reference exists in the validated evidence set.

    Missed, Partial, and NoData verdicts can never be marked as Met.
    """

    if verdict.verdict != "Detected":
        return False

    if not verdict.matched_evidence_ref:
        return False

    if verdict.matched_evidence_ref not in evidence_refs:
        return False

    return True


def get_compliance_status(
    verdict: Verdict,
    evidence_refs: List[str],
) -> str:
    """
    Return the compliance status for a validation verdict.

    Met is returned only when explicit validated evidence exists.
    Otherwise the status is NotMet.
    """

    if verify_compliance_evidence(
        verdict,
        evidence_refs,
    ):
        return "Met"

    return "NotMet"
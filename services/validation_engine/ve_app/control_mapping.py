"""
Regulatory control mapping for Validation Engine.

Maps validation verdicts to regulatory control references.

The actual control references are kept behind a registry interface so
the mapping logic does not depend directly on a specific framework
implementation.
"""

from typing import Dict, List, Protocol

from ve_app.models import Verdict


class ControlRegistry(Protocol):
    """
    Frozen control registry interface.

    Implementations should return the controls applicable to a given
    verdict.
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

    The control registry is the source of truth. This function only
    validates the requested framework and delegates the actual mapping
    to the registry.
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
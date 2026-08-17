import pytest

from ve_app.control_mapping import (
    SUPPORTED_FRAMEWORKS,
    map_verdict_to_all_frameworks,
    map_verdict_to_controls,
)
from ve_app.models import Verdict


class FakeControlRegistry:
    """
    Test implementation of the frozen registry interface.
    """

    def __init__(self):
        self.calls = []

    def get_controls(self, framework, verdict):
        self.calls.append((framework, verdict))

        return [
            f"{framework}-CONTROL-{verdict}"
        ]


def make_verdict(verdict="Detected"):
    return Verdict(
        action_id="A001",
        verdict=verdict,
        confidence=0.9,
        mttd_seconds=10,
        matched_evidence_ref="EV001",
        causal_chain=[],
        rule_id="R001",
        technique_ref="T1059",
    )


@pytest.mark.parametrize(
    "framework",
    [
        "NIST CSF 2.0",
        "ISO 27001:2022",
        "PCI-DSS 4.0",
        "GDPR",
    ],
)
def test_supported_framework_mapping(framework):
    registry = FakeControlRegistry()
    verdict = make_verdict("Detected")

    controls = map_verdict_to_controls(
        verdict,
        framework,
        registry,
    )

    assert controls == [
        f"{framework}-CONTROL-Detected"
    ]

    assert registry.calls == [
        (framework, "Detected")
    ]


def test_unsupported_framework_is_rejected():
    registry = FakeControlRegistry()
    verdict = make_verdict()

    with pytest.raises(ValueError, match="Unsupported regulatory framework"):
        map_verdict_to_controls(
            verdict,
            "Unknown Framework",
            registry,
        )


def test_all_frameworks_are_mapped():
    registry = FakeControlRegistry()
    verdict = make_verdict("Partial")

    result = map_verdict_to_all_frameworks(
        verdict,
        registry,
    )

    assert set(result.keys()) == SUPPORTED_FRAMEWORKS

    for framework in SUPPORTED_FRAMEWORKS:
        assert result[framework] == [
            f"{framework}-CONTROL-Partial"
        ]



def test_compliance_is_met_with_validated_evidence():
    verdict = make_verdict("Detected")

    from ve_app.control_mapping import get_compliance_status

    status = get_compliance_status(
        verdict,
        ["EV001"],
    )

    assert status == "Met"


def test_compliance_is_not_met_without_evidence_reference():
    verdict = make_verdict("Detected")
    verdict.matched_evidence_ref = None

    from ve_app.control_mapping import get_compliance_status

    status = get_compliance_status(
        verdict,
        [],
    )

    assert status == "NotMet"


def test_compliance_is_not_met_when_evidence_reference_is_invalid():
    verdict = make_verdict("Detected")

    from ve_app.control_mapping import get_compliance_status

    status = get_compliance_status(
        verdict,
        ["EV999"],
    )

    assert status == "NotMet"


@pytest.mark.parametrize(
    "verdict_value",
    [
        "Missed",
        "Partial",
        "NoData",
    ],
)
def test_non_detected_verdict_can_never_be_marked_met(verdict_value):
    verdict = make_verdict(verdict_value)

    from ve_app.control_mapping import get_compliance_status

    status = get_compliance_status(
        verdict,
        ["EV001"],
    )

    assert status == "NotMet"
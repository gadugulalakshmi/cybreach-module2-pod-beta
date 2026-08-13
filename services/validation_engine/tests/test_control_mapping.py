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


@pytest.mark.parametrize(
    "verdict_value",
    [
        "Detected",
        "Missed",
        "Partial",
        "NoData",
    ],
)
def test_mapping_preserves_verdict(verdict_value):
    registry = FakeControlRegistry()
    verdict = make_verdict(verdict_value)

    map_verdict_to_controls(
        verdict,
        "NIST CSF 2.0",
        registry,
    )

    assert registry.calls[-1] == (
        "NIST CSF 2.0",
        verdict_value,
    )
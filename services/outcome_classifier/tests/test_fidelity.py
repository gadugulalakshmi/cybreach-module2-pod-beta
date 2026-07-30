"""
Tests for alert fidelity assessment: High / Medium / Low based on
detection specificity, with a confidence-band fallback.
"""
from oc_app.fidelity import assess_fidelity


def test_exact_specificity_is_high_fidelity_regardless_of_confidence():
    assert assess_fidelity(confidence=0.75, match_specificity="exact") == "high"


def test_substring_specificity_is_medium_fidelity():
    assert assess_fidelity(confidence=0.99, match_specificity="substring") == "medium"


def test_partial_specificity_is_low_fidelity():
    assert assess_fidelity(confidence=0.95, match_specificity="partial") == "low"


def test_flat_technique_specificity_is_low_fidelity():
    assert assess_fidelity(confidence=0.9, match_specificity="flat_technique") == "low"


def test_falls_back_to_confidence_bands_when_no_specificity_given():
    assert assess_fidelity(confidence=0.95) == "high"
    assert assess_fidelity(confidence=0.75) == "medium"
    assert assess_fidelity(confidence=0.5) == "low"


def test_unrecognised_specificity_value_falls_back_to_confidence_bands():
    assert assess_fidelity(confidence=0.95, match_specificity="something_unexpected") == "high"

"""
Tests for the causal chain builder: the step-by-step reasoning trail
explaining how each verdict was derived.
"""
from types import SimpleNamespace

from oc_app.causal_chain import build_causal_chain


def make_result(**overrides):
    base = dict(action_id="act-0001", rule_id="DET-001", confidence=0.9)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_basic_chain_has_evidence_and_rule_and_confidence_steps():
    result = make_result()
    chain = build_causal_chain(result, "Detected")

    descriptions = [s.description for s in chain]
    assert any("Evidence event received" in d for d in descriptions)
    assert any("Rule executed" in d for d in descriptions)
    assert any("Confidence" in d and "Detected" in d for d in descriptions)


def test_chain_includes_match_specificity_when_present():
    result = make_result(match_specificity="exact")
    chain = build_causal_chain(result, "Detected")
    descriptions = [s.description for s in chain]
    assert any("Match specificity: exact" in d for d in descriptions)


def test_chain_omits_match_specificity_when_absent():
    result = make_result()
    chain = build_causal_chain(result, "Detected")
    descriptions = [s.description for s in chain]
    assert not any("Match specificity" in d for d in descriptions)


def test_chain_includes_keywords_checked_when_present():
    result = make_result(keywords_checked=["vssadmin.exe", "cipher /e"])
    chain = build_causal_chain(result, "Detected")
    descriptions = [s.description for s in chain]
    assert any("Keywords checked" in d and "vssadmin.exe" in d for d in descriptions)


def test_chain_includes_mttd_step_when_provided():
    result = make_result()
    chain = build_causal_chain(result, "Detected", mttd_seconds=42.0)
    descriptions = [s.description for s in chain]
    assert any("MTTD computed: 42.0 seconds" in d for d in descriptions)


def test_chain_omits_mttd_step_when_not_provided():
    result = make_result()
    chain = build_causal_chain(result, "Missed", mttd_seconds=None)
    descriptions = [s.description for s in chain]
    assert not any("MTTD" in d for d in descriptions)


def test_step_numbers_are_sequential_starting_at_one():
    result = make_result(match_specificity="exact", keywords_checked=["a"])
    chain = build_causal_chain(result, "Detected", mttd_seconds=10.0)
    assert [s.step_number for s in chain] == list(range(1, len(chain) + 1))

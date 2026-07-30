"""
Tests for observable matching: weighted confidence scoring between an
evidence event's expected_observable and a SIEM result's observable text.
"""
from ve_app.observable_matching import best_observable_match, match_observable


def test_exact_match_scores_full_confidence():
    assert match_observable("vssadmin.exe invoked", "vssadmin.exe invoked") == 1.0


def test_exact_match_is_case_insensitive():
    assert match_observable("VSSAdmin.exe Invoked", "vssadmin.exe invoked") == 1.0


def test_substring_match_scores_high_but_not_perfect():
    score = match_observable("vssadmin.exe invoked with cipher /e", "vssadmin.exe invoked")
    assert score == 0.7


def test_partial_token_overlap_scores_lower_than_substring_match():
    score = match_observable("vssadmin.exe invoked with cipher /e flag", "cipher /e flag detected on host")
    assert 0.0 < score < 0.7


def test_no_overlap_scores_zero():
    assert match_observable("vssadmin.exe invoked", "completely unrelated text here") == 0.0


def test_empty_siem_observable_scores_zero():
    assert match_observable("vssadmin.exe invoked", "") == 0.0


def test_empty_expected_observable_scores_zero():
    assert match_observable("", "vssadmin.exe invoked") == 0.0


def test_best_observable_match_picks_the_strongest_of_several_results():
    results = [
        {"observable": "unrelated noise"},
        {"observable": "vssadmin.exe invoked"},
        {"observable": "cipher /e"},
    ]
    score = best_observable_match("vssadmin.exe invoked", results)
    assert score == 1.0


def test_best_observable_match_returns_zero_for_no_results():
    assert best_observable_match("vssadmin.exe invoked", []) == 0.0

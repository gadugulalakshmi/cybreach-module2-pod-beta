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

def test_whitespace_is_ignored():
    assert match_observable(
        "  vssadmin.exe invoked  ",
        "vssadmin.exe invoked",
    ) == 1.0


def test_both_observables_empty():
    assert match_observable("", "") == 0.0


def test_expected_observable_only_whitespace():
    assert match_observable(
        "   ",
        "vssadmin.exe invoked",
    ) == 0.0


def test_siem_observable_only_whitespace():
    assert match_observable(
        "vssadmin.exe invoked",
        "   ",
    ) == 0.0


def test_partial_match_with_duplicate_tokens():
    score = match_observable(
        "vssadmin vssadmin invoked",
        "vssadmin invoked detected",
    )
    assert 0.0 < score < 0.7


def test_special_character_observable():
    score = match_observable(
        "powershell.exe -enc",
        "powershell.exe -enc detected",
    )
    assert score == 0.7


def test_multiple_results_with_no_match():
    results = [
        {"observable": "network connection"},
        {"observable": "login successful"},
        {"observable": "file created"},
    ]

    assert best_observable_match(
        "vssadmin.exe invoked",
        results,
    ) == 0.0


def test_multiple_results_with_empty_observable_field():
    results = [
        {},
        {"observable": ""},
        {"observable": "vssadmin.exe invoked"},
    ]

    assert best_observable_match(
        "vssadmin.exe invoked",
        results,
    ) == 1.0
def test_partial_match_with_duplicate_tokens_is_not_overcounted():
    score = match_observable(
        "powershell powershell encoded command",
        "powershell encoded",
    )

    assert 0.0 < score < 0.7


def test_whitespace_is_normalized_for_exact_match():
    assert match_observable(
        "  vssadmin.exe invoked  ",
        "vssadmin.exe invoked",
    ) == 1.0


def test_case_and_whitespace_are_normalized_together():
    assert match_observable(
        "  VSSADMIN.EXE INVOKED ",
        "vssadmin.exe invoked",
    ) == 1.0


def test_unrelated_long_observable_does_not_get_high_score():
    score = match_observable(
        "vssadmin.exe invoked with cipher /e",
        "completely unrelated security event with many tokens",
    )

    assert score == 0.0


def test_best_match_handles_missing_observable_field():
    results = [
        {},
        {"observable": ""},
        {"observable": "vssadmin.exe invoked"},
    ]

    assert best_observable_match(
        "vssadmin.exe invoked",
        results,
    ) == 1.0


def test_best_match_returns_highest_score_not_first_score():
    results = [
        {"observable": "vssadmin"},
        {"observable": "completely unrelated"},
        {"observable": "vssadmin.exe invoked"},
    ]

    assert best_observable_match(
        "vssadmin.exe invoked",
        results,
    ) == 1.0

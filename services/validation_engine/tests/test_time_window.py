"""
Tests for the time-window bounding logic used to keep SIEM results that
are too far away in time from being counted as a match.
"""
from ve_app.time_window import filter_results_in_window, within_time_window

EVIDENCE_TS = "2026-06-17T09:12:00Z"


def test_result_at_same_timestamp_is_within_window():
    assert within_time_window(EVIDENCE_TS, "2026-06-17T09:12:00Z") is True


def test_result_a_few_seconds_later_is_within_default_window():
    assert within_time_window(EVIDENCE_TS, "2026-06-17T09:14:00Z") is True  # 2 minutes later


def test_result_an_hour_later_is_outside_default_window():
    assert within_time_window(EVIDENCE_TS, "2026-06-17T10:12:00Z") is False


def test_result_before_the_evidence_timestamp_can_still_be_in_window():
    assert within_time_window(EVIDENCE_TS, "2026-06-17T09:10:00Z") is True  # 2 minutes earlier


def test_window_seconds_is_configurable():
    far_result = "2026-06-17T09:20:00Z"  # 8 minutes later
    assert within_time_window(EVIDENCE_TS, far_result, window_seconds=300) is False
    assert within_time_window(EVIDENCE_TS, far_result, window_seconds=600) is True


def test_filter_results_in_window_drops_out_of_range_results():
    results = [
        {"observable": "in range", "timestamp": "2026-06-17T09:13:00Z"},
        {"observable": "out of range", "timestamp": "2026-06-17T12:00:00Z"},
    ]
    filtered = filter_results_in_window(EVIDENCE_TS, results)
    assert len(filtered) == 1
    assert filtered[0]["observable"] == "in range"


def test_filter_results_in_window_ignores_results_missing_timestamp():
    results = [{"observable": "no timestamp field"}]
    assert filter_results_in_window(EVIDENCE_TS, results) == []

def test_overlapping_windows_keep_results_for_both_attacks():
    """
    Two attacks occur close enough that their validation windows overlap.

    A result that falls inside both windows is valid for both attacks'
    time-window checks.
    """
    attack_one_ts = "2026-06-17T09:12:00Z"
    attack_two_ts = "2026-06-17T09:14:00Z"

    shared_result_ts = "2026-06-17T09:13:00Z"

    assert within_time_window(
        attack_one_ts,
        shared_result_ts,
    ) is True

    assert within_time_window(
        attack_two_ts,
        shared_result_ts,
    ) is True


def test_overlapping_windows_do_not_include_distant_results():
    """
    Overlapping windows must still reject results outside both windows.
    """
    attack_one_ts = "2026-06-17T09:12:00Z"
    attack_two_ts = "2026-06-17T09:14:00Z"

    distant_result_ts = "2026-06-17T10:30:00Z"

    assert within_time_window(
        attack_one_ts,
        distant_result_ts,
    ) is False

    assert within_time_window(
        attack_two_ts,
        distant_result_ts,
    ) is False


def test_filter_preserves_multiple_results_inside_overlapping_window():
    """
    Multiple SIEM results inside the validation window must all remain
    available for observable matching.
    """
    results = [
        {
            "observable": "attack-one activity",
            "timestamp": "2026-06-17T09:12:30Z",
        },
        {
            "observable": "attack-two activity",
            "timestamp": "2026-06-17T09:13:30Z",
        },
        {
            "observable": "unrelated old activity",
            "timestamp": "2026-06-17T12:00:00Z",
        },
    ]

    filtered = filter_results_in_window(
        EVIDENCE_TS,
        results,
    )

    assert len(filtered) == 2
    assert filtered[0]["observable"] == "attack-one activity"
    assert filtered[1]["observable"] == "attack-two activity"

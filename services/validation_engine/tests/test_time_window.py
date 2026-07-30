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

"""
Tests for MTTD (Mean Time To Detect) computation.
"""
from oc_app.mttd import compute_mttd


def test_mttd_is_zero_when_alert_and_attack_happen_at_the_same_instant():
    assert compute_mttd("2026-06-17T09:12:00Z", "2026-06-17T09:12:00Z") == 0.0


def test_mttd_computes_seconds_between_attack_and_alert():
    # attack at 09:12:00, alert 90 seconds later at 09:13:30
    assert compute_mttd("2026-06-17T09:12:00Z", "2026-06-17T09:13:30Z") == 90.0


def test_mttd_is_none_when_evidence_timestamp_missing():
    assert compute_mttd(None, "2026-06-17T09:13:30Z") is None


def test_mttd_is_none_when_alert_timestamp_missing():
    assert compute_mttd("2026-06-17T09:12:00Z", None) is None


def test_mttd_is_none_when_both_timestamps_missing():
    assert compute_mttd(None, None) is None


def test_mttd_reports_absolute_value_when_alert_precedes_attack_timestamp():
    """Clock skew / edge case: never report a negative MTTD."""
    result = compute_mttd("2026-06-17T09:12:30Z", "2026-06-17T09:12:00Z")
    assert result == 30.0

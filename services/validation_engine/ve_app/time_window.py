"""
Time-Window Bounding Logic -- Pod Beta, Week 4.

"Validation only considers evidence events within a configurable time
range around the simulated attack timestamp" (Technical Doc, Week 5
execution plan). A SIEM result that happens to mention the right
observable but occurred hours away from the simulated action is not
credible evidence of detection -- it's coincidence -- so results outside
the configured window are excluded before scoring.
"""
from datetime import datetime, timedelta, timezone

DEFAULT_WINDOW_SECONDS = 300  # 5 minutes, configurable per call


def parse_timestamp(ts: str) -> datetime:
    """Parses the ISO 8601 timestamps used throughout EvidenceEvent /
    SIEM results ("...Z" suffix included) into timezone-aware datetimes."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def within_time_window(evidence_timestamp: str, result_timestamp: str, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> bool:
    """
    True if result_timestamp falls within +/- window_seconds of
    evidence_timestamp. window_seconds is configurable per call so
    different rule types (e.g. slow-burn OT attacks vs. fast credential
    stuffing) can use different tolerances.
    """
    evidence_ts = parse_timestamp(evidence_timestamp)
    result_ts = parse_timestamp(result_timestamp)
    return abs(result_ts - evidence_ts) <= timedelta(seconds=window_seconds)


def filter_results_in_window(evidence_timestamp: str, results: list, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> list:
    """Convenience helper: keeps only the SIEM results whose timestamp
    falls inside the configured window around the evidence event."""
    return [
        r for r in results
        if "timestamp" in r and within_time_window(evidence_timestamp, r["timestamp"], window_seconds)
    ]

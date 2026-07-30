"""
MTTD (Mean Time To Detect) Computation -- Pod Beta, Week 5.

Measures the time difference between when a simulated attack action
actually happened (the evidence event's timestamp) and when the first
corresponding alert was raised (the matched SIEM result's timestamp).
This is the number security teams actually care about: not just "did we
detect it" but "how long did it take us to notice".
"""
from datetime import datetime
from typing import Optional


def _parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def compute_mttd(evidence_timestamp: Optional[str], alert_timestamp: Optional[str]) -> Optional[float]:
    """
    Returns the number of seconds between the attack's execution
    timestamp and the alert's timestamp, or None if either timestamp is
    missing (e.g. the action was Missed or NoData, so there is no alert
    to measure against).

    A negative raw difference (alert timestamp before the attack
    timestamp -- clock skew, or a coincidental earlier alert) is reported
    as its absolute value rather than a negative MTTD, since "time to
    detect" is never meaningfully negative.
    """
    if not evidence_timestamp or not alert_timestamp:
        return None

    attack_time = _parse_timestamp(evidence_timestamp)
    alert_time = _parse_timestamp(alert_timestamp)
    delta_seconds = (alert_time - attack_time).total_seconds()
    return round(abs(delta_seconds), 2)

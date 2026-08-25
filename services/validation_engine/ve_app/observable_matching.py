"""
Observable Matching -- Pod Beta, Week 9.

Confidence scoring between an expected observable and a SIEM observable.

Scoring:
    Exact match             -> 1.0
    Strong substring match  -> 0.7
    Partial token overlap   -> 0.0 - 0.6
    No meaningful overlap   -> 0.0
"""

from collections import Counter

STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "the",
    "to",
    "with",
}


def _meaningful_tokens(value: str) -> set[str]:
    """Return unique, non-generic tokens."""
    return {
        token
        for token in value.split()
        if token and token not in STOP_WORDS
    }


def match_observable(
    expected_observable: str,
    siem_observable: str,
) -> float:
    """
    Compare expected and SIEM observables and return a confidence score.
    """

    if not siem_observable:
        return 0.0

    expected = expected_observable.strip().lower()
    actual = siem_observable.strip().lower()

    if not expected:
        return 0.0

    # Exact match.
    if expected == actual:
        return 1.0

    expected_tokens = _meaningful_tokens(expected)
    actual_tokens = _meaningful_tokens(actual)

    if not expected_tokens or not actual_tokens:
        return 0.0

       # Strong substring match.
    # A true substring match gets 0.7, but repeated tokens in the
    # expected observable must not artificially increase confidence.
    expected_counts = Counter(expected.split())
    actual_counts = Counter(actual.split())

    has_duplicate_expected_tokens = any(
        count > 1 for count in expected_counts.values()
    )

    if not has_duplicate_expected_tokens:
        if expected in actual or actual in expected:
            if len(expected_tokens) >= 2 and len(actual_tokens) >= 2:
                return 0.7

    # Partial token overlap.
    overlap = expected_tokens & actual_tokens

    if not overlap:
        return 0.0

    # A single shared token is not enough evidence for a long
    # expected observable.
    if len(overlap) == 1 and len(expected_tokens) >= 4:
        return 0.0

    ratio = len(overlap) / len(expected_tokens)

    # Partial matches must remain below substring confidence.
    return round(min(ratio * 0.6, 0.6), 2)


def best_observable_match(
    expected_observable: str,
    siem_results: list,
) -> float:
    """
    Return the strongest match among multiple SIEM results.
    """

    if not siem_results:
        return 0.0

    scores = [
        match_observable(
            expected_observable,
            result.get("observable", ""),
        )
        for result in siem_results
    ]

    return max(scores)
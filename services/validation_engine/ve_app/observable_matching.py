"""
Observable Matching -- Pod Beta, Week 4.

Compares an EvidenceEvent's expected_observable against the observable
text returned by a SIEM connector's query results, and scores how well
they match. This is the "Confidence Score Logic: weighted matching" and
"Observable Matching" pieces of Week 4:

    Exact field matches   -> higher weight
    Partial field matches -> lower weight
    No match at all       -> 0.0

Score bands returned by match_observable():
    1.0            exact match (case-insensitive)
    0.7            one string contains the other (substring match)
    0.0 - 0.6      partial token overlap, scaled by how much overlaps
    0.0            no overlap at all
"""


def match_observable(expected_observable: str, siem_observable: str) -> float:
    """
    Weighted comparison between what we expected to see (from the
    evidence event) and what the SIEM connector actually returned.
    """
    if not siem_observable:
        return 0.0

    expected = expected_observable.strip().lower()
    actual = siem_observable.strip().lower()

    if not expected:
        return 0.0

    # Exact field match -> highest weight.
    if expected == actual:
        return 1.0

    # One fully contains the other -> strong (but not perfect) match.
    if expected in actual or actual in expected:
        return 0.7

    # Partial field match: score by token overlap, capped below the
    # substring-match band so a handful of shared words never outscores
    # an actual substring match.
    expected_tokens = set(expected.split())
    actual_tokens = set(actual.split())
    if not expected_tokens:
        return 0.0

    overlap = expected_tokens & actual_tokens
    ratio = len(overlap) / len(expected_tokens)
    return round(ratio * 0.6, 2)


def best_observable_match(expected_observable: str, siem_results: list) -> float:
    """
    Given several SIEM query results, returns the single best observable
    match score among them (a query can return multiple rows; we only
    care about the strongest evidence).
    """
    if not siem_results:
        return 0.0
    scores = [match_observable(expected_observable, r.get("observable", "")) for r in siem_results]
    return max(scores)

def compute_confidence(evidence, rule):
    """
    Week 2 weighted confidence scoring.

    Technique match provides the base score, while keyword evidence
    contributes the remaining confidence.
    """
    if rule.technique_ref != evidence.technique_ref:
        return 0.0

    if not rule.keywords:
        return 0.9

    observable_text = evidence.expected_observable.lower()
    matched = sum(
        1 for kw in rule.keywords
        if kw.lower() in observable_text
    )

    keyword_ratio = matched / len(rule.keywords)
    score = 0.2 + (0.8 * keyword_ratio)

    return round(min(score, 1.0), 2)

"""
Alert Fidelity Assessment -- Pod Beta, Week 5.

Classifies a Detected verdict's alert into High, Medium, or Low fidelity
based on how specific the detection actually was -- not just how
confident the number happens to be. A rule that exact-matched the
expected observable in a live SIEM result is a much higher-fidelity
signal than a rule that merely matched on MITRE technique with no
supporting detail.

match_specificity, when available from the Validation Engine's
Week 4 rule execution, is the primary signal:
    "exact"           -> High   (SIEM observable text matched exactly)
    "substring"        -> Medium (SIEM observable contained/was contained by the expected text)
    "partial"          -> Low    (only some keyword/token overlap)
    "flat_technique"    -> Low    (rule had no keyword detail; matched on technique alone)

If match_specificity isn't available (older/simpler rules, per Week 1-3),
fidelity falls back to the original confidence-band behaviour so nothing
that previously worked changes.
"""
from typing import Optional

SPECIFICITY_FIDELITY_MAP = {
    "exact": "high",
    "substring": "medium",
    "partial": "low",
    "flat_technique": "low",
}


def assess_fidelity(confidence: float, match_specificity: Optional[str] = None) -> str:
    if match_specificity in SPECIFICITY_FIDELITY_MAP:
        return SPECIFICITY_FIDELITY_MAP[match_specificity]

    # Fallback: no specificity detail supplied, use the original
    # confidence-band behaviour from Week 1-3.
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.7:
        return "medium"
    return "low"

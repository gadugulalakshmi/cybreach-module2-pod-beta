"""The v2.0 verdict contract as Beta publishes it.

This module is the single definition of the published verdict in Beta. It
previously existed twice -- once here with the old `integrity_hash` field and
once inline in `main.py` with the new `content_hash` -- so which shape a caller
got depended on which module they imported. The model now lives here only, and
`main.py` imports it.
"""
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

# Plan Section 5 / Delta's frozen schema
# (contracts/verdict-event/verdict.schema.json). These four values are the
# complete enum; nothing else is publishable.
VERDICT_DETECTED = "Detected"
VERDICT_MISSED = "Missed"
VERDICT_PARTIAL = "Partial"
VERDICT_NODATA = "NoData"

CANONICAL_VERDICTS = (
    VERDICT_DETECTED,
    VERDICT_MISSED,
    VERDICT_PARTIAL,
    VERDICT_NODATA,
)

# The plan's field set, exactly. The frozen schema sets
# `additionalProperties: false`, so a published event may contain these eight
# fields and nothing else.
CONTRACT_FIELDS = (
    "action_id",
    "verdict",
    "confidence",
    "causal_chain",
    "mttd_seconds",
    "matched_evidence_ref",
    "regulatory_control_refs",
    "content_hash",
)

# Legacy spellings callers still send, mapped to their canonical form.
#
# This normalisation is load-bearing, not cosmetic. `content_hash` is a digest
# over the serialised contract fields, so if Beta accepted "No Data" verbatim
# while Delta normalised it to "NoData", the two pods would derive different
# digests for the same event and Delta's `verify_content_hash` would reject
# Beta's event. Normalising at the edge keeps both sides hashing identical
# bytes. Mirrors Delta's alias table in
# app/contracts/verdict_event.py::_VERDICT_ALIASES.
_VERDICT_ALIASES = {
    "no data": VERDICT_NODATA,
    "nodata": VERDICT_NODATA,
    "no_data": VERDICT_NODATA,
    "detected": VERDICT_DETECTED,
    "missed": VERDICT_MISSED,
    "partial": VERDICT_PARTIAL,
    # "PartialDetection" is Beta's Outcome Classifier internal token.
    "partialdetection": VERDICT_PARTIAL,
}


class PublishedVerdict(BaseModel):
    """A verdict, ready to publish to `cybreach.verdicts.v2`.

    B2/B3: `content_hash` replaces `integrity_hash`, and
    `regulatory_control_refs` is now one of the eight required contract fields.
    Beta previously exposed neither the plan's field name nor one of its
    required fields, so every event Beta produced was invalid against the
    frozen schema.
    """

    action_id: str = Field(..., min_length=1)
    verdict: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    causal_chain: List[str] = Field(default_factory=list)
    mttd_seconds: Optional[float] = Field(default=None, ge=0.0)
    matched_evidence_ref: Optional[str] = None
    regulatory_control_refs: List[str] = Field(default_factory=list)
    content_hash: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")

    # Beta-local context. Accepted on input so the caller can keep sending its
    # internal identifiers, but deliberately not published: they are not in the
    # contract and the frozen schema rejects unknown properties.
    rule_id: Optional[str] = None
    technique_ref: Optional[str] = None

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalise_verdict(cls, value):
        """Fold legacy spellings to canonical form before hashing.

        Delta's frozen schema allows only the four canonical tokens, so an
        unnormalised value would be published successfully and then rejected by
        every consumer.
        """

        if not isinstance(value, str):
            return value

        return _VERDICT_ALIASES.get(value.strip().lower(), value.strip())

    @field_validator("verdict")
    @classmethod
    def _verdict_must_be_canonical(cls, value):
        if value not in CANONICAL_VERDICTS:
            raise ValueError(
                f"verdict must be one of {CANONICAL_VERDICTS}, got {value!r}"
            )

        return value

"""B5/M11: the Outcome Classifier must respect the same confidence scale and
causal-chain shape as every other pod."""
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from oc_app.main import app
from oc_app.models import OutcomeVerdict

client = TestClient(app)


class TestConfidenceBounds:
    """B5: the Validation Engine and Publisher constrained 0.0-1.0; this path
    accepted any float, so the same evidence could score 95 here and 0.95
    elsewhere and no threshold comparison behaved predictably."""

    def test_confidence_above_one_is_rejected(self):
        with pytest.raises(ValidationError):
            OutcomeVerdict(
                action_id="a",
                verdict="Detected",
                confidence=95,
                causal_chain=[],
            )

    def test_negative_confidence_is_rejected(self):
        with pytest.raises(ValidationError):
            OutcomeVerdict(
                action_id="a",
                verdict="Missed",
                confidence=-0.1,
                causal_chain=[],
            )

    @pytest.mark.parametrize("confidence", [0.0, 0.5, 0.95, 1.0])
    def test_unit_range_is_accepted(self, confidence):
        verdict = OutcomeVerdict(
            action_id="a",
            verdict="Detected",
            confidence=confidence,
            causal_chain=[],
        )

        assert verdict.confidence == confidence

    def test_api_rejects_out_of_range_confidence(self):
        response = client.post(
            "/classify",
            json={
                "action_id": "act-0001",
                "confidence": 95,
                "rule_id": "DET-001",
            },
        )

        assert response.status_code == 422


class TestCausalChainShape:
    """M11: the plan's `causal_chain` is `array of string`. Beta emitted a list
    of objects, so the same logical field had two incompatible shapes."""

    def test_contract_projection_is_a_list_of_strings(self):
        response = client.post(
            "/classify",
            json={
                "action_id": "act-0001",
                "confidence": 0.9,
                "rule_id": "DET-001",
            },
        )

        assert response.status_code == 200

        verdict = OutcomeVerdict(**response.json())

        # The rich object form is retained for the UI...
        assert all(hasattr(step, "description") for step in verdict.causal_chain)

        # ...and the v2.0 wire form is a flat list of strings.
        flat = verdict.causal_chain_strings

        assert flat
        assert all(isinstance(entry, str) for entry in flat)

    def test_entries_are_ordered_and_numbered(self):
        response = client.post(
            "/classify",
            json={
                "action_id": "act-0001",
                "confidence": 0.9,
                "rule_id": "DET-001",
            },
        )

        flat = OutcomeVerdict(**response.json()).causal_chain_strings

        assert flat[0].startswith("1.")
        assert flat[-1].startswith(f"{len(flat)}.")

    def test_evidence_ref_is_rendered_into_the_entry(self):
        from oc_app.models import CausalStep

        step = CausalStep(
            step_number=3, description="Rule executed", evidence_ref="ev-9"
        )

        assert step.as_contract_entry() == "3. Rule executed [ev-9]"

    def test_entry_without_evidence_ref_omits_the_marker(self):
        from oc_app.models import CausalStep

        step = CausalStep(step_number=1, description="Evidence received")

        assert step.as_contract_entry() == "1. Evidence received"

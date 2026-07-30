"""
Contract test: verifies the frozen evidence fixture conforms to both the
published JSON Schema and the Pydantic EvidenceEvent model.
"""
import json
from pathlib import Path

import pytest

from ve_app.models import EvidenceEvent

REPO_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = REPO_ROOT / "contracts" / "evidence_event_schema.json"
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "mock_evidence_events.json"


@pytest.fixture(scope="module")
def schema() -> dict:
    with open(SCHEMA_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def fixture_events() -> list:
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_fixture_is_not_empty(fixture_events):
    assert len(fixture_events) > 0


def test_fixture_conforms_to_json_schema(schema, fixture_events):
    import jsonschema
    for event in fixture_events:
        jsonschema.validate(instance=event, schema=schema)


def test_fixture_conforms_to_pydantic_model(fixture_events):
    for event in fixture_events:
        parsed = EvidenceEvent(**event)
        assert parsed.action_id == event["action_id"]


def test_fixture_covers_multiple_techniques(fixture_events):
    techniques = {e["technique_ref"] for e in fixture_events}
    assert len(techniques) >= 4

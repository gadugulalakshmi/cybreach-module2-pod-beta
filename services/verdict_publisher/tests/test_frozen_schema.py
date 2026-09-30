"""B2: Beta's published verdicts must validate against the frozen schema.

B2 recorded that the plan's frozen verdict schema "exists only as a
hand-maintained constant in Delta" and that nothing gated an actual verdict
against it. The schema now lives in the workspace contract registry
(`contracts/verdict-event/verdict.schema.json`), and this test is the gate.

The point is not that the publisher's field list *looks* right -- the publisher
already declares CONTRACT_FIELDS -- but that the payload the publisher actually
puts on `cybreach.verdicts.v2` satisfies the schema a third party would
validate against. That closes the gap where Beta and Delta could each be
internally consistent and still disagree on the wire.

Note the payload is `build_event(verdict)`, not the HTTP response body. The
response is the richer `PublishedVerdict` model and legitimately carries
`rule_id`/`technique_ref`, which are Beta-local context and are deliberately
stripped before publishing. Validating the response body would therefore be
validating the wrong object; these tests assert on what reaches the broker.

The schema is loaded from the shared registry, resolved relative to this file so
the test works from any working directory. If the registry is unreachable the
test fails rather than skipping: a missing contract registry is exactly the
condition this test exists to catch.
"""

import json
from pathlib import Path

import pytest

from fastapi.testclient import TestClient

from auth_helpers import auth_headers
from vp_app.main import app, build_event
from vp_app.models import PublishedVerdict, CONTRACT_FIELDS

jsonschema = pytest.importorskip("jsonschema", reason="jsonschema is required to gate the frozen contract")

# <workspace-root>/contracts/verdict-event/verdict.schema.json
SCHEMA_PATH = (
    Path(__file__).resolve().parents[4]
    / "contracts"
    / "verdict-event"
    / "verdict.schema.json"
)

client = TestClient(app)
# B11: /api/v2 is JWT-gated, so the suite's client presents a valid token.
client.headers.update(auth_headers())

VERDICTS = ["Detected", "Missed", "Partial", "NoData"]


@pytest.fixture(scope="module")
def schema():
    assert SCHEMA_PATH.exists(), (
        f"frozen verdict schema not found at {SCHEMA_PATH}. B2's resolution is to "
        "load the contract from the shared registry, so a missing registry is a "
        "failure, not a skip."
    )
    with open(SCHEMA_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def test_schema_is_a_valid_draft7_schema(schema):
    jsonschema.Draft7Validator.check_schema(schema)


def test_publisher_field_set_matches_the_schema_exactly(schema):
    """The publisher's declared field set and the schema must not drift."""

    assert set(CONTRACT_FIELDS) == set(schema["properties"]), (
        "Beta's CONTRACT_FIELDS and the frozen schema's properties disagree: "
        f"Beta-only={sorted(set(CONTRACT_FIELDS) - set(schema['properties']))} "
        f"schema-only={sorted(set(schema['properties']) - set(CONTRACT_FIELDS))}"
    )
    assert set(CONTRACT_FIELDS) == set(schema["required"]), (
        "the frozen schema requires fields the publisher does not treat as "
        f"required: {sorted(set(schema['required']) - set(CONTRACT_FIELDS))}"
    )


@pytest.mark.parametrize("verdict", VERDICTS)
def test_published_payload_validates_against_the_frozen_schema(
    schema, fake_producer, verdict
):
    response = client.post(
        "/api/v2/publish",
        json={
            "action_id": f"act-schema-{verdict}",
            "verdict": verdict,
            "confidence": 0.87,
            "mttd_seconds": 42.5,
            "matched_evidence_ref": "act-schema-1",
            "causal_chain": ["first observable", "second observable"],
            "regulatory_control_refs": ["ISO27001-A.5.15", "NIST-800-53-AC-2"],
        },
    )

    assert response.status_code == 200, response.text

    # The wire payload, as handed to the producer.
    assert len(fake_producer.sent) == 1
    topic, event = fake_producer.sent[0]
    assert topic == "cybreach.verdicts.v2"

    jsonschema.validate(instance=event, schema=schema)

    # `additionalProperties: false` is what makes this a contract, so the eight
    # contract fields must be the whole payload -- rule_id/technique_ref are
    # Beta-local and must not leak onto the bus.
    assert set(event) == set(CONTRACT_FIELDS)


@pytest.mark.parametrize("verdict", VERDICTS)
def test_build_event_output_validates(schema, verdict):
    """Validate the serialiser directly, independently of the HTTP layer.

    Testing build_event on its own keeps the route from masking a divergence
    between what the endpoint returns and what the serialiser emits.
    """

    from vp_app.main import compute_content_hash

    source = PublishedVerdict(
        action_id=f"act-build-{verdict}",
        verdict=verdict,
        confidence=0.5,
        mttd_seconds=None,
        matched_evidence_ref=None,
        causal_chain=[],
        regulatory_control_refs=[],
        rule_id="DET-001",
        technique_ref="T1486",
    )
    source.content_hash = compute_content_hash(source)

    event = build_event(source)

    jsonschema.validate(instance=event, schema=schema)
    assert set(event) == set(CONTRACT_FIELDS)


def test_schema_rejects_an_extra_field(schema):
    """`additionalProperties: false` is the property that makes the schema a
    contract. Confirm a stray field is actually refused, so the gate is real."""

    validator = jsonschema.Draft7Validator(schema)
    valid = {
        "action_id": "act-1",
        "verdict": "Detected",
        "confidence": 0.9,
        "mttd_seconds": None,
        "matched_evidence_ref": None,
        "causal_chain": [],
        "regulatory_control_refs": [],
        "content_hash": "0" * 64,
    }

    assert not list(validator.iter_errors(valid))
    assert list(validator.iter_errors({**valid, "integrity_hash": "legacy"}))
    assert list(validator.iter_errors({k: v for k, v in valid.items() if k != "content_hash"}))


def test_normalised_aliases_still_validate(schema, fake_producer):
    """A caller sending a legacy spelling must not be able to smuggle an
    off-contract verdict past the schema."""

    for alias in ("No Data", "nodata", "no_data", "PartialDetection"):
        response = client.post(
            "/api/v2/publish",
            json={
                "action_id": f"act-alias-{alias.replace(' ', '-')}",
                "verdict": alias,
                "confidence": 0.3,
            },
        )

        assert response.status_code == 200, response.text

        event = fake_producer.last_event
        jsonschema.validate(instance=event, schema=schema)

        # And it is the canonical spelling on the wire, not the alias.
        assert event["verdict"] in VERDICTS

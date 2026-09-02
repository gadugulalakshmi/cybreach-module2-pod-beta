# Week 3 – Evidence Ingestion & Rule Matching

## Task

Implement the evidence ingestion pipeline and rule-matching functionality so that evidence events can be processed and matched against validation rules.

## What I Implemented

- Implemented the Evidence Event ingestion pipeline.
- Read evidence events from local fixtures.
- Fed evidence into the Validation Engine.
- Developed a mock evidence replay mechanism.
- Simulated the Module 1 evidence event stream.
- Implemented rule matching logic.
- Added MITRE Technique ID based rule matching.
- Added Asset Class based rule matching.
- Added tests for evidence replay and rule matching.

## Implementation

### Evidence Ingestion

**File:** `services/validation_engine/ve_app/ingestion.py`

Implemented the ingestion logic for processing evidence events and feeding them into the Validation Engine.

### Rule Matching

**File:** `services/validation_engine/ve_app/rule_matching.py`

Implemented rule matching based on:

- MITRE Technique ID
- Asset Class

### Evidence Replay

Implemented a mock evidence replay mechanism to simulate the Module 1 evidence event stream during local testing.

## Testing

Relevant tests include:

- `services/validation_engine/tests/test_ingestion.py`
- `services/validation_engine/tests/test_rule_matching.py`
- `services/validation_engine/tests/test_replay_and_matching.py`

## Result

Week 3 established the Evidence Ingestion and Rule Matching pipeline required for the Validation Engine to process evidence and identify matching validation rules.
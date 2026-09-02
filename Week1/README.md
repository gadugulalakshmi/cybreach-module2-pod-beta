# Week 1 – Project Setup & Foundation

## Task

Set up the initial Pod Beta Validation Engine and Outcome Classifier architecture and define the core data contracts.

## What I Implemented

- Configured Docker Compose for local development.
- Set up PostgreSQL, Redis, and Kafka services.
- Created Pydantic models for Evidence Events and Verdicts.
- Defined the consumed Evidence Event contract from Module 1.
- Created mock evidence events for testing.
- Scaffolded the Validation Engine service.
- Scaffolded the Outcome Classifier service.
- Set up the shared pytest testing framework.

## Implementation

### Validation Engine

**File:** `services/validation_engine/ve_app/models.py`

**Classes:** `EvidenceEvent`, `Verdict`

Implemented the core data models required by the Validation Engine.

### Outcome Classifier

**File:** `services/outcome_classifier/oc_app/models.py`

**Classes:** `CausalStep`, `OutcomeVerdict`

Implemented the initial data structures required by the Outcome Classifier.

### Project Infrastructure

**Files:**

- `docker-compose.yml`
- `requirements.txt`
- `pytest.ini`
- `alembic.ini`
- `contracts/`

Configured the basic development and testing infrastructure.

## Testing

Relevant tests include:

- `services/validation_engine/tests/test_evidence_contract.py`
- `services/outcome_classifier/tests/test_classifier.py`

## Result

Week 1 established the project structure, infrastructure, data models, contracts, and testing foundation.
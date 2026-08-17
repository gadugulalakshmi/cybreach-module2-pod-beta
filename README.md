# Module 2 - Pod Beta (Validation Engine + Outcome Classifier)

## Folder map

* `docker-compose.yml` -- Postgres, Redis, Kafka for local dev
* `requirements.txt` -- Python packages needed for everything below
* `pytest.ini` -- lets one `pytest` command run both services' tests
* `alembic.ini` / `migrations/` -- database migrations (Week 2)
* `contracts/` -- the frozen EvidenceEvent contract consumed from Module 1
* `services/validation\_engine/` -- Service 1 (validation logic, confidence scoring, evidence ingestion pipeline)
* `services/outcome\_classifier/` -- Service 2 (verdict classification + causal chain)

## First-time setup

```
pip install -r requirements.txt
```

## Run the tests

```
pytest -v
```

123 tests should pass across both services (contract validation, evidence
ingestion, rule matching by technique and asset class, connector-based
rule execution with time-window bounding and observable matching,
outcome classification, causal chain analysis, alert fidelity, and MTTD
computation).

## Run the database migrations (needs Docker running)

```
docker compose up -d
alembic upgrade head
```

## Run the evidence ingestion demo (Week 3)

```
cd services/validation\_engine
python -m ve\_app.ingestion
```

This loads the mock evidence fixtures, replays them in timestamp order
through the Validation Engine, and prints a verdict for each one.

## What's done

### Week 1

* \[x] Configure Docker Compose (Postgres, Redis, Kafka)
* \[x] Create Pydantic models for EvidenceEvent and Verdict
* \[x] Publish consumed contract requirements from Module 1
* \[x] Create mock evidence events
* \[x] Scaffold Validation Engine project
* \[x] Scaffold Outcome Classifier project
* \[x] Set up shared testing framework (pytest)

### Week 2

* \[x] Build the Validation Engine models
* \[x] Build the Outcome Classifier models
* \[x] Create the database migrations for validation\_runs and evidence\_events
* \[x] Write the confidence scoring function (weighted keyword matching)
* \[x] Start the causal chain builder skeleton

### Week 3 (Person A -- Evidence Ingestion)

* \[x] Implement evidence event ingestion pipeline
* \[x] Read frozen evidence fixtures from the local repository
* \[x] Feed evidence into the Validation Engine
* \[x] Develop the mock evidence replay harness
* \[x] Simulate Module 1 evidence event stream

### Week 3 (Person B -- Rule Matching)

* \[x] Implement rule matching logic (`ve\_app/rule\_matching.py`)
* \[x] Match rules using MITRE Technique ID
* \[x] Match rules using Asset Class
* \[x] Test evidence replay and rule matching (`tests/test\_rule\_matching.py`, `tests/test\_replay\_and\_matching.py`)

### Week 4 (Validation Engine + Connector Framework Integration)

* \[x] Implement detection rule execution (`ve\_app/rule\_execution.py`)
* \[x] Execute rules against mock evidence events
* \[x] Compute confidence scores
* \[x] Generate raw validation results
* \[x] Integrate with BaseConnector (`ve\_app/connectors.py`)
* \[x] Use mock connectors for testing (`MockConnector`)
* \[x] Integration tests: evidence event input, rule execution, raw result generation (`tests/test\_rule\_execution\_integration.py`)
* \[x] Time-window bounding logic, configurable time range (`ve\_app/time\_window.py`)
* \[x] Weighted confidence scoring: exact vs partial field matches (`ve\_app/observable\_matching.py`)
* \[x] Expected observable matching vs SIEM query results

### Week 5 (Outcome Classifier)

* \[x] Complete Outcome Classifier implementation (raw result -> Detected/Missed/Partial/NoData)
* \[x] Causal chain analysis (`oc\_app/causal\_chain.py`) -- step-by-step reasoning per verdict
* \[x] Alert fidelity assessment (`oc\_app/fidelity.py`) -- High/Medium/Low by detection specificity
* \[x] MTTD computation (`oc\_app/mttd.py`) -- time between attack execution and first matching alert
* \[x] Tests: `test\_mttd.py`, `test\_fidelity.py`, `test\_causal\_chain.py`, `test\_classify\_week5.py`

### Week 6 (Performance Enhancements)

* \[x] Add batch validation support for multiple evidence events
* \[x] Implement `/validate/batch` endpoint
* \[x] Add Redis query-result caching with automatic TTL expiration
* \[x] Configure default Redis cache TTL of 60 seconds
* \[x] Implement parallel execution across multiple SIEM connectors using `ThreadPoolExecutor`
* \[x] Add tests for concurrent SIEM connector execution
* \[x] Add performance load test with 1,000 mock evidence events
* \[x] Measure total and average processing time for 1,000 events
* \[x] Verify all 1,000 events are processed successfully
* \[x] All tests passed: 123 passed

## Week 7 – Validation Engine & Outcome Processing

### Verdict Aggregation
- Implemented verdict aggregation for validation results.
- Supports Detected, Missed, Partial, and NoData outcomes.

### Regulatory Control Mapping
- Added regulatory control mapping support for:
  - NIST CSF 2.0
  - ISO 27001:2022
  - PCI-DSS 4.0
  - GDPR

### Incremental Validation
- Implemented incremental validation to process new evidence without unnecessary reprocessing.

### Validation Result Diffing
- Implemented validation result comparison to identify changes between validation runs.


## Week 8 – Validation Engine & Compliance Logic

### Engine Hardening & Reliability
- Implemented robust error handling for SIEM connector failures.
- Added graceful degradation with NoData results when a connector is unavailable.
- Added comprehensive audit logging for validation execution and connector failures.

### Evidence-Backed Compliance Verification
- Implemented explicit evidence reference validation.
- Controls can be marked as Met only when valid evidence is linked.
- Missing or invalid evidence results in NotMet.
- Missed, Partial, and NoData verdicts cannot be marked as Met.

### Validation
- 105 validation engine tests passed successfully.
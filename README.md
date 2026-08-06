# Module 2 - Pod Beta (Validation Engine + Outcome Classifier)

## Folder map
- `docker-compose.yml` -- Postgres, Redis, Kafka for local dev
- `requirements.txt` -- Python packages needed for everything below
- `pytest.ini` -- lets one `pytest` command run both services' tests
- `alembic.ini` / `migrations/` -- database migrations (Week 2)
- `contracts/` -- the frozen EvidenceEvent contract consumed from Module 1
- `services/validation_engine/` -- Service 1 (validation logic, confidence scoring, evidence ingestion pipeline)
- `services/outcome_classifier/` -- Service 2 (verdict classification + causal chain)

## First-time setup
```
pip install -r requirements.txt
```

## Run the tests
```
pytest -v
```
102 tests should pass across both services (contract validation, evidence
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
cd services/validation_engine
python -m ve_app.ingestion
```
This loads the mock evidence fixtures, replays them in timestamp order
through the Validation Engine, and prints a verdict for each one.

## What's done

### Week 1
- [x] Configure Docker Compose (Postgres, Redis, Kafka)
- [x] Create Pydantic models for EvidenceEvent and Verdict
- [x] Publish consumed contract requirements from Module 1
- [x] Create mock evidence events
- [x] Scaffold Validation Engine project
- [x] Scaffold Outcome Classifier project
- [x] Set up shared testing framework (pytest)

### Week 2
- [x] Build the Validation Engine models
- [x] Build the Outcome Classifier models
- [x] Create the database migrations for validation_runs and evidence_events
- [x] Write the confidence scoring function (weighted keyword matching)
- [x] Start the causal chain builder skeleton

### Week 3 (Person A -- Evidence Ingestion)
- [x] Implement evidence event ingestion pipeline
- [x] Read frozen evidence fixtures from the local repository
- [x] Feed evidence into the Validation Engine
- [x] Develop the mock evidence replay harness
- [x] Simulate Module 1 evidence event stream

### Week 3 (Person B -- Rule Matching)
- [x] Implement rule matching logic (`ve_app/rule_matching.py`)
- [x] Match rules using MITRE Technique ID
- [x] Match rules using Asset Class
- [x] Test evidence replay and rule matching (`tests/test_rule_matching.py`, `tests/test_replay_and_matching.py`)

### Week 4 (Validation Engine + Connector Framework Integration)
- [x] Implement detection rule execution (`ve_app/rule_execution.py`)
- [x] Execute rules against mock evidence events
- [x] Compute confidence scores
- [x] Generate raw validation results
- [x] Integrate with BaseConnector (`ve_app/connectors.py`)
- [x] Use mock connectors for testing (`MockConnector`)
- [x] Integration tests: evidence event input, rule execution, raw result generation (`tests/test_rule_execution_integration.py`)
- [x] Time-window bounding logic, configurable time range (`ve_app/time_window.py`)
- [x] Weighted confidence scoring: exact vs partial field matches (`ve_app/observable_matching.py`)
- [x] Expected observable matching vs SIEM query results

### Week 5 (Outcome Classifier)
- [x] Complete Outcome Classifier implementation (raw result -> Detected/Missed/Partial/NoData)
- [x] Causal chain analysis (`oc_app/causal_chain.py`) -- step-by-step reasoning per verdict
- [x] Alert fidelity assessment (`oc_app/fidelity.py`) -- High/Medium/Low by detection specificity
- [x] MTTD computation (`oc_app/mttd.py`) -- time between attack execution and first matching alert
- [x] Tests: `test_mttd.py`, `test_fidelity.py`, `test_causal_chain.py`, `test_classify_week5.py`

### Week 6 (Performance Enhancements)
- [x] Add batch validation support for multiple evidence events
- [x] Implement `/validate/batch` endpoint
- [x] Add Redis query-result caching with automatic TTL expiration
- [x] Configure default Redis cache TTL of 60 seconds
- [x] Implement parallel execution across multiple SIEM connectors using `ThreadPoolExecutor`
- [x] Add tests for concurrent SIEM connector execution
- [x] Add performance load test with 1,000 mock evidence events
- [x] Measure total and average processing time for 1,000 events
- [x] Verify all 1,000 events are processed successfully
- [x] All tests passed: 107 passed
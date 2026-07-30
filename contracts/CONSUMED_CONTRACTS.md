# Consumed Contract: Evidence Event (from Module 1)

**Owner:** Pod Beta (Validation Engine + Outcome Classifier)
**Source module:** Module 1 (The Strike Engine)
**Contract version:** v1.0

Pod Beta consumes the EvidenceEvent contract as a frozen JSON Schema plus
recorded fixtures, never calling Module 1's live code during build. See
`evidence_event_schema.json` for the schema and
`services/validation_engine/tests/fixtures/mock_evidence_events.json` for
sample data.

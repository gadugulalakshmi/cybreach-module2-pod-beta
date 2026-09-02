# Week 5 – Outcome Classifier

## Task

The main tasks for Week 5 were:

1. Complete the Outcome Classifier implementation.
2. Convert raw validation results into final outcomes:
   - Detected
   - Missed
   - Partial
   - NoData
3. Implement causal chain analysis.
4. Implement alert fidelity assessment.
5. Implement Mean Time to Detect (MTTD) calculation.
6. Add tests for the Outcome Classifier functionality.

## What I Implemented

### 1. Outcome Classification

**File:** `services/outcome_classifier/oc_app/main.py`

Implemented the Outcome Classifier logic to process raw validation results and generate the final outcome.

**Supported outcomes:**
- Detected
- Missed
- Partial
- NoData

The classifier determines the appropriate outcome based on the validation result and available evidence.

### 2. Causal Chain Analysis

**File:** `services/outcome_classifier/oc_app/causal_chain.py`

Implemented causal chain analysis to provide step-by-step reasoning for the generated verdict.

**What I did:**
- Built the causal chain from validation information.
- Represented the sequence of events contributing to the verdict.
- Connected validation evidence with the final outcome.

### 3. Alert Fidelity Assessment

**File:** `services/outcome_classifier/oc_app/fidelity.py`

Implemented alert fidelity assessment.

**What I did:**
- Evaluated how specifically an alert represents the detected activity.
- Classified alert fidelity as:
  - High
  - Medium
  - Low

### 4. MTTD Calculation

**File:** `services/outcome_classifier/oc_app/mttd.py`

Implemented Mean Time to Detect (MTTD) calculation.

**What I did:**
- Calculated the time between attack execution and the first matching alert.
- Used the detection timing to measure how quickly an activity was identified.

### 5. Outcome Classifier Models

**File:** `services/outcome_classifier/oc_app/models.py`

Used the Outcome Classifier models to represent the data required for causal-chain processing and outcome generation.

## Testing

Added and executed tests for the Week 5 functionality.

**Test files:**

- `services/outcome_classifier/tests/test_mttd.py`
- `services/outcome_classifier/tests/test_fidelity.py`
- `services/outcome_classifier/tests/test_causal_chain.py`
- `services/outcome_classifier/tests/test_classify_week5.py`

These tests cover outcome classification, MTTD calculation, alert fidelity, and causal chain analysis.

## Result

Week 5 completed the Outcome Classifier functionality.

Raw validation results can now be processed into final outcomes such as Detected, Missed, Partial, and NoData, with additional causal-chain analysis, alert fidelity assessment, and MTTD calculation.
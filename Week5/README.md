# Week 5 - Outcome Classification, Causal Chains & Alert Metrics

## Objective

Week 5 focused on extending the Outcome Classifier with causal-chain generation, alert fidelity evaluation, and Mean Time to Detect (MTTD) calculation.

## Tasks Completed

### 1. Causal Chain Generation

**File:** `outcome_classifier/oc_app/causal_chain.py`

Implemented causal-chain generation to explain how validation results lead to the final outcome.

The causal chain records key validation steps such as:

- Evidence event received
- Detection rule executed
- Confidence score generated
- Final verdict produced

This provides an explainable sequence behind the classification result.

### 2. Alert Fidelity

**File:** `outcome_classifier/oc_app/fidelity.py`

Implemented alert fidelity evaluation for measuring the quality of generated detection outcomes.

The implementation evaluates validation results against expected detection outcomes and provides fidelity-related metrics for the classifier.

### 3. Mean Time to Detect (MTTD)

**File:** `outcome_classifier/oc_app/mttd.py`

Implemented MTTD calculation to measure the time between attack execution and detection.

This provides a measurable indicator for evaluating detection responsiveness.

### 4. Outcome Classification Testing

Added automated tests covering the Week 5 Outcome Classifier functionality.

Test areas include:

- Causal-chain generation
- Outcome classification
- Alert fidelity calculation
- MTTD calculation

## Implementation Files

```text
Week5/
└── outcome_classifier/
    ├── oc_app/
    │   ├── causal_chain.py
    │   ├── fidelity.py
    │   └── mttd.py
    └── tests/
        ├── test_causal_chain.py
        ├── test_classify_week5.py
        ├── test_fidelity.py
        └── test_mttd.py
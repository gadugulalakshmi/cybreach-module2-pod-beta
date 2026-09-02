# Week 9 – Validation Engine & Outcome Classifier Optimization

## Task

The main tasks for Week 9 were:

1. Perform a comprehensive code review of the Validation Engine and Outcome Classifier.
2. Optimize the confidence score algorithm for accuracy and performance.
3. Improve observable matching.
4. Add edge-case test scenarios.
5. Test simultaneous attacks.
6. Test overlapping time windows.
7. Test multi-connector validation.
8. Verify parallel connector execution.
9. Perform a performance test using 1,000 events.
10. Create Validation Engine configuration documentation.

## What I Implemented

### 1. Confidence Score Optimization

Improved the confidence scoring logic to make matching more accurate and prevent false confidence.

**What I implemented:**

- Optimized confidence score calculation.
- Added meaningful token-based matching.
- Prevented duplicate tokens from artificially increasing confidence.
- Prevented unrelated long observables from producing false confidence.
- Improved case-insensitive matching.

### 2. Observable Matching Improvements

Improved observable matching so that evidence is compared more accurately against expected values.

**Match strength:**

| Match Type | Score |
|------------|-------|
| Exact | 1.0 |
| Strong substring | 0.7 |
| Partial token overlap | 0.0–0.6 |
| No meaningful overlap | 0.0 |

### 3. Edge-Case Testing

Added tests for scenarios that can create incorrect validation results.

**Test scenarios included:**

- Simultaneous attacks
- Overlapping time windows
- Multi-connector validation
- Duplicate tokens
- Special characters
- Long unrelated observables
- No meaningful overlap
- Connector failures
- Out-of-window results

### 4. Multi-Connector Validation

Verified validation when evidence is retrieved from multiple connectors.

**What I implemented:**

- Tested multiple SIEM connectors.
- Verified parallel connector execution.
- Used the existing `ThreadPoolExecutor` based execution model.
- Tested connector failure scenarios.

### 5. Performance Testing

Performed a load test using **1,000 mock evidence events**.

**Result:**

- Events processed: 1,000
- Processing time: approximately 0.0103 seconds
- Average processing time: approximately 0.0103 ms/event

### 6. Configuration Documentation

Created documentation describing the requirements and configuration needed to run the Validation Engine.

**Configuration includes:**

- Python 3.13+
- Docker Desktop
- Docker Compose
- Git
- Python dependencies
- `pip install -r requirements.txt`

## Testing

The optimized Validation Engine and Outcome Classifier were tested using the project test suite.

Testing covered:

- Confidence scoring
- Observable matching
- Edge cases
- Simultaneous attacks
- Overlapping time windows
- Multi-connector validation
- Connector failures
- Performance testing

The implementation was verified with the complete test suite.

## Result

Week 9 improved the accuracy, reliability, and performance of the Validation Engine and Outcome Classifier.

Confidence scoring and observable matching were optimized, edge cases were covered with additional tests, multi-connector validation was verified, and a 1,000-event performance test was completed.
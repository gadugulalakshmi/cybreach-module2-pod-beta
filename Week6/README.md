# Week 6 – Validation Engine Performance Enhancements

## Task

The main tasks for Week 6 were:

1. Add batch validation support.
2. Implement a batch validation API.
3. Cache SIEM query results using Redis.
4. Configure cache expiration using TTL.
5. Execute multiple SIEM connectors in parallel.
6. Add tests for parallel connector execution.
7. Perform a performance load test using 1,000 mock evidence events.

## What I Implemented

### 1. Batch Validation

Added support for processing multiple evidence events in a single validation request.

**What I did:**
- Added batch validation support.
- Enabled multiple evidence events to be processed together.
- Added the `/validate/batch` endpoint.

### 2. Redis Query-Result Caching

Implemented Redis caching to avoid repeatedly executing the same SIEM queries.

**What I did:**
- Added Redis-based query-result caching.
- Configured automatic cache expiration.
- Set the default cache TTL to **60 seconds**.

**Cache configuration:**

```text
DEFAULT_CACHE_TTL_SECONDS = 60
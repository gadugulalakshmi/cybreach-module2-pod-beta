# Verdict Publisher (vp_app), Pod Beta.
#
# N-B2: no deployable artefact existed for this service. See
# services/validation_engine/Dockerfile for the rationale; the build context is
# the pod root for the same reason.
#
#   docker build -f services/verdict_publisher/Dockerfile -t m2/verdict-publisher .
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY services/verdict_publisher/ ./services/verdict_publisher/

# kafka-python is imported at module scope by this service, so the pinned
# kafka-python from the pod manifest is what gets installed above.
#
# The shared topic manifest is NOT copied: it lives at the workspace root and
# the build context is this pod. Compose mounts it read-only and points
# M2_TOPICS_PATH at it; without that mount the service falls back to the
# pod-local topic constant.

ENV VP_PORT=8004 \
    KAFKA_BOOTSTRAP_SERVERS=kafka:29092

EXPOSE 8004

# No container healthcheck. This service's correctness depends on the broker
# being reachable, and a healthcheck that only probes the process's own /health
# would report healthy while every publish silently failed -- the publisher
# deliberately logs a broker outage rather than raising, precisely so an
# infrastructure failure does not become a 500 that loses the verdict. The
# endpoint's `kafka_connected` field is the honest signal and is left for the
# operator to read.
CMD ["uvicorn", "vp_app.main:app", "--host", "0.0.0.0", "--port", "8004"]

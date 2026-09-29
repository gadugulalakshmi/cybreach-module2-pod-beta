# Validation Engine (ve_app), Pod Beta.
#
# N-B2: there were no Dockerfiles anywhere in Beta, so the pod that produces
# the verdict the rest of the system depends on had no deployable artefact at
# all -- only an infra compose file.
#
# The context is the pod root, not this directory, because the pinned manifest
# and the shared topic manifest both live above the service:
#
#   docker build -f services/validation_engine/Dockerfile -t m2/validation-engine .
#
# PYTHONPATH is the service directory so `uvicorn ve_app.main:app` resolves the
# same way it does when the service is run directly on the host.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

# Dependencies are installed before the source is copied so an edit to the
# service does not invalidate the (slow) dependency layer.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY services/validation_engine/ ./services/validation_engine/

# The shared topic manifest is NOT copied: it lives at the workspace root, and
# the build context is this pod. Compose mounts it read-only and points
# M2_TOPICS_PATH at it. Without that mount the service still runs, on the
# pod-local topic constants.

ENV VE_PORT=8002 \
    KAFKA_EVIDENCE_ENABLED=false

EXPOSE 8002

# No healthcheck against the app here: the Validation Engine has no /health
# route, and adding one to satisfy a Dockerfile would be a change to the
# service's API surface for a packaging reason. Compose waits on nothing and
# the service is expected to come up independently of the broker -- the
# evidence consumer is opt-in and the API serves regardless.
CMD ["uvicorn", "ve_app.main:app", "--host", "0.0.0.0", "--port", "8002"]

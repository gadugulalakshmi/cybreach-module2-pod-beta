# Outcome Classifier (oc_app), Pod Beta.
#
# N-B2: no deployable artefact existed for this service. See
# services/validation_engine/Dockerfile for the rationale; the build context is
# the pod root for the same reason.
#
#   docker build -f services/outcome_classifier/Dockerfile -t m2/outcome-classifier .
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY services/outcome_classifier/ ./services/outcome_classifier/

ENV OC_PORT=8003

EXPOSE 8003

# This service is stateless and talks to no broker, so it is the one Beta
# service that is genuinely ready to serve the moment the container starts.
# The healthcheck is the port's own /health route.
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8003/health', timeout=3).status == 200 else 1)"

CMD ["uvicorn", "oc_app.main:app", "--host", "0.0.0.0", "--port", "8003"]

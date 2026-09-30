"""B11: the auth gate on Beta's three services must actually fail closed.

The gap B11 recorded was that Beta's whole `/api/v2` surface was reachable with
no credential at all. Adding a dependency is only half the fix -- these tests
pin the failure modes, so a later refactor that loosens the check (a permissive
default, a try/except around verification, a route that forgets the dependency)
fails here rather than silently reopening the pod.

Covered per service:
  * no Authorization header            -> 401
  * a non-bearer scheme                -> 401
  * a token signed with the wrong key  -> 401
  * an expired token                   -> 401
  * a valid token with no tenant_id    -> 403
  * a valid token with a blank tenant  -> 403
  * a valid token                      -> 200
  * /health stays public               -> 200 without a token
  * missing SECRET_KEY                 -> 500 (fail closed, not fail open)
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt

from auth_helpers import TEST_SECRET_KEY, TEST_TENANT_ID, auth_headers
from oc_app.main import app as classifier_app
from ve_app.main import app as engine_app
from vp_app.main import app as publisher_app


VALIDATE_BODY = {
    "evidence": {
        "action_id": "act-auth-001",
        "correlation_key": "camp-auth",
        "technique_ref": "T1486",
        "target_asset_ref": "host-01",
        "expected_observable": "vssadmin.exe invoked with cipher /e",
        "timestamp": "2026-06-17T09:12:00Z",
    },
    "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}],
}

CLASSIFY_BODY = {
    "action_id": "act-auth-001",
    "confidence": 0.9,
    "rule_id": "DET-001",
    "no_data": False,
}

PUBLISH_BODY = {
    "action_id": "act-auth-001",
    "verdict": "Detected",
    "confidence": 0.9,
}

# (app, path, body) for each of the three gated routes.
GATED_ROUTES = [
    (engine_app, "/api/v2/validate", VALIDATE_BODY),
    (classifier_app, "/api/v2/classify", CLASSIFY_BODY),
    (publisher_app, "/api/v2/publish", PUBLISH_BODY),
]

ROUTE_IDS = ["validate", "classify", "publish"]


@pytest.fixture(autouse=True)
def _no_broker(monkeypatch):
    """This suite lives outside the publisher's own tests dir, so that suite's
    autouse `get_producer` stub does not apply here. Without this, the `publish`
    cases would build a real KafkaProducer and attempt a live connection."""

    class _NullProducer:
        def send(self, topic, event):
            return None

        def flush(self):
            return None

    monkeypatch.setattr("vp_app.main.get_producer", lambda: _NullProducer())


def _token(**overrides) -> str:
    payload = {
        "sub": "test-user",
        "tenant_id": TEST_TENANT_ID,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    payload.update(overrides)
    return jwt.encode(payload, TEST_SECRET_KEY, algorithm="HS256")


def _expired_token() -> str:
    return _token(exp=datetime.now(timezone.utc) - timedelta(hours=1))


def _client(app) -> TestClient:
    """A client with no default auth, so each test states its own credential."""
    return TestClient(app)


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_rejects_request_with_no_authorization_header(app, path, body):
    assert _client(app).post(path, json=body).status_code == 401


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_rejects_a_non_bearer_scheme(app, path, body):
    resp = _client(app).post(
        path, json=body, headers={"Authorization": "Basic dXNlcjpwYXNz"}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_rejects_a_token_signed_with_a_different_key(app, path, body):
    forged = jwt.encode(
        {"sub": "attacker", "tenant_id": TEST_TENANT_ID},
        "not-the-module-secret",
        algorithm="HS256",
    )
    resp = _client(app).post(
        path, json=body, headers={"Authorization": f"Bearer {forged}"}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_rejects_an_expired_token(app, path, body):
    resp = _client(app).post(
        path, json=body, headers={"Authorization": f"Bearer {_expired_token()}"}
    )
    assert resp.status_code == 401


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_rejects_a_token_with_no_tenant_claim(app, path, body):
    token = _token()
    claims = jwt.get_unverified_claims(token)
    claims.pop("tenant_id", None)
    stripped = jwt.encode(claims, TEST_SECRET_KEY, algorithm="HS256")

    resp = _client(app).post(
        path, json=body, headers={"Authorization": f"Bearer {stripped}"}
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_rejects_a_blank_tenant_claim(app, path, body):
    resp = _client(app).post(
        path,
        json=body,
        headers={"Authorization": f"Bearer {_token(tenant_id='   ')}"},
    )
    assert resp.status_code == 403


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_accepts_a_valid_token(app, path, body):
    resp = _client(app).post(path, json=body, headers=auth_headers())
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize(
    "app", [engine_app, classifier_app, publisher_app], ids=ROUTE_IDS
)
def test_health_stays_public(app):
    """The run plan health-checks every pod without holding a credential."""
    assert _client(app).get("/health").status_code == 200


@pytest.mark.parametrize("app,path,body", GATED_ROUTES, ids=ROUTE_IDS)
def test_fails_closed_when_the_module_secret_is_unset(app, path, body, monkeypatch):
    """No configured secret must be a 500, never an unauthenticated 200.

    Defaulting `SECRET_KEY` to a shipped constant would make every deployment
    that forgot to configure one accept a token signed with a value published in
    the source.
    """
    monkeypatch.delenv("SECRET_KEY", raising=False)
    resp = _client(app).post(path, json=body, headers=auth_headers())
    assert resp.status_code == 500

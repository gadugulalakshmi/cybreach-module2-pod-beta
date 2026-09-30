"""
Shared auth helpers for the Beta suites.

B11: the three services now gate `/api/v2` on the module's shared JWT, so a test
that posts to a route has to present a token. Rather than copy token-minting
boilerplate into every module, each suite gets `auth_headers` and a client whose
default headers already carry one.

`SECRET_KEY` is assigned (not `setdefault`) here, before the app modules are
imported, because the security dependency reads it from the environment at call
time while `TestClient` objects are built at module import. Forcing the test
value keeps the suite hermetic: a developer's real `SECRET_KEY` in their shell
or `.env` would otherwise leave token minting and verification on different
secrets and fail every request with 401.
"""
import os

TEST_SECRET_KEY = "test-secret-key-0123456789abcdef"
TEST_TENANT_ID = "tenant-test-0001"

os.environ["SECRET_KEY"] = TEST_SECRET_KEY


def make_token(
    tenant_id: str = TEST_TENANT_ID,
    secret_key: str = TEST_SECRET_KEY,
    **claims,
) -> str:
    """Mint a token the way the other three pods' tests do."""
    from datetime import datetime, timedelta, timezone

    from jose import jwt

    payload = {
        "sub": "test-user",
        "tenant_id": tenant_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    payload.update(claims)
    return jwt.encode(payload, secret_key, algorithm="HS256")


def auth_headers(tenant_id: str = TEST_TENANT_ID, **claims) -> dict:
    return {"Authorization": f"Bearer {make_token(tenant_id, **claims)}"}


def authed_client(app, tenant_id: str = TEST_TENANT_ID):
    """A TestClient that sends a valid bearer token on every request."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    client.headers.update(auth_headers(tenant_id))
    return client

"""B11: shared JWT authentication and tenant scoping for this service.

The plan (Section 5, "Security Model") requires every `/api/v2` endpoint to be
JWT-authenticated. Before this module the pod's whole surface was open -- zero
`Depends(...)`, `OAuth2`, `APIKeyHeader` or `Authorization` references -- which
is the half of **B11** this pod still carried after Alpha and Delta were gated.

The design is the same one Alpha (`app/security/security.py`) and Delta
(`app/security/security.py`) use so one token works across the module:

* `SECRET_KEY` is env-only with **no default**. It is the shared module secret,
  so a pod cannot mint a token another pod would reject, and a pod with no
  configured secret fails closed (500) rather than serving unauthenticated.
* The signing algorithm is fixed to HS256, and the token's `aud` is not checked
  because every pod signs with the same module key; `iss`/`exp` are honoured if
  present.
* `get_current_tenant` requires a non-empty `tenant_id` claim. Tenant scoping is
  a data-layer concern (each query filters on it), not something the route guard
  can enforce, so the dependency's job is to fail fast and to hand the verified
  tenant to the handler.
"""

import os
from typing import Dict

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

ALGORITHM = "HS256"
security_scheme = HTTPBearer(auto_error=False)


def _require_secret_key() -> str:
    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SECRET_KEY is not configured",
        )
    return secret_key


def get_current_claims(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> Dict[str, object]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        return jwt.decode(
            credentials.credentials,
            _require_secret_key(),
            algorithms=[ALGORITHM],
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_tenant(
    claims: Dict[str, object] = Depends(get_current_claims),
) -> str:
    tenant_id = claims.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="tenant_id claim is required",
        )
    return tenant_id


def get_current_token(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> str:
    """The raw bearer token, for forwarding to another pod.

    `get_current_tenant` deliberately returns only the tenant so no handler can
    accidentally echo a token. Propagating the caller's own credential to Alpha
    is a different thing: Alpha resolves the tenant from the token, so
    re-minting a Beta token for the upstream call would report usage against the
    wrong tenant. The token is returned only after the same `get_current_claims`
    verification has run.
    """

    get_current_claims(credentials)
    return credentials.credentials


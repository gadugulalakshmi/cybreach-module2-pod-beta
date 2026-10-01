"""Service identity for Beta's background (Kafka) path.

B11 gates `/api/v2` on a caller-supplied bearer token, which the REST handlers
forward to Alpha. The evidence consumer has no caller: it wakes up on a message
off `cybreach.evidence.v1` and there is nobody to hand it a credential. On the
first live run of the B1 flow this surfaced as `401 Unauthorized` from Alpha on
every fetch, so `rules` was empty and every event was validated into a `NoData`
verdict -- a silently wrong answer rather than a failure.

Rather than let the consumer call Alpha anonymously (impossible: Alpha enforces
B11) or borrow a token from a request (there is none), Beta mints a short-lived
service token from the module's own shared secret. This is available because
B11 is symmetric: every pod signs with the same `SECRET_KEY`, so any pod can mint
a token its peers accept. That is a property of the agreed design, not a
workaround, but it is also a real trust assumption and is documented as one:

    **Anything able to publish to `cybreach.evidence.v1` is implicitly trusted
    to cause validation and publication as `B11_SERVICE_TENANT_ID`.** There is
    no per-producer identity on the bus, so the topic's ACLs are the boundary.
    A deployment that needs per-producer attribution needs a signed envelope on
    the topic; that is not built here.

The tenant is **not** defaulted. An unconfigured tenant means no identity, which
means no Alpha fetch and no publish, with a warning -- the same fail-closed
posture as a missing `SECRET_KEY`. Guessing a tenant here would silently
validate one tenant's evidence against another tenant's rules.
"""

import logging
import os
import time

from jose import jwt

from ve_app.security import ALGORITHM

logger = logging.getLogger(__name__)

# Explicit, no default: see the module docstring.
SERVICE_TENANT_ID = os.getenv("B11_SERVICE_TENANT_ID", "").strip()

SERVICE_SUBJECT = os.getenv("B11_SERVICE_SUBJECT", "beta-validation-engine").strip()

# Short, because the token is minted per use and only has to survive one hop.
SERVICE_TOKEN_TTL_SECONDS = int(os.getenv("B11_SERVICE_TOKEN_TTL_SECONDS", "300"))


def mint_service_token() -> str | None:
    """Mint a short-lived service token, or return None if not configured.

    Returning None rather than raising is deliberate: this runs on the consumer
    thread, where an exception would kill the loop, and the callers all treat a
    missing token as "do not make this call" rather than "fail the event".
    """

    if not SERVICE_TENANT_ID:
        logger.warning(
            "No service identity: B11_SERVICE_TENANT_ID is not set, so the Kafka "
            "path cannot authenticate to Alpha or to the Verdict Publisher. "
            "Events will be validated with no rules (NoData) and no verdict will "
            "be published. Set B11_SERVICE_TENANT_ID to enable the bus path."
        )
        return None

    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        logger.warning(
            "No service identity: SECRET_KEY is not configured, so no service "
            "token can be minted. The Kafka path stays inert rather than "
            "calling Alpha anonymously."
        )
        return None

    now = int(time.time())
    claims = {
        "sub": SERVICE_SUBJECT,
        "tenant_id": SERVICE_TENANT_ID,
        "role": "service",
        "iat": now,
        "exp": now + SERVICE_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(claims, secret_key, algorithm=ALGORITHM)


def service_identity_configured() -> bool:
    """True when the bus path has an identity. Used by `/health`."""

    return bool(SERVICE_TENANT_ID) and bool(os.environ.get("SECRET_KEY", ""))
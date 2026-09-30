"""M4: the Validation Engine must report rule usage back to Alpha.

M4 recorded that Alpha's `RuleDependencyTracker` existed to stop a rule being
edited or deleted while a validation run still depended on it, but no pod ever
called `POST /api/v2/rules/{rule_id}/dependencies`. The tracker was therefore
always empty, `dependent_count` was always 0, and `safe_to_delete` was
unconditionally `True` -- the exact guarantee the tracker exists to provide was
not in force.

These tests pin the three properties that matter:
  * a rule that actually ran is reported, to the URL Alpha serves;
  * a `NoData` verdict (sentinel `rule_id` "NONE") is not, because no such rule
    exists and the report would be a guaranteed 404;
  * a reporting failure never turns a successful validation into an error, and
    never blocks the verdict.
"""
import httpx
import pytest
from fastapi.testclient import TestClient

import ve_app.main as ve_main
from auth_helpers import auth_headers


EVIDENCE = {
    "action_id": "act-dep-001",
    "correlation_key": "camp-dep",
    "technique_ref": "T1486",
    "target_asset_ref": "host-fileserver-01",
    "expected_observable": "vssadmin.exe invoked with cipher /e",
    "timestamp": "2026-06-17T09:12:00Z",
}


@pytest.fixture
def client():
    return TestClient(ve_main.app)


@pytest.fixture
def reported(monkeypatch):
    """Capture outbound dependency reports instead of sending them."""
    calls = []

    class _Recorder:
        def __init__(self):
            self.calls = calls

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None, headers=None):
            calls.append({"url": url, "json": json, "headers": headers})
            return httpx.Response(200, json={"recorded": True})

    monkeypatch.setattr(ve_main.httpx, "AsyncClient", lambda *a, **k: _Recorder())
    monkeypatch.setattr(ve_main, "DEPENDENCY_REPORTING_ENABLED", True)
    return calls


def test_a_rule_that_ran_is_reported(client, reported):
    resp = client.post(
        "/api/v2/validate",
        json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}]},
        headers=auth_headers(),
    )
    assert resp.status_code == 200

    assert len(reported) == 1
    call = reported[0]
    assert call["url"].endswith("/DET-001/dependencies")
    assert call["json"]["dependent_type"] == "validation_run"
    assert call["json"]["dependent_id"] == "act-dep-001"
    assert call["json"]["metadata"]["verdict"] == "Detected"


def test_the_callers_token_is_forwarded_so_alpha_resolves_the_same_tenant(
    client, reported
):
    """Alpha scopes the rule by the token's `tenant_id` claim, not the body.

    Re-minting a token for the upstream call would record the dependency
    against whichever tenant Beta chose, which is the bug this guards.
    """
    headers = auth_headers("tenant-dep-9999")
    client.post(
        "/api/v2/validate",
        json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}]},
        headers=headers,
    )
    assert reported[0]["headers"]["Authorization"] == headers["Authorization"]


def test_a_nodata_verdict_is_not_reported(client, reported):
    """`rule_id` is the sentinel "NONE"; Alpha has no such rule."""
    resp = client.post(
        "/api/v2/validate",
        json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-001", "technique_ref": "T9999"}]},
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "NoData"
    assert reported == []


def test_every_rule_that_matched_in_a_batch_is_reported(client, reported):
    resp = client.post(
        "/api/v2/validate/batch",
        json={
            "evidence": [EVIDENCE, {**EVIDENCE, "action_id": "act-dep-002"}],
            "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}],
        },
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert [call["json"]["dependent_id"] for call in reported] == [
        "act-dep-001",
        "act-dep-002",
    ]


def test_reporting_is_off_unless_enabled(client, monkeypatch):
    """A pod running on its own has no Alpha; it must not pay for a call."""
    monkeypatch.setattr(ve_main, "DEPENDENCY_REPORTING_ENABLED", False)

    def _explode(*args, **kwargs):
        raise AssertionError("reporting ran while disabled")

    monkeypatch.setattr(ve_main.httpx, "AsyncClient", _explode)

    resp = client.post(
        "/api/v2/validate",
        json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}]},
        headers=auth_headers(),
    )
    assert resp.status_code == 200


def test_an_unreachable_alpha_does_not_fail_the_validation(client, monkeypatch):
    """Telemetry must never cost a verdict."""

    class _Broken:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            raise httpx.ConnectError("alpha is down")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(ve_main, "DEPENDENCY_REPORTING_ENABLED", True)
    monkeypatch.setattr(ve_main.httpx, "AsyncClient", _Broken)

    resp = client.post(
        "/api/v2/validate",
        json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}]},
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "Detected"


def test_a_rejected_report_does_not_fail_the_validation(client, monkeypatch):
    class _Rejecting:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None, headers=None):
            return httpx.Response(404, json={"detail": "no such rule"})

    monkeypatch.setattr(ve_main, "DEPENDENCY_REPORTING_ENABLED", True)
    monkeypatch.setattr(ve_main.httpx, "AsyncClient", _Rejecting)

    resp = client.post(
        "/api/v2/validate",
        json={"evidence": EVIDENCE, "rules": [{"rule_id": "DET-001", "technique_ref": "T1486"}]},
        headers=auth_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "Detected"

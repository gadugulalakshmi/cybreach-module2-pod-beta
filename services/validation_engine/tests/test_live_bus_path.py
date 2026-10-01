"""Tests for the live Kafka path's two missing links (B1, M4).

Both defects were found by booting the stack rather than by reading tests, and
both were invisible to the existing suite because it injects its own
synchronous `rule_provider` and never asserts that a verdict goes anywhere:

1. `fetch_alpha_rules` is a coroutine function but was injected as a sync
   provider, so the consumer cached a coroutine and every live event died with
   "'coroutine' object is not iterable".
2. The consumer validated and discarded: `on_verdict` was never set, so nothing
   reached `cybreach.verdicts.v2` and B1's acceptance step could not be met.

These tests pin the fix at both seams and pin the fail-closed behaviour when no
service identity is configured.
"""

import pytest

from ve_app.evidence_consumer import EvidenceConsumer
from ve_app.models import EvidenceEvent

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

EVIDENCE = {
    "action_id": "act-live-1",
    "correlation_key": "campaign-1",
    "technique_ref": "T1059",
    "target_asset_ref": "web-01",
    "expected_observable": "powershell.exe spawned",
    "timestamp": "2026-09-28T10:00:00Z",
}


def _rule():
    from ve_app.main import DetectionRule

    return DetectionRule(
        rule_id="DET-001",
        technique_ref="T1059",
        keywords=["powershell.exe"],
    )


class TestAsyncRuleProvider:
    """The provider may be sync or async; an async one must be awaited."""

    def test_async_provider_is_awaited_not_cached_as_a_coroutine(self):
        async def provider():
            return [_rule()]

        consumer = EvidenceConsumer(rule_provider=provider)
        rules = consumer._current_rules()

        assert [r.rule_id for r in rules] == ["DET-001"]

    def test_sync_provider_still_works(self):
        consumer = EvidenceConsumer(rule_provider=lambda: [_rule()])
        assert len(consumer._current_rules()) == 1

    def test_async_provider_failure_keeps_previous_rules(self):
        state = {"fail": False}

        async def provider():
            if state["fail"]:
                raise RuntimeError("alpha down")
            return [_rule()]

        consumer = EvidenceConsumer(rule_provider=provider)
        assert len(consumer._current_rules()) == 1

        state["fail"] = True
        consumer._rules_loaded_at = 0.0  # force a refresh

        # A stale set yields a possibly-wrong verdict; an empty set yields
        # NoData for everything. The consumer keeps the rules it had.
        assert len(consumer._current_rules()) == 1


class TestVerdictIsPublished:
    """A verdict produced from the bus must actually reach the bus."""

    def test_on_verdict_is_invoked_with_the_produced_verdict(self):
        seen = []

        consumer = EvidenceConsumer(
            rule_provider=lambda: [_rule()],
            on_verdict=lambda ev, verdict: seen.append((ev, verdict)),
        )

        verdict = consumer.handle(EVIDENCE)

        assert verdict is not None
        assert len(seen) == 1
        assert seen[0][0].action_id == "act-live-1"
        assert seen[0][1].verdict == verdict.verdict

    def test_malformed_event_does_not_publish(self):
        seen = []
        consumer = EvidenceConsumer(
            rule_provider=lambda: [_rule()],
            on_verdict=lambda ev, verdict: seen.append(verdict),
        )

        assert consumer.handle({"action_id": "broken"}) is None
        assert seen == []


class TestServiceIdentity:
    def test_no_tenant_configured_means_no_token(self, monkeypatch):
        from ve_app import service_identity as si

        monkeypatch.setattr(si, "SERVICE_TENANT_ID", "")
        monkeypatch.setenv("SECRET_KEY", "x" * 32)

        assert si.mint_service_token() is None
        assert si.service_identity_configured() is False

    def test_no_secret_key_means_no_token(self, monkeypatch):
        from ve_app import service_identity as si

        monkeypatch.setattr(si, "SERVICE_TENANT_ID", "acme")
        monkeypatch.delenv("SECRET_KEY", raising=False)

        assert si.mint_service_token() is None
        assert si.service_identity_configured() is False

    def test_configured_identity_mints_a_valid_tenant_token(self, monkeypatch):
        from jose import jwt

        from ve_app import service_identity as si

        monkeypatch.setattr(si, "SERVICE_TENANT_ID", "acme")
        monkeypatch.setenv("SECRET_KEY", "x" * 32)

        token = si.mint_service_token()
        assert token

        claims = jwt.decode(token, "x" * 32, algorithms=["HS256"])
        assert claims["tenant_id"] == "acme"
        assert claims["role"] == "service"
        assert si.service_identity_configured() is True


class TestVerdictProjection:
    """The publish path must match vp_app's frozen contract, not invent one."""

    def test_only_the_eight_contract_fields_are_sent(self):
        from ve_app.verdict_publish import verdict_to_published

        class _V:
            action_id = "act-1"
            verdict = "Detected"
            confidence = 0.9
            causal_chain = ["x"]
            mttd_seconds = 12.0
            matched_evidence_ref = "obs-1"
            regulatory_control_refs = ["GDPR 32"]
            rule_id = "DET-001"          # Beta-local, must be dropped
            technique_ref = "T1059"      # Beta-local, must be dropped
            content_hash = "deadbeef"    # vp_app recomputes it, must be dropped

        payload = verdict_to_published(_V())

        assert set(payload) == {
            "action_id",
            "verdict",
            "confidence",
            "causal_chain",
            "mttd_seconds",
            "matched_evidence_ref",
            "regulatory_control_refs",
        }
        assert "content_hash" not in payload
        assert "rule_id" not in payload
        assert "technique_ref" not in payload

    def test_disabled_publish_is_a_no_op(self, monkeypatch):
        from ve_app import verdict_publish as vp

        monkeypatch.setattr(vp, "PUBLISH_ENABLED", False)

        class _V:
            action_id = "act-1"
            verdict = "Detected"
            confidence = 0.9
            causal_chain = []
            mttd_seconds = None
            matched_evidence_ref = None
            regulatory_control_refs = []

        assert vp.publish_verdict(_V(), "token") is False

    def test_publish_without_a_token_is_refused(self, monkeypatch):
        from ve_app import verdict_publish as vp

        monkeypatch.setattr(vp, "PUBLISH_ENABLED", True)

        class _V:
            action_id = "act-1"
            verdict = "Detected"
            confidence = 0.9
            causal_chain = []
            mttd_seconds = None
            matched_evidence_ref = None
            regulatory_control_refs = []

        assert vp.publish_verdict(_V(), "") is False


class TestAlphaFetchReceivesTheServiceToken:
    def test_forwarded_token_reaches_the_alpha_request(self, monkeypatch):
        """M4: the token must be attached to the Alpha call, not dropped."""
        import asyncio

        import httpx

        from ve_app import main as ve

        captured = {}

        class _Resp:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return []

        class _Client:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url, headers=None):
                captured["url"] = url
                captured["headers"] = headers or {}
                return _Resp()

        monkeypatch.setattr(ve.httpx, "AsyncClient", _Client)
        monkeypatch.setattr(ve, "ALPHA_RULES_URL", "http://alpha/api/v2/rules/search")

        asyncio.run(ve.fetch_alpha_rules("service-token-abc"))

        assert captured["headers"].get("Authorization") == "Bearer service-token-abc"

    def test_no_token_sends_no_authorization_header(self, monkeypatch):
        import asyncio

        from ve_app import main as ve

        captured = {}

        class _Resp:
            def raise_for_status(self):
                return None

            def json(self):
                return []

        class _Client:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url, headers=None):
                captured["headers"] = headers or {}
                return _Resp()

        monkeypatch.setattr(ve.httpx, "AsyncClient", _Client)

        asyncio.run(ve.fetch_alpha_rules(None))

        assert "Authorization" not in captured["headers"]


class TestDefaultAlphaUrlIsARealRoute:
    def test_default_url_targets_the_search_route(self):
        """The old default was `/api/v2/rules`, which is not a route (404).

        Alpha serves the list at `/api/v2/rules/search`; every other path is
        parameterised. Pointing at the collection root made every fetch 404 and
        every verdict silently NoData.
        """

        from ve_app.main import ALPHA_RULES_URL

        assert ALPHA_RULES_URL.endswith("/api/v2/rules/search")
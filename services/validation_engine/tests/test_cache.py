"""
Tests for Redis cache helpers -- Pod Beta, Week 6.
"""

import time

import redis

from ve_app.cache import (
    DEFAULT_CACHE_TTL_SECONDS,
    get_cached_results,
    set_cached_results,
)


def test_cache_set_and_get():
    client = redis.Redis(
        host="localhost",
        port=6379,
        db=0,
        decode_responses=True,
    )

    client.flushdb()

    results = [
        {
            "observable": "vssadmin.exe seen",
            "timestamp": "2026-06-17T09:12:00Z",
        }
    ]

    time_range = (
        "2026-06-17T09:00:00Z",
        "2026-06-17T09:30:00Z",
    )

    set_cached_results(
        "DET-001",
        time_range,
        results,
        redis_client=client,
    )

    cached = get_cached_results(
        "DET-001",
        time_range,
        redis_client=client,
    )

    assert cached == results

    client.flushdb()


def test_cache_expires_after_ttl():
    client = redis.Redis(
        host="localhost",
        port=6379,
        db=0,
        decode_responses=True,
    )

    client.flushdb()

    results = [{"observable": "test-event"}]

    time_range = (
        "2026-06-17T09:00:00Z",
        "2026-06-17T09:30:00Z",
    )

    set_cached_results(
        "DET-TTL",
        time_range,
        results,
        ttl_seconds=1,
        redis_client=client,
    )

    assert get_cached_results(
        "DET-TTL",
        time_range,
        redis_client=client,
    ) == results

    time.sleep(2)

    assert get_cached_results(
        "DET-TTL",
        time_range,
        redis_client=client,
    ) is None

    client.flushdb()
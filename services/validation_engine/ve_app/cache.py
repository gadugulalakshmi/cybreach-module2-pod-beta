"""
Redis cache helpers for the Validation Engine -- Pod Beta, Week 6.

Caches SIEM query results so repeated queries can be served from Redis
instead of querying the connector again.

Cached entries automatically expire using a TTL.
"""

import json
import os
from typing import Any, Dict, List, Optional

import redis


DEFAULT_CACHE_TTL_SECONDS = 60


def get_redis_client() -> redis.Redis:
    """Create a Redis client using environment configuration."""
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        decode_responses=True,
    )


def build_cache_key(
    query_str: str,
    time_range: tuple[str, str],
) -> str:
    """Build a stable Redis key for a query and its time range."""
    start, end = time_range
    return f"validation_engine:query:{query_str}:{start}:{end}"


def get_cached_results(
    query_str: str,
    time_range: tuple[str, str],
    redis_client: Optional[redis.Redis] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Return cached query results, or None when the cache has no entry."""
    client = redis_client or get_redis_client()

    key = build_cache_key(query_str, time_range)
    cached = client.get(key)

    if cached is None:
        return None

    return json.loads(cached)


def set_cached_results(
    query_str: str,
    time_range: tuple[str, str],
    results: List[Dict[str, Any]],
    ttl_seconds: int = DEFAULT_CACHE_TTL_SECONDS,
    redis_client: Optional[redis.Redis] = None,
) -> None:
    """Store query results in Redis with automatic expiration."""
    client = redis_client or get_redis_client()

    key = build_cache_key(query_str, time_range)

    client.setex(
        key,
        ttl_seconds,
        json.dumps(results),
    )
"""Redis-backed sliding-window rate limiting, per app_id and per user_id.

Wired via Depends() so it composes with auth (Principal) and so tests can
override get_rate_limiter / get_redis with a fake or no-op via
app.dependency_overrides -- e.g. to force a 429 without sending hundreds
of requests, or to disable limiting entirely in unrelated tests.

Algorithm: sliding-window log using a Redis sorted set per key (member =
request timestamp, score = same timestamp). Each check trims entries
older than the window, adds the current request, and reads the
resulting cardinality. O(log N) per request, no separate cleanup job.
"""
from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

import redis.asyncio as redis
from fastapi import Depends, HTTPException, status

from app.middleware.auth import Principal, get_principal

REDIS_URL_ENV = "SENTRAGUARD_REDIS_URL"
# "redis" (default, real Redis or fakeredis) | "memory" (no Redis at all)
RATE_LIMIT_BACKEND_ENV = "SENTRAGUARD_RATE_LIMIT_BACKEND"

_redis_client: Optional[redis.Redis] = None


def get_redis() -> redis.Redis:
    """Lazily-initialized shared Redis client.

    Override in tests with app.dependency_overrides[get_redis] pointed at
    fakeredis.aioredis.FakeRedis() for a real-Redis-API-shaped fake with
    no server required, or a real Redis test container for full fidelity.
    """
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(
            os.environ.get(REDIS_URL_ENV, "redis://localhost:6379/0"),
            decode_responses=True,
        )
    return _redis_client


@dataclass(frozen=True)
class RateLimitConfig:
    app_id_limit: int = 600  # requests per window, per tenant
    app_id_window_s: int = 60
    user_id_limit: int = 60  # requests per window, per end user within a tenant
    user_id_window_s: int = 60


class RateLimiter:
    """Sliding-window rate limiter over a Redis sorted-set-per-key scheme."""

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()

    async def _check(
        self, client: redis.Redis, key: str, limit: int, window_s: int
    ) -> tuple[bool, int]:
        now = time.time()
        window_start = now - window_s
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zadd(key, {f"{now:.6f}:{id(object())}": now})
        pipe.zcard(key)
        pipe.expire(key, window_s)
        _, _, count, _ = await pipe.execute()
        return count <= limit, int(count)

    async def enforce(self, principal: Principal, client: redis.Redis) -> None:
        ok, _ = await self._check(
            client,
            f"ratelimit:app:{principal.app_id}",
            self.config.app_id_limit,
            self.config.app_id_window_s,
        )
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded for app_id={principal.app_id} "
                    f"({self.config.app_id_limit}/{self.config.app_id_window_s}s)"
                ),
            )
        if principal.user_id:
            ok, _ = await self._check(
                client,
                f"ratelimit:user:{principal.app_id}:{principal.user_id}",
                self.config.user_id_limit,
                self.config.user_id_window_s,
            )
            if not ok:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Rate limit exceeded for user_id={principal.user_id} "
                        f"({self.config.user_id_limit}/{self.config.user_id_window_s}s)"
                    ),
                )


class InMemoryRateLimiter:
    """Redis-free sliding-window limiter, process memory only.

    Same sliding-window-log algorithm as RateLimiter, backed by a
    collections.deque per key instead of a Redis sorted set. Useful for:
      - local dev before Redis is stood up
      - unit tests that shouldn't need any external service at all

    NOT suitable for a multi-process or multi-replica deployment: each
    worker/pod has its own memory, so limits are enforced per-instance,
    not globally. If you deploy more than one instance, use RateLimiter
    (Redis or fakeredis) instead so state is shared.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def _check(self, key: str, limit: int, window_s: int) -> bool:
        now = time.time()
        window_start = now - window_s
        async with self._lock:
            hits = self._hits[key]
            while hits and hits[0] < window_start:
                hits.popleft()
            hits.append(now)
            return len(hits) <= limit

    async def enforce(self, principal: Principal, client: object = None) -> None:
        # `client` accepted (and ignored) so this drops in wherever a
        # RateLimiter is expected without changing call sites.
        ok = await self._check(
            f"app:{principal.app_id}",
            self.config.app_id_limit,
            self.config.app_id_window_s,
        )
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded for app_id={principal.app_id} "
                    f"({self.config.app_id_limit}/{self.config.app_id_window_s}s)"
                ),
            )
        if principal.user_id:
            ok = await self._check(
                f"user:{principal.app_id}:{principal.user_id}",
                self.config.user_id_limit,
                self.config.user_id_window_s,
            )
            if not ok:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Rate limit exceeded for user_id={principal.user_id} "
                        f"({self.config.user_id_limit}/{self.config.user_id_window_s}s)"
                    ),
                )


def _build_default_limiter():
    backend = os.environ.get(RATE_LIMIT_BACKEND_ENV, "redis").lower()
    if backend == "memory":
        return InMemoryRateLimiter()
    return RateLimiter()


_rate_limiter = _build_default_limiter()


def get_rate_limiter():
    """Returns the process-wide limiter, chosen by SENTRAGUARD_RATE_LIMIT_BACKEND
    ("redis" [default] or "memory").

    Override in tests, e.g.:

    app.dependency_overrides[get_rate_limiter] = (
        lambda: RateLimiter(RateLimitConfig(app_id_limit=0, app_id_window_s=60))
    )
    to force every request to 429 without crafting hundreds of calls, or

    app.dependency_overrides[get_rate_limiter] = lambda: InMemoryRateLimiter()

    to test rate limiting end-to-end with zero external services.
    """
    return _rate_limiter


async def enforce_rate_limit(
    principal: Principal = Depends(get_principal),
    limiter=Depends(get_rate_limiter),
    client: redis.Redis = Depends(get_redis),
) -> Principal:
    """Composite dependency: resolves identity (auth) then enforces limits.

    Returns the Principal so route handlers get identity + rate limiting
    from a single Depends(), matching the get_registry / get_policy style
    already used in main.py.

    `client` is only actually used when `limiter` is a RateLimiter (Redis
    backend); InMemoryRateLimiter ignores it. It's still resolved via
    Depends(get_redis) unconditionally today for simplicity -- if you run
    purely in-memory long-term, gate this behind the same backend env var
    so no Redis connection is attempted at all.
    """
    await limiter.enforce(principal, client)
    return principal
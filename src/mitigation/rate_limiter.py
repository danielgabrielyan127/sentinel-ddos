"""
Sentinel DDoS — Redis-backed Rate Limiter.

Sliding-window rate limiter using Redis sorted sets.
Supports per-IP, per-subnet, and global limits.
"""

from __future__ import annotations

import logging
import time
import uuid
from ipaddress import IPv4Address, IPv4Network

from src.config import settings
from src.storage.redis_client import redis_manager

logger = logging.getLogger("sentinel.mitigation.rate_limiter")


class RateLimiter:
    """
    Sliding-window rate limiter.

    Uses Redis sorted sets keyed on IP / subnet / global
    with timestamps as scores to provide accurate per-minute windows.
    """

    WINDOW_SEC = 60  # 1-minute sliding window

    async def allow(self, client_ip: str) -> bool:
        """Return True if the request is within rate limits."""
        redis = redis_manager.client
        if redis is None:
            return True  # No Redis → fail-open

        now = time.time()
        window_start = now - self.WINDOW_SEC
        # Unique member per request so zadd doesn't deduplicate
        member = f"{now}:{uuid.uuid4().hex[:8]}"

        # ── Per-IP limit ─────────────────────────────────
        ip_key = f"rl:ip:{client_ip}"
        if not await self._check_key(ip_key, now, window_start, member, settings.rate_limit_per_ip):
            return False

        # ── Per-Subnet (/24) limit ───────────────────────
        subnet = self._ip_to_subnet(client_ip)
        sub_key = f"rl:sub:{subnet}"
        if not await self._check_key(sub_key, now, window_start, member, settings.rate_limit_per_subnet):
            return False

        # ── Global limit ─────────────────────────────────
        global_key = "rl:global"
        if not await self._check_key(global_key, now, window_start, member, settings.rate_limit_global):
            return False

        return True

    async def allow_with_count(self, client_ip: str) -> tuple[bool, int]:
        """Like allow(), but also returns the current per-IP request count."""
        redis = redis_manager.client
        if redis is None:
            return True, 0

        now = time.time()
        window_start = now - self.WINDOW_SEC
        member = f"{now}:{uuid.uuid4().hex[:8]}"

        ip_key = f"rl:ip:{client_ip}"
        if not await self._check_key(ip_key, now, window_start, member, settings.rate_limit_per_ip):
            count = await self._get_count(ip_key, window_start)
            return False, count

        subnet = self._ip_to_subnet(client_ip)
        sub_key = f"rl:sub:{subnet}"
        if not await self._check_key(sub_key, now, window_start, member, settings.rate_limit_per_subnet):
            count = await self._get_count(ip_key, window_start)
            return False, count

        global_key = "rl:global"
        if not await self._check_key(global_key, now, window_start, member, settings.rate_limit_global):
            count = await self._get_count(ip_key, window_start)
            return False, count

        count = await self._get_count(ip_key, window_start)
        return True, count

    async def check_rule_limit(
        self, client_ip: str, rule_name: str, limit: int, window_sec: int,
    ) -> tuple[bool, int]:
        """
        Check a per-rule rate limit (e.g. "5/minute" for /api/login).
        Returns (allowed, current_count).
        """
        redis = redis_manager.client
        if redis is None:
            return True, 0

        now = time.time()
        window_start = now - window_sec
        member = f"{now}:{uuid.uuid4().hex[:8]}"
        key = f"rl:rule:{rule_name}:{client_ip}"

        pipe = redis.pipeline()
        pipe.zremrangebyscore(key, "-inf", window_start)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.expire(key, window_sec + 10)
        results = await pipe.execute()
        count = results[2]
        return count <= limit, count

    async def get_ip_count(self, client_ip: str) -> int:
        """Current request count for an IP in the window."""
        redis = redis_manager.client
        if redis is None:
            return 0
        window_start = time.time() - self.WINDOW_SEC
        return await self._get_count(f"rl:ip:{client_ip}", window_start)

    # ── Internal ─────────────────────────────────────────

    async def _get_count(self, key: str, window_start: float) -> int:
        redis = redis_manager.client
        if redis is None:
            return 0
        return await redis.zcount(key, window_start, "+inf")

    async def _check_key(
        self, key: str, now: float, window_start: float, member: str, limit: int,
    ) -> bool:
        redis = redis_manager.client
        if redis is None:
            return True
        pipe = redis.pipeline()
        pipe.zremrangebyscore(key, "-inf", window_start)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.expire(key, self.WINDOW_SEC + 10)
        results = await pipe.execute()
        count = results[2]  # zcard result
        return count <= limit

    @staticmethod
    def _ip_to_subnet(ip: str) -> str:
        """Convert an IP address to its /24 subnet."""
        try:
            addr = IPv4Address(ip)
            network = IPv4Network(f"{addr}/24", strict=False)
            return str(network)
        except ValueError:
            return ip


rate_limiter = RateLimiter()

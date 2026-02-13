"""
Sentinel DDoS — Redis Client Manager.

Manages async Redis connection lifecycle.
"""

from __future__ import annotations

import logging
from typing import Optional

import redis.asyncio as aioredis

from src.config import settings

logger = logging.getLogger("sentinel.storage.redis")


class RedisManager:
    """Manages a shared async Redis connection pool."""

    def __init__(self) -> None:
        self.client: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        """Connect to Redis."""
        client = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=50,
        )
        # Test connection — if this fails, self.client stays None
        await client.ping()
        self.client = client
        logger.info("Redis connected: %s", settings.redis_url)

    async def disconnect(self) -> None:
        """Close Redis connection."""
        if self.client:
            await self.client.close()
            self.client = None
            logger.info("Redis disconnected")

    async def health_check(self) -> bool:
        """Check if Redis is reachable."""
        try:
            if self.client:
                await self.client.ping()
                return True
        except Exception:
            pass
        return False


redis_manager = RedisManager()

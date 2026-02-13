"""
Sentinel DDoS — IP / Subnet Blocker.

Manages blocklist and allowlist using Redis sets
with optional TTL for temporary blocks.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from src.storage.redis_client import redis_manager

logger = logging.getLogger("sentinel.mitigation.blocker")


class IPBlocker:
    """Manages IP and subnet blocking via Redis."""

    BLOCKLIST_KEY = "sentinel:blocklist"
    ALLOWLIST_KEY = "sentinel:allowlist"

    async def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        redis = redis_manager.client
        if redis is None:
            return False

        # Allowlist takes priority
        if await redis.sismember(self.ALLOWLIST_KEY, ip):
            return False

        # Check individual IP block
        if await redis.exists(f"block:{ip}"):
            return True

        # Check set-based blocklist
        return await redis.sismember(self.BLOCKLIST_KEY, ip)

    async def block(
        self,
        ip: str,
        reason: str = "",
        duration_sec: Optional[int] = None,
    ) -> None:
        """Block an IP address, optionally with TTL."""
        redis = redis_manager.client
        if redis is None:
            return

        block_data = {
            "ip": ip,
            "reason": reason,
            "blocked_at": time.time(),
        }

        if duration_sec:
            await redis.set(f"block:{ip}", reason, ex=duration_sec)
            logger.info(
                "Blocked %s for %ds — reason: %s", ip, duration_sec, reason,
            )
        else:
            await redis.sadd(self.BLOCKLIST_KEY, ip)
            logger.info("Permanently blocked %s — reason: %s", ip, reason)

    async def unblock(self, ip: str) -> None:
        """Remove IP from all blocklists."""
        redis = redis_manager.client
        if redis is None:
            return
        await redis.delete(f"block:{ip}")
        await redis.srem(self.BLOCKLIST_KEY, ip)
        logger.info("Unblocked %s", ip)

    async def allow(self, ip: str) -> None:
        """Add IP to allowlist (always permitted)."""
        redis = redis_manager.client
        if redis is None:
            return
        await redis.sadd(self.ALLOWLIST_KEY, ip)
        logger.info("Allowlisted %s", ip)

    async def get_blocked_ips(self) -> list[str]:
        """Return all permanently blocked IPs."""
        redis = redis_manager.client
        if redis is None:
            return []
        members = await redis.smembers(self.BLOCKLIST_KEY)
        return [m.decode() if isinstance(m, bytes) else m for m in members]


ip_blocker = IPBlocker()

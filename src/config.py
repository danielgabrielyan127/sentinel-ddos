"""
Sentinel DDoS — Configuration via Pydantic Settings.

All settings are loaded from environment variables or .env file.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class ProtectionLevel(str, Enum):
    """Global protection level (graduated response)."""
    MONITOR = "monitor"          # Level 0 — observe only
    JS_CHALLENGE = "js_challenge"  # Level 1 — JS challenge for suspicious
    RATE_LIMIT = "rate_limit"    # Level 2 — enforce rate limits
    BLOCK = "block"              # Level 3 — block IPs / subnets
    BLACKHOLE = "blackhole"      # Level 4 — full block + alert


class Settings(BaseSettings):
    """Application-wide settings loaded from env / .env."""

    # ── General ──────────────────────────────────────────────
    app_name: str = "Sentinel DDoS"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"

    # ── Reverse Proxy ────────────────────────────────────────
    target_url: str = Field(
        default="http://localhost:3000",
        description="Upstream application URL to proxy traffic to",
    )
    proxy_timeout: float = Field(
        default=30.0,
        description="Timeout in seconds for upstream requests",
    )

    # ── Redis ────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for rate limits and counters",
    )

    # ── Database ─────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./sentinel.db",
        description="SQLAlchemy database URL for persistent storage",
    )

    # ── Protection ───────────────────────────────────────────
    protection_level: ProtectionLevel = ProtectionLevel.MONITOR
    under_attack_mode: bool = False

    # ── Rate Limits ──────────────────────────────────────────
    rate_limit_per_ip: int = Field(
        default=100, description="Requests per minute per IP",
    )
    rate_limit_per_subnet: int = Field(
        default=1000, description="Requests per minute per /24 subnet",
    )
    rate_limit_global: int = Field(
        default=10000, description="Requests per minute global",
    )

    # ── AI / Detection ───────────────────────────────────────
    baseline_learning_hours: int = Field(
        default=24,
        description="Hours of traffic to observe before baseline is ready",
    )
    anomaly_threshold: float = Field(
        default=0.75,
        description="Anomaly score threshold (0–1) to trigger escalation",
    )

    # ── GeoIP ────────────────────────────────────────────────
    geoip_db_path: Optional[str] = Field(
        default=None, description="Path to MaxMind GeoLite2 City database",
    )

    # ── Alerts ───────────────────────────────────────────────
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    webhook_url: Optional[str] = None

    # ── Rules ────────────────────────────────────────────────
    rules_dir: str = Field(
        default="rules/", description="Directory with YAML rule files",
    )

    # ── Dashboard ────────────────────────────────────────────
    dashboard_enabled: bool = True
    dashboard_username: str = "admin"
    dashboard_password: str = "sentinel"
    jwt_secret: str = "change-me-in-production"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"debug", "info", "warning", "error", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v.lower()

    model_config = {
        "env_prefix": "SENTINEL_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# Singleton
settings = Settings()

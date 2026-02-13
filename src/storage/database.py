"""
Sentinel DDoS — SQLite Database (async via aiosqlite).

Stores configuration, rules history, attack logs, and session data.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, Boolean, func
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from src.config import settings

logger = logging.getLogger("sentinel.storage.database")


# ── ORM Base ─────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


# ── Models ───────────────────────────────────────────────


class AttackLog(Base):
    """Persisted log of detected attacks."""
    __tablename__ = "attack_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    attack_type = Column(String(50), nullable=True)
    threat_score = Column(Float, nullable=False)
    action_taken = Column(String(50), nullable=False)  # blocked / challenged / monitored
    path = Column(String(2048), nullable=True)
    method = Column(String(10), nullable=True)
    user_agent = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)


class BlockedIP(Base):
    """Persistent IP blocklist (supplements Redis)."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False, unique=True, index=True)
    reason = Column(Text, nullable=True)
    blocked_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)


class TrafficSnapshot(Base):
    """Minute-by-minute traffic snapshots for dashboard history."""
    __tablename__ = "traffic_snapshots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False)
    requests_per_second = Column(Float, default=0.0)
    unique_ips = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)
    avg_threat_score = Column(Float, default=0.0)


# ── Engine & Session ─────────────────────────────────────

engine = create_async_engine(settings.database_url, echo=False)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    """Create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created / verified")


async def get_session() -> AsyncSession:
    """Dependency: yield an async DB session."""
    async with async_session() as session:
        yield session

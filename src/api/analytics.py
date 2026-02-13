"""
Sentinel DDoS — Analytics API Routes.

Provides historical attack data, time-series analytics,
and aggregated statistics from the database.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Query
from sqlalchemy import func, select, and_, desc, text

from src.storage.database import async_session, AttackLog, TrafficSnapshot

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/attacks")
async def get_attack_history(
    hours: int = Query(24, ge=1, le=720, description="Hours of history"),
    limit: int = Query(100, ge=1, le=1000),
    attack_type: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
):
    """
    Return recent attack events from the database.
    Supports filtering by time window, attack type, action, and IP.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    async with async_session() as session:
        stmt = select(AttackLog).where(AttackLog.timestamp >= since)

        if attack_type:
            stmt = stmt.where(AttackLog.attack_type == attack_type)
        if action:
            stmt = stmt.where(AttackLog.action_taken == action)
        if ip:
            stmt = stmt.where(AttackLog.source_ip == ip)

        stmt = stmt.order_by(desc(AttackLog.timestamp)).limit(limit)
        result = await session.execute(stmt)
        rows = result.scalars().all()

    return {
        "attacks": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp is not None else None,
                "source_ip": r.source_ip,
                "attack_type": r.attack_type,
                "threat_score": r.threat_score,
                "action_taken": r.action_taken,
                "path": r.path,
                "method": r.method,
                "user_agent": r.user_agent,
            }
            for r in rows
        ],
        "count": len(rows),
        "window_hours": hours,
    }


@router.get("/attacks/timeline")
async def get_attack_timeline(
    hours: int = Query(24, ge=1, le=720),
    bucket_minutes: int = Query(5, ge=1, le=60),
):
    """
    Return attack counts bucketed by time intervals.
    Useful for time-series charts.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    async with async_session() as session:
        # Fetch all attacks in the time window
        stmt = (
            select(AttackLog.timestamp, AttackLog.attack_type, AttackLog.action_taken)
            .where(AttackLog.timestamp >= since)
            .order_by(AttackLog.timestamp)
        )
        result = await session.execute(stmt)
        rows = result.all()

    # Bucket into time intervals
    bucket_sec = bucket_minutes * 60
    buckets: dict[int, dict] = {}

    for ts, attack_type, action in rows:
        if ts is None:
            continue
        epoch = int(ts.timestamp())
        bucket_key = (epoch // bucket_sec) * bucket_sec

        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "timestamp": bucket_key,
                "total": 0,
                "blocked": 0,
                "rate_limited": 0,
                "challenged": 0,
                "monitored": 0,
                "by_type": {},
            }
        b = buckets[bucket_key]
        b["total"] += 1

        if action == "blocked":
            b["blocked"] += 1
        elif action == "rate_limited":
            b["rate_limited"] += 1
        elif action == "challenged":
            b["challenged"] += 1
        elif action == "monitored":
            b["monitored"] += 1

        if attack_type:
            b["by_type"][attack_type] = b["by_type"].get(attack_type, 0) + 1

    # Sort by time
    timeline = sorted(buckets.values(), key=lambda x: x["timestamp"])

    return {
        "timeline": timeline,
        "bucket_minutes": bucket_minutes,
        "window_hours": hours,
    }


@router.get("/attacks/top-ips")
async def get_top_attacking_ips(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(20, ge=1, le=100),
):
    """
    Return the top attacking IPs by event count.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    async with async_session() as session:
        stmt = (
            select(
                AttackLog.source_ip,
                func.count().label("event_count"),
                func.avg(AttackLog.threat_score).label("avg_score"),
                func.max(AttackLog.timestamp).label("last_seen"),
            )
            .where(AttackLog.timestamp >= since)
            .group_by(AttackLog.source_ip)
            .order_by(desc("event_count"))
            .limit(limit)
        )
        result = await session.execute(stmt)
        rows = result.all()

    return {
        "top_ips": [
            {
                "ip": r.source_ip,
                "event_count": r.event_count,
                "avg_score": round(float(r.avg_score or 0), 3),
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in rows
        ],
        "window_hours": hours,
    }


@router.get("/attacks/by-type")
async def get_attacks_by_type(
    hours: int = Query(24, ge=1, le=720),
):
    """
    Aggregate attack counts by attack_type.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    async with async_session() as session:
        stmt = (
            select(
                AttackLog.attack_type,
                func.count().label("count"),
                func.avg(AttackLog.threat_score).label("avg_score"),
            )
            .where(AttackLog.timestamp >= since)
            .group_by(AttackLog.attack_type)
            .order_by(desc("count"))
        )
        result = await session.execute(stmt)
        rows = result.all()

    return {
        "by_type": [
            {
                "attack_type": r.attack_type or "unknown",
                "count": r.count,
                "avg_score": round(float(r.avg_score or 0), 3),
            }
            for r in rows
        ],
        "window_hours": hours,
    }


@router.get("/summary")
async def get_analytics_summary(
    hours: int = Query(24, ge=1, le=720),
):
    """
    High-level summary of attack activity.
    """
    since = datetime.utcnow() - timedelta(hours=hours)
    async with async_session() as session:
        # Total events
        total_q = await session.execute(
            select(func.count()).select_from(AttackLog).where(AttackLog.timestamp >= since)
        )
        total = total_q.scalar() or 0

        # Unique IPs
        ips_q = await session.execute(
            select(func.count(func.distinct(AttackLog.source_ip))).where(
                AttackLog.timestamp >= since
            )
        )
        unique_ips = ips_q.scalar() or 0

        # Average score
        score_q = await session.execute(
            select(func.avg(AttackLog.threat_score)).where(AttackLog.timestamp >= since)
        )
        avg_score = score_q.scalar() or 0

        # Action distribution
        action_q = await session.execute(
            select(AttackLog.action_taken, func.count().label("cnt"))
            .where(AttackLog.timestamp >= since)
            .group_by(AttackLog.action_taken)
        )
        actions = {r.action_taken: r.cnt for r in action_q.all()}

    return {
        "window_hours": hours,
        "total_events": total,
        "unique_attacking_ips": unique_ips,
        "avg_threat_score": round(float(avg_score), 3),
        "actions": actions,
    }

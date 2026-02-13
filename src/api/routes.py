"""
Sentinel DDoS — REST API Routes.

Dashboard API: stats, traffic, blocking, settings, events.
"""

from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.config import settings, ProtectionLevel
from src.mitigation.blocker import ip_blocker
from src.detection.engine import detection_engine
from src.proxy.handler import traffic
from src.geoip.lookup import lookup as geoip_lookup

router = APIRouter(tags=["Dashboard API"])


# ── Schemas ──────────────────────────────────────────────


class StatsResponse(BaseModel):
    uptime: float
    protection_level: str
    under_attack_mode: bool
    baseline_ready: bool
    observation_count: int
    blocked_ips_count: int
    target_url: str
    total_requests: int
    forwarded_requests: int
    blocked_requests: int
    rate_limited_requests: int
    requests_per_second: float
    active_ips_count: int


class BlockIPRequest(BaseModel):
    ip: str
    reason: str = ""
    duration_sec: Optional[int] = None


class UnblockIPRequest(BaseModel):
    ip: str


class ProtectionLevelRequest(BaseModel):
    level: str


class UnderAttackRequest(BaseModel):
    enabled: bool


# ── State ────────────────────────────────────────────────

_start_time = time.time()


# ── Endpoints ────────────────────────────────────────────


@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Return current system stats for dashboard."""
    blocked = await ip_blocker.get_blocked_ips()
    return StatsResponse(
        uptime=time.time() - _start_time,
        protection_level=settings.protection_level.value,
        under_attack_mode=settings.under_attack_mode,
        baseline_ready=detection_engine.baseline.is_ready,
        observation_count=detection_engine.baseline.observation_count,
        blocked_ips_count=len(blocked),
        target_url=settings.target_url,
        total_requests=traffic.total_requests,
        forwarded_requests=traffic.forwarded_requests,
        blocked_requests=traffic.blocked_requests,
        rate_limited_requests=traffic.rate_limited_requests,
        requests_per_second=round(traffic.requests_per_second, 2),
        active_ips_count=len(traffic.active_ips),
    )


@router.get("/blocked")
async def get_blocked_ips():
    """List all blocked IPs."""
    ips = await ip_blocker.get_blocked_ips()
    return {"blocked_ips": ips, "count": len(ips)}


@router.post("/block")
async def block_ip(req: BlockIPRequest):
    """Manually block an IP."""
    await ip_blocker.block(req.ip, reason=req.reason, duration_sec=req.duration_sec)
    return {"status": "blocked", "ip": req.ip}


@router.post("/unblock")
async def unblock_ip(req: UnblockIPRequest):
    """Unblock an IP."""
    await ip_blocker.unblock(req.ip)
    return {"status": "unblocked", "ip": req.ip}


@router.post("/protection-level")
async def set_protection_level(req: ProtectionLevelRequest):
    """Change global protection level."""
    try:
        level = ProtectionLevel(req.level)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid level. Use: {[l.value for l in ProtectionLevel]}",
        )
    settings.protection_level = level
    return {"status": "ok", "protection_level": level.value}


@router.post("/under-attack")
async def toggle_under_attack(req: UnderAttackRequest):
    """Toggle Under Attack Mode."""
    settings.under_attack_mode = req.enabled
    return {"status": "ok", "under_attack_mode": req.enabled}


@router.get("/events")
async def get_recent_events():
    """Return recent security events for the threat feed."""
    events = list(traffic.recent_events)
    events.reverse()  # newest first
    return {"events": events, "count": len(events)}


@router.get("/health")
async def health_check():
    """Simple health check."""
    return {"status": "healthy", "version": "0.1.0"}


@router.get("/ml/status")
async def ml_status():
    """Return ML model status and training info."""
    return detection_engine.ml_info()


@router.post("/ml/train")
async def ml_trigger_train():
    """Manually trigger ML model training."""
    info = detection_engine.ml_info()
    if info["buffer_size"] < info["min_train_samples"]:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Not enough samples: {info['buffer_size']}"
                f" / {info['min_train_samples']} required"
            ),
        )
    trained = await detection_engine.ml.maybe_train()
    return {
        "status": "trained" if trained else "skipped",
        "info": detection_engine.ml_info(),
    }


@router.get("/attack-map")
async def get_attack_map():
    """
    Return geo-aggregated attack data for the world map.
    Collects unique attacking IPs from recent events with GeoIP.
    """
    # Aggregate by country from recent blocked/rate_limited events
    geo_points: list[dict] = []
    seen_ips: set[str] = set()

    for ev in traffic.recent_events:
        ip = ev.get("ip", "")
        action = ev.get("action", "")
        if action not in ("blocked", "rate_limited", "auto_blocked", "challenged"):
            continue
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        geo = ev.get("geo")
        if not geo:
            geo_result = geoip_lookup(ip)
            geo = geo_result.to_dict()

        geo_points.append({
            "ip": ip,
            "action": action,
            "latitude": geo["latitude"],
            "longitude": geo["longitude"],
            "country_code": geo["country_code"],
            "country_name": geo["country_name"],
            "score": ev.get("score"),
            "attack_type": ev.get("attack_type"),
        })

    # Also aggregate by country
    country_counts: dict[str, int] = {}
    for pt in geo_points:
        cc = pt["country_code"]
        country_counts[cc] = country_counts.get(cc, 0) + 1

    return {
        "points": geo_points,
        "by_country": [
            {"code": k, "count": v}
            for k, v in sorted(country_counts.items(), key=lambda x: -x[1])
        ],
        "total_attacking_ips": len(geo_points),
    }


@router.get("/geoip/{ip}")
async def geoip_lookup_endpoint(ip: str):
    """Look up GeoIP info for a specific IP."""
    result = geoip_lookup(ip)
    return result.to_dict()

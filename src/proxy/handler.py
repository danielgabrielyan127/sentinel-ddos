"""
Sentinel DDoS — Async Reverse Proxy Handler.

Catches ALL incoming requests, runs them through the detection pipeline,
and forwards legitimate traffic to the upstream target.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import httpx
from fastapi import APIRouter, Request, Response

from src.config import settings, ProtectionLevel
from src.detection.engine import detection_engine
from src.detection.behavior import behavior_analyzer
from src.mitigation.rate_limiter import rate_limiter
from src.mitigation.blocker import ip_blocker
from src.mitigation.challenge import challenge_manager
from src.rules.engine import rules_engine
from src.alerts.dispatcher import alert_manager, AlertEvent
from src.storage.database import async_session, AttackLog
from src.geoip.lookup import lookup as geoip_lookup

logger = logging.getLogger("sentinel.proxy")

router = APIRouter()

# Persistent async HTTP client (connection-pooled)
_http_client: Optional[httpx.AsyncClient] = None


# ── Real-time traffic counters ──────────────────────────────


@dataclass
class TrafficCounters:
    """In-memory counters for real-time dashboard stats."""
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limited_requests: int = 0
    forwarded_requests: int = 0
    challenged_requests: int = 0
    active_ips: set = field(default_factory=set)
    recent_events: deque = field(default_factory=lambda: deque(maxlen=200))
    # Per-second request timestamps for RPS calculation
    _request_times: deque = field(default_factory=lambda: deque(maxlen=10000))

    @property
    def requests_per_second(self) -> float:
        """Calculate RPS from last 10 seconds."""
        now = time.time()
        cutoff = now - 10
        count = sum(1 for t in self._request_times if t > cutoff)
        return count / 10.0

    def record_request(self) -> None:
        self.total_requests += 1
        self._request_times.append(time.time())


traffic = TrafficCounters()


async def get_http_client() -> httpx.AsyncClient:
    """Lazily initialise the shared httpx async client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            base_url=settings.target_url,
            timeout=httpx.Timeout(settings.proxy_timeout),
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=200,
                max_keepalive_connections=50,
            ),
        )
    return _http_client


def get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"


# ── DB logging helper (fire-and-forget) ─────────────────────

async def _log_attack(
    source_ip: str,
    action: str,
    threat_score: float,
    path: str = "",
    method: str = "",
    user_agent: str = "",
    attack_type: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Persist an attack event to the database (best-effort)."""
    try:
        async with async_session() as session:
            log = AttackLog(
                source_ip=source_ip,
                attack_type=attack_type,
                threat_score=threat_score,
                action_taken=action,
                path=path,
                method=method,
                user_agent=user_agent,
                metadata_json=json.dumps(metadata) if metadata else None,
            )
            session.add(log)
            await session.commit()
    except Exception:
        logger.debug("Failed to write attack log", exc_info=True)


# ── Alert helper (fire-and-forget) ──────────────────────────

async def _send_alert(
    level: str,
    title: str,
    message: str,
    source_ip: str | None = None,
    attack_type: str | None = None,
) -> None:
    """Send an alert via configured dispatchers (best-effort)."""
    try:
        event = AlertEvent(
            level=level,
            title=title,
            message=message,
            source_ip=source_ip,
            attack_type=attack_type,
        )
        await alert_manager.alert(event)
    except Exception:
        logger.debug("Failed to send alert", exc_info=True)


def _make_event(
    client_ip: str, action: str, path: str, method: str, **extra
) -> dict:
    """Build an event dict with GeoIP data."""
    geo = geoip_lookup(client_ip)
    event = {
        "time": time.time(),
        "ip": client_ip,
        "action": action,
        "path": path,
        "method": method,
        "geo": geo.to_dict(),
        **extra,
    }
    return event


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    include_in_schema=False,
)
async def reverse_proxy(request: Request, path: str = "") -> Response:
    """
    Main reverse-proxy endpoint.

    Pipeline:
      1. Extract client IP
      2. Check blocklist
      3. Per-rule rate limits (YAML rules engine)
      4. Global rate limits (returns count for scorer)
      5. AI detection scoring (baseline + behavior + rate signal)
      6. Graduated mitigation (monitor → challenge → rate_limit → block)
      7. Forward to upstream
      8. Async: DB logging + alerts for threats
    """
    # Skip proxying for internal API / WS / docs paths
    request_path = request.url.path
    if request_path.startswith(("/api/", "/ws/", "/openapi.json")):
        return Response(status_code=404)

    start = time.monotonic()
    client_ip = get_client_ip(request)
    url_path = f"/{path}" if path else "/"
    ua = request.headers.get("user-agent", "")
    traffic.record_request()
    traffic.active_ips.add(client_ip)

    # ── 1. Blocklist check ───────────────────────────────
    if await ip_blocker.is_blocked(client_ip):
        traffic.blocked_requests += 1
        traffic.recent_events.append(
            _make_event(client_ip, "blocked", url_path, request.method)
        )
        logger.debug("Blocked IP tried to connect: %s", client_ip)
        return Response(status_code=403, content="Forbidden")

    # ── 2. Per-rule rate limits (YAML rules) ─────────────
    matched_rules = rules_engine.match_request(url_path, request.method)
    for rule in matched_rules:
        if rule.limits and rule.limits.per_ip:
            limit_count, limit_window = rules_engine.parse_rate_string(rule.limits.per_ip)
            allowed, count = await rate_limiter.check_rule_limit(
                client_ip, rule.name, limit_count, limit_window,
            )
            if not allowed:
                traffic.rate_limited_requests += 1
                traffic.recent_events.append(
                    _make_event(client_ip, "rate_limited", url_path, request.method, rule=rule.name)
                )
                logger.info(
                    "Rule '%s' rate limit exceeded for %s (%d/%d)",
                    rule.name, client_ip, count, limit_count,
                )
                # Check escalation steps for this rule
                usage_pct = (count / limit_count * 100) if limit_count else 0
                escalation_action = _resolve_escalation(rule.escalation, usage_pct)

                if escalation_action == "block":
                    duration = _parse_duration(rule.escalation)
                    await ip_blocker.block(
                        client_ip,
                        reason=f"Rule escalation: {rule.name}",
                        duration_sec=duration,
                    )
                    traffic.blocked_requests += 1
                    asyncio.create_task(_log_attack(
                        client_ip, "rule_blocked", 0.0, url_path,
                        request.method, ua, attack_type="rule_violation",
                        metadata={"rule": rule.name, "count": count},
                    ))
                    asyncio.create_task(_send_alert(
                        "warning",
                        f"Rule escalation: {rule.name}",
                        f"IP {client_ip} blocked — {count} requests in {limit_window}s",
                        source_ip=client_ip,
                    ))
                    return Response(status_code=403, content="Forbidden")

                if escalation_action == "js_challenge":
                    challenge_resp = await challenge_manager.maybe_challenge(request, client_ip)
                    if challenge_resp is not None:
                        traffic.challenged_requests += 1
                        return challenge_resp

                return Response(status_code=429, content="Too Many Requests")

    # ── 3. Global rate limiting ──────────────────────────
    rate_allowed, rate_count = await rate_limiter.allow_with_count(client_ip)
    if not rate_allowed:
        traffic.rate_limited_requests += 1
        traffic.recent_events.append(
            _make_event(client_ip, "rate_limited", url_path, request.method)
        )
        logger.info("Global rate limit exceeded: %s (%d reqs)", client_ip, rate_count)
        asyncio.create_task(_log_attack(
            client_ip, "rate_limited", 0.0, url_path,
            request.method, ua,
            metadata={"rate_count": rate_count},
        ))
        return Response(status_code=429, content="Too Many Requests")

    # ── 4. AI detection scoring ──────────────────────────
    threat_score = await detection_engine.score_request(
        request, client_ip,
        rate_count=rate_count,
        rate_limit=settings.rate_limit_per_ip,
    )

    # ── 5. Graduated mitigation ──────────────────────────
    level = settings.protection_level
    if settings.under_attack_mode:
        level = ProtectionLevel.BLOCK

    if threat_score >= settings.anomaly_threshold:
        # Classify the attack for logging/alerts
        bscore = behavior_analyzer.get_session(client_ip)
        bscore_val = 0.0
        if bscore and bscore.request_count >= 3:
            from src.detection.behavior import BehaviorAnalyzer
            bscore_val = BehaviorAnalyzer._compute_score(BehaviorAnalyzer(), bscore)

        attack_type = await detection_engine.classify_attack(
            request, client_ip,
            rate_count=rate_count,
            rate_limit=settings.rate_limit_per_ip,
            behavior_score=bscore_val,
        )

        event_data = _make_event(
            client_ip, "", url_path, request.method,
            score=round(threat_score, 3),
            attack_type=attack_type,
        )

        if level == ProtectionLevel.MONITOR:
            # Just log, don't act
            event_data["action"] = "monitored"
            traffic.recent_events.append(event_data)
            asyncio.create_task(_log_attack(
                client_ip, "monitored", threat_score, url_path,
                request.method, ua, attack_type=attack_type,
            ))

        elif level == ProtectionLevel.JS_CHALLENGE:
            challenge_resp = await challenge_manager.maybe_challenge(request, client_ip)
            if challenge_resp is not None:
                event_data["action"] = "challenged"
                traffic.recent_events.append(event_data)
                traffic.challenged_requests += 1
                asyncio.create_task(_log_attack(
                    client_ip, "challenged", threat_score, url_path,
                    request.method, ua, attack_type=attack_type,
                ))
                return challenge_resp

        elif level == ProtectionLevel.RATE_LIMIT:
            event_data["action"] = "rate_limited"
            traffic.recent_events.append(event_data)
            traffic.rate_limited_requests += 1
            asyncio.create_task(_log_attack(
                client_ip, "rate_limited", threat_score, url_path,
                request.method, ua, attack_type=attack_type,
            ))
            return Response(status_code=429, content="Too Many Requests")

        elif level in (ProtectionLevel.BLOCK, ProtectionLevel.BLACKHOLE):
            await ip_blocker.block(client_ip, reason=f"threat score {threat_score:.2f}")
            event_data["action"] = "auto_blocked"
            traffic.recent_events.append(event_data)
            traffic.blocked_requests += 1
            asyncio.create_task(_log_attack(
                client_ip, "blocked", threat_score, url_path,
                request.method, ua, attack_type=attack_type,
            ))
            asyncio.create_task(_send_alert(
                "critical",
                f"Attack detected: {attack_type or 'unknown'}",
                f"IP {client_ip} blocked — score {threat_score:.2f} on {request.method} {url_path}",
                source_ip=client_ip,
                attack_type=attack_type,
            ))
            return Response(status_code=403, content="Forbidden")

    # ── 6. Forward to upstream ───────────────────────────
    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)
    headers["x-forwarded-for"] = client_ip
    headers["x-sentinel-score"] = str(round(threat_score, 4))

    client = await get_http_client()
    try:
        upstream_resp = await client.request(
            method=request.method,
            url=url_path,
            headers=headers,
            content=body,
            params=dict(request.query_params),
        )
    except httpx.RequestError as exc:
        logger.error("Upstream error: %s", exc)
        return Response(status_code=502, content="Bad Gateway")

    traffic.forwarded_requests += 1
    elapsed = time.monotonic() - start
    logger.debug(
        "%s %s → %d (%.1fms, score=%.2f)",
        request.method, url_path, upstream_resp.status_code,
        elapsed * 1000, threat_score,
    )

    # Filter hop-by-hop headers from upstream response
    resp_headers = {}
    skip_headers = {"transfer-encoding", "connection", "keep-alive"}
    for k, v in upstream_resp.headers.items():
        if k.lower() not in skip_headers:
            resp_headers[k] = v

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=resp_headers,
    )


# ── Helpers ──────────────────────────────────────────────

def _resolve_escalation(steps: list, usage_pct: float) -> str:
    """Given usage percentage, return the highest matching escalation action."""
    action = "rate_limit"
    for step in sorted(steps, key=lambda s: s.threshold):
        if usage_pct >= step.threshold:
            action = step.action
    return action


def _parse_duration(steps: list) -> int | None:
    """Extract block duration from the highest escalation step that has one."""
    for step in reversed(sorted(steps, key=lambda s: s.threshold)):
        if step.duration:
            return _duration_to_seconds(step.duration)
    return None


def _duration_to_seconds(dur: str) -> int:
    """Parse '10m', '1h', '2d' into seconds."""
    dur = dur.strip().lower()
    if dur.endswith("m"):
        return int(dur[:-1]) * 60
    if dur.endswith("h"):
        return int(dur[:-1]) * 3600
    if dur.endswith("d"):
        return int(dur[:-1]) * 86400
    if dur.endswith("s"):
        return int(dur[:-1])
    return int(dur)

"""
Sentinel DDoS — WebSocket Endpoints.

Real-time traffic feed and attack events for the dashboard.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from src.detection.engine import detection_engine
from src.proxy.handler import traffic

logger = logging.getLogger("sentinel.api.websocket")

router = APIRouter(tags=["WebSocket"])

# Active WebSocket connections
_connections: Set[WebSocket] = set()


@router.websocket("/traffic")
async def traffic_feed(websocket: WebSocket):
    """
    Real-time traffic feed.

    Pushes traffic stats every second to connected dashboards:
      - requests per second
      - total / blocked / rate limited counters
      - active IPs count
      - baseline status
      - recent events
    """
    await websocket.accept()
    _connections.add(websocket)
    logger.info("Dashboard connected (total: %d)", len(_connections))

    last_event_count = 0

    try:
        while True:
            # Gather current events that are new since last push
            all_events = list(traffic.recent_events)
            new_events = all_events[last_event_count:] if last_event_count < len(all_events) else []
            last_event_count = len(all_events)

            stats = {
                "type": "traffic",
                "timestamp": time.time(),
                "rps": round(traffic.requests_per_second, 2),
                "total_requests": traffic.total_requests,
                "blocked_requests": traffic.blocked_requests,
                "rate_limited_requests": traffic.rate_limited_requests,
                "forwarded_requests": traffic.forwarded_requests,
                "challenged_requests": traffic.challenged_requests,
                "active_ips": len(traffic.active_ips),
                "observation_count": detection_engine.baseline.observation_count,
                "baseline_ready": detection_engine.baseline.is_ready,
                "mean_rps": round(detection_engine.baseline.mean_rps, 2),
                "new_events": new_events,
            }
            await websocket.send_text(json.dumps(stats))
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket error")
    finally:
        _connections.discard(websocket)
        logger.info("Dashboard disconnected (total: %d)", len(_connections))


async def broadcast_event(event: dict) -> None:
    """Broadcast an event to all connected dashboards."""
    if not _connections:
        return
    message = json.dumps(event)
    dead: list[WebSocket] = []
    for ws in _connections:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _connections.discard(ws)

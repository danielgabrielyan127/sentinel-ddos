"""
Sentinel DDoS — Application Entry Point.

Starts the FastAPI application with reverse proxy, detection engine,
and API + WebSocket endpoints.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config import settings
from src.api.routes import router as api_router
from src.api.analytics import router as analytics_router
from src.api.websocket import router as ws_router
from src.proxy.handler import router as proxy_router
from src.storage.redis_client import redis_manager
from src.storage.database import init_db
from src.detection.engine import detection_engine
from src.rules.engine import rules_engine
from src.geoip.lookup import init_geoip

logger = logging.getLogger("sentinel")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle."""
    # ── Startup ──────────────────────────────────────────
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper()),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        force=True,
    )
    logger.info("🛡️  Sentinel DDoS v%s starting…", "0.1.0")

    # Connect Redis (graceful — works without it in dev mode)
    try:
        await redis_manager.connect()
        logger.info("✅ Redis connected: %s", settings.redis_url)
    except Exception as exc:
        logger.warning(
            "⚠️  Redis unavailable (%s) — running without rate limiting. "
            "Set SENTINEL_REDIS_URL for full protection.",
            exc,
        )

    # Init database
    await init_db()
    logger.info("✅ Database initialised")

    # Start detection engine
    await detection_engine.start()
    logger.info("✅ Detection engine started")

    # Load YAML rules
    rules_count = rules_engine.load_from_directory()
    logger.info("✅ Loaded %d rule file(s)", rules_count)

    # Init GeoIP
    geoip_ok = init_geoip(settings.geoip_db_path)
    logger.info("✅ GeoIP: %s", "MaxMind DB loaded" if geoip_ok else "fallback mode")

    logger.info(
        "🚀 Proxying traffic to %s | Protection: %s",
        settings.target_url,
        settings.protection_level.value,
    )
    logger.info("📊 Dashboard: http://%s:%d", settings.host, settings.port)
    logger.info("📖 API docs:  http://%s:%d/api/docs", settings.host, settings.port)

    yield

    # ── Shutdown ─────────────────────────────────────────
    await detection_engine.stop()
    await redis_manager.disconnect()
    logger.info("🛡️  Sentinel DDoS stopped.")


def create_app() -> FastAPI:
    """Factory for the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="AI-Powered Anti-DDoS L7 Firewall",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=lifespan,
    )

    # CORS (for dashboard)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ──────────────────────────────────────────
    app.include_router(api_router, prefix="/api")
    app.include_router(analytics_router, prefix="/api")
    app.include_router(ws_router, prefix="/ws")

    # Catch-all reverse proxy — must be last
    app.include_router(proxy_router)

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level,
    )

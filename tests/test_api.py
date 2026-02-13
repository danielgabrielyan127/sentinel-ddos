"""
Tests for the API endpoints.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch

from src.main import app


@pytest.fixture
async def client():
    """Create a test client with mocked dependencies."""
    # Mock Redis and DB to avoid real connections in tests
    with patch("src.storage.redis_client.redis_manager.connect", new_callable=AsyncMock), \
         patch("src.storage.redis_client.redis_manager.disconnect", new_callable=AsyncMock), \
         patch("src.storage.database.init_db", new_callable=AsyncMock), \
         patch("src.detection.engine.detection_engine.start", new_callable=AsyncMock), \
         patch("src.detection.engine.detection_engine.stop", new_callable=AsyncMock):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


@pytest.mark.asyncio
async def test_health_check(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_get_stats(client):
    resp = await client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "uptime" in data
    assert "protection_level" in data

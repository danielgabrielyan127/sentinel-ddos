"""
Tests for the attack classifier.
"""

import pytest

from src.detection.classifier import AttackClassifier, AttackType


@pytest.fixture
def classifier():
    return AttackClassifier()


@pytest.mark.asyncio
async def test_http_flood_detection(classifier):
    """High rate + empty UA → HTTP_FLOOD."""
    result = await classifier.classify(
        {"method": "GET", "path": "/", "user_agent": "", "content_length": 0},
        rate_count=80,
        rate_limit=100,
        behavior_score=0.6,
    )
    assert result == AttackType.HTTP_FLOOD


@pytest.mark.asyncio
async def test_high_rate_alone_is_flood(classifier):
    """Very high rate alone → HTTP_FLOOD."""
    result = await classifier.classify(
        {"method": "GET", "path": "/", "user_agent": "Mozilla/5.0", "content_length": 0},
        rate_count=90,
        rate_limit=100,
        behavior_score=0.0,
    )
    assert result == AttackType.HTTP_FLOOD


@pytest.mark.asyncio
async def test_slowloris_detection(classifier):
    """Empty POST body with behavioral signal → SLOWLORIS."""
    result = await classifier.classify(
        {"method": "POST", "path": "/", "user_agent": "bot/1.0", "content_length": 0},
        rate_count=10,
        rate_limit=100,
        behavior_score=0.5,
    )
    assert result == AttackType.SLOWLORIS


@pytest.mark.asyncio
async def test_credential_stuffing(classifier):
    """Repeated POSTs to login → CREDENTIAL_STUFFING."""
    result = await classifier.classify(
        {"method": "POST", "path": "/api/login", "user_agent": "Mozilla/5.0", "content_length": 100},
        rate_count=40,
        rate_limit=100,
        behavior_score=0.2,
    )
    assert result == AttackType.CREDENTIAL_STUFFING


@pytest.mark.asyncio
async def test_api_abuse(classifier):
    """High rate on API endpoint → API_ABUSE."""
    result = await classifier.classify(
        {"method": "POST", "path": "/api/users", "user_agent": "okhttp/4.0", "content_length": 200},
        rate_count=55,
        rate_limit=100,
        behavior_score=0.3,
    )
    assert result == AttackType.API_ABUSE


@pytest.mark.asyncio
async def test_scraping(classifier):
    """High behavior score GET → SCRAPING."""
    result = await classifier.classify(
        {"method": "GET", "path": "/products", "user_agent": "Mozilla/5.0", "content_length": 0},
        rate_count=50,
        rate_limit=100,
        behavior_score=0.7,
    )
    assert result == AttackType.SCRAPING


@pytest.mark.asyncio
async def test_benign_traffic(classifier):
    """Low rate, normal UA → None (benign)."""
    result = await classifier.classify(
        {"method": "GET", "path": "/about", "user_agent": "Mozilla/5.0 Chrome/120", "content_length": 0},
        rate_count=5,
        rate_limit=100,
        behavior_score=0.1,
    )
    assert result is None

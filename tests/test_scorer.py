"""
Tests for the anomaly scorer.
"""

import pytest

from src.detection.scorer import AnomalyScorer
from src.detection.baseline import BaselineModel


@pytest.fixture
def trained_baseline():
    """Create a baseline with enough observations to be ready."""
    baseline = BaselineModel(window_sec=3600)
    import time
    now = time.time()
    for i in range(200):
        baseline.record_observation({
            "timestamp": now - 200 + i,
            "client_ip": f"192.168.1.{i % 256}",
            "method": "GET",
            "path": "/",
            "query": "",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "content_length": 0,
            "header_count": 8,
            "accept_language": "en-US",
        })
    baseline.update_model()
    return baseline


@pytest.fixture
def scorer():
    return AnomalyScorer()


@pytest.mark.asyncio
async def test_normal_request_low_score(scorer, trained_baseline):
    """Normal-looking request should have a low threat score."""
    features = {
        "timestamp": 0,
        "client_ip": "192.168.1.1",
        "method": "GET",
        "path": "/",
        "user_agent": "Mozilla/5.0 Chrome/120.0",
        "content_length": 0,
        "header_count": 8,
    }
    score = await scorer.score(features, trained_baseline)
    assert score < 0.5, f"Normal request got score {score}"


@pytest.mark.asyncio
async def test_missing_ua_high_score(scorer, trained_baseline):
    """Request with missing User-Agent should score higher."""
    features = {
        "timestamp": 0,
        "client_ip": "10.0.0.1",
        "method": "GET",
        "path": "/",
        "user_agent": "",
        "content_length": 0,
        "header_count": 8,
    }
    score = await scorer.score(features, trained_baseline)
    assert score > 0.1, f"Missing UA got score {score}"


@pytest.mark.asyncio
async def test_untrained_baseline_returns_zero(scorer):
    """When baseline is not ready, score should be 0 (learning mode)."""
    baseline = BaselineModel()
    features = {"user_agent": "", "header_count": 0, "content_length": 0, "path": "/"}
    score = await scorer.score(features, baseline)
    assert score == 0.0


@pytest.mark.asyncio
async def test_suspicious_ua_moderate_score(scorer, trained_baseline):
    """Requests from script-like UAs should have moderate scores."""
    features = {
        "timestamp": 0,
        "client_ip": "10.0.0.1",
        "method": "GET",
        "path": "/",
        "user_agent": "python-requests/2.31.0",
        "content_length": 0,
        "header_count": 8,
    }
    score = await scorer.score(features, trained_baseline)
    assert 0.05 < score < 0.8, f"Suspicious UA got score {score}"

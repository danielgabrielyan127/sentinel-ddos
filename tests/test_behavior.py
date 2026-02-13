"""
Tests for the behavioral analysis engine.
"""

import pytest
import time

from src.detection.behavior import BehaviorAnalyzer, IPSession


@pytest.fixture
def analyzer():
    return BehaviorAnalyzer()


def test_new_ip_low_score(analyzer: BehaviorAnalyzer):
    """First request from a new IP should have a low score."""
    score = analyzer.record_and_score(
        client_ip="1.2.3.4",
        path="/",
        method="GET",
        user_agent="Mozilla/5.0 Chrome/120.0",
        accept_language="en-US",
        referer=None,
        cookie="session=abc",
        header_order_hash="abc123",
    )
    assert score < 0.3, f"New IP got score {score}"


def test_repeated_requests_increase_score(analyzer: BehaviorAnalyzer):
    """Many rapid requests from same IP should increase the score."""
    scores = []
    for i in range(20):
        s = analyzer.record_and_score(
            client_ip="10.0.0.1",
            path="/",
            method="GET",
            user_agent="",
            accept_language="",
            referer=None,
            cookie=None,
            header_order_hash="same",
        )
        scores.append(s)

    # Score should trend upward with rapid identical requests
    assert scores[-1] > scores[0], "Score should increase with repeated requests"


def test_diverse_paths_lower_score(analyzer: BehaviorAnalyzer):
    """Browsing multiple paths (like a human) should keep score low."""
    paths = ["/", "/about", "/contact", "/blog", "/products"]
    score = 0.0
    for path in paths:
        score = analyzer.record_and_score(
            client_ip="192.168.1.1",
            path=path,
            method="GET",
            user_agent="Mozilla/5.0 Chrome/120.0",
            accept_language="en-US",
            referer="/",
            cookie="session=xyz",
            header_order_hash="human_hash",
        )
    assert score < 0.5, f"Diverse browsing got score {score}"


def test_bot_indicators_raise_score(analyzer: BehaviorAnalyzer):
    """No cookies, no referer, empty UA should score higher."""
    score = 0.0
    for _ in range(10):
        score = analyzer.record_and_score(
            client_ip="10.10.10.10",
            path="/api/data",
            method="GET",
            user_agent="python-requests/2.31.0",
            accept_language="",
            referer=None,
            cookie=None,
            header_order_hash="bot_hash",
        )
    # Should be meaningful after 10 requests
    assert score > 0.2, f"Bot-like traffic got score {score}"


def test_session_cleanup(analyzer: BehaviorAnalyzer):
    """Sessions should be accessible via get_session."""
    analyzer.record_and_score(
        client_ip="5.5.5.5",
        path="/",
        method="GET",
        user_agent="Mozilla/5.0",
        accept_language="en",
        referer=None,
        cookie=None,
        header_order_hash="hash1",
    )
    session = analyzer.get_session("5.5.5.5")
    assert session is not None
    assert session.request_count == 1


def test_unknown_ip_returns_none(analyzer: BehaviorAnalyzer):
    """Unknown IP should return None for get_session."""
    session = analyzer.get_session("99.99.99.99")
    assert session is None

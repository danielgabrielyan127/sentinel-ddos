"""
Sentinel DDoS — Attack Classifier.

Classifies detected attacks into known categories
(HTTP Flood, Slowloris, API abuse, credential stuffing, etc.).
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger("sentinel.detection.classifier")


class AttackType(str, Enum):
    HTTP_FLOOD = "http_flood"
    SLOWLORIS = "slowloris"
    API_ABUSE = "api_abuse"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SCRAPING = "scraping"
    UNKNOWN = "unknown"


class AttackClassifier:
    """
    Heuristic + context-aware classifier.

    Uses request features combined with rate and behavior context
    to classify attacks more accurately and reduce false positives.
    """

    async def classify(
        self,
        features: dict,
        rate_count: int = 0,
        rate_limit: int = 100,
        behavior_score: float = 0.0,
    ) -> Optional[str]:
        """Return attack type string or None if benign."""

        method = features.get("method", "GET")
        path = features.get("path", "/")
        ua = features.get("user_agent", "")
        content_length = features.get("content_length", 0)
        rate_ratio = rate_count / rate_limit if rate_limit > 0 else 0.0

        # ── HTTP Flood ───────────────────────────────────
        # High rate + bot-like behavior + minimal/no UA
        if rate_ratio > 0.6 and (not ua or behavior_score > 0.5):
            return AttackType.HTTP_FLOOD

        # Very high rate alone is a strong flood signal
        if rate_ratio > 0.85:
            return AttackType.HTTP_FLOOD

        # ── Slowloris ────────────────────────────────────
        # Slow POST with no body — connection-exhaustion attack
        if content_length == 0 and method == "POST" and behavior_score > 0.3:
            return AttackType.SLOWLORIS

        # ── Credential Stuffing ──────────────────────────
        # Repeated POSTs to login/auth paths at elevated rate
        login_paths = {"/login", "/auth", "/api/login", "/api/auth", "/signin", "/api/signin"}
        if path.lower() in login_paths and method == "POST" and rate_ratio > 0.3:
            return AttackType.CREDENTIAL_STUFFING

        # ── API Abuse ────────────────────────────────────
        # High rate on API endpoints with bot-like behavior
        if "/api/" in path and method in ("POST", "PUT", "DELETE"):
            if rate_ratio > 0.5 or behavior_score > 0.6:
                return AttackType.API_ABUSE

        # ── Scraping ─────────────────────────────────────
        # High rate GET with bot-like behavior but not login paths
        if method == "GET" and behavior_score > 0.6 and rate_ratio > 0.4:
            return AttackType.SCRAPING

        return None

"""
Sentinel DDoS — Anomaly Scorer.

Scores individual requests against the learned baseline
to produce a threat level between 0.0 and 1.0.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.detection.baseline import BaselineModel

logger = logging.getLogger("sentinel.detection.scorer")


class AnomalyScorer:
    """
    Multi-signal anomaly scorer.

    Combines z-score deviations across several features
    and normalises the result to [0, 1].
    """

    # Weights for each signal (must sum to 1.0)
    WEIGHTS = {
        "header_count": 0.15,
        "content_length": 0.10,
        "user_agent": 0.20,
        "path_entropy": 0.10,
        "rate": 0.20,
        "behavior": 0.25,
    }

    async def score(
        self,
        features: dict,
        baseline: "BaselineModel",
        rate_ratio: float = 0.0,
        behavior_score: float = 0.0,
    ) -> float:
        """Return a composite threat score for the given features."""
        if not baseline.is_ready:
            # Baseline not trained yet — allow everything (learning mode)
            return 0.0

        signals: dict[str, float] = {}

        # ── Header-count deviation ────────────────────────
        hc = features.get("header_count", 0)
        signals["header_count"] = self._z_to_score(
            hc, baseline.mean_header_count, baseline.std_header_count,
        )

        # ── Content-length deviation ──────────────────────
        cl = features.get("content_length", 0)
        signals["content_length"] = self._z_to_score(
            cl, baseline.mean_content_length, baseline.std_content_length,
        )

        # ── User-Agent check ─────────────────────────────
        ua = features.get("user_agent", "")
        signals["user_agent"] = self._score_user_agent(ua)

        # ── Path entropy ─────────────────────────────────
        path = features.get("path", "/")
        signals["path_entropy"] = self._score_path(path)

        # ── Rate signal (fed from rate limiter) ─────────
        signals["rate"] = min(1.0, max(0.0, rate_ratio))

        # ── Behavioral analysis signal ─────────────────
        signals["behavior"] = min(1.0, max(0.0, behavior_score))

        # ── Weighted composite ───────────────────────────
        composite = sum(
            signals.get(k, 0) * w for k, w in self.WEIGHTS.items()
        )
        return min(1.0, max(0.0, composite))

    # ── Helpers ──────────────────────────────────────────

    @staticmethod
    def _z_to_score(value: float, mean: float, std: float) -> float:
        """Convert a z-score to a 0–1 threat contribution."""
        z = abs(value - mean) / std if std else 0.0
        if z < 1.5:
            return 0.0
        if z < 3.0:
            return (z - 1.5) / 1.5  # linear ramp 0→1
        return 1.0

    @staticmethod
    def _score_user_agent(ua: str) -> float:
        """Heuristic: missing or suspicious User-Agent."""
        if not ua:
            return 0.9
        suspicious = [
            "python-requests", "curl", "wget", "go-http-client",
            "httpclient", "java/", "libwww", "okhttp",
        ]
        ua_lower = ua.lower()
        for s in suspicious:
            if s in ua_lower:
                return 0.5
        return 0.0

    @staticmethod
    def _score_path(path: str) -> float:
        """High entropy / unusually long paths are suspicious."""
        if len(path) > 512:
            return 0.8
        unique_chars = len(set(path))
        if unique_chars > 40:
            return 0.5
        return 0.0

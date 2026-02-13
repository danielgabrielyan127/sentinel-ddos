"""
Sentinel DDoS — AI Detection Engine.

Orchestrates baseline learning, anomaly scoring, ML model, and attack classification.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

from fastapi import Request

from src.detection.baseline import BaselineModel
from src.detection.scorer import AnomalyScorer
from src.detection.classifier import AttackClassifier
from src.detection.behavior import behavior_analyzer
from src.detection.ml_model import ml_model
from src.proxy.fingerprint import compute_header_order_hash

logger = logging.getLogger("sentinel.detection")

# How much weight the ML score gets vs the heuristic score (when ML is ready)
ML_BLEND_WEIGHT = 0.4


class DetectionEngine:
    """Central detection engine that composes baseline, scorer, ML model, classifier."""

    def __init__(self) -> None:
        self.baseline = BaselineModel()
        self.scorer = AnomalyScorer()
        self.classifier = AttackClassifier()
        self.ml = ml_model
        self._running = False
        self._background_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start background baseline-learning loop."""
        self._running = True
        self._background_task = asyncio.create_task(self._learn_loop())
        logger.info("Detection engine started (ML ready: %s)", self.ml.is_ready)

    async def stop(self) -> None:
        """Stop background tasks."""
        self._running = False
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
        logger.info("Detection engine stopped")

    async def score_request(
        self,
        request: Request,
        client_ip: str,
        rate_count: int = 0,
        rate_limit: int = 100,
    ) -> float:
        """
        Score an incoming request for threat level.

        Returns a float between 0.0 (safe) and 1.0 (malicious).
        Blends heuristic score with ML score when the model is trained.
        """
        features = self._extract_features(request, client_ip)

        # Rate ratio: how close this IP is to exhausting its rate limit
        rate_ratio = (rate_count / rate_limit) if rate_limit > 0 else 0.0

        # Behavioral analysis
        headers = dict(request.headers)
        header_order_hash = compute_header_order_hash(headers)
        behavior_score = behavior_analyzer.record_and_score(
            client_ip=client_ip,
            path=features["path"],
            method=features["method"],
            user_agent=features["user_agent"],
            accept_language=features.get("accept_language", ""),
            referer=headers.get("referer"),
            cookie=headers.get("cookie"),
            header_order_hash=header_order_hash,
        )

        # Store raw headers for ML feature extraction
        features["_raw_headers"] = headers

        # Heuristic score (baseline + signals)
        heuristic_score = await self.scorer.score(
            features,
            self.baseline,
            rate_ratio=rate_ratio,
            behavior_score=behavior_score,
        )

        # ML score (IsolationForest)
        ml_score = self.ml.score(features, rate_ratio, behavior_score)

        # Blend: if ML is ready, combine; otherwise pure heuristic
        if self.ml.is_ready:
            score = (
                (1 - ML_BLEND_WEIGHT) * heuristic_score
                + ML_BLEND_WEIGHT * ml_score
            )
        else:
            score = heuristic_score

        # Feed sample to ML training buffer
        self.ml.record_sample(features, rate_ratio, behavior_score)

        # Record observation for baseline learning
        self.baseline.record_observation(features)

        return min(1.0, max(0.0, score))

    async def classify_attack(
        self,
        request: Request,
        client_ip: str,
        rate_count: int = 0,
        rate_limit: int = 100,
        behavior_score: float = 0.0,
    ) -> Optional[str]:
        """Classify the type of attack if threat score is high."""
        features = self._extract_features(request, client_ip)
        return await self.classifier.classify(
            features,
            rate_count=rate_count,
            rate_limit=rate_limit,
            behavior_score=behavior_score,
        )

    def _extract_features(self, request: Request, client_ip: str) -> dict:
        """Extract raw feature dict from a request."""
        return {
            "timestamp": time.time(),
            "client_ip": client_ip,
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "user_agent": request.headers.get("user-agent", ""),
            "content_length": int(request.headers.get("content-length", 0)),
            "header_count": len(request.headers),
            "accept_language": request.headers.get("accept-language", ""),
        }

    async def _learn_loop(self) -> None:
        """Periodically update the baseline model and retrain ML."""
        while self._running:
            try:
                await asyncio.sleep(60)  # every minute

                # Update statistical baseline
                self.baseline.update_model()
                logger.debug(
                    "Baseline updated — %d observations",
                    self.baseline.observation_count,
                )

                # Train / retrain ML model if conditions are met
                trained = await self.ml.maybe_train()
                if trained:
                    logger.info(
                        "ML model retrained (#%d) — buffer=%d",
                        self.ml._train_count, self.ml.sample_count,
                    )

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in learning loop")

    def ml_info(self) -> dict:
        """Return ML model status for API endpoints."""
        return self.ml.info()


# Module-level singleton
detection_engine = DetectionEngine()

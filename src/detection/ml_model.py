"""
Sentinel DDoS — ML Anomaly Detection (IsolationForest).

Trains on traffic feature vectors and scores requests as
normal vs anomalous. Works alongside the heuristic scorer.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import pickle
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("sentinel.detection.ml")

# Feature names in order — MUST match _extract_vector()
FEATURE_NAMES = [
    "header_count",
    "content_length",
    "ua_score",
    "path_length",
    "path_unique_chars",
    "method_is_post",
    "has_cookie",
    "has_referer",
    "has_accept_language",
    "rate_ratio",
    "behavior_score",
]

_SUSPICIOUS_UA_TOKENS = frozenset([
    "python-requests", "curl", "wget", "go-http-client",
    "httpclient", "java/", "libwww", "okhttp",
])

# Defaults
DEFAULT_MIN_TRAIN_SAMPLES = 500
DEFAULT_RETRAIN_INTERVAL = 300  # seconds
DEFAULT_MODEL_DIR = "models"


@dataclass
class MLModelConfig:
    """Configuration for the ML anomaly model."""
    min_train_samples: int = DEFAULT_MIN_TRAIN_SAMPLES
    retrain_interval_sec: int = DEFAULT_RETRAIN_INTERVAL
    model_dir: str = DEFAULT_MODEL_DIR
    contamination: float = 0.05  # expected fraction of anomalies
    n_estimators: int = 200
    max_samples: int = 2048  # max training batch size


class MLAnomalyModel:
    """
    IsolationForest-based anomaly detector.

    Lifecycle:
      1. Collect observations during warm-up (no predictions)
      2. Auto-train when min_train_samples reached
      3. After training, score every request (0.0 = normal, 1.0 = anomaly)
      4. Retrain periodically with fresh data
    """

    def __init__(self, config: MLModelConfig | None = None) -> None:
        self.config = config or MLModelConfig()
        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None
        self._training_buffer: Deque[np.ndarray] = deque(
            maxlen=self.config.max_samples * 4,
        )
        self._is_trained = False
        self._last_train_time: float = 0.0
        self._train_count: int = 0
        self._lock = asyncio.Lock()

        # Try to load persisted model on init
        self._load_model()

    @property
    def is_ready(self) -> bool:
        return self._is_trained and self._model is not None

    @property
    def sample_count(self) -> int:
        return len(self._training_buffer)

    # ── Feature Extraction ───────────────────────────────

    @staticmethod
    def extract_vector(features: dict, rate_ratio: float = 0.0, behavior_score: float = 0.0) -> np.ndarray:
        """
        Extract a fixed-length numeric vector from request features.
        Returns shape (11,) numpy array.
        """
        ua = features.get("user_agent", "")
        ua_lower = ua.lower() if ua else ""

        # UA score: 0.0=normal, 0.5=suspicious lib, 0.9=empty
        ua_score = 0.0
        if not ua:
            ua_score = 0.9
        else:
            for token in _SUSPICIOUS_UA_TOKENS:
                if token in ua_lower:
                    ua_score = 0.5
                    break

        path = features.get("path", "/")
        headers = features.get("_raw_headers", {})

        return np.array([
            features.get("header_count", 0),
            features.get("content_length", 0),
            ua_score,
            len(path),
            len(set(path)),
            1.0 if features.get("method", "GET") == "POST" else 0.0,
            1.0 if headers.get("cookie") else 0.0,
            1.0 if headers.get("referer") else 0.0,
            1.0 if features.get("accept_language") else 0.0,
            rate_ratio,
            behavior_score,
        ], dtype=np.float64)

    # ── Training ─────────────────────────────────────────

    def record_sample(
        self, features: dict, rate_ratio: float = 0.0, behavior_score: float = 0.0,
    ) -> None:
        """Add a sample to the training buffer."""
        vec = self.extract_vector(features, rate_ratio, behavior_score)
        self._training_buffer.append(vec)

    async def maybe_train(self) -> bool:
        """Train or retrain if conditions are met. Returns True if trained."""
        now = time.time()

        # First train: need enough samples
        if not self._is_trained:
            if len(self._training_buffer) < self.config.min_train_samples:
                return False
        else:
            # Retrain: check interval
            if now - self._last_train_time < self.config.retrain_interval_sec:
                return False
            if len(self._training_buffer) < 100:
                return False

        async with self._lock:
            await asyncio.to_thread(self._train_sync)
        return True

    def _train_sync(self) -> None:
        """Synchronous training (runs in thread)."""
        samples = list(self._training_buffer)
        if not samples:
            return

        X = np.array(samples)

        # Cap training set size
        if len(X) > self.config.max_samples:
            indices = np.random.choice(len(X), self.config.max_samples, replace=False)
            X = X[indices]

        # Fit scaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # Fit IsolationForest
        model = IsolationForest(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            max_samples=min(len(X_scaled), self.config.max_samples),
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_scaled)

        self._model = model
        self._scaler = scaler
        self._is_trained = True
        self._last_train_time = time.time()
        self._train_count += 1

        logger.info(
            "ML model trained (#%d) — %d samples, %d features",
            self._train_count, len(X), X.shape[1],
        )

        self._save_model()

    # ── Prediction ───────────────────────────────────────

    def score(
        self, features: dict, rate_ratio: float = 0.0, behavior_score: float = 0.0,
    ) -> float:
        """
        Score a single request.

        Returns:
            - float in [0, 1] where 1.0 = highly anomalous
            - 0.0 if model is not ready
        """
        if not self.is_ready:
            return 0.0

        vec = self.extract_vector(features, rate_ratio, behavior_score)
        X = vec.reshape(1, -1)
        X_scaled = self._scaler.transform(X)  # type: ignore[union-attr]

        # decision_function returns negative for anomalies
        raw_score = self._model.decision_function(X_scaled)[0]  # type: ignore[union-attr]

        # Convert to 0–1 range where 1.0 = most anomalous
        # IsolationForest: lower raw_score → more anomalous
        # Typical range: -0.5 (anomaly) to 0.5 (normal)
        # Map to [0, 1]: clamp and invert
        normalized = 1.0 - (raw_score + 0.5)  # -0.5→1.0, 0.5→0.0
        return float(min(1.0, max(0.0, normalized)))

    def predict_label(
        self, features: dict, rate_ratio: float = 0.0, behavior_score: float = 0.0,
    ) -> int:
        """
        Predict label: 1 = normal, -1 = anomaly.
        Returns 1 if model not ready.
        """
        if not self.is_ready:
            return 1

        vec = self.extract_vector(features, rate_ratio, behavior_score)
        X = vec.reshape(1, -1)
        X_scaled = self._scaler.transform(X)  # type: ignore[union-attr]
        return int(self._model.predict(X_scaled)[0])  # type: ignore[union-attr]

    # ── Persistence ──────────────────────────────────────

    def _model_path(self) -> Path:
        return Path(self.config.model_dir) / "isolation_forest.pkl"

    def _save_model(self) -> None:
        """Persist model and scaler to disk."""
        try:
            path = self._model_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump(
                    {
                        "model": self._model,
                        "scaler": self._scaler,
                        "train_count": self._train_count,
                        "timestamp": time.time(),
                    },
                    f,
                )
            logger.info("ML model saved to %s", path)
        except Exception:
            logger.exception("Failed to save ML model")

    def _load_model(self) -> None:
        """Load persisted model from disk."""
        path = self._model_path()
        if not path.exists():
            return
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
            self._model = data["model"]
            self._scaler = data["scaler"]
            self._train_count = data.get("train_count", 0)
            self._is_trained = True
            logger.info(
                "ML model loaded from %s (train #%d)",
                path, self._train_count,
            )
        except Exception:
            logger.exception("Failed to load ML model — starting fresh")

    # ── Info ─────────────────────────────────────────────

    def info(self) -> dict:
        """Return model status for API."""
        return {
            "is_ready": self.is_ready,
            "train_count": self._train_count,
            "buffer_size": len(self._training_buffer),
            "min_train_samples": self.config.min_train_samples,
            "last_trained": self._last_train_time or None,
            "n_estimators": self.config.n_estimators,
            "contamination": self.config.contamination,
        }


# Module-level singleton
ml_model = MLAnomalyModel()

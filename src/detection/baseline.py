"""
Sentinel DDoS — Baseline Traffic Model.

Learns "normal" traffic patterns over a configurable window (24–72 h)
and provides statistical baselines for anomaly detection.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict

import numpy as np

logger = logging.getLogger("sentinel.detection.baseline")

# Default sliding window: 24 hours of observations
DEFAULT_WINDOW_SEC = 24 * 3600


@dataclass
class TrafficStats:
    """Aggregated statistics for a single time bucket."""
    request_count: int = 0
    unique_ips: int = 0
    avg_content_length: float = 0.0
    avg_header_count: float = 0.0
    method_distribution: Dict[str, int] = field(default_factory=dict)
    path_distribution: Dict[str, int] = field(default_factory=dict)


class BaselineModel:
    """
    Sliding-window baseline that keeps traffic observations
    and computes statistical summaries (mean, std) for scoring.
    """

    def __init__(self, window_sec: int = DEFAULT_WINDOW_SEC) -> None:
        self.window_sec = window_sec
        self._observations: Deque[dict] = deque()
        self._ips_seen: set = set()

        # Computed baselines (updated periodically)
        self.mean_rps: float = 0.0
        self.std_rps: float = 1.0
        self.mean_header_count: float = 0.0
        self.std_header_count: float = 1.0
        self.mean_content_length: float = 0.0
        self.std_content_length: float = 1.0
        self.is_ready: bool = False

    @property
    def observation_count(self) -> int:
        return len(self._observations)

    def record_observation(self, features: dict) -> None:
        """Append a new observation and evict old ones outside the window."""
        self._observations.append(features)
        self._ips_seen.add(features.get("client_ip"))
        self._evict_old()

    def update_model(self) -> None:
        """Recompute baseline statistics from the observation window."""
        self._evict_old()
        n = len(self._observations)
        if n < 100:
            logger.debug("Not enough observations for baseline (%d)", n)
            return

        header_counts = np.array([o.get("header_count", 0) for o in self._observations])
        content_lengths = np.array([o.get("content_length", 0) for o in self._observations])

        # RPS: requests per second over window buckets
        timestamps = np.array([o["timestamp"] for o in self._observations])
        span = timestamps[-1] - timestamps[0]
        if span > 0:
            bucket_size = 60  # 1-minute buckets
            n_buckets = max(1, int(span / bucket_size))
            rps_values = np.histogram(timestamps, bins=n_buckets)[0] / bucket_size
            self.mean_rps = float(np.mean(rps_values))
            self.std_rps = float(np.std(rps_values)) or 1.0

        self.mean_header_count = float(np.mean(header_counts))
        self.std_header_count = float(np.std(header_counts)) or 1.0
        self.mean_content_length = float(np.mean(content_lengths))
        self.std_content_length = float(np.std(content_lengths)) or 1.0
        self.is_ready = True

        logger.info(
            "Baseline ready — mean_rps=%.2f std_rps=%.2f obs=%d ips=%d",
            self.mean_rps, self.std_rps, n, len(self._ips_seen),
        )

    def _evict_old(self) -> None:
        cutoff = time.time() - self.window_sec
        while self._observations and self._observations[0]["timestamp"] < cutoff:
            self._observations.popleft()

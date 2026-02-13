"""
Sentinel DDoS — Behavioral Analysis Engine.

Tracks per-IP session behavior to distinguish bots from humans:
  • Request timing patterns (inter-arrival intervals)
  • Navigation flow (referrer chains, path diversity)
  • Header consistency (same UA / accept-language across session)
  • Mouse / JS indicators (cookie support, referer presence)
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Deque
from collections import deque

logger = logging.getLogger("sentinel.detection.behavior")

# Keep per-IP sessions for 10 minutes of inactivity
SESSION_TTL = 600
# Maximum number of IPs to track concurrently
MAX_TRACKED = 50_000


@dataclass
class IPSession:
    """Accumulated behavior signals for a single client IP."""
    first_seen: float = 0.0
    last_seen: float = 0.0
    request_count: int = 0

    # Timing
    inter_arrival_times: Deque[float] = field(default_factory=lambda: deque(maxlen=200))

    # Navigation
    paths_visited: Deque[str] = field(default_factory=lambda: deque(maxlen=100))
    methods_used: set = field(default_factory=set)
    has_referer: bool = False
    has_cookies: bool = False

    # Header consistency
    user_agents: set = field(default_factory=set)
    accept_languages: set = field(default_factory=set)
    header_order_hashes: set = field(default_factory=set)

    def record(
        self,
        now: float,
        path: str,
        method: str,
        user_agent: str,
        accept_language: str,
        referer: str | None,
        cookie: str | None,
        header_order_hash: str,
    ) -> None:
        if self.first_seen == 0:
            self.first_seen = now
        if self.last_seen > 0:
            delta = now - self.last_seen
            self.inter_arrival_times.append(delta)
        self.last_seen = now
        self.request_count += 1

        self.paths_visited.append(path)
        self.methods_used.add(method)
        if user_agent:
            self.user_agents.add(user_agent)
        if accept_language:
            self.accept_languages.add(accept_language)
        self.header_order_hashes.add(header_order_hash)
        if referer:
            self.has_referer = True
        if cookie:
            self.has_cookies = True


class BehaviorAnalyzer:
    """
    Tracks per-IP session behavior and produces a bot-likelihood score.

    Score semantics:
        0.0 = clearly human-like
        1.0 = clearly bot-like
    """

    def __init__(self) -> None:
        self._sessions: dict[str, IPSession] = {}
        self._last_cleanup: float = 0.0

    def record_and_score(
        self,
        client_ip: str,
        path: str,
        method: str,
        user_agent: str,
        accept_language: str,
        referer: str | None,
        cookie: str | None,
        header_order_hash: str,
    ) -> float:
        """Record the request to the IP's session and return a bot score."""
        now = time.time()
        self._maybe_cleanup(now)

        session = self._sessions.get(client_ip)
        if session is None:
            session = IPSession()
            # Evict oldest if at capacity
            if len(self._sessions) >= MAX_TRACKED:
                oldest_ip = min(self._sessions, key=lambda k: self._sessions[k].last_seen)
                del self._sessions[oldest_ip]
            self._sessions[client_ip] = session

        session.record(
            now=now,
            path=path,
            method=method,
            user_agent=user_agent,
            accept_language=accept_language,
            referer=referer,
            cookie=cookie,
            header_order_hash=header_order_hash,
        )

        return self._compute_score(session)

    def get_session(self, client_ip: str) -> IPSession | None:
        return self._sessions.get(client_ip)

    # ── Scoring ──────────────────────────────────────────

    def _compute_score(self, s: IPSession) -> float:
        """Combine multiple behavioral signals into [0, 1]."""
        signals: list[tuple[float, float]] = []  # (value, weight)

        # Need at least 3 requests to judge
        if s.request_count < 3:
            return 0.0

        # 1) Timing regularity — bots have very uniform timing
        timing_score = self._timing_regularity(s)
        signals.append((timing_score, 0.30))

        # 2) Path diversity — bots often hit the same path
        path_div = self._path_diversity(s)
        signals.append((1.0 - path_div, 0.15))  # low diversity = more suspicious

        # 3) Header consistency — humans don't change UA mid-session
        header_score = self._header_consistency(s)
        signals.append((header_score, 0.15))

        # 4) Request rate — very high rate = suspicious
        rate_score = self._rate_score(s)
        signals.append((rate_score, 0.20))

        # 5) Browser indicators — no referer + no cookies + no accept-language = bot
        browser_score = self._browser_indicators(s)
        signals.append((browser_score, 0.20))

        composite = sum(v * w for v, w in signals)
        return min(1.0, max(0.0, composite))

    @staticmethod
    def _timing_regularity(s: IPSession) -> float:
        """
        Bots tend to have very consistent inter-arrival times (low CV).
        Humans are irregular (high CV).
        Returns 0.0 for human-like timing, up to 1.0 for bot-like.
        """
        intervals = list(s.inter_arrival_times)
        if len(intervals) < 5:
            return 0.0

        mean_iat = sum(intervals) / len(intervals)
        if mean_iat == 0:
            return 1.0  # zero-delay → definitely automated

        variance = sum((x - mean_iat) ** 2 for x in intervals) / len(intervals)
        std_iat = math.sqrt(variance)
        cv = std_iat / mean_iat  # coefficient of variation

        # CV < 0.1 → extremely regular → bot-like
        # CV > 0.8 → very irregular → human-like
        if cv < 0.05:
            return 1.0
        if cv < 0.15:
            return 0.7
        if cv < 0.3:
            return 0.3
        return 0.0

    @staticmethod
    def _path_diversity(s: IPSession) -> float:
        """Fraction of unique paths visited. Humans browse diversely."""
        paths = list(s.paths_visited)
        if not paths:
            return 0.0
        unique = len(set(paths))
        return unique / len(paths)

    @staticmethod
    def _header_consistency(s: IPSession) -> float:
        """Multiple UAs or accept-languages in a session = suspicious."""
        score = 0.0
        if len(s.user_agents) > 1:
            score += 0.5
        if len(s.accept_languages) > 2:
            score += 0.3
        if len(s.header_order_hashes) > 2:
            score += 0.2
        return min(1.0, score)

    @staticmethod
    def _rate_score(s: IPSession) -> float:
        """Very high request rate → bot-like."""
        duration = s.last_seen - s.first_seen
        if duration < 1.0:
            return 0.0  # too early to judge
        rps = s.request_count / duration
        if rps > 20:
            return 1.0
        if rps > 10:
            return 0.7
        if rps > 5:
            return 0.3
        return 0.0

    @staticmethod
    def _browser_indicators(s: IPSession) -> float:
        """Missing browser-typical headers = suspicious."""
        score = 0.0
        if not s.has_referer and s.request_count > 5:
            score += 0.4  # humans usually have referer after first click
        if not s.has_cookies and s.request_count > 3:
            score += 0.3  # real browsers accept cookies
        if not s.accept_languages:
            score += 0.3  # browsers send accept-language
        return min(1.0, score)

    # ── Maintenance ──────────────────────────────────────

    def _maybe_cleanup(self, now: float) -> None:
        """Evict expired sessions every 60s."""
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        cutoff = now - SESSION_TTL
        expired = [ip for ip, s in self._sessions.items() if s.last_seen < cutoff]
        for ip in expired:
            del self._sessions[ip]
        if expired:
            logger.debug("Evicted %d expired sessions", len(expired))


behavior_analyzer = BehaviorAnalyzer()

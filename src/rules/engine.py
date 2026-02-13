"""
Sentinel DDoS — YAML Rules Engine.

Loads protection rules from YAML files and evaluates them
against incoming requests for path-specific rate limits and escalation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from src.config import settings

logger = logging.getLogger("sentinel.rules")


@dataclass
class RateLimit:
    """Rate limit definition."""
    per_ip: Optional[str] = None        # e.g. "5/minute"
    per_subnet: Optional[str] = None    # e.g. "50/minute"


@dataclass
class EscalationStep:
    """Single escalation step."""
    threshold: float = 0.0    # percentage (0–100)
    action: str = "monitor"   # monitor | js_challenge | rate_limit | block
    duration: Optional[str] = None  # e.g. "1h", "30m"


@dataclass
class Rule:
    """A single protection rule."""
    name: str
    match_path: Optional[str] = None
    match_method: Optional[str] = None
    limits: Optional[RateLimit] = None
    escalation: list[EscalationStep] = field(default_factory=list)
    enabled: bool = True


class RulesEngine:
    """Loads and evaluates YAML-defined protection rules."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def load_from_directory(self, rules_dir: Optional[str] = None) -> int:
        """Load all YAML files from the rules directory. Returns count loaded."""
        directory = Path(rules_dir or settings.rules_dir)
        if not directory.exists():
            logger.warning("Rules directory not found: %s", directory)
            return 0

        loaded = 0
        for path in sorted(directory.glob("*.yml")):
            try:
                self._load_file(path)
                loaded += 1
            except Exception:
                logger.exception("Failed to load rule file: %s", path)

        for path in sorted(directory.glob("*.yaml")):
            try:
                self._load_file(path)
                loaded += 1
            except Exception:
                logger.exception("Failed to load rule file: %s", path)

        logger.info("Loaded %d rule file(s) from %s", loaded, directory)
        return loaded

    def match_request(self, path: str, method: str) -> list[Rule]:
        """Return all rules matching the given path and method."""
        matched: list[Rule] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.match_path and not self._path_matches(path, rule.match_path):
                continue
            if rule.match_method and rule.match_method.upper() != method.upper():
                continue
            matched.append(rule)
        return matched

    def parse_rate_string(self, rate_str: str) -> tuple[int, int]:
        """
        Parse rate string like '5/minute' into (count, window_seconds).
        """
        parts = rate_str.split("/")
        count = int(parts[0])
        unit = parts[1].lower() if len(parts) > 1 else "minute"
        unit_map = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}
        window = unit_map.get(unit, 60)
        return count, window

    # ── Internal ─────────────────────────────────────────

    def _load_file(self, path: Path) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return

        for raw in data["rules"]:
            rule = self._parse_rule(raw)
            self._rules.append(rule)
            logger.debug("Loaded rule: %s", rule.name)

    def _parse_rule(self, raw: dict[str, Any]) -> Rule:
        match = raw.get("match", {})
        limits_raw = raw.get("limits", {})
        escalation_raw = raw.get("escalation", [])

        limits = RateLimit(
            per_ip=limits_raw.get("per_ip"),
            per_subnet=limits_raw.get("per_subnet"),
        ) if limits_raw else None

        escalation = [
            EscalationStep(
                threshold=step.get("threshold", 0),
                action=step.get("action", "monitor"),
                duration=step.get("duration"),
            )
            for step in escalation_raw
        ]

        return Rule(
            name=raw.get("name", "unnamed"),
            match_path=match.get("path"),
            match_method=match.get("method"),
            limits=limits,
            escalation=escalation,
            enabled=raw.get("enabled", True),
        )

    @staticmethod
    def _path_matches(request_path: str, rule_path: str) -> bool:
        """Simple prefix / exact path matching."""
        if rule_path.endswith("*"):
            return request_path.startswith(rule_path[:-1])
        return request_path == rule_path


rules_engine = RulesEngine()

"""
Tests for the rules engine.
"""

import pytest
from pathlib import Path

from src.rules.engine import RulesEngine


@pytest.fixture
def rules_engine(tmp_path: Path):
    """Rules engine loaded from test fixtures."""
    rule_file = tmp_path / "test_rules.yml"
    rule_file.write_text("""
rules:
  - name: "Login Protection"
    match:
      path: "/api/login"
      method: "POST"
    limits:
      per_ip: "5/minute"
      per_subnet: "50/minute"
    escalation:
      - threshold: 80
        action: js_challenge
      - threshold: 95
        action: block
        duration: "1h"

  - name: "Catch All"
    match:
      path: "/*"
    limits:
      per_ip: "100/minute"
""")
    engine = RulesEngine()
    engine.load_from_directory(str(tmp_path))
    return engine


def test_load_rules(rules_engine):
    """Rules should load from YAML."""
    assert len(rules_engine.rules) == 2


def test_match_exact_path(rules_engine):
    """Exact path match should work."""
    matched = rules_engine.match_request("/api/login", "POST")
    names = [r.name for r in matched]
    assert "Login Protection" in names


def test_match_wildcard(rules_engine):
    """Wildcard rules should match all paths."""
    matched = rules_engine.match_request("/any/path", "GET")
    names = [r.name for r in matched]
    assert "Catch All" in names


def test_method_filter(rules_engine):
    """Rules with method filter should not match other methods."""
    matched = rules_engine.match_request("/api/login", "GET")
    names = [r.name for r in matched]
    assert "Login Protection" not in names


def test_parse_rate_string(rules_engine):
    count, window = rules_engine.parse_rate_string("5/minute")
    assert count == 5
    assert window == 60

    count, window = rules_engine.parse_rate_string("100/hour")
    assert count == 100
    assert window == 3600

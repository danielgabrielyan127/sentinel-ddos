"""
Tests for the attack simulator configuration and report.
"""

import pytest

from simulator.attack_simulator import (
    AttackSimulator,
    SimulatorConfig,
    SimulatorReport,
    AttackScenario,
)


def test_report_block_rate():
    """Block rate should calculate correctly."""
    r = SimulatorReport(scenario="test", duration_sec=10, total_requests=100, blocked=30, rate_limited=20)
    assert r.block_rate == 50.0


def test_report_block_rate_zero_total():
    """Block rate with zero requests should not divide by zero."""
    r = SimulatorReport(scenario="test", duration_sec=0)
    assert r.block_rate == 0.0


def test_report_summary():
    """Summary should return a formatted string."""
    r = SimulatorReport(scenario="http_flood", duration_sec=30, total_requests=1000)
    summary = r.summary()
    assert "http_flood" in summary
    assert "1000" in summary


def test_config_defaults():
    """Default config should have sensible values."""
    c = SimulatorConfig()
    assert c.target_url == "http://localhost:8000"
    assert c.scenario == AttackScenario.HTTP_FLOOD
    assert c.duration_sec == 30
    assert c.concurrency == 50
    assert c.rps == 500
    assert c.source_ips == 10


def test_attack_scenarios_enum():
    """All scenario values should be valid."""
    assert AttackScenario.HTTP_FLOOD.value == "http_flood"
    assert AttackScenario.SLOWLORIS.value == "slowloris"
    assert AttackScenario.DISTRIBUTED.value == "distributed"
    assert AttackScenario.MIXED.value == "mixed"


def test_simulator_init():
    """Simulator should initialize with config."""
    config = SimulatorConfig(
        scenario=AttackScenario.DISTRIBUTED,
        duration_sec=10,
        rps=50,
        source_ips=100,
    )
    sim = AttackSimulator(config)
    assert sim.report.scenario == "distributed"
    assert sim._stop is False


def test_random_ip(monkeypatch):
    """Random IP should be in the 10.x.x.x range and tracked."""
    config = SimulatorConfig(source_ips=5)
    sim = AttackSimulator(config)
    ip = sim._random_ip()
    assert ip.startswith("10.")
    assert ip in sim._ips_used


def test_record_response():
    """Recording responses should update counters correctly."""
    config = SimulatorConfig()
    sim = AttackSimulator(config)

    sim._record_response(200, 10.0)
    assert sim.report.successful == 1
    assert sim.report.total_requests == 1

    sim._record_response(403, 5.0)
    assert sim.report.blocked == 1

    sim._record_response(429, 3.0)
    assert sim.report.rate_limited == 1

    sim._record_response(503, 50.0)
    assert sim.report.challenged == 1

    sim._record_response(500, 100.0)
    assert sim.report.errors == 1

    assert sim.report.total_requests == 5

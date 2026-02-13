"""
Tests for the GeoIP lookup module.
"""

import pytest

from src.geoip.lookup import GeoResult, lookup, _fallback_lookup


def test_fallback_returns_result():
    """Fallback lookup should always return a GeoResult."""
    result = lookup("1.2.3.4")
    assert isinstance(result, GeoResult)
    assert result.country_code != ""
    assert result.country_name != ""


def test_deterministic_mapping():
    """Same IP should always map to the same country."""
    r1 = _fallback_lookup("10.0.1.5")
    r2 = _fallback_lookup("10.0.1.5")
    assert r1.country_code == r2.country_code
    assert r1.latitude == r2.latitude


def test_different_ips_vary():
    """Different IPs should map to different countries (mostly)."""
    countries = set()
    for i in range(50):
        r = _fallback_lookup(f"10.0.{i}.1")
        countries.add(r.country_code)
    # With 20 countries, 50 different IPs should hit at least 5
    assert len(countries) >= 5


def test_to_dict():
    """GeoResult.to_dict should return all fields."""
    r = GeoResult(
        country_code="US",
        country_name="United States",
        city="New York",
        latitude=40.7,
        longitude=-74.0,
    )
    d = r.to_dict()
    assert d["country_code"] == "US"
    assert d["latitude"] == 40.7
    assert "city" in d
    assert "org" in d


def test_private_ip_works():
    """Private/RFC1918 IPs should not crash."""
    result = lookup("192.168.1.1")
    assert result.country_code
    result = lookup("10.0.0.1")
    assert result.country_code
    result = lookup("127.0.0.1")
    assert result.country_code

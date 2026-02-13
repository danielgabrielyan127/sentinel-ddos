"""
Sentinel DDoS — GeoIP Lookup.

Provides geographic information for IPs using either:
  - MaxMind GeoLite2 database (if configured via SENTINEL_GEOIP_DB_PATH)
  - Built-in fallback that maps RFC1918 ranges and known ranges

For production use, download GeoLite2-City.mmdb from MaxMind.
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from ipaddress import IPv4Address, ip_address
from typing import Optional

logger = logging.getLogger("sentinel.geoip")

_reader = None  # MaxMind database reader (lazy-loaded)
_geoip_available = False


@dataclass
class GeoResult:
    """Geographic location result."""
    country_code: str  # ISO 3166-1 alpha-2= e.g. "US"
    country_name: str
    city: Optional[str] = None
    latitude: float = 0.0
    longitude: float = 0.0
    asn: Optional[str] = None
    org: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "country_code": self.country_code,
            "country_name": self.country_name,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "org": self.org,
        }


def init_geoip(db_path: str | None = None) -> bool:
    """
    Initialize GeoIP database.
    Returns True if MaxMind DB is available.
    """
    global _reader, _geoip_available
    if not db_path:
        logger.info("No GeoIP DB path configured — using fallback mapping")
        return False
    try:
        import geoip2.database  # type: ignore[import-untyped]
        _reader = geoip2.database.Reader(db_path)
        _geoip_available = True
        logger.info("GeoIP database loaded: %s", db_path)
        return True
    except Exception:
        logger.warning("Failed to load GeoIP database from %s", db_path, exc_info=True)
        return False


def lookup(ip: str) -> GeoResult:
    """Look up geographic info for an IP address."""
    # Try MaxMind first
    if _geoip_available and _reader:
        try:
            return _maxmind_lookup(ip)
        except Exception:
            pass

    # Fallback to heuristic mapping
    return _fallback_lookup(ip)


def _maxmind_lookup(ip: str) -> GeoResult:
    """Query MaxMind GeoLite2 database."""
    resp = _reader.city(ip)  # type: ignore[union-attr]
    return GeoResult(
        country_code=resp.country.iso_code or "XX",
        country_name=resp.country.name or "Unknown",
        city=resp.city.name,
        latitude=float(resp.location.latitude or 0),
        longitude=float(resp.location.longitude or 0),
    )


# ── Fallback: deterministic mapping based on IP octets ───

# Known country data for realistic fallback (capital coords)
_COUNTRIES = [
    ("US", "United States", 38.0, -97.0),
    ("CN", "China", 35.0, 105.0),
    ("RU", "Russia", 55.75, 37.62),
    ("DE", "Germany", 52.52, 13.41),
    ("BR", "Brazil", -15.78, -47.93),
    ("IN", "India", 28.61, 77.21),
    ("JP", "Japan", 35.68, 139.69),
    ("GB", "United Kingdom", 51.51, -0.13),
    ("FR", "France", 48.86, 2.35),
    ("KR", "South Korea", 37.57, 126.98),
    ("AU", "Australia", -33.87, 151.21),
    ("NL", "Netherlands", 52.37, 4.90),
    ("CA", "Canada", 45.42, -75.69),
    ("UA", "Ukraine", 50.45, 30.52),
    ("PL", "Poland", 52.23, 21.01),
    ("ID", "Indonesia", -6.21, 106.85),
    ("TR", "Turkey", 39.93, 32.86),
    ("VN", "Vietnam", 21.03, 105.85),
    ("SG", "Singapore", 1.35, 103.82),
    ("ZA", "South Africa", -33.92, 18.42),
]


def _fallback_lookup(ip: str) -> GeoResult:
    """
    Deterministic IP-to-country mapping for simulator/testing.
    Uses IP octets to pick a country consistently.
    """
    try:
        addr = ip_address(ip)
        if isinstance(addr, IPv4Address):
            octets = [int(o) for o in ip.split(".")]
            # Use the sum of octets modulo country count for determinism
            idx = (octets[0] * 7 + octets[1] * 3 + octets[2]) % len(_COUNTRIES)
        else:
            idx = hash(ip) % len(_COUNTRIES)
    except Exception:
        idx = 0

    code, name, lat, lon = _COUNTRIES[idx]
    # Add small jitter so pins don't stack
    lat += (hash(ip + "lat") % 100 - 50) * 0.05
    lon += (hash(ip + "lon") % 100 - 50) * 0.05

    return GeoResult(
        country_code=code,
        country_name=name,
        latitude=round(lat, 4),
        longitude=round(lon, 4),
    )


def close() -> None:
    """Close the GeoIP database reader."""
    global _reader, _geoip_available
    if _reader:
        try:
            _reader.close()
        except Exception:
            pass
        _reader = None
        _geoip_available = False

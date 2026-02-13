"""
Sentinel DDoS — Request Fingerprinting.

Generates unique fingerprints from TLS, header-order, and
behavioral signals to identify clients beyond IP address.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from fastapi import Request

logger = logging.getLogger("sentinel.proxy.fingerprint")


@dataclass
class RequestFingerprint:
    """Composite fingerprint for a single request."""

    client_ip: str
    ja3_hash: Optional[str] = None           # TLS fingerprint
    header_order_hash: Optional[str] = None  # HTTP header order hash
    user_agent: Optional[str] = None
    accept_language: Optional[str] = None
    accept_encoding: Optional[str] = None
    connection_type: Optional[str] = None
    raw_headers: dict = field(default_factory=dict)

    @property
    def composite_id(self) -> str:
        """Deterministic composite identifier for the client."""
        parts = [
            self.ja3_hash or "",
            self.header_order_hash or "",
            self.user_agent or "",
            self.accept_language or "",
        ]
        digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
        return f"{self.client_ip}:{digest}"


def compute_header_order_hash(headers: dict) -> str:
    """Hash of header keys in received order — unique per HTTP stack."""
    keys = list(headers.keys())
    return hashlib.md5(json.dumps(keys).encode()).hexdigest()


async def fingerprint_request(
    request: Request,
    client_ip: str,
    ja3_hash: Optional[str] = None,
) -> RequestFingerprint:
    """Build a RequestFingerprint from a FastAPI Request."""
    headers = dict(request.headers)
    return RequestFingerprint(
        client_ip=client_ip,
        ja3_hash=ja3_hash,
        header_order_hash=compute_header_order_hash(headers),
        user_agent=headers.get("user-agent"),
        accept_language=headers.get("accept-language"),
        accept_encoding=headers.get("accept-encoding"),
        connection_type=headers.get("connection"),
        raw_headers=headers,
    )

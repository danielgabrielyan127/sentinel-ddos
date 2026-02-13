"""
Sentinel DDoS — JavaScript Challenge / Proof-of-Browser.

Serves a JS challenge page to suspicious clients.
Clients that solve the challenge get a signed cookie
and are allowed through on subsequent requests.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from typing import Optional

from fastapi import Request, Response

from src.config import settings

logger = logging.getLogger("sentinel.mitigation.challenge")

CHALLENGE_COOKIE = "sentinel_challenge"
CHALLENGE_TTL = 3600  # 1 hour validity


class ChallengeManager:
    """JS challenge generation and verification."""

    def __init__(self) -> None:
        self._secret = settings.jwt_secret.encode()

    async def maybe_challenge(
        self,
        request: Request,
        client_ip: str,
    ) -> Optional[Response]:
        """
        If client has a valid challenge cookie → return None (pass through).
        Otherwise → return challenge HTML page.
        """
        cookie = request.cookies.get(CHALLENGE_COOKIE)
        if cookie and self._verify_token(cookie, client_ip):
            return None

        # Serve JS challenge page
        token = self._generate_challenge(client_ip)
        html = self._render_challenge_page(token)
        response = Response(content=html, media_type="text/html", status_code=503)
        return response

    def _generate_challenge(self, client_ip: str) -> str:
        """Create a challenge token tied to the client IP."""
        nonce = secrets.token_hex(16)
        ts = str(int(time.time()))
        data = f"{client_ip}:{nonce}:{ts}"
        sig = hmac.new(self._secret, data.encode(), hashlib.sha256).hexdigest()
        return f"{data}:{sig}"

    def _verify_token(self, token: str, client_ip: str) -> bool:
        """Verify a solved challenge token (includes PoW nonce)."""
        try:
            parts = token.split(":")
            # Format: ip:nonce:ts:sig:pow_nonce
            if len(parts) != 5:
                return False
            ip, nonce, ts, sig, pow_nonce = parts
            if ip != client_ip:
                return False
            if time.time() - int(ts) > CHALLENGE_TTL:
                return False
            # Verify HMAC signature on original challenge
            original = f"{ip}:{nonce}:{ts}"
            expected = hmac.new(
                self._secret,
                original.encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return False
            # Verify proof-of-work: SHA256(original_token:pow_nonce) starts with "00"
            full_token = f"{original}:{sig}"
            pow_input = f"{full_token}:{pow_nonce}"
            pow_hash = hashlib.sha256(pow_input.encode()).hexdigest()
            return pow_hash.startswith("00")
        except Exception:
            return False

    @staticmethod
    def _render_challenge_page(token: str) -> str:
        """Render the JS challenge HTML page."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Checking your browser — Sentinel DDoS</title>
    <style>
        body {{
            background: #0d1117; color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex; align-items: center; justify-content: center;
            height: 100vh; margin: 0;
        }}
        .container {{ text-align: center; }}
        .spinner {{
            border: 4px solid #30363d; border-top: 4px solid #58a6ff;
            border-radius: 50%; width: 48px; height: 48px;
            animation: spin 1s linear infinite; margin: 20px auto;
        }}
        @keyframes spin {{ 100% {{ transform: rotate(360deg); }} }}
        h1 {{ font-size: 1.5rem; margin-bottom: 8px; }}
        p {{ color: #8b949e; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Sentinel DDoS Protection</h1>
        <div class="spinner"></div>
        <p>Checking your browser before accessing the site…</p>
        <p id="status">Solving challenge…</p>
    </div>
    <script>
        // Simple proof-of-work: find a nonce that creates a hash starting with "00"
        (async function() {{
            const token = "{token}";
            let nonce = 0;
            while (true) {{
                const data = token + ":" + nonce;
                const hash = await crypto.subtle.digest(
                    "SHA-256",
                    new TextEncoder().encode(data)
                );
                const hex = Array.from(new Uint8Array(hash))
                    .map(b => b.toString(16).padStart(2, '0')).join('');
                if (hex.startsWith("00")) {{
                    document.cookie = "{CHALLENGE_COOKIE}=" + token
                        + ":" + nonce
                        + "; path=/; max-age={CHALLENGE_TTL}; SameSite=Lax";
                    document.getElementById("status").textContent = "Verified! Redirecting…";
                    setTimeout(() => location.reload(), 500);
                    return;
                }}
                nonce++;
                if (nonce % 10000 === 0) {{
                    document.getElementById("status").textContent =
                        "Solving challenge… (" + nonce + " attempts)";
                    await new Promise(r => setTimeout(r, 0));
                }}
            }}
        }})();
    </script>
</body>
</html>"""


challenge_manager = ChallengeManager()

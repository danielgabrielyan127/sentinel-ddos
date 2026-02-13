"""
Sentinel DDoS — Alert Dispatchers.

Sends notifications via Telegram and Webhooks.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import httpx

from src.config import settings

logger = logging.getLogger("sentinel.alerts")


@dataclass
class AlertEvent:
    """Represents a single alert event."""
    level: str          # info | warning | critical
    title: str
    message: str
    source_ip: Optional[str] = None
    attack_type: Optional[str] = None
    metadata: Optional[dict] = None


class AlertDispatcher(ABC):
    """Base class for alert dispatchers."""

    @abstractmethod
    async def send(self, event: AlertEvent) -> bool:
        ...


class TelegramAlert(AlertDispatcher):
    """Send alerts via Telegram Bot API."""

    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
    ) -> None:
        self.bot_token = bot_token or settings.telegram_bot_token
        self.chat_id = chat_id or settings.telegram_chat_id

    async def send(self, event: AlertEvent) -> bool:
        if not self.bot_token or not self.chat_id:
            logger.debug("Telegram not configured, skipping alert")
            return False

        icon = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(event.level, "📢")
        text = (
            f"{icon} *Sentinel DDoS Alert*\n\n"
            f"*{event.title}*\n"
            f"{event.message}\n"
        )
        if event.source_ip:
            text += f"\n🌐 Source IP: `{event.source_ip}`"
        if event.attack_type:
            text += f"\n🎯 Attack type: `{event.attack_type}`"

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                })
                resp.raise_for_status()
                logger.info("Telegram alert sent: %s", event.title)
                return True
        except Exception:
            logger.exception("Failed to send Telegram alert")
            return False


class WebhookAlert(AlertDispatcher):
    """Send alerts via configurable webhook URL."""

    def __init__(self, url: Optional[str] = None) -> None:
        self.url = url or settings.webhook_url

    async def send(self, event: AlertEvent) -> bool:
        if not self.url:
            logger.debug("Webhook not configured, skipping alert")
            return False

        payload = {
            "level": event.level,
            "title": event.title,
            "message": event.message,
            "source_ip": event.source_ip,
            "attack_type": event.attack_type,
            "metadata": event.metadata,
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(self.url, json=payload, timeout=10)
                resp.raise_for_status()
                logger.info("Webhook alert sent: %s", event.title)
                return True
        except Exception:
            logger.exception("Failed to send webhook alert")
            return False


class AlertManager:
    """Aggregates all dispatchers and sends alerts to all of them."""

    def __init__(self) -> None:
        self.dispatchers: list[AlertDispatcher] = [
            TelegramAlert(),
            WebhookAlert(),
        ]

    async def alert(self, event: AlertEvent) -> None:
        for dispatcher in self.dispatchers:
            try:
                await dispatcher.send(event)
            except Exception:
                logger.exception("Dispatcher %s failed", type(dispatcher).__name__)


alert_manager = AlertManager()

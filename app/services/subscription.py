"""Токены подписок, совместимые с Marzban.

Формат Marzban:
    token = base64url("<username>,<created_at_unix>").rstrip("=")
            + base64url(sha256(token_part + SECRET))[:10]

Мы повторяем алгоритм байт в байт и берём секрет из SUBSCRIPTION_SECRET —
его нужно перенести из таблицы `jwt` старой базы Marzban. Тогда все ссылки,
которые уже лежат у пользователей в приложениях, продолжают работать после
перехода на эту панель.

Дополнительно поддерживаем JWT-форму токена (Marzban выдавал такие в старых
версиях): HS256 с полями sub/access=subscription/iat.
"""

import time
from base64 import b64decode, b64encode
from math import ceil
from datetime import datetime
from hashlib import sha256
from typing import Optional, TypedDict

import jwt

from app.core.config import settings

_JWT_PREFIX = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."


class SubscriptionPayload(TypedDict):
    username: str
    created_at: datetime


def _secret() -> str:
    return settings.subscription_secret


def create_subscription_token(username: str, created_at: Optional[int] = None) -> str:
    """Собирает токен подписки в формате Marzban."""
    timestamp = created_at if created_at is not None else ceil(time.time())
    data = f"{username},{timestamp}"
    data_b64_str = (
        b64encode(data.encode("utf-8"), altchars=b"-_").decode("utf-8").rstrip("=")
    )
    signature = b64encode(
        sha256((data_b64_str + _secret()).encode("utf-8")).digest(), altchars=b"-_"
    ).decode("utf-8")[:10]
    return data_b64_str + signature


def get_subscription_payload(token: str) -> Optional[SubscriptionPayload]:
    """Разбирает и проверяет токен. None — если подпись не сошлась."""
    if not token or len(token) < 15:
        return None

    if token.startswith(_JWT_PREFIX):
        try:
            payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        except jwt.PyJWTError:
            return None
        if payload.get("access") != "subscription":
            return None
        return {
            "username": payload["sub"],
            "created_at": datetime.utcfromtimestamp(payload["iat"]),
        }

    data_part, signature = token[:-10], token[-10:]
    try:
        padded = data_part.encode("utf-8") + b"=" * (-len(data_part.encode()) % 4)
        decoded = b64decode(padded, altchars=b"-_", validate=True).decode("utf-8")
    except Exception:
        return None

    expected = b64encode(
        sha256((data_part + _secret()).encode("utf-8")).digest(), altchars=b"-_"
    ).decode("utf-8")[:10]
    if signature != expected:
        return None

    try:
        username, created_at = decoded.split(",")
        return {
            "username": username,
            "created_at": datetime.utcfromtimestamp(int(created_at)),
        }
    except (ValueError, OverflowError, OSError):
        return None

"""Генерация ключей и паролей для подключений.

Раньше ключи REALITY приходилось получать на сервере командой
`xray x25519` и вписывать в панель руками — самый неприятный шаг настройки.
Здесь то же самое делается на стороне панели: пара X25519 в том же формате,
что печатает Xray (base64url без выравнивающих «=»).
"""

import secrets
from base64 import urlsafe_b64encode
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _b64(raw: bytes) -> str:
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def generate_reality_keypair() -> Tuple[str, str]:
    """Пара ключей REALITY: (приватный, публичный).

    Приватный уходит в конфиг Xray на ноде, публичный — в ссылку клиента.
    """
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return _b64(private_raw), _b64(public_raw)


def generate_short_id(length: int = 8) -> str:
    """shortId для REALITY — шестнадцатеричная строка чётной длины (до 16)."""
    length = max(2, min(16, length + length % 2))
    return secrets.token_hex(length // 2)


def generate_agent_token() -> str:
    return secrets.token_urlsafe(32)


def generate_path() -> str:
    """Неугадываемый путь для ws/httpupgrade — чтобы inbound не искался перебором."""
    return "/" + secrets.token_urlsafe(8)

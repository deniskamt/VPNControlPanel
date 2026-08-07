"""Пароли Shadowsocks, включая версию 2022.

Обычный Shadowsocks принимает пароль любой длины, а 2022-blake3-* требует
ключ строго заданного размера в base64. Поэтому для таких методов ключ
выводится из пароля пользователя: длина всегда верная, значение стабильное
(не меняется между перезаписями конфига) и у каждого своё.
"""

import hashlib
import secrets
from base64 import b64encode
from typing import Optional

# Сколько байт требует метод.
KEY_SIZES = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}

DEFAULT_METHOD = "chacha20-ietf-poly1305"
DEFAULT_2022_METHOD = "2022-blake3-aes-128-gcm"


def is_2022(method: Optional[str]) -> bool:
    return bool(method) and method.startswith("2022-")


def generate_server_key(method: str) -> str:
    """Ключ самого сервера — общий для inbound'а."""
    size = KEY_SIZES.get(method, 16)
    return b64encode(secrets.token_bytes(size)).decode("ascii")


def derive_user_key(password: str, method: str) -> str:
    """Ключ пользователя нужной длины, выведенный из его пароля."""
    size = KEY_SIZES.get(method, 16)
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return b64encode(digest[:size]).decode("ascii")


def client_password(password: str, method: str) -> str:
    """Что положить в конфиг Xray как пароль клиента."""
    return derive_user_key(password, method) if is_2022(method) else password


def link_userinfo(password: str, method: str, server_key: Optional[str]) -> str:
    """Часть ссылки ss:// до «@».

    Для 2022 клиент должен знать оба ключа — серверный и свой.
    """
    if is_2022(method) and server_key:
        return f"{method}:{server_key}:{derive_user_key(password, method)}"
    return f"{method}:{password}"

"""Токены подписок должны быть совместимы с Marzban байт в байт.

Эталон — алгоритм из Gozargah/Marzban (app/utils/jwt.py), воспроизведённый
здесь независимо от нашей реализации.
"""

from base64 import b64encode
from hashlib import sha256

import pytest

from app.core.config import settings
from app.services.subscription import (
    create_subscription_token,
    get_subscription_payload,
)

SECRET = "marzban-secret-key-for-tests"


@pytest.fixture(autouse=True)
def _fixed_secret(monkeypatch):
    """Секрет берём из настроек, поэтому фиксируем его явно."""
    monkeypatch.setattr(settings, "SUBSCRIPTION_SECRET", SECRET)


def marzban_token(username: str, created_at: int) -> str:
    """Точная копия create_subscription_token из Marzban."""
    data = username + "," + str(created_at)
    data_b64_str = b64encode(data.encode("utf-8"), altchars=b"-_").decode().rstrip("=")
    data_b64_sign = b64encode(
        sha256((data_b64_str + SECRET).encode("utf-8")).digest(), altchars=b"-_"
    ).decode("utf-8")[:10]
    return data_b64_str + data_b64_sign


def test_token_matches_marzban():
    assert create_subscription_token("user_123", 1700000000) == marzban_token(
        "user_123", 1700000000
    )


def test_old_marzban_link_still_opens():
    """Ссылка, выданная старой панелью, должна проходить проверку у нас."""
    token = marzban_token("nexlo_42", 1690000000)
    payload = get_subscription_payload(token)

    assert payload is not None
    assert payload["username"] == "nexlo_42"
    assert int(payload["created_at"].timestamp()) == 1690000000


def test_username_with_padding_edge_cases():
    # Длина имени влияет на base64-паддинг — проверяем несколько вариантов.
    for username in ("a", "ab", "abc", "abcd", "user_1234567890"):
        token = create_subscription_token(username, 1700000000)
        payload = get_subscription_payload(token)
        assert payload is not None, username
        assert payload["username"] == username


def test_tampered_token_rejected():
    token = create_subscription_token("victim", 1700000000)
    assert get_subscription_payload(token[:-1] + ("A" if token[-1] != "A" else "B")) is None


def test_foreign_token_rejected():
    """Токен, подписанный чужим секретом, принимать нельзя."""
    data = "hacker,1700000000"
    data_b64 = b64encode(data.encode(), altchars=b"-_").decode().rstrip("=")
    signature = b64encode(
        sha256((data_b64 + "another-secret").encode()).digest(), altchars=b"-_"
    ).decode()[:10]

    assert get_subscription_payload(data_b64 + signature) is None


def test_garbage_rejected():
    for token in ("", "short", "!" * 40, "a" * 14):
        assert get_subscription_payload(token) is None

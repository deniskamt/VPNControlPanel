"""Токены подписок должны быть совместимы с Marzban байт в байт.

Эталон — алгоритм из Gozargah/Marzban (app/utils/jwt.py), воспроизведённый
здесь независимо от нашей реализации.
"""

from base64 import b64encode
from hashlib import sha256

import pytest

from app.core.config import settings
from app.services import links, subscription_view
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


class _FakeRef:
    def __init__(self, ref_id: int, sort_order: int = 0) -> None:
        self.id = ref_id
        self.sort_order = sort_order


def _row(node, inbound_id, host=None):
    return (node, _FakeRef(inbound_id), host)


def test_row_order_is_flat():
    # Две записи одного сервера должны уметь разойтись: между ними встаёт
    # запись другого сервера.
    first = _FakeRef(1, sort_order=0)
    second = _FakeRef(2, sort_order=1)
    rows = [
        _row(first, 10, _FakeRef(100, sort_order=0)),
        _row(second, 20),
        _row(first, 10, _FakeRef(101, sort_order=2)),
    ]

    order = sorted(rows, key=lambda row: links.row_sort_key(*row))

    assert [row[2].id if row[2] else 0 for row in order] == [100, 0, 101]


def test_apply_order_numbers_every_row():
    node = _FakeRef(1, sort_order=7)
    other = _FakeRef(2, sort_order=9)
    hosts = [_FakeRef(100), _FakeRef(101)]
    rows = [_row(node, 10, hosts[0]), _row(other, 20), _row(node, 10, hosts[1])]

    subscription_view.apply_order(rows)

    assert [host.sort_order for host in hosts] == [0, 2]
    # У строки по умолчанию своего места нет — его получает сервер.
    assert other.sort_order == 1


def test_apply_order_keeps_default_rows_of_one_server_together():
    # Сервер хранит одно число на все свои строки без хоста: они получают
    # место первой из них.
    node = _FakeRef(1)
    rows = [_row(node, 10), _row(node, 20)]

    subscription_view.apply_order(rows)

    assert node.sort_order == 0

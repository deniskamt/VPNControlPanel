"""Токены подписок должны быть совместимы с Marzban байт в байт.

Эталон — алгоритм из Gozargah/Marzban (app/utils/jwt.py), воспроизведённый
здесь независимо от нашей реализации.
"""

from base64 import b64encode
from hashlib import sha256

import pytest

from app.core.config import settings
from app.services import subscription_view
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


class _FakeRow:
    """Порядок считается по полям, а не по базе — этого достаточно."""

    def __init__(self, node_id: int, sort_order: int = 0) -> None:
        self.id = node_id
        self.sort_order = sort_order


def _order(nodes):
    return [node.id for node in sorted(nodes, key=lambda n: (n.sort_order, n.id))]


def test_reorder_up_when_order_not_set():
    # По умолчанию у всех серверов sort_order = 0: обмен значениями ничего бы
    # не дал, поэтому нумерация раздаётся заново.
    nodes = [_FakeRow(1), _FakeRow(2), _FakeRow(3)]

    assert subscription_view.reorder(nodes, 3, up=True) is True
    assert _order(nodes) == [1, 3, 2]


def test_reorder_down():
    nodes = [_FakeRow(1), _FakeRow(2), _FakeRow(3)]

    assert subscription_view.reorder(nodes, 1, up=False) is True
    assert _order(nodes) == [2, 1, 3]


def test_reorder_at_the_edge_does_nothing():
    nodes = [_FakeRow(1), _FakeRow(2)]

    assert subscription_view.reorder(nodes, 1, up=True) is False
    assert _order(nodes) == [1, 2]


def test_reorder_unknown_row_is_ignored():
    nodes = [_FakeRow(1, sort_order=5), _FakeRow(2, sort_order=7)]

    assert subscription_view.reorder(nodes, 99, up=True) is False
    # Чужой запрос не должен перетасовывать список.
    assert _order(nodes) == [1, 2]
    assert [node.sort_order for node in nodes] == [5, 7]


class _FakeRef:
    def __init__(self, ref_id: int) -> None:
        self.id = ref_id


class _FakeEntry:
    """Строка подписки: для группировки важны только сервер, подключение и хост."""

    def __init__(self, node_id: int, inbound_id: int, host_id=None) -> None:
        self.node = _FakeRef(node_id)
        self.inbound = _FakeRef(inbound_id)
        self.host = _FakeRef(host_id) if host_id else None

    @property
    def key(self) -> str:
        return f"{self.node.id}-{self.inbound.id}-{self.host.id if self.host else 0}"


def test_group_moves_marks_first_and_last_row():
    # Два хоста на одном подключении: прямой и через промежуточный узел.
    entries = [_FakeEntry(1, 10, host_id=5), _FakeEntry(1, 10, host_id=6)]

    moves = subscription_view.group_moves(entries)

    assert moves["1-10-5"] == {"up": False, "down": True}
    assert moves["1-10-6"] == {"up": True, "down": False}


def test_group_moves_skips_single_rows():
    # Одну строку двигать не с чем — стрелки показывать незачем.
    entries = [_FakeEntry(1, 10, host_id=5), _FakeEntry(2, 20)]

    assert subscription_view.group_moves(entries) == {}


def test_group_moves_does_not_mix_different_servers():
    entries = [_FakeEntry(1, 10, host_id=5), _FakeEntry(2, 10, host_id=6)]

    # Хосты разных серверов — это разные списки, каждый по одной строке.
    assert subscription_view.group_moves(entries) == {}

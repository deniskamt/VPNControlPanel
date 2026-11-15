"""Режим доступа к серверу: «всем» (по умолчанию) или «только выбранным»."""

from types import SimpleNamespace

from app.models.access import UserNodeAccess
from app.models.enums import NodeAccessMode, UserStatus
from app.models.node import Node
from app.models.user import User
from app.services.xray_config import allowed_users_by_inbound


def node(mode=NodeAccessMode.all, node_id=1):
    return Node(id=node_id, name=f"N{node_id}", address="n.example.com", access_mode=mode)


def user(*rows):
    return User(username="u", node_access=list(rows))


def access(node_id=1, granted=False, is_allowed=True, data_limit=None, used=0):
    return UserNodeAccess(
        node_id=node_id, granted=granted, is_allowed=is_allowed,
        data_limit=data_limit, used_traffic=used,
    )


def test_public_server_is_open_by_default():
    assert user().allowed_on(node()) is True


def test_public_server_respects_manual_block_and_limit():
    assert user(access(is_allowed=False)).allowed_on(node()) is False
    assert user(access(data_limit=10, used=10)).allowed_on(node()) is False


def test_private_server_hidden_without_grant():
    assert user().allowed_on(node(NodeAccessMode.selected)) is False


def test_traffic_row_is_not_a_grant():
    # Строку с is_allowed=True заводит учёт трафика — это ещё не выдача.
    assert user(access(granted=False)).allowed_on(node(NodeAccessMode.selected)) is False


def test_private_server_open_for_granted():
    assert user(access(granted=True)).allowed_on(node(NodeAccessMode.selected)) is True


def test_grant_does_not_override_block_or_exhausted_limit():
    private = node(NodeAccessMode.selected)
    assert user(access(granted=True, is_allowed=False)).allowed_on(private) is False
    assert user(access(granted=True, data_limit=5, used=7)).allowed_on(private) is False


def test_grant_on_other_server_does_not_leak():
    assert user(access(node_id=2, granted=True)).allowed_on(node(NodeAccessMode.selected)) is False


def test_node_id_still_accepted():
    # Старые вызовы с id сервера режима не видят и ведут себя как раньше.
    assert user().allowed_on(1) is True
    assert user(access(is_allowed=False)).allowed_on(1) is False


def test_node_config_only_gets_granted_users():
    inbound = SimpleNamespace(id=7)
    private = node(NodeAccessMode.selected)

    def make(name, *rows):
        u = User(username=name, status=UserStatus.active, node_access=list(rows))
        u.inbounds = [inbound]
        return u

    granted = make("granted", access(granted=True))
    traffic_only = make("traffic_only", access(granted=False))
    stranger = make("stranger")

    result = allowed_users_by_inbound(private, [granted, traffic_only, stranger])
    assert [u.username for u in result[7]] == ["granted"]

    result = allowed_users_by_inbound(node(), [granted, traffic_only, stranger])
    assert sorted(u.username for u in result[7]) == ["granted", "stranger", "traffic_only"]

"""Почему выбранное подключение может не появиться у пользователя.

Две причины, обе молчаливые:
  * у пользователя нет ключа нужного протокола — ссылку не из чего собрать;
  * новое подключение никому не выдано — оно есть на серверах и ни у кого.
"""

from types import SimpleNamespace

from app.models.enums import NetworkType, ProxyType, SecurityType, UserStatus
from app.models.user import User, UserProxy
from app.services import users as user_service
from app.services.links import build_user_links


def make_inbound(inbound_id, protocol, **overrides):
    data = {
        "id": inbound_id, "tag": f"IN{inbound_id}", "protocol": protocol,
        "listen": "0.0.0.0", "port": 443, "network": NetworkType.tcp,
        "security": SecurityType.tls, "settings": {}, "sniffing": True,
        "is_enabled": True, "hosts": [],
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def make_node(inbounds):
    return SimpleNamespace(id=1, name="NL", address="nl.example.com", country="NL",
                           inbounds=inbounds, is_enabled=True, sort_order=0)


def test_selected_inbound_without_credentials_yields_no_link():
    """Ровно то, что видел администратор: Trojan отмечен, а в подписке его нет."""
    vless = make_inbound(1, ProxyType.vless, security=SecurityType.reality,
                         settings={"publicKey": "PUB", "shortIds": ["ab12"],
                                   "serverNames": ["m.com"]})
    trojan = make_inbound(2, ProxyType.trojan)
    user = SimpleNamespace(
        username="u", status=UserStatus.active, expired=False, limited=False,
        inbounds=[vless, trojan],
        proxy_settings=lambda p: {"id": "uuid"} if p == ProxyType.vless else None,
        allowed_on=lambda node_id: True,
    )

    links = build_user_links(user, [make_node([vless, trojan])])
    assert len(links) == 1 and links[0].startswith("vless://")


def test_ensure_credentials_issues_keys_for_selected_protocols():
    user = User(username="u")
    user.proxies.append(
        UserProxy(protocol=ProxyType.vless, settings={"id": "uuid"})
    )
    user.inbounds = [
        make_inbound(1, ProxyType.vless),
        make_inbound(2, ProxyType.trojan),
        make_inbound(3, ProxyType.shadowsocks),
    ]

    issued = user_service.ensure_credentials(user)

    assert set(issued) == {ProxyType.trojan, ProxyType.shadowsocks}
    by_protocol = {proxy.protocol: proxy.settings for proxy in user.proxies}
    assert by_protocol[ProxyType.trojan]["password"]
    assert by_protocol[ProxyType.shadowsocks]["password"]
    # Существующий ключ трогать нельзя: у пользователя сломались бы все конфиги.
    assert by_protocol[ProxyType.vless]["id"] == "uuid"


def test_ensure_credentials_is_idempotent():
    user = User(username="u")
    user.inbounds = [make_inbound(1, ProxyType.trojan)]

    first = user_service.ensure_credentials(user)
    password = next(
        proxy.settings["password"] for proxy in user.proxies
        if proxy.protocol == ProxyType.trojan
    )
    second = user_service.ensure_credentials(user)

    assert first == [ProxyType.trojan]
    assert second == []
    assert len(user.proxies) == 1
    # Повторный вызов не должен перевыпускать пароль.
    assert user.proxies[0].settings["password"] == password


def test_link_appears_once_credentials_exist():
    trojan = make_inbound(2, ProxyType.trojan, settings={"sni": "vpn.example.com"})
    user = User(username="u")
    user.inbounds = [trojan]
    user_service.ensure_credentials(user)

    password = user.proxies[0].settings["password"]
    fake = SimpleNamespace(
        username="u", status=UserStatus.active, expired=False, limited=False,
        inbounds=[trojan],
        proxy_settings=lambda p: {"password": password} if p == ProxyType.trojan else None,
        allowed_on=lambda node_id: True,
    )

    links = build_user_links(fake, [make_node([trojan])])
    assert len(links) == 1
    assert links[0].startswith(f"trojan://{password}@")

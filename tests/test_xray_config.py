"""Генерация конфига Xray и клиентских ссылок."""

import os
from types import SimpleNamespace

os.environ.setdefault("SUBSCRIPTION_SECRET", "test-secret")

from app.models.enums import (  # noqa: E402
    NetworkType,
    ProxyType,
    SecurityType,
    UserStatus,
)
from app.services.links import build_link, build_user_links  # noqa: E402
from app.services.xray_config import (  # noqa: E402
    build_node_config,
    config_hash,
)

REALITY_SETTINGS = {
    "dest": "www.microsoft.com:443",
    "serverNames": ["www.microsoft.com"],
    "privateKey": "PRIVATE",
    "publicKey": "PUBLIC",
    "shortIds": ["ab12"],
    "fingerprint": "chrome",
    "flow": "xtls-rprx-vision",
}


def make_inbound(**overrides):
    data = {
        "id": 1,
        "tag": "VLESS-REALITY",
        "protocol": ProxyType.vless,
        "listen": "0.0.0.0",
        "port": 443,
        "network": NetworkType.tcp,
        "security": SecurityType.reality,
        "settings": dict(REALITY_SETTINGS),
        "sniffing": True,
        "is_enabled": True,
        "hosts": [],
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def make_user(
    inbounds, protocol=ProxyType.vless, settings=None, blocked_nodes=(), **overrides
):
    creds = settings or {"id": "11111111-2222-3333-4444-555555555555"}
    data = {
        "username": "user_1",
        "status": UserStatus.active,
        "expired": False,
        "limited": False,
        "inbounds": inbounds,
        "proxy_settings": lambda wanted, _creds=creds, _p=protocol: (
            _creds if wanted == _p else None
        ),
        "allowed_on": lambda node_id, _blocked=set(blocked_nodes): node_id not in _blocked,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def make_node(inbounds, **overrides):
    data = {
        "id": 1,
        "name": "NL-1",
        "address": "nl1.example.com",
        "country": "NL",
        "inbounds": inbounds,
        "is_enabled": True,
        "sort_order": 0,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_config_contains_api_inbound_and_client():
    inbound = make_inbound()
    user = make_user([inbound])
    config = build_node_config(make_node([inbound]), [user])

    tags = [item["tag"] for item in config["inbounds"]]
    assert tags == ["api", "VLESS-REALITY"]

    clients = config["inbounds"][1]["settings"]["clients"]
    assert clients[0]["email"] == "user_1"
    assert clients[0]["flow"] == "xtls-rprx-vision"
    assert config["inbounds"][1]["streamSettings"]["realitySettings"]["privateKey"] == "PRIVATE"
    # Статистика по пользователям должна быть включена, иначе не будет учёта.
    assert config["policy"]["levels"]["0"]["statsUserUplink"] is True


def test_inactive_users_are_not_in_config():
    inbound = make_inbound()
    active = make_user([inbound])
    expired = make_user([inbound], username="user_2", expired=True)
    disabled = make_user([inbound], username="user_3", status=UserStatus.disabled)
    over_limit = make_user([inbound], username="user_4", limited=True)

    config = build_node_config(
        make_node([inbound]), [active, expired, disabled, over_limit]
    )
    emails = [
        client["email"] for client in config["inbounds"][1]["settings"]["clients"]
    ]
    assert emails == ["user_1"]


def test_user_without_access_to_inbound_is_excluded():
    inbound = make_inbound()
    other = make_inbound(id=2, tag="OTHER", port=8443)
    user = make_user([other])  # доступ только к другому inbound

    config = build_node_config(make_node([inbound]), [user])
    assert config["inbounds"][1]["settings"]["clients"] == []


def test_hash_is_stable_and_sensitive():
    inbound = make_inbound()
    node = make_node([inbound])
    first = build_node_config(node, [make_user([inbound])])
    second = build_node_config(node, [make_user([inbound])])
    assert config_hash(first) == config_hash(second)

    changed = build_node_config(
        node, [make_user([inbound], settings={"id": "different-uuid"})]
    )
    assert config_hash(first) != config_hash(changed)


def test_reality_link_carries_public_key_not_private():
    inbound = make_inbound()
    user = make_user([inbound])
    link = build_link(user, inbound, make_node([inbound]))

    assert link.startswith("vless://11111111-2222-3333-4444-555555555555@nl1.example.com:443?")
    assert "security=reality" in link
    assert "pbk=PUBLIC" in link
    assert "PRIVATE" not in link
    assert "sid=ab12" in link
    assert "flow=xtls-rprx-vision" in link
    # Название по умолчанию начинается с флага страны — по нему клиент рисует
    # иконку (🇳🇱 в процентной кодировке).
    assert link.endswith("#%F0%9F%87%B3%F0%9F%87%B1%20NL-1")


def test_ws_link_has_no_flow():
    """flow осмыслен только на tcp — на ws он ломает клиентов."""
    inbound = make_inbound(
        network=NetworkType.ws,
        security=SecurityType.tls,
        settings={"path": "/ws", "host": "cdn.example.com", "sni": "cdn.example.com",
                  "flow": "xtls-rprx-vision"},
    )
    link = build_link(make_user([inbound]), inbound, make_node([inbound]))

    assert "type=ws" in link
    assert "flow" not in link
    assert "path=%2Fws" in link


def test_trojan_and_shadowsocks_links():
    trojan_inbound = make_inbound(
        protocol=ProxyType.trojan, security=SecurityType.tls, settings={"sni": "x.example.com"}
    )
    trojan_user = make_user([trojan_inbound], protocol=ProxyType.trojan,
                            settings={"password": "secret"})
    trojan_link = build_link(trojan_user, trojan_inbound, make_node([trojan_inbound]))
    assert trojan_link.startswith("trojan://secret@nl1.example.com:443?")

    ss_inbound = make_inbound(
        protocol=ProxyType.shadowsocks,
        security=SecurityType.none,
        settings={"method": "aes-256-gcm"},
    )
    ss_user = make_user([ss_inbound], protocol=ProxyType.shadowsocks,
                        settings={"password": "pw", "method": "aes-256-gcm"})
    ss_link = build_link(ss_user, ss_inbound, make_node([ss_inbound]))
    assert ss_link.startswith("ss://")


def test_links_are_built_for_every_enabled_node():
    inbound = make_inbound()
    nodes = [
        make_node([inbound]),
        make_node([inbound], id=2, name="DE-1", address="de1.example.com"),
        make_node([inbound], id=3, name="OFF", address="off.example.com", is_enabled=False),
    ]
    links = build_user_links(make_user([inbound]), nodes)

    assert len(links) == 2
    assert any("nl1.example.com" in link for link in links)
    assert any("de1.example.com" in link for link in links)
    assert not any("off.example.com" in link for link in links)


def make_host(**overrides):
    data = {
        "id": 1, "node_id": None, "remark": "{node} CDN", "address": "cdn.example.com",
        "port": 8443, "sni": "cdn.example.com", "host": None, "path": None,
        "alpn": None, "fingerprint": None, "security": None, "allowinsecure": False,
        "is_disabled": False, "sort_order": 0,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_host_override_replaces_address_in_link():
    host = make_host()
    inbound = make_inbound(security=SecurityType.tls, settings={"sni": "direct"}, hosts=[host])
    links = build_user_links(make_user([inbound]), [make_node([inbound])])

    assert len(links) == 1
    assert "@cdn.example.com:8443" in links[0]
    assert links[0].endswith("#NL-1%20CDN")


def test_host_security_overrides_inbound_for_cdn():
    """За CDN inbound слушает без TLS, а клиент идёт к CDN уже по TLS."""
    inbound = make_inbound(
        protocol=ProxyType.vless,
        network=NetworkType.ws,
        security=SecurityType.none,
        settings={"path": "/ws"},
        hosts=[make_host(security=SecurityType.tls, port=443)],
    )
    link = build_user_links(make_user([inbound]), [make_node([inbound])])[0]

    assert "security=tls" in link
    assert "sni=cdn.example.com" in link

    # А в конфиге на сервере TLS по-прежнему выключен — им занимается CDN.
    config = build_node_config(make_node([inbound]), [make_user([inbound])])
    assert config["inbounds"][1]["streamSettings"]["security"] == "none"


def test_vmess_host_security_override():
    inbound = make_inbound(
        protocol=ProxyType.vmess,
        network=NetworkType.ws,
        security=SecurityType.none,
        settings={"path": "/vm"},
        hosts=[make_host(security=SecurityType.tls)],
    )
    user = make_user([inbound], protocol=ProxyType.vmess)
    link = build_user_links(user, [make_node([inbound])])[0]

    import base64 as b64
    import json

    payload = json.loads(b64.b64decode(link[len("vmess://"):]).decode())
    assert payload["tls"] == "tls"
    assert payload["add"] == "cdn.example.com"


def test_blocked_node_excludes_user_from_config():
    """Закрытый сервер не должен получать ключ пользователя."""
    inbound = make_inbound()
    allowed = make_user([inbound])
    blocked = make_user([inbound], username="user_2", blocked_nodes=[1])

    config = build_node_config(make_node([inbound]), [allowed, blocked])
    emails = [c["email"] for c in config["inbounds"][1]["settings"]["clients"]]

    assert emails == ["user_1"]


def test_blocked_node_disappears_from_subscription():
    """И из подписки тоже — иначе клиент будет биться в закрытый сервер."""
    inbound = make_inbound()
    nodes = [
        make_node([inbound]),
        make_node([inbound], id=2, name="DE-1", address="de1.example.com"),
    ]
    links = build_user_links(make_user([inbound], blocked_nodes=[2]), nodes)

    assert len(links) == 1
    assert "nl1.example.com" in links[0]


def test_shadowsocks_2022_keys_differ_from_plain():
    """У 2022-методов ключ клиента выводится из пароля и имеет свою длину."""
    from base64 import b64decode

    from app.services import presets as preset_service

    preset = preset_service.PRESETS_BY_KEY["shadowsocks_2022"]
    settings = preset_service.build_settings(preset)
    inbound = make_inbound(
        protocol=ProxyType.shadowsocks, security=SecurityType.none, settings=settings
    )
    user = make_user(
        [inbound], protocol=ProxyType.shadowsocks, settings={"password": "secret-pass"}
    )

    config = build_node_config(make_node([inbound]), [user])
    inbound_settings = config["inbounds"][1]["settings"]

    # Ключ сервера обязателен и лежит на самом inbound'е, а не у клиента.
    assert inbound_settings["method"] == "2022-blake3-aes-128-gcm"
    assert len(b64decode(inbound_settings["password"])) == 16
    client = inbound_settings["clients"][0]
    assert "method" not in client
    assert len(b64decode(client["password"])) == 16
    assert client["password"] != "secret-pass"

    # В ссылку попадают оба ключа — серверный и пользовательский.
    link = build_link(user, inbound, make_node([inbound]))
    userinfo = b64decode(link[len("ss://"):].split("@")[0] + "==").decode()
    assert userinfo.count(":") == 2
    assert userinfo.startswith("2022-blake3-aes-128-gcm:")


def test_link_name_starts_with_flag():
    """Название конфигурации должно начинаться с эмодзи флага."""
    from urllib.parse import unquote

    inbound = make_inbound()
    link = build_link(make_user([inbound]), inbound, make_node([inbound], country="SE"))
    remark = unquote(link.split("#", 1)[1])

    assert remark == "🇸🇪 NL-1"


def test_link_name_without_country_has_no_stray_spaces():
    inbound = make_inbound()
    link = build_link(make_user([inbound]), inbound, make_node([inbound], country=None))

    assert link.endswith("#NL-1")


def test_config_hash_does_not_depend_on_user_order():
    """Иначе у людей рвётся соединение раз в полминуты.

    Postgres отдаёт строки в физическом порядке, а он меняется при каждой
    записи трафика. Если от порядка зависит отпечаток конфига, панель
    считает его новым, перезаливает на ноду, и агент перезапускает Xray —
    ровно на интервале опроса.
    """
    from app.services.xray_config import build_node_config, config_hash

    inbound = make_inbound()
    node = make_node([inbound])
    users = [
        make_user([inbound], username=name, settings={"id": f"uuid-{name}"})
        for name in ("b", "a", "c")
    ]

    прямой = config_hash(build_node_config(node, users))
    обратный = config_hash(build_node_config(node, list(reversed(users))))
    перемешанный = config_hash(build_node_config(node, [users[2], users[0], users[1]]))

    assert прямой == обратный == перемешанный

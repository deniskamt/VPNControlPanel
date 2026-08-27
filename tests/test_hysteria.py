"""Hysteria2: конфиг ноды и ссылка для клиента.

Проверено на живом бинарнике 2.12.2: этот конфиг поднимается, эта ссылка
подключается, счётчики читаются. Здесь закрепляем форму того и другого.
"""

from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from app.models.enums import NetworkType, ProxyType, SecurityType
from app.services import hysteria, links, presets


def make_inbound(settings, port=443, enabled=True):
    return SimpleNamespace(
        id=1, tag="HY2", protocol=ProxyType.hysteria2, listen="0.0.0.0", port=port,
        network=NetworkType.udp, security=SecurityType.tls, settings=settings,
        sniffing=False, is_enabled=enabled, hosts=[],
    )


def make_node(inbounds):
    return SimpleNamespace(id=1, name="NL", address="nl.example.com", country="NL",
                           inbounds=inbounds, is_enabled=True, sort_order=0)


def make_user(password="pass-1", username="user1"):
    return SimpleNamespace(
        username=username, status=SimpleNamespace(value="active"),
        expired=False, limited=False, inbounds=[], allowed_on=lambda node_id: True,
        proxy_settings=lambda p: {"password": password} if password else None,
    )


@pytest.fixture
def settings():
    preset = next(p for p in presets.PRESETS if p.key == "hysteria2")
    return presets.build_settings(preset, masking_domain="www.microsoft.com")


def test_preset_gives_obfuscation_and_masquerade(settings):
    # Без обфускации QUIC опознают по первому пакету — она обязательна.
    assert settings["obfsPassword"]
    assert settings["masquerade"] == "https://www.microsoft.com/"
    assert settings["sni"] == "www.microsoft.com"
    assert settings["statsSecret"]


def test_config_carries_users_and_obfuscation(settings):
    inbound = make_inbound(settings)
    user = make_user()

    config = hysteria.build_config(make_node([inbound]), [inbound], {1: [user]})

    assert config["listen"] == ":443"
    assert config["auth"] == {"type": "userpass", "userpass": {"user1": "pass-1"}}
    assert config["obfs"]["salamander"]["password"] == settings["obfsPassword"]
    assert config["masquerade"]["proxy"]["rewriteHost"] is True
    # Счётчики агент забирает с localhost — наружу их отдавать незачем.
    assert config["trafficStats"]["listen"].startswith("127.0.0.1:")


def test_config_asks_agent_for_a_certificate(settings):
    config = hysteria.build_config(
        make_node([make_inbound(settings)]), [make_inbound(settings)], {1: []}
    )
    # Своего домена у ноды нет, поэтому сертификат выписывает агент.
    assert config["selfSignedFor"] == "www.microsoft.com"
    assert "tls" not in config


def test_own_certificate_is_used_as_is(settings):
    settings = dict(settings, certificateFile="/etc/ssl/a.crt", keyFile="/etc/ssl/a.key")
    inbound = make_inbound(settings)

    config = hysteria.build_config(make_node([inbound]), [inbound], {1: []})

    assert config["tls"] == {"cert": "/etc/ssl/a.crt", "key": "/etc/ssl/a.key"}
    assert "selfSignedFor" not in config


def test_no_config_without_a_hysteria_inbound():
    assert hysteria.build_config(make_node([]), [], {}) is None


def test_disabled_inbound_stops_the_process(settings):
    inbound = make_inbound(settings, enabled=False)

    # None значит «останови»: иначе выключённое подключение продолжало бы
    # работать на ноде.
    assert hysteria.build_config(make_node([inbound]), [inbound], {1: []}) is None


def test_link_matches_what_the_client_needs(settings):
    inbound = make_inbound(settings)
    node = make_node([inbound])
    user = make_user()
    user.inbounds = [inbound]

    link = links.build_link(user, inbound, node)
    parsed = urlparse(link)
    query = {k: v[0] for k, v in parse_qs(parsed.query).items()}

    assert parsed.scheme == "hysteria2"
    # Режим userpass: сервер должен понять, чей это ключ.
    assert unquote(parsed.username) == "user1"
    assert unquote(parsed.password) == "pass-1"
    assert parsed.hostname == "nl.example.com" and parsed.port == 443
    assert query["sni"] == "www.microsoft.com"
    assert query["obfs"] == "salamander"
    assert query["obfs-password"] == settings["obfsPassword"]
    # Самоподписанный сертификат клиент обязан принять явно.
    assert query["insecure"] == "1"


def test_link_without_insecure_when_certificate_is_real(settings):
    settings = dict(settings, certificateFile="/etc/ssl/a.crt", keyFile="/etc/ssl/a.key")
    inbound = make_inbound(settings)
    user = make_user()
    user.inbounds = [inbound]

    link = links.build_link(user, inbound, make_node([inbound]))

    assert "insecure" not in link


def test_no_link_without_a_key(settings):
    inbound = make_inbound(settings)
    user = make_user(password="")
    user.inbounds = [inbound]

    assert links.build_link(user, inbound, make_node([inbound])) is None


def test_hysteria_stays_out_of_the_xray_config(settings):
    from app.services import xray_config

    inbound = make_inbound(settings)
    node = make_node([inbound])
    user = make_user()
    user.inbounds = [inbound]
    user.status = SimpleNamespace(value="active")

    config = xray_config.build_node_config(node, [])
    tags = [item["tag"] for item in config["inbounds"]]

    # В конфиге Xray остаётся только служебный api-inbound.
    assert tags == ["api"]

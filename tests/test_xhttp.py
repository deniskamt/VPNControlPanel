"""Транспорт XHTTP: режим, маскировка и то, как она доезжает до клиента."""

from types import SimpleNamespace

import pytest

from app.models.enums import NetworkType, ProxyType, SecurityType, UserStatus
from app.services import client_config, presets as preset_service, xhttp
from app.services.links import build_link
from app.services.xray_config import build_node_config

UUID = "11111111-2222-3333-4444-555555555555"

# Значения, которые ядро Xray принимает. Проверено запуском 26.7.28: path и
# none для добивки оно отвергает, а из методов знает только tokenish.
VALID_PAD_PLACEMENTS = {"header", "query", "queryInHeader", "cookie"}
VALID_SEQ_PLACEMENTS = {"query", "header", "cookie"}
VALID_SESSION_PLACEMENTS = {"header", "query"}


def make_inbound(settings, **overrides):
    data = {
        "id": 1, "tag": "XHTTP", "protocol": ProxyType.vless, "listen": "0.0.0.0",
        "port": 443, "network": NetworkType.xhttp, "security": SecurityType.reality,
        "settings": settings, "sniffing": True, "is_enabled": True, "hosts": [],
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def make_node(inbounds):
    return SimpleNamespace(id=1, name="NL", address="nl.example.com", country="NL",
                           inbounds=inbounds, is_enabled=True, sort_order=0)


def make_user(inbounds):
    return SimpleNamespace(
        username="user_1", status=UserStatus.active, expired=False, limited=False,
        inbounds=inbounds,
        proxy_settings=lambda protocol: {"id": UUID} if protocol == ProxyType.vless else None,
        allowed_on=lambda node_id: True,
    )


def test_xhttp_splits_connections_instead_of_one_long_stream():
    """Под REALITY «auto» выбирает stream-one — тот самый длинный поток,
    который зависает после ~16 КБ. Значит, режим надо задавать явно."""
    for key in ("vless_reality_xhttp", "vless_xhttp_cdn"):
        settings = preset_service.build_settings(preset_service.PRESETS_BY_KEY[key])
        assert settings["mode"] == "packet-up", key

        extra = settings["extra"]
        # Ни одно соединение не должно нести много: ограничен размер POST'а,
        # даунлинк пересоздаётся, соединение переиспользуется ограниченно.
        assert extra["scMaxEachPostBytes"]
        assert extra["scStreamUpServerSecs"]
        assert extra["xmux"]["cMaxReuseTimes"]
        assert extra["xmux"]["hMaxRequestTimes"]


@pytest.mark.parametrize("_", range(20))
def test_generated_obfuscation_only_uses_values_the_core_accepts(_):
    obfs = xhttp.generate_obfuscation()

    assert obfs["xPaddingPlacement"] in VALID_PAD_PLACEMENTS
    assert obfs["seqPlacement"] in VALID_SEQ_PLACEMENTS
    assert obfs["sessionIDPlacement"] in VALID_SESSION_PLACEMENTS
    # Ядро знает единственный метод добивки; остальные оно отвергает.
    assert obfs["xPaddingMethod"] == "tokenish"

    low, _, high = obfs["xPaddingBytes"].partition("-")
    assert 0 < int(low) < int(high)
    assert obfs["sessionIDLength"] >= 16


def test_obfuscation_differs_between_connections():
    """Одинаковый у всех набор имён сам становится приметой."""
    variants = {
        tuple(sorted(xhttp.generate_obfuscation().items(), key=lambda kv: kv[0]))
        for _ in range(15)
    }
    assert len(variants) > 1


def test_has_obfuscation_detects_plain_settings():
    assert xhttp.has_obfuscation({"path": "/x", "mode": "stream-one"}) is False
    assert xhttp.has_obfuscation({"path": "/x", "seqKey": "part"}) is True


def test_transport_settings_carry_obfuscation_to_the_core():
    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"], obfuscate=True
    )
    node = make_node([make_inbound(settings)])
    user = make_user(node.inbounds)

    config = build_node_config(node, [user])
    block = config["inbounds"][1]["streamSettings"]["xhttpSettings"]

    for key in xhttp.OBFUSCATION_KEYS:
        assert block[key] == settings[key], key
    assert block["mode"] == "packet-up"


def test_obfuscated_inbound_carries_settings_in_extra():
    """Клиенту хватает обычной ссылки: маскировка едет в параметре extra."""
    import json
    import urllib.parse

    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"], obfuscate=True
    )
    inbound = make_inbound(settings)
    node = make_node([inbound])

    link = build_link(make_user([inbound]), inbound, node)
    assert link, "ссылка обязана быть: без неё подключение не дойдёт до клиента"

    params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(link).query))
    extra = json.loads(params["extra"])

    # extra должно точно повторять то, что стоит на сервере.
    for key in xhttp.OBFUSCATION_KEYS:
        assert extra[key] == settings[key], key
    # path и mode остаются обычными параметрами, дублировать их незачем.
    assert "path" not in extra and "mode" not in extra
    assert params["mode"] == "packet-up"


def test_link_carries_the_splitting_settings():
    """Без них клиент откроет один длинный поток, и смысл XHTTP пропадёт."""
    import json
    import urllib.parse

    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"]
    )
    inbound = make_inbound(settings)
    node = make_node([inbound])

    link = build_link(make_user([inbound]), inbound, node)
    assert link and "type=xhttp" in link and "mode=packet-up" in link

    params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(link).query))
    extra = json.loads(params["extra"])
    assert extra == settings["extra"]


def test_json_profile_repeats_server_settings_exactly():
    """Клиент обязан получить те же параметры, иначе соединения не будет."""
    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"],
        masking_domain="www.samsung.com", obfuscate=True,
    )
    inbound = make_inbound(settings)
    node = make_node([inbound])
    user = make_user([inbound])

    server_block = build_node_config(node, [user])["inbounds"][1]["streamSettings"]
    profile = client_config.build_profile(user, inbound, node)
    client_stream = profile["outbounds"][0]["streamSettings"]

    assert client_stream["xhttpSettings"] == server_block["xhttpSettings"]
    assert client_stream["realitySettings"]["publicKey"] == settings["publicKey"]
    assert client_stream["realitySettings"]["shortId"] == settings["shortIds"][0]
    assert client_stream["realitySettings"]["serverName"] == "www.samsung.com"
    assert client_stream["realitySettings"]["fingerprint"] == "firefox"
    # Приватный ключ сервера в клиентский конфиг попасть не должен.
    assert settings["privateKey"] not in str(profile)


def test_json_profile_is_a_runnable_config():
    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"], obfuscate=True
    )
    inbound = make_inbound(settings)
    node = make_node([inbound])
    profile = client_config.build_profile(make_user([inbound]), inbound, node)

    assert profile["remarks"]
    assert {item["protocol"] for item in profile["inbounds"]} == {"socks", "http"}
    tags = [item["tag"] for item in profile["outbounds"]]
    assert tags[0] == "proxy" and "direct" in tags and "block" in tags
    # Локальная сеть мимо туннеля, иначе у пользователя отвалится роутер.
    assert profile["routing"]["rules"][0]["outboundTag"] == "direct"


def test_vision_profile_keeps_flow_only_on_tcp():
    tcp_settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality"]
    )
    tcp = make_inbound(tcp_settings, network=NetworkType.tcp)
    node = make_node([tcp])
    profile = client_config.build_profile(make_user([tcp]), tcp, node)
    account = profile["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert account["flow"] == "xtls-rprx-vision"

    xhttp_settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"]
    )
    over_xhttp = make_inbound(xhttp_settings)
    node = make_node([over_xhttp])
    profile = client_config.build_profile(make_user([over_xhttp]), over_xhttp, node)
    account = profile["outbounds"][0]["settings"]["vnext"][0]["users"][0]
    assert "flow" not in account


def test_reality_does_not_gate_clients_by_core_version():
    """minClientVer отсекает клиентов, а не защищает от них.

    Проверка в исходниках REALITY:
        config.MinClientVer == nil || Value(ClientVer) >= Value(MinClientVer)
    Без поля проверки нет вовсе; с полем клиент обязан прислать версию ядра.
    Реализации не на Xray шлют нули и получают маскировочный сайт вместо
    прокси — снаружи это «подключение есть, интернета нет».
    """
    for key in ("vless_reality_xhttp", "vless_reality", "vless_reality_grpc"):
        settings = preset_service.build_settings(preset_service.PRESETS_BY_KEY[key])
        assert "minClientVer" not in settings, key

    # Поле могло остаться в настройках от прежних версий панели — на ноду
    # оно всё равно не уезжает.
    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"]
    )
    settings["minClientVer"] = "1.8.0"
    inbound = make_inbound(settings)
    node = make_node([inbound])
    config = build_node_config(node, [make_user([inbound])])
    reality = config["inbounds"][1]["streamSettings"]["realitySettings"]
    assert "minClientVer" not in reality


def test_obfuscation_is_not_enabled_by_default():
    """Она несовместима между версиями ядра — по умолчанию её быть не должно."""
    for preset in preset_service.CURRENT_PRESETS:
        settings = preset_service.build_settings(preset)
        assert not xhttp.has_obfuscation(settings), preset.key


def test_obfuscated_inbound_is_flagged_as_a_problem():
    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality_xhttp"], obfuscate=True
    )
    warning = preset_service.legacy_warning(make_inbound(settings))
    assert "ровно той же версии" in warning

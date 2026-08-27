"""Шаблоны подключений и генерация ключей.

Ключи REALITY панель делает сама — если их формат разойдётся с тем, что
ожидает Xray, подключение не поднимется, а ошибка будет невнятной. Поэтому
проверяем формат и математическое соответствие пары.
"""

from base64 import urlsafe_b64decode

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.models.enums import NetworkType, ProxyType, SecurityType
from app.services import presets as preset_service
from app.services.keys import (
    generate_path,
    generate_reality_keypair,
    generate_short_id,
)


def _decode(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_reality_keypair_format():
    private, public = generate_reality_keypair()

    # Xray печатает ключи в base64url без выравнивания, по 32 байта каждый.
    assert "=" not in private and "=" not in public
    assert len(_decode(private)) == 32
    assert len(_decode(public)) == 32


def test_reality_public_key_matches_private():
    """Публичный ключ обязан быть выведен из приватного, иначе клиент не подключится."""
    private, public = generate_reality_keypair()

    recomputed = (
        X25519PrivateKey.from_private_bytes(_decode(private))
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    )
    assert recomputed == _decode(public)


def test_keys_are_unique():
    assert generate_reality_keypair()[0] != generate_reality_keypair()[0]


@pytest.mark.parametrize("length", [2, 4, 8, 15, 16, 100])
def test_short_id_is_valid_hex(length):
    short_id = generate_short_id(length)
    assert len(short_id) % 2 == 0
    assert 2 <= len(short_id) <= 16
    int(short_id, 16)  # бросит ValueError, если не шестнадцатеричная строка


def test_generated_path_starts_with_slash():
    assert generate_path().startswith("/")


def test_reality_preset_is_ready_to_use():
    preset = preset_service.PRESETS_BY_KEY["vless_reality"]
    settings = preset_service.build_settings(preset, masking_domain="www.samsung.com")

    assert settings["dest"] == "www.samsung.com:443"
    assert settings["serverNames"] == ["www.samsung.com"]
    assert settings["privateKey"] and settings["publicKey"]
    assert settings["privateKey"] != settings["publicKey"]
    assert settings["shortIds"] and settings["shortIds"][0]
    assert settings["flow"] == "xtls-rprx-vision"


def test_default_fingerprint_is_not_chrome():
    """chrome/safari/ios у части операторов в подозрительных, firefox проходит."""
    settings = preset_service.build_settings(
        preset_service.PRESETS_BY_KEY["vless_reality"]
    )
    assert settings["fingerprint"] == "firefox"


def test_xhttp_reality_preset_is_the_first_offer():
    """Первый шаблон в списке — тот, что предлагается по умолчанию в форме."""
    first = preset_service.CURRENT_PRESETS[0]
    assert first.key == "vless_reality_xhttp"
    assert first.network == NetworkType.xhttp
    assert first.security == SecurityType.reality

    settings = preset_service.build_settings(first, masking_domain="www.microsoft.com")
    # packet-up: под REALITY «auto» выбирает stream-one — один длинный поток,
    # который зависает после ~16 КБ.
    assert settings["mode"] == "packet-up"
    assert settings["path"].startswith("/")
    assert settings["privateKey"] and settings["publicKey"]
    # Vision живёт только на TCP: на xhttp он ломает клиента.
    assert "flow" not in settings


def test_cdn_preset_keeps_the_domain_for_the_client():
    preset = preset_service.PRESETS_BY_KEY["vless_xhttp_cdn"]
    settings = preset_service.build_settings(preset, sni="cdn.example.com")

    assert settings["host"] == "cdn.example.com"
    # За CDN длинный ответ часто режут, поэтому здесь нужен packet-up.
    assert settings["mode"] == "packet-up"
    assert "privateKey" not in settings  # TLS терминирует CDN, REALITY тут нет


def test_current_presets_are_reality_or_cdn_or_ss2022():
    """Ни один «актуальный» шаблон не должен быть тем, что уже ловят."""
    for preset in preset_service.CURRENT_PRESETS:
        assert preset.protocol != ProxyType.vmess
        if preset.protocol == ProxyType.hysteria2:
            # У Hysteria2 TLS живёт внутри QUIC, а ловят по рукопожатию
            # обычного TLS поверх TCP — это разные вещи. От опознания по
            # QUIC его закрывает обфускация, она в шаблоне обязательна.
            assert preset.network == NetworkType.udp
            continue
        assert preset.security != SecurityType.tls
        if preset.protocol == ProxyType.shadowsocks:
            assert preset.key.endswith("_2022")


def test_legacy_presets_explain_themselves():
    assert preset_service.LEGACY_PRESETS
    for preset in preset_service.LEGACY_PRESETS:
        assert preset.legacy is True
        assert preset.legacy_reason, f"{preset.key} без объяснения, чем плох"
    # Старые шаблоны никуда не делись — на них переезжают с Marzban.
    keys = {preset.key for preset in preset_service.LEGACY_PRESETS}
    assert {"vmess_ws", "trojan_tls", "shadowsocks", "vless_ws"} <= keys


def test_ws_preset_generates_random_path():
    preset = preset_service.PRESETS_BY_KEY["vless_ws"]
    first = preset_service.build_settings(preset)
    second = preset_service.build_settings(preset)

    assert first["path"].startswith("/")
    assert first["path"] != second["path"]


def test_tls_preset_carries_certificate_paths():
    preset = preset_service.PRESETS_BY_KEY["trojan_tls"]
    settings = preset_service.build_settings(
        preset, certificate_file="/etc/ssl/cert.pem", key_file="/etc/ssl/key.pem",
        sni="vpn.example.com",
    )

    assert settings["certificateFile"] == "/etc/ssl/cert.pem"
    assert settings["keyFile"] == "/etc/ssl/key.pem"
    assert settings["sni"] == "vpn.example.com"


def test_shadowsocks_preset_sets_method():
    preset = preset_service.PRESETS_BY_KEY["shadowsocks"]
    assert preset_service.build_settings(preset)["method"] == "chacha20-ietf-poly1305"


def test_every_preset_declares_consistent_protocol():
    for preset in preset_service.PRESETS:
        assert isinstance(preset.protocol, ProxyType)
        assert isinstance(preset.network, NetworkType)
        assert isinstance(preset.security, SecurityType)
        assert preset.default_port > 0
        assert preset.title and preset.description


def test_tag_suggestion_avoids_collisions():
    preset = preset_service.PRESETS_BY_KEY["vless_reality_xhttp"]
    base = "VLESS-REALITY-XHTTP"

    assert preset_service.suggest_tag(preset, []) == base
    assert preset_service.suggest_tag(preset, [base]) == f"{base}-2"
    assert preset_service.suggest_tag(preset, [base, f"{base}-2"]) == f"{base}-3"


def test_tags_of_different_presets_do_not_collide():
    """Иначе два разных подключения на ноде получат один tag и статистика слипнется."""
    tags = [preset_service.suggest_tag(preset, []) for preset in preset_service.PRESETS]
    assert len(tags) == len(set(tags))


def test_legacy_warning_names_the_problem():
    """Предупреждение на уже созданном подключении — по фактической форме."""

    class FakeInbound:
        def __init__(self, protocol, network, security, settings=None):
            self.protocol = protocol
            self.network = network
            self.security = security
            self.settings = settings or {}

    vmess = FakeInbound(ProxyType.vmess, NetworkType.ws, SecurityType.none)
    assert "VMess" in preset_service.legacy_warning(vmess)

    old_ss = FakeInbound(
        ProxyType.shadowsocks, NetworkType.tcp, SecurityType.none,
        {"method": "chacha20-ietf-poly1305"},
    )
    assert "Shadowsocks 2022" in preset_service.legacy_warning(old_ss)

    new_ss = FakeInbound(
        ProxyType.shadowsocks, NetworkType.tcp, SecurityType.none,
        {"method": "2022-blake3-aes-128-gcm"},
    )
    assert preset_service.legacy_warning(new_ss) == ""

    own_tls = FakeInbound(ProxyType.vless, NetworkType.ws, SecurityType.tls)
    assert "REALITY" in preset_service.legacy_warning(own_tls)

    plaintext = FakeInbound(ProxyType.vless, NetworkType.tcp, SecurityType.none)
    assert "без шифрования" in preset_service.legacy_warning(plaintext)


def test_no_warning_on_good_and_on_cdn_setups():
    class FakeInbound:
        def __init__(self, protocol, network, security, settings=None):
            self.protocol = protocol
            self.network = network
            self.security = security
            self.settings = settings or {}

    reality = FakeInbound(ProxyType.vless, NetworkType.xhttp, SecurityType.reality)
    assert preset_service.legacy_warning(reality) == ""

    # За CDN шифрования на сервере и не должно быть — это исправная схема,
    # ругаться на неё нельзя, иначе предупреждения перестанут читать.
    behind_cdn = FakeInbound(
        ProxyType.vless, NetworkType.xhttp, SecurityType.none, {"host": "cdn.example.com"}
    )
    assert preset_service.legacy_warning(behind_cdn) == ""


def test_public_key_can_be_derived_from_private():
    """При переносе из Marzban публичного ключа нет — он считается из приватного.

    Сверено с выводом самого Xray 26.3.27: значения совпадают.
    """
    from app.services.keys import public_key_from_private

    private, public = generate_reality_keypair()
    assert public_key_from_private(private) == public

    # Мусор не должен превращаться в правдоподобный ключ: пусть лучше поле
    # останется пустым и администратор увидит предупреждение.
    assert public_key_from_private("не ключ вовсе") == ""
    assert public_key_from_private("") == ""

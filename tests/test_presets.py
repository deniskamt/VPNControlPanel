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
    preset = preset_service.PRESETS_BY_KEY["vless_reality"]
    assert preset_service.suggest_tag(preset, []) == "VLESS-REALITY"
    assert preset_service.suggest_tag(preset, ["VLESS-REALITY"]) == "VLESS-REALITY-2"
    assert (
        preset_service.suggest_tag(preset, ["VLESS-REALITY", "VLESS-REALITY-2"])
        == "VLESS-REALITY-3"
    )

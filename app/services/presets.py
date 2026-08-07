"""Готовые шаблоны подключений.

Смысл шаблона — чтобы рабочее подключение создавалось выбором строки из
списка, а не написанием JSON руками. Всё, что можно сгенерировать (ключи
REALITY, shortId, пути, пароли), панель генерирует сама.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.models.enums import NetworkType, ProxyType, SecurityType
from app.services import shadowsocks
from app.services.keys import generate_path, generate_reality_keypair, generate_short_id


@dataclass(frozen=True)
class Preset:
    key: str
    title: str
    description: str
    protocol: ProxyType
    network: NetworkType
    security: SecurityType
    default_port: int
    # Что спросить у администратора в форме.
    asks_masking_domain: bool = False
    asks_certificate: bool = False
    notes: List[str] = field(default_factory=list)
    recommended: bool = False


PRESETS: List[Preset] = [
    Preset(
        key="vless_reality",
        title="VLESS + REALITY",
        description=(
            "Маскируется под обращение к чужому сайту. Не требует ни домена, "
            "ни сертификата — работает сразу на голом IP."
        ),
        protocol=ProxyType.vless,
        network=NetworkType.tcp,
        security=SecurityType.reality,
        default_port=443,
        asks_masking_domain=True,
        recommended=True,
        notes=["Ключи и shortId панель сгенерирует сама"],
    ),
    Preset(
        key="vless_reality_grpc",
        title="VLESS + REALITY + gRPC",
        description=(
            "Тот же REALITY, но поверх gRPC: лучше держится на плохих сетях "
            "и мобильном интернете."
        ),
        protocol=ProxyType.vless,
        network=NetworkType.grpc,
        security=SecurityType.reality,
        default_port=2053,
        asks_masking_domain=True,
        notes=["Имя сервиса будет сгенерировано"],
    ),
    Preset(
        key="vless_ws",
        title="VLESS + WebSocket",
        description=(
            "Для схемы с CDN: сам сервер слушает без шифрования, TLS "
            "терминирует CDN. Адрес CDN потом задаётся в «Хостах»."
        ),
        protocol=ProxyType.vless,
        network=NetworkType.ws,
        security=SecurityType.none,
        default_port=8080,
        notes=["Путь будет сгенерирован случайным", "Напрямую, без CDN, трафик не шифруется"],
    ),
    Preset(
        key="vless_ws_tls",
        title="VLESS + WebSocket + TLS",
        description="WebSocket со своим сертификатом на сервере — без CDN.",
        protocol=ProxyType.vless,
        network=NetworkType.ws,
        security=SecurityType.tls,
        default_port=443,
        asks_certificate=True,
        notes=["Нужен домен и сертификат"],
    ),
    Preset(
        key="vless_httpupgrade",
        title="VLESS + HTTPUpgrade",
        description=(
            "Легче WebSocket при той же совместимости с CDN. "
            "Поддерживается свежими клиентами."
        ),
        protocol=ProxyType.vless,
        network=NetworkType.httpupgrade,
        security=SecurityType.none,
        default_port=8081,
        notes=["Путь будет сгенерирован случайным"],
    ),
    Preset(
        key="vmess_ws",
        title="VMess + WebSocket",
        description=(
            "Старый добрый VMess. Пригодится ради совместимости со "
            "старыми клиентами."
        ),
        protocol=ProxyType.vmess,
        network=NetworkType.ws,
        security=SecurityType.none,
        default_port=8082,
        notes=["Путь будет сгенерирован случайным"],
    ),
    Preset(
        key="vmess_tcp",
        title="VMess + TCP",
        description="Простейший VMess без транспорта — как запасной канал.",
        protocol=ProxyType.vmess,
        network=NetworkType.tcp,
        security=SecurityType.none,
        default_port=8083,
    ),
    Preset(
        key="trojan_tls",
        title="Trojan + TLS",
        description="Классический TLS. Нужен домен и сертификат на сервере.",
        protocol=ProxyType.trojan,
        network=NetworkType.tcp,
        security=SecurityType.tls,
        default_port=443,
        asks_certificate=True,
        notes=["Укажите пути к сертификату и ключу на сервере"],
    ),
    Preset(
        key="trojan_ws",
        title="Trojan + WebSocket",
        description="Trojan за CDN: шифрование берёт на себя CDN.",
        protocol=ProxyType.trojan,
        network=NetworkType.ws,
        security=SecurityType.none,
        default_port=8084,
        notes=["Путь будет сгенерирован случайным"],
    ),
    Preset(
        key="shadowsocks",
        title="Shadowsocks",
        description="Простой и быстрый протокол без TLS. Хорош как запасной вариант.",
        protocol=ProxyType.shadowsocks,
        network=NetworkType.tcp,
        security=SecurityType.none,
        default_port=8388,
        notes=["Шифрование chacha20-ietf-poly1305"],
    ),
    Preset(
        key="shadowsocks_2022",
        title="Shadowsocks 2022",
        description=(
            "Новая версия протокола: устойчивее к активному зондированию. "
            "Нужен свежий клиент."
        ),
        protocol=ProxyType.shadowsocks,
        network=NetworkType.tcp,
        security=SecurityType.none,
        default_port=8389,
        notes=["Шифрование 2022-blake3-aes-128-gcm"],
    ),
]

PRESETS_BY_KEY: Dict[str, Preset] = {preset.key: preset for preset in PRESETS}

# Домены, под которые прячется REALITY. Годятся сайты с TLS 1.3 и HTTP/2,
# которые не блокируются и не принадлежат вам.
MASKING_DOMAINS = [
    "www.microsoft.com",
    "www.samsung.com",
    "www.cloudflare.com",
    "dl.google.com",
    "www.lovelive-anime.jp",
]


def build_settings(
    preset: Preset,
    masking_domain: Optional[str] = None,
    certificate_file: Optional[str] = None,
    key_file: Optional[str] = None,
    sni: Optional[str] = None,
) -> Dict[str, Any]:
    """Собирает параметры inbound'а, генерируя всё, что можно сгенерировать."""
    settings: Dict[str, Any] = {}

    if preset.security == SecurityType.reality:
        domain = (masking_domain or MASKING_DOMAINS[0]).strip()
        private_key, public_key = generate_reality_keypair()
        settings.update(
            {
                "dest": f"{domain}:443",
                "serverNames": [domain],
                "privateKey": private_key,
                "publicKey": public_key,
                "shortIds": [generate_short_id()],
                "fingerprint": "chrome",
                "flow": "xtls-rprx-vision",
            }
        )
    elif preset.security == SecurityType.tls:
        settings.update(
            {
                "sni": (sni or "").strip(),
                "certificateFile": (certificate_file or "").strip(),
                "keyFile": (key_file or "").strip(),
                "alpn": "h2,http/1.1",
            }
        )

    if preset.network in (NetworkType.ws, NetworkType.httpupgrade, NetworkType.xhttp):
        settings["path"] = generate_path()
        if sni:
            settings["host"] = sni.strip()
    elif preset.network == NetworkType.grpc:
        settings["serviceName"] = generate_path().lstrip("/")

    if preset.protocol == ProxyType.shadowsocks:
        if preset.key.endswith("_2022"):
            method = shadowsocks.DEFAULT_2022_METHOD
            settings["method"] = method
            # Ключ самого inbound'а: у 2022 он общий и обязателен.
            settings["password"] = shadowsocks.generate_server_key(method)
        else:
            settings["method"] = shadowsocks.DEFAULT_METHOD

    if preset.protocol == ProxyType.vless and preset.network != NetworkType.tcp:
        # flow работает только на tcp — на остальных транспортах он ломает клиента.
        settings.pop("flow", None)

    return settings


def suggest_tag(preset: Preset, existing_tags: List[str]) -> str:
    """Имя вида «VLESS-REALITY», при повторе — с номером."""
    base = preset.title.upper().replace(" + ", "-").replace(" ", "-")
    if base not in existing_tags:
        return base
    index = 2
    while f"{base}-{index}" in existing_tags:
        index += 1
    return f"{base}-{index}"

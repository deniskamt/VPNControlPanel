"""Готовые шаблоны подключений.

Смысл шаблона — чтобы рабочее подключение создавалось выбором строки из
списка, а не написанием JSON руками. Всё, что можно сгенерировать (ключи
REALITY, shortId, пути, пароли), панель генерирует сама.

Набор шаблонов подобран под российские блокировки образца 2026 года. Коротко,
что про них известно:

  * ТСПУ «замораживает» TCP-соединение с зарубежным сервером после ~15–20 КБ
    переданных данных — соединение не сбрасывается, а зависает, и клиент видит
    таймаут. Простой VLESS поверх TLS/WS этим и ловится;
  * XHTTP разносит трафик по нескольким обычным HTTP-запросам, поэтому под
    порог не подпадает — это и есть главный шаблон на сегодня;
  * REALITY заимствует TLS-рукопожатие настоящего сайта, поэтому активное
    зондирование сервера ничего не находит; отдельный сертификат и домен не
    нужны;
  * отпечаток TLS-клиента chrome/safari/ios у части операторов помечается как
    подозрительный, firefox проходит — поэтому он и стоит по умолчанию;
  * протоколы поверх UDP/QUIC (Hysteria2, AmneziaWG) у части операторов
    зарезаны целиком и требуют другого ядра — их здесь нет.

Устаревшие шаблоны (VMess, Trojan, обычный Shadowsocks, VLESS без REALITY)
оставлены с пометкой legacy: они нужны при переезде с Marzban, где такие
подключения уже раздавались, но начинать с них не стоит.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.models.enums import NetworkType, ProxyType, SecurityType
from app.services import shadowsocks, xhttp
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
    # Шаблон оставлен ради совместимости, для новых подключений не годится.
    legacy: bool = False
    # Чем именно плох устаревший шаблон — показывается рядом с ним.
    legacy_reason: str = ""


PRESETS: List[Preset] = [
    Preset(
        key="vless_reality_xhttp",
        title="VLESS + REALITY + XHTTP",
        description=(
            "Основной вариант на 2026 год. Трафик разложен по обычным "
            "HTTP-запросам, поэтому не попадает под «заморозку» соединения "
            "после ~16 КБ, а рукопожатие берётся у настоящего сайта. "
            "Ни домена, ни сертификата не нужно."
        ),
        protocol=ProxyType.vless,
        network=NetworkType.xhttp,
        security=SecurityType.reality,
        default_port=443,
        asks_masking_domain=True,
        recommended=True,
        notes=[
            "Ключи, shortId и путь панель сгенерирует сама",
            "Нужен свежий клиент: v2rayTun, Happ, Hiddify, v2rayNG, Streisand",
        ],
    ),
    Preset(
        key="vless_reality",
        title="VLESS + REALITY + Vision",
        description=(
            "Классический REALITY поверх TCP с потоком xtls-rprx-vision: "
            "самый быстрый вариант, работает у большинства проводных "
            "провайдеров. На мобильных операторах чаще упирается в «заморозку» "
            "— тогда берите XHTTP."
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
            "Тот же REALITY поверх gRPC — запасной транспорт: держится там, "
            "где придушен обычный TCP, и переживает плохую мобильную связь."
        ),
        protocol=ProxyType.vless,
        network=NetworkType.grpc,
        security=SecurityType.reality,
        default_port=2053,
        asks_masking_domain=True,
        recommended=True,
        notes=["Имя сервиса будет сгенерировано"],
    ),
    Preset(
        key="vless_xhttp_cdn",
        title="VLESS + XHTTP за CDN",
        description=(
            "Для сетей с «белыми списками», где напрямую к зарубежному "
            "серверу не пускают вовсе: трафик идёт через Cloudflare, а тот "
            "в списках есть. Сервер слушает без шифрования, TLS терминирует "
            "CDN — снаружи это обычный HTTPS к сайту за Cloudflare."
        ),
        protocol=ProxyType.vless,
        network=NetworkType.xhttp,
        security=SecurityType.none,
        default_port=8080,
        notes=[
            "Домен за CDN укажите в поле SNI, потом добавьте его в «Хостах»",
            "Порт наружу открывает Cloudflare: 443 или 2053/2083/2087/2096",
        ],
    ),
    Preset(
        key="shadowsocks_2022",
        title="Shadowsocks 2022",
        description=(
            "Запасной канал без TLS вообще: иногда проходит там, где "
            "зажимают именно TLS-соединения. Устойчив к активному "
            "зондированию, но не маскируется под сайт."
        ),
        protocol=ProxyType.shadowsocks,
        network=NetworkType.tcp,
        security=SecurityType.none,
        default_port=8389,
        notes=["Шифрование 2022-blake3-aes-128-gcm"],
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
        legacy=True,
        legacy_reason=(
            "обычный TLS к зарубежному серверу ТСПУ подвешивает после ~16 КБ"
        ),
        notes=["Нужен домен и сертификат"],
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
        legacy=True,
        legacy_reason="за CDN лучше работает XHTTP, а напрямую WebSocket виден",
        notes=["Путь будет сгенерирован случайным", "Напрямую, без CDN, трафик не шифруется"],
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
        legacy=True,
        legacy_reason="вытеснен XHTTP, который дробит и сам поток данных",
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
        legacy=True,
        legacy_reason="VMess опознаётся по рукопожатию, в России давно ловится",
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
        legacy=True,
        legacy_reason="VMess опознаётся по рукопожатию, в России давно ловится",
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
        legacy=True,
        legacy_reason="то же, что у VLESS+TLS: обычное TLS-соединение подвешивают",
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
        legacy=True,
        legacy_reason="за CDN лучше работает XHTTP",
        notes=["Путь будет сгенерирован случайным"],
    ),
    Preset(
        key="shadowsocks",
        title="Shadowsocks (старый)",
        description="Простой и быстрый протокол без TLS.",
        protocol=ProxyType.shadowsocks,
        network=NetworkType.tcp,
        security=SecurityType.none,
        default_port=8388,
        legacy=True,
        legacy_reason="уязвим к активному зондированию, берите Shadowsocks 2022",
        notes=["Шифрование chacha20-ietf-poly1305"],
    ),
]

PRESETS_BY_KEY: Dict[str, Preset] = {preset.key: preset for preset in PRESETS}

CURRENT_PRESETS: List[Preset] = [preset for preset in PRESETS if not preset.legacy]
LEGACY_PRESETS: List[Preset] = [preset for preset in PRESETS if preset.legacy]

# Домены, под которые прячется REALITY. Годятся сайты с TLS 1.3 и HTTP/2,
# которые не блокируются и не принадлежат вам.
MASKING_DOMAINS = [
    "www.microsoft.com",
    "www.samsung.com",
    "www.cloudflare.com",
    "dl.google.com",
    "www.lovelive-anime.jp",
]

# Отпечаток TLS-клиента. Не chrome: у части российских операторов отпечатки
# chrome/safari/ios попали в подозрительные, а firefox проходит. Клиент может
# переопределить его в «Хостах».
DEFAULT_FINGERPRINT = "firefox"

# Минимальная версия клиентского ядра для REALITY. Проверено на живых ядрах:
# сервер 26.7.28 без этого поля не пускает клиента 25.6.8, а с ним — пускает.
MIN_CLIENT_VERSION = "1.8.0"


def build_settings(
    preset: Preset,
    masking_domain: Optional[str] = None,
    certificate_file: Optional[str] = None,
    key_file: Optional[str] = None,
    sni: Optional[str] = None,
    obfuscate: bool = False,
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
                "fingerprint": DEFAULT_FINGERPRINT,
                "flow": "xtls-rprx-vision",
                # Свежие ядра по умолчанию пускают только клиентов не старше
                # себя: сервер на 26.7.28 отказывает клиенту на 25.6.8, и
                # выглядит это как «протокол не работает». Приложения из
                # магазинов обновляются когда захотят, поэтому планку снимаем.
                # Плата: старые клиенты чуть заметнее для активного зондирования.
                "minClientVer": MIN_CLIENT_VERSION,
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
        if preset.network == NetworkType.xhttp:
            # stream-one, а не auto: на замерах (Xray 26.7.28, один и тот же
            # файл через один и тот же канал) auto давал ~60 МБ/с, stream-one
            # ~78 МБ/с. За CDN длинный ответ часто режут — там packet-up.
            settings["mode"] = "packet-up" if preset.security == SecurityType.none \
                else xhttp.DEFAULT_MODE
            if obfuscate:
                settings.update(xhttp.generate_obfuscation())
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


def legacy_warning(inbound: Any) -> str:
    """Чем плохо уже существующее подключение — или пустая строка.

    Смотрим только на то, в чём ошибиться нельзя: VMess, старый Shadowsocks,
    свой TLS и полное отсутствие шифрования. Транспорт без шифрования за CDN
    (ws/xhttp) — нормальная схема, TLS там терминирует CDN, и ругаться на неё
    значило бы кричать «волки» на исправной настройке.
    """
    opts = inbound.settings or {}

    # Маскировочные поля XHTTP совместимы только между одинаковыми версиями
    # ядра: проверено на живых сборках — сервер 26.3.27 не пускает клиента
    # 26.7.28 и наоборот. У приложений версия своя и меняется сама, поэтому
    # такое подключение работает у одних и молчит у других.
    if inbound.network == NetworkType.xhttp and xhttp.has_obfuscation(opts):
        return (
            "включена усиленная маскировка XHTTP: она работает, только если "
            "ядро в приложении ровно той же версии, что на ноде, — у части "
            "пользователей подключение не поднимется. Уберите поля xPadding*, "
            "seqKey и sessionID* в «Настроить»"
        )

    if inbound.protocol == ProxyType.vmess:
        return (
            "VMess опознаётся по рукопожатию и в России давно ловится — "
            "переведите пользователей на VLESS + REALITY"
        )

    if inbound.protocol == ProxyType.shadowsocks:
        method = str(opts.get("method") or "")
        if not method.startswith("2022-"):
            return (
                "старый Shadowsocks уязвим к активному зондированию — "
                "замените на Shadowsocks 2022"
            )
        return ""

    if inbound.security == SecurityType.reality:
        return ""

    if inbound.security == SecurityType.tls:
        return (
            "обычный TLS к зарубежному серверу ТСПУ подвешивает примерно "
            "после 16 КБ — надёжнее REALITY"
        )

    if inbound.network == NetworkType.tcp:
        return "подключение идёт без шифрования вовсе — так работать не будет"

    return ""


def suggest_tag(preset: Preset, existing_tags: List[str]) -> str:
    """Имя вида «VLESS-REALITY», при повторе — с номером."""
    base = preset.title.upper().replace(" + ", "-").replace(" ", "-")
    if base not in existing_tags:
        return base
    index = 2
    while f"{base}-{index}" in existing_tags:
        index += 1
    return f"{base}-{index}"

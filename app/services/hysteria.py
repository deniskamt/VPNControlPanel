"""Hysteria2 — отдельный процесс на ноде рядом с Xray.

Зачем он нужен. VLESS+REALITY идёт по TCP, и на сетях с потерями — мобильный
интернет, вокзальный Wi-Fi — одно потерянное окно роняет скорость всего
соединения. Hysteria2 работает поверх QUIC и восстанавливает потери сам,
поэтому там, где REALITY еле дышит, он держится.

Плата — заметность: QUIC отличается от обычного веб-трафика, и ТСПУ его
распознаёт. Поэтому обфускация Salamander включается всегда: она перемешивает
первый пакет, по которому QUIC и опознают.

Хитрость с портом: Hysteria2 слушает UDP, а REALITY — TCP, так что оба спокойно
живут на 443. Для человека это один и тот же «порт 443», а для сети — разные
протоколы.

Конфиг у Hysteria2 свой (не Xray), но JSON он понимает — проверено на 2.12.2,
поэтому собираем обычный словарь и отдаём агенту как есть.
"""

import secrets
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote, urlencode, urlparse

from app.models.enums import ProxyType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.models.user import User

# Куда Hysteria2 отправляет всех, кто постучался без правильного пароля.
# Сервер притворяется обратным прокси к настоящему сайту: на сканирование
# отвечает так же, как ответил бы он.
DEFAULT_MASQUERADE = "https://www.microsoft.com/"

# Имя в сертификате. Своего домена у ноды обычно нет, поэтому сертификат
# самоподписанный, а клиент не проверяет его (insecure в ссылке): проверка
# всё равно ничего не дала бы, а имя нужно, чтобы SNI выглядел обычным.
DEFAULT_SNI = "www.microsoft.com"

# Порт статистики. Слушает только localhost: наружу его отдавать незачем,
# агент ходит к нему сам.
STATS_PORT = 9411


def is_hysteria(inbound: Inbound) -> bool:
    return inbound.protocol == ProxyType.hysteria2


def new_obfs_password() -> str:
    """Пароль обфускации. Общий для всех пользователей подключения: он
    перемешивает пакеты, а не разделяет людей."""
    return secrets.token_urlsafe(16)


def masquerade_host(url: str) -> str:
    """Домен из адреса маскировки — его же ставим в сертификат."""
    host = urlparse(url or DEFAULT_MASQUERADE).hostname
    return host or DEFAULT_SNI


def server_name(inbound: Inbound) -> str:
    options = inbound.settings or {}
    return (options.get("sni") or "").strip() or masquerade_host(
        options.get("masquerade") or DEFAULT_MASQUERADE
    )


def build_config(
    node: Node, inbounds: Iterable[Inbound], users_by_inbound: Dict[int, List[User]]
) -> Optional[Dict[str, Any]]:
    """Конфиг Hysteria2 для ноды — или None, если такого подключения нет.

    У Hysteria2 один процесс слушает один порт, поэтому из нескольких
    подключений берём первое включённое: остальные всё равно не поднялись бы.
    """
    for inbound in sorted(inbounds, key=lambda item: item.id):
        if not is_hysteria(inbound) or not inbound.is_enabled:
            continue

        options = inbound.settings or {}
        users = users_by_inbound.get(inbound.id, [])
        credentials = {}
        for user in users:
            settings = user.proxy_settings(ProxyType.hysteria2) or {}
            password = str(settings.get("password") or "")
            if password:
                credentials[user.username] = password

        config: Dict[str, Any] = {
            "listen": f":{inbound.port}",
            "auth": {"type": "userpass", "userpass": credentials},
            "masquerade": {
                "type": "proxy",
                "proxy": {
                    "url": options.get("masquerade") or DEFAULT_MASQUERADE,
                    "rewriteHost": True,
                },
            },
            # Счётчики агент забирает отсюда и складывает с Xray-статистикой.
            "trafficStats": {
                "listen": f"127.0.0.1:{STATS_PORT}",
                "secret": options.get("statsSecret") or "",
            },
        }

        obfs = options.get("obfsPassword")
        if obfs:
            config["obfs"] = {"type": "salamander", "salamander": {"password": obfs}}

        certificate = (options.get("certificateFile") or "").strip()
        key_file = (options.get("keyFile") or "").strip()
        if certificate and key_file:
            config["tls"] = {"cert": certificate, "key": key_file}
        else:
            # Своего сертификата нет — пусть агент выпишет самоподписанный на
            # это имя. Он же подставит пути, они известны только ему.
            config["selfSignedFor"] = server_name(inbound)

        bandwidth = {}
        for field in ("up", "down"):
            value = (options.get(field) or "").strip() if options.get(field) else ""
            if value:
                bandwidth[field] = value
        if bandwidth:
            config["bandwidth"] = bandwidth

        return config

    return None


def build_link(
    user: User,
    inbound: Inbound,
    node: Node,
    host: Optional[Host] = None,
    remark: str = "",
) -> Optional[str]:
    """Ссылка hysteria2:// для клиентского приложения."""
    settings = user.proxy_settings(ProxyType.hysteria2) or {}
    password = str(settings.get("password") or "")
    if not password:
        return None

    options = inbound.settings or {}
    address = (host.address if host and host.address else None) or node.address
    port = (host.port if host and host.port else None) or inbound.port
    sni = (host.sni if host and host.sni else None) or server_name(inbound)

    params: Dict[str, Any] = {"sni": sni}
    if options.get("obfsPassword"):
        params["obfs"] = "salamander"
        params["obfs-password"] = options["obfsPassword"]
    # Самоподписанный сертификат клиент обязан принять явно, иначе соединение
    # оборвётся на проверке. С настоящим сертификатом этого не нужно.
    if not (options.get("certificateFile") and options.get("keyFile")):
        params["insecure"] = 1

    query = urlencode(params)
    # Пароль уезжает в userinfo, а имя пользователя нужно потому, что на
    # сервере включён режим userpass: без него сервер не поймёт, чей это ключ.
    userinfo = f"{quote(user.username, safe='')}:{quote(password, safe='')}"
    return f"hysteria2://{userinfo}@{address}:{port}/?{query}#{quote(remark)}"

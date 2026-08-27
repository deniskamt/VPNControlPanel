"""JSON-подписка: готовые конфиги Xray для клиентского приложения.

Обычная ссылка `vless://…` умеет передать только то, для чего есть
общепринятый параметр в query. Маскировочные поля XHTTP (добивка, место
порядкового номера, имя заголовка сессии) такого параметра не имеют: клиент
их не увидит, возьмёт значения по умолчанию — и не соединится. Поэтому
подключения с усиленной маскировкой отдаются JSON-подпиской, где настройки
описаны целиком и точно.

Формат — массив конфигов Xray с полем `remarks`: так его понимают клиенты на
Xray-core (v2rayTun, Happ, v2rayNG, Streisand, NekoBox). Каждый конфиг
самодостаточен и запускается ядром как есть.
"""

from typing import Any, Dict, List, Optional

from app.models.enums import NetworkType, ProxyType, SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.models.user import User
from app.services import shadowsocks, xhttp
from app.services.links import DEFAULT_REMARK, _effective_security, _remark

# Локальные порты, которые клиент поднимает у себя.
SOCKS_PORT = 10808
HTTP_PORT = 10809


def _stream_settings(inbound: Inbound, host: Optional[Host], address: str) -> Dict[str, Any]:
    opts = inbound.settings or {}
    security = _effective_security(inbound, host)
    stream: Dict[str, Any] = {"network": inbound.network.value, "security": security.value}

    if inbound.network == NetworkType.xhttp:
        stream["xhttpSettings"] = xhttp.transport_settings(opts)
    elif inbound.network == NetworkType.ws:
        ws: Dict[str, Any] = {"path": opts.get("path", "/")}
        if opts.get("host"):
            ws["headers"] = {"Host": opts["host"]}
        stream["wsSettings"] = ws
    elif inbound.network == NetworkType.httpupgrade:
        stream["httpupgradeSettings"] = {
            "path": opts.get("path", "/"),
            "host": opts.get("host", ""),
        }
    elif inbound.network == NetworkType.grpc:
        stream["grpcSettings"] = {"serviceName": opts.get("serviceName", "")}

    sni = (host.sni if host and host.sni else None) or opts.get("sni") or opts.get("host")
    fingerprint = (
        (host.fingerprint if host and host.fingerprint else None)
        or opts.get("fingerprint")
        or "firefox"
    )

    if security == SecurityType.reality:
        stream["realitySettings"] = {
            "serverName": (opts.get("serverNames") or [sni or address])[0]
            if opts.get("serverNames")
            else (sni or address),
            "publicKey": opts.get("publicKey", ""),
            "shortId": (opts.get("shortIds") or [""])[0],
            "fingerprint": fingerprint,
        }
    elif security == SecurityType.tls:
        tls: Dict[str, Any] = {"serverName": sni or address, "fingerprint": fingerprint}
        if opts.get("alpn"):
            tls["alpn"] = [part for part in str(opts["alpn"]).split(",") if part]
        if opts.get("allowInsecure"):
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls

    return stream


def build_outbound(
    user: User, inbound: Inbound, node: Node, host: Optional[Host] = None
) -> Optional[Dict[str, Any]]:
    """Исходящее соединение клиента к одному подключению на одной ноде."""
    creds = user.proxy_settings(inbound.protocol)
    if creds is None:
        return None

    address = (host.address if host and host.address else None) or node.address
    port = (host.port if host and host.port else None) or inbound.port
    opts = inbound.settings or {}

    # Hysteria2 — не Xray: в профиль Xray-клиента его выразить нечем.
    # Такие подключения человек получает ссылкой hysteria2:// из подписки,
    # её понимают Happ, v2rayTun, Hiddify и остальные свежие приложения.
    if inbound.protocol == ProxyType.hysteria2:
        return None

    if inbound.protocol == ProxyType.shadowsocks:
        method = opts.get("method", shadowsocks.DEFAULT_METHOD)
        password = shadowsocks.client_password(method, opts.get("password"), creds)
        return {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [
                    {"address": address, "port": port, "method": method,
                     "password": password}
                ]
            },
            "streamSettings": {"network": "tcp"},
        }

    if inbound.protocol == ProxyType.trojan:
        return {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {"address": address, "port": port, "password": creds.get("password", "")}
                ]
            },
            "streamSettings": _stream_settings(inbound, host, address),
        }

    account: Dict[str, Any] = {"id": creds.get("id", "")}
    if inbound.protocol == ProxyType.vless:
        account["encryption"] = "none"
        flow = creds.get("flow") or opts.get("flow") or ""
        # flow живёт только на tcp: на остальных транспортах клиент с ним падает.
        if flow and inbound.network == NetworkType.tcp:
            account["flow"] = flow
    else:
        account["security"] = creds.get("security", "auto")
        account["alterId"] = 0

    return {
        "tag": "proxy",
        "protocol": inbound.protocol.value,
        "settings": {"vnext": [{"address": address, "port": port, "users": [account]}]},
        "streamSettings": _stream_settings(inbound, host, address),
    }


def build_profile(
    user: User, inbound: Inbound, node: Node, host: Optional[Host] = None
) -> Optional[Dict[str, Any]]:
    """Самодостаточный конфиг Xray — один профиль в списке у клиента."""
    outbound = build_outbound(user, inbound, node, host)
    if outbound is None:
        return None

    remark = _remark(host.remark if host else DEFAULT_REMARK, node, user, inbound)
    return {
        "remarks": remark,
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks",
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "tag": "http",
                "listen": "127.0.0.1",
                "port": HTTP_PORT,
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                # Локальные адреса мимо туннеля: иначе не открывается роутер
                # и не работает домашняя сеть.
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
            ],
        },
    }


def build_user_profiles(user: User, nodes: List[Node]) -> List[Dict[str, Any]]:
    """Профили по всем доступным пользователю подключениям."""
    allowed_ids = {inbound.id for inbound in user.inbounds}
    profiles: List[Dict[str, Any]] = []

    for node in sorted(nodes, key=lambda item: (item.sort_order, item.id)):
        if not node.is_enabled or not user.allowed_on(node.id):
            continue
        for inbound in sorted(node.inbounds, key=lambda item: item.id):
            if not inbound.is_enabled or inbound.id not in allowed_ids:
                continue

            hosts = [
                host
                for host in inbound.hosts
                if not host.is_disabled and host.node_id in (None, node.id)
            ]
            if hosts:
                for host in hosts:
                    profile = build_profile(user, inbound, node, host)
                    if profile:
                        profiles.append(profile)
            else:
                profile = build_profile(user, inbound, node)
                if profile:
                    profiles.append(profile)

    return profiles

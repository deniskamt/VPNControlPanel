"""Генерация конфига Xray для конкретной ноды.

Панель — единственный источник правды: конфиг целиком собирается здесь и
целиком заливается на ноду. Руками на сервере ничего править не нужно.

В конфиг всегда добавляется служебный api-inbound на 127.0.0.1 — через него
агент снимает статистику трафика по каждому пользователю.
"""

import hashlib
import json
from typing import Any, Dict, Iterable, List

from app.models.enums import NetworkType, ProxyType, SecurityType, UserStatus
from app.models.inbound import Inbound
from app.models.node import Node
from app.models.user import User

API_PORT = 10085
API_TAG = "api"


def _stream_settings(inbound: Inbound) -> Dict[str, Any]:
    opts = inbound.settings or {}
    stream: Dict[str, Any] = {"network": inbound.network.value}

    if inbound.network == NetworkType.ws:
        ws: Dict[str, Any] = {"path": opts.get("path", "/")}
        if opts.get("host"):
            ws["headers"] = {"Host": opts["host"]}
        stream["wsSettings"] = ws
    elif inbound.network == NetworkType.grpc:
        stream["grpcSettings"] = {"serviceName": opts.get("serviceName", "")}
        if opts.get("multiMode"):
            stream["grpcSettings"]["multiMode"] = True
    elif inbound.network == NetworkType.httpupgrade:
        stream["httpupgradeSettings"] = {
            "path": opts.get("path", "/"),
            "host": opts.get("host", ""),
        }
    elif inbound.network == NetworkType.xhttp:
        stream["xhttpSettings"] = {
            "path": opts.get("path", "/"),
            "host": opts.get("host", ""),
            "mode": opts.get("mode", "auto"),
        }
    elif inbound.network == NetworkType.tcp and opts.get("header_type") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [opts.get("path", "/")],
                    "headers": {"Host": [opts.get("host", "")]},
                },
            }
        }

    if inbound.security == SecurityType.tls:
        tls: Dict[str, Any] = {}
        if opts.get("sni"):
            tls["serverName"] = opts["sni"]
        if opts.get("alpn"):
            tls["alpn"] = [part for part in str(opts["alpn"]).split(",") if part]
        certificate_file = opts.get("certificateFile")
        key_file = opts.get("keyFile")
        if certificate_file and key_file:
            tls["certificates"] = [
                {"certificateFile": certificate_file, "keyFile": key_file}
            ]
        elif opts.get("certificate") and opts.get("key"):
            tls["certificates"] = [
                {
                    "certificate": opts["certificate"].splitlines(),
                    "key": opts["key"].splitlines(),
                }
            ]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif inbound.security == SecurityType.reality:
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "show": False,
            "dest": opts.get("dest", "www.google.com:443"),
            "xver": opts.get("xver", 0),
            "serverNames": opts.get("serverNames") or [],
            "privateKey": opts.get("privateKey", ""),
            "shortIds": opts.get("shortIds") or [""],
        }
    else:
        stream["security"] = "none"

    return stream


def _client_entry(inbound: Inbound, user: User) -> Dict[str, Any] | None:
    creds = user.proxy_settings(inbound.protocol)
    if creds is None:
        return None

    opts = inbound.settings or {}
    email = user.username

    if inbound.protocol == ProxyType.vless:
        client: Dict[str, Any] = {"id": creds.get("id"), "email": email, "level": 0}
        flow = creds.get("flow") or opts.get("flow") or ""
        # Xray принимает flow только на tcp+tls/reality; на ws он ломает клиента.
        if flow and inbound.network == NetworkType.tcp:
            client["flow"] = flow
        return client if client["id"] else None

    if inbound.protocol == ProxyType.vmess:
        return (
            {"id": creds.get("id"), "email": email, "level": 0}
            if creds.get("id")
            else None
        )

    if inbound.protocol == ProxyType.trojan:
        return (
            {"password": creds.get("password"), "email": email, "level": 0}
            if creds.get("password")
            else None
        )

    # shadowsocks
    if not creds.get("password"):
        return None
    return {
        "password": creds["password"],
        "method": creds.get("method") or opts.get("method", "chacha20-ietf-poly1305"),
        "email": email,
        "level": 0,
    }


def _inbound_settings(inbound: Inbound, clients: List[Dict[str, Any]]) -> Dict[str, Any]:
    if inbound.protocol == ProxyType.vless:
        return {"clients": clients, "decryption": "none"}
    if inbound.protocol == ProxyType.vmess:
        return {"clients": clients}
    if inbound.protocol == ProxyType.trojan:
        return {"clients": clients}
    return {"clients": clients, "network": "tcp,udp"}


def build_inbound(inbound: Inbound, users: Iterable[User]) -> Dict[str, Any]:
    clients: List[Dict[str, Any]] = []
    for user in users:
        entry = _client_entry(inbound, user)
        if entry:
            clients.append(entry)

    config: Dict[str, Any] = {
        "tag": inbound.tag,
        "listen": inbound.listen or "0.0.0.0",
        "port": inbound.port,
        "protocol": inbound.protocol.value,
        "settings": _inbound_settings(inbound, clients),
        "streamSettings": _stream_settings(inbound),
    }
    if inbound.sniffing:
        config["sniffing"] = {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": False,
        }
    return config


def build_node_config(node: Node, users: Iterable[User]) -> Dict[str, Any]:
    """Полный конфиг Xray для ноды: служебный api + все её inbound'ы."""
    active_users = [
        user
        for user in users
        if user.status == UserStatus.active and not user.expired and not user.limited
    ]
    allowed_by_inbound: Dict[int, List[User]] = {}
    for user in active_users:
        for inbound in user.inbounds:
            allowed_by_inbound.setdefault(inbound.id, []).append(user)

    inbounds: List[Dict[str, Any]] = [
        {
            "tag": API_TAG,
            "listen": "127.0.0.1",
            "port": API_PORT,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        }
    ]
    for inbound in sorted(node.inbounds, key=lambda i: i.id):
        if not inbound.is_enabled:
            continue
        inbounds.append(build_inbound(inbound, allowed_by_inbound.get(inbound.id, [])))

    return {
        "log": {"loglevel": "warning"},
        "api": {
            "tag": API_TAG,
            "services": ["HandlerService", "StatsService", "LoggerService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "tag": "DIRECT"},
            {"protocol": "blackhole", "tag": "BLOCK"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "inboundTag": [API_TAG], "outboundTag": API_TAG},
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "BLOCK"},
            ],
        },
    }


def config_hash(config: Dict[str, Any]) -> str:
    """Стабильный хеш конфига — чтобы не перезаливать одно и то же."""
    payload = json.dumps(config, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

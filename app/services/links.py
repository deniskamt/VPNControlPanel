"""Сборка клиентских ссылок (vless://, vmess://, trojan://, ss://).

Ссылка строится из трёх источников:
  * inbound  — протокол, транспорт, тип шифрования, порт на сервере;
  * node     — адрес сервера и его название;
  * host     — необязательное переопределение (CDN, отдельный SNI/порт).
"""

import json
from base64 import b64encode
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

from app.models.enums import NetworkType, ProxyType, SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.models.user import User
from app.services import shadowsocks, xhttp
from app.services.flags import country_flag


# Название по умолчанию: флаг впереди, потому что клиентские приложения
# рисуют иконку страны только по эмодзи в названии, а не по нашему полю.
DEFAULT_REMARK = "{flag} {node}"


def _remark(template: str, node: Node, user: User, inbound: Inbound) -> str:
    result = (
        (template or DEFAULT_REMARK)
        .replace("{flag}", country_flag(node.country))
        .replace("{node}", node.name)
        .replace("{country}", node.country or "")
        .replace("{username}", user.username)
        .replace("{protocol}", inbound.protocol.value)
        .replace("{tag}", inbound.tag)
    )
    # Без страны шаблон оставил бы лишние пробелы в начале названия.
    return " ".join(result.split()) or node.name


def _b64(value: str) -> str:
    return b64encode(value.encode("utf-8")).decode("utf-8")


def _transport_params(
    inbound: Inbound, host: Optional[Host], params: Dict[str, Any]
) -> None:
    """Параметры транспорта, общие для vless/trojan (в vmess своя схема)."""
    opts = inbound.settings or {}
    network = inbound.network

    if network == NetworkType.ws:
        params["path"] = (host.path if host and host.path else opts.get("path")) or "/"
        header_host = (host.host if host and host.host else opts.get("host")) or ""
        if header_host:
            params["host"] = header_host
    elif network in (NetworkType.httpupgrade, NetworkType.xhttp):
        params["path"] = (host.path if host and host.path else opts.get("path")) or "/"
        header_host = (host.host if host and host.host else opts.get("host")) or ""
        if header_host:
            params["host"] = header_host
        if network == NetworkType.xhttp:
            if opts.get("mode"):
                params["mode"] = opts["mode"]
            # Всё, для чего нет своего query-параметра, едет в extra — туда
            # клиент на Xray-core кладёт содержимое как есть в xhttpSettings.
            # Это и дробление соединений (scMaxEachPostBytes, xmux и прочее),
            # без которого XHTTP теряет смысл, и маскировочные поля.
            extra: Dict[str, Any] = {}
            if isinstance(opts.get("extra"), dict):
                extra.update(opts["extra"])
            extra.update(
                {
                    key: opts[key]
                    for key in xhttp.OBFUSCATION_KEYS
                    if opts.get(key) not in (None, "")
                }
            )
            if extra:
                params["extra"] = json.dumps(extra, separators=(",", ":"))
    elif network == NetworkType.grpc:
        params["serviceName"] = (
            host.path if host and host.path else opts.get("serviceName")
        ) or ""
        if opts.get("multiMode"):
            params["mode"] = "multi"
    elif network == NetworkType.tcp and opts.get("header_type") == "http":
        params["headerType"] = "http"
        header_host = (host.host if host and host.host else opts.get("host")) or ""
        if header_host:
            params["host"] = header_host


def _effective_security(inbound: Inbound, host: Optional[Host]) -> SecurityType:
    """Что писать в ссылку: настройку хоста, если задана, иначе inbound'а."""
    if host is not None and host.security is not None:
        return host.security
    return inbound.security


def _security_params(
    inbound: Inbound, host: Optional[Host], node: Node, params: Dict[str, Any]
) -> None:
    opts = inbound.settings or {}
    security = _effective_security(inbound, host)

    if security == SecurityType.none:
        params["security"] = "none"
        return

    if security == SecurityType.tls:
        params["security"] = "tls"
        sni = (host.sni if host and host.sni else opts.get("sni")) or node.address
        params["sni"] = sni
        fingerprint = (
            host.fingerprint if host and host.fingerprint else opts.get("fingerprint")
        )
        if fingerprint:
            params["fp"] = fingerprint
        alpn = (host.alpn if host and host.alpn else opts.get("alpn")) or ""
        if alpn:
            params["alpn"] = alpn
        if host and host.allowinsecure:
            params["allowInsecure"] = 1
        return

    # reality
    params["security"] = "reality"
    server_names: List[str] = opts.get("serverNames") or []
    sni = (host.sni if host and host.sni else None) or (
        server_names[0] if server_names else node.address
    )
    params["sni"] = sni
    if opts.get("publicKey"):
        params["pbk"] = opts["publicKey"]
    short_ids = opts.get("shortIds") or []
    if short_ids:
        params["sid"] = short_ids[0]
    params["fp"] = (
        (host.fingerprint if host and host.fingerprint else None)
        or opts.get("fingerprint")
        or "chrome"
    )
    if opts.get("spiderX"):
        params["spx"] = opts["spiderX"]


def build_link(
    user: User, inbound: Inbound, node: Node, host: Optional[Host] = None
) -> Optional[str]:
    """Одна ссылка для пары (нода, inbound). None — если у юзера нет ключа."""
    creds = user.proxy_settings(inbound.protocol)
    if creds is None:
        return None

    address = (host.address if host and host.address else None) or node.address
    port = (host.port if host and host.port else None) or inbound.port
    remark = _remark(host.remark if host else DEFAULT_REMARK, node, user, inbound)
    opts = inbound.settings or {}

    if inbound.protocol == ProxyType.shadowsocks:
        method = opts.get("method", shadowsocks.DEFAULT_METHOD)
        userinfo = shadowsocks.link_userinfo(
            creds.get("password", ""), method, opts.get("password")
        )
        return f"ss://{_b64(userinfo).rstrip('=')}@{address}:{port}#{quote(remark)}"

    if inbound.protocol == ProxyType.vmess:
        payload = {
            "v": "2",
            "ps": remark,
            "add": address,
            "port": str(port),
            "id": creds.get("id", ""),
            "aid": "0",
            "scy": creds.get("security", "auto"),
            "net": inbound.network.value,
            "type": opts.get("header_type", "none"),
            "host": (host.host if host and host.host else opts.get("host")) or "",
            "path": (host.path if host and host.path else opts.get("path")) or "",
            "tls": "tls" if _effective_security(inbound, host) == SecurityType.tls else "",
            "sni": (host.sni if host and host.sni else opts.get("sni")) or "",
            "alpn": (host.alpn if host and host.alpn else opts.get("alpn")) or "",
            "fp": (
                host.fingerprint if host and host.fingerprint else opts.get("fingerprint")
            )
            or "",
        }
        if inbound.network == NetworkType.grpc:
            payload["path"] = opts.get("serviceName", "")
        return "vmess://" + _b64(json.dumps(payload, ensure_ascii=False))

    params: Dict[str, Any] = {"type": inbound.network.value}
    _security_params(inbound, host, node, params)
    _transport_params(inbound, host, params)

    if inbound.protocol == ProxyType.vless:
        flow = creds.get("flow") or opts.get("flow") or ""
        # flow работает только с TCP+reality/tls, на ws его быть не должно.
        if flow and inbound.network == NetworkType.tcp:
            params["flow"] = flow
        secret = creds.get("id", "")
        scheme = "vless"
    else:  # trojan
        secret = creds.get("password", "")
        scheme = "trojan"

    query = urlencode({k: v for k, v in params.items() if v not in (None, "")})
    return f"{scheme}://{secret}@{address}:{port}?{query}#{quote(remark)}"


def build_user_links(user: User, nodes: List[Node]) -> List[str]:
    """Все ссылки пользователя: по каждому доступному inbound на каждой ноде."""
    allowed_ids = {inbound.id for inbound in user.inbounds}
    links: List[str] = []

    for node in sorted(nodes, key=lambda n: (n.sort_order, n.id)):
        if not node.is_enabled:
            continue
        # Закрытый для пользователя сервер не должен появляться в подписке:
        # иначе клиент будет упорно долбиться в него и показывать ошибки.
        if not user.allowed_on(node.id):
            continue
        for inbound in sorted(node.inbounds, key=lambda i: i.id):
            if not inbound.is_enabled or inbound.id not in allowed_ids:
                continue

            hosts = [
                host
                for host in inbound.hosts
                if not host.is_disabled and host.node_id in (None, node.id)
            ]
            if not hosts:
                link = build_link(user, inbound, node)
                if link:
                    links.append(link)
                continue

            for host in sorted(hosts, key=lambda h: (h.sort_order, h.id)):
                link = build_link(user, inbound, node, host)
                if link:
                    links.append(link)

    return links

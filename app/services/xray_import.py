"""Разбор inbound'а из конфига Xray.

Нужен в двух местах: при переносе установки Marzban (там параметры лежат в
xray_config.json) и при ручном добавлении подключения вставкой готового
JSON — так переносится настройка из любой другой панели.
"""

from typing import Any, Dict, Optional

from app.models.enums import NetworkType, ProxyType, SecurityType

NETWORK_ALIASES = {
    "tcp": NetworkType.tcp,
    "raw": NetworkType.tcp,
    "ws": NetworkType.ws,
    "websocket": NetworkType.ws,
    "grpc": NetworkType.grpc,
    "httpupgrade": NetworkType.httpupgrade,
    "xhttp": NetworkType.xhttp,
    "splithttp": NetworkType.xhttp,
}


class ImportError_(ValueError):
    """Понятная человеку причина, почему JSON не подошёл."""


def parse_inbound(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Превращает inbound Xray в параметры нашей модели.

    None — если это служебный inbound (api, dokodemo-door) и переносить
    его не нужно.
    """
    if not isinstance(raw, dict):
        raise ImportError_("Ожидается JSON-объект с описанием inbound")

    protocol = str(raw.get("protocol") or "").lower()
    if protocol in ("dokodemo-door", "http", "socks", ""):
        return None
    if protocol not in {item.value for item in ProxyType}:
        raise ImportError_(
            f"Протокол «{protocol}» не поддерживается. Доступны: "
            + ", ".join(item.value for item in ProxyType)
        )

    port = raw.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ImportError_("Не вижу корректного поля port")

    stream = raw.get("streamSettings") or {}
    network_raw = str(stream.get("network") or "tcp").lower()
    security_raw = str(stream.get("security") or "none").lower()

    options: Dict[str, Any] = {}

    ws = stream.get("wsSettings") or {}
    if ws:
        options["path"] = ws.get("path", "/")
        options["host"] = (ws.get("headers") or {}).get("Host", "")

    grpc = stream.get("grpcSettings") or {}
    if grpc:
        options["serviceName"] = grpc.get("serviceName", "")
        if grpc.get("multiMode"):
            options["multiMode"] = True

    upgrade = stream.get("httpupgradeSettings") or stream.get("xhttpSettings") or {}
    if upgrade:
        options["path"] = upgrade.get("path", "/")
        options["host"] = upgrade.get("host", "")
        if upgrade.get("mode"):
            options["mode"] = upgrade["mode"]

    tcp = stream.get("tcpSettings") or stream.get("rawSettings") or {}
    header = (tcp.get("header") or {}).get("type")
    if header == "http":
        options["header_type"] = "http"
        request = (tcp.get("header") or {}).get("request") or {}
        options["path"] = (request.get("path") or ["/"])[0]
        options["host"] = ((request.get("headers") or {}).get("Host") or [""])[0]

    tls = stream.get("tlsSettings") or {}
    if tls:
        options["sni"] = tls.get("serverName", "")
        if tls.get("alpn"):
            options["alpn"] = ",".join(tls["alpn"])
        certificates = tls.get("certificates") or []
        if certificates:
            options["certificateFile"] = certificates[0].get("certificateFile", "")
            options["keyFile"] = certificates[0].get("keyFile", "")

    reality = stream.get("realitySettings") or {}
    if reality:
        options["dest"] = reality.get("dest", "")
        options["serverNames"] = reality.get("serverNames") or []
        options["privateKey"] = reality.get("privateKey", "")
        options["shortIds"] = reality.get("shortIds") or [""]
        options["xver"] = reality.get("xver", 0)
        # publicKey в серверном конфиге не хранится: Xray его не использует.
        # Без него клиенты не подключатся, поэтому вписать придётся вручную.
        options["publicKey"] = reality.get("publicKey", "")

    clients = (raw.get("settings") or {}).get("clients") or []
    if clients:
        if clients[0].get("flow"):
            options["flow"] = clients[0]["flow"]
        if clients[0].get("method"):
            options["method"] = clients[0]["method"]
    if raw.get("settings", {}).get("method"):
        options["method"] = raw["settings"]["method"]

    security = (
        SecurityType(security_raw)
        if security_raw in {item.value for item in SecurityType}
        else SecurityType.none
    )

    return {
        "tag": raw.get("tag") or f"{protocol}-{port}",
        "protocol": ProxyType(protocol),
        "port": port,
        "listen": raw.get("listen") or "0.0.0.0",
        "network": NETWORK_ALIASES.get(network_raw, NetworkType.tcp),
        "security": security,
        "settings": options,
        # Чего не хватает для работы — скажем администратору сразу.
        "warnings": _warnings(security, options),
    }


def _warnings(security: SecurityType, options: Dict[str, Any]) -> list:
    warnings = []
    if security == SecurityType.reality and not options.get("publicKey"):
        warnings.append(
            "Для REALITY не хватает publicKey — его нет в серверном конфиге. "
            "Получите на сервере: xray x25519 -i <privateKey>"
        )
    if security == SecurityType.tls and not options.get("certificateFile"):
        warnings.append(
            "Для TLS не указан сертификат — впишите certificateFile и keyFile"
        )
    return warnings

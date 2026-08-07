"""Перечисления. Значения намеренно совпадают с Marzban — так проще
мигрировать базу и держать совместимый REST API."""

import enum


class UserStatus(str, enum.Enum):
    active = "active"
    disabled = "disabled"
    limited = "limited"
    expired = "expired"
    on_hold = "on_hold"


class DataLimitResetStrategy(str, enum.Enum):
    no_reset = "no_reset"
    day = "day"
    week = "week"
    month = "month"
    year = "year"


class ProxyType(str, enum.Enum):
    vless = "vless"
    vmess = "vmess"
    trojan = "trojan"
    shadowsocks = "shadowsocks"


class NodeStatus(str, enum.Enum):
    connected = "connected"
    connecting = "connecting"
    error = "error"
    disabled = "disabled"


class SecurityType(str, enum.Enum):
    none = "none"
    tls = "tls"
    reality = "reality"


class NetworkType(str, enum.Enum):
    tcp = "tcp"
    ws = "ws"
    grpc = "grpc"
    httpupgrade = "httpupgrade"
    xhttp = "xhttp"

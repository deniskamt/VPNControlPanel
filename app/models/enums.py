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
    # Hysteria2 живёт не в Xray, а отдельным процессом рядом: у него свой
    # конфиг, свои счётчики и QUIC вместо TCP. В перечислении он всё равно
    # нужен — ключи пользователей и подписка устроены одинаково для всех.
    hysteria2 = "hysteria2"


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
    # QUIC поверх UDP — транспорт Hysteria2. В Xray такого network нет,
    # поэтому дальше конфига ноды это значение не уходит.
    udp = "udp"
    ws = "ws"
    grpc = "grpc"
    httpupgrade = "httpupgrade"
    xhttp = "xhttp"

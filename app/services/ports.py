"""Порты подключений на серверах: занятость, конфликты и свободный порт.

Два подключения на одном порту одного сервера Xray НЕ отвергает: проверка
конфига проходит, ядро запускается и открывает порт дважды (SO_REUSEPORT).
Дальше ядро Linux раздаёт входящие соединения между ними вслепую, и клиент
VISION, попавший в подключение XHTTP, не подключается. Проверено на
Xray 25.10: с одним подключением на порту проходило 40 соединений из 40, с
двумя — 20 из 40. Снаружи это выглядит как «работает через раз» — и никакой
ошибки нигде нет. Поэтому панель не даёт такого собрать и чинит уже собранное.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Iterable, List, Optional, Sequence, Tuple

from app.models.enums import ProxyType

# Куда переносить подключение, если 443 занят. 443 — лучший порт для
# маскировки, остальные — привычные HTTPS-порты (их же использует
# Cloudflare), трафик на них не выглядит странно.
CANDIDATES = [443, 2053, 2083, 2087, 2096, 8443, 9443, 10443, 4443, 5443, 6443, 7443]

_ANY = {"", "0.0.0.0", "::", "[::]"}


def transport(protocol: ProxyType) -> str:
    """Hysteria2 слушает UDP, остальные — TCP: на одном номере они не мешают."""
    return "udp" if protocol == ProxyType.hysteria2 else "tcp"


def _overlap(listen_a: Optional[str], listen_b: Optional[str]) -> bool:
    a, b = (listen_a or "").strip(), (listen_b or "").strip()
    return a in _ANY or b in _ANY or a == b


def clashes(
    port: int,
    protocol: ProxyType,
    listen: Optional[str],
    nodes: Iterable,
    exclude_id: Optional[int] = None,
) -> List[Tuple[object, object]]:
    """С кем это подключение столкнётся на этих серверах: [(сервер, подключение)].

    Порт агента панели тоже занят: агент слушает его на ноде сам.
    """
    found: List[Tuple[object, object]] = []
    kind = transport(protocol)
    for node in nodes:
        if kind == "tcp" and port == getattr(node, "agent_port", None):
            found.append((node, None))
        for other in node.inbounds:
            if other.id == exclude_id or not other.is_enabled:
                continue
            if (
                other.port == port
                and transport(other.protocol) == kind
                and _overlap(listen, other.listen)
            ):
                found.append((node, other))
    return found


def describe(found: Sequence[Tuple[object, object]]) -> str:
    """Человеческое перечисление конфликтов для сообщения об ошибке."""
    parts = []
    for node, other in found:
        if other is None:
            parts.append(f"{node.name}: порт агента панели")
        else:
            parts.append(f"{node.name}: «{other.tag}»")
    return "; ".join(parts)


def free_port(
    protocol: ProxyType,
    listen: Optional[str],
    nodes: Sequence,
    exclude_id: Optional[int] = None,
    prefer: Optional[int] = None,
) -> Optional[int]:
    """Первый порт, свободный на всех этих серверах сразу."""
    order = ([prefer] if prefer else []) + [port for port in CANDIDATES if port != prefer]
    for port in order:
        if not clashes(port, protocol, listen, nodes, exclude_id):
            return port
    return None


def node_conflicts(node) -> List[Tuple[object, object]]:
    """Пары подключений одного сервера, делящие порт: [(первое, второе)]."""
    pairs = []
    active = sorted((i for i in node.inbounds if i.is_enabled), key=lambda i: i.id)
    for index, first in enumerate(active):
        for second in active[index + 1:]:
            if (
                first.port == second.port
                and transport(first.protocol) == transport(second.protocol)
                and _overlap(first.listen, second.listen)
            ):
                pairs.append((first, second))
    return pairs


def split_clashing(inbounds: Sequence, agent_port: Optional[int]) -> Tuple[List, List]:
    """Разделить набор подключений сервера на совместимые и лишние.

    Берём по порядку создания: первое подключение на порту остаётся, следующие
    на том же порту (и на порту агента) — лишние.
    """
    kept: List = []
    dropped: List = []
    holder = SimpleNamespace(name="", agent_port=agent_port, inbounds=kept)
    for inbound in sorted(inbounds, key=lambda item: item.id):
        if inbound.is_enabled and clashes(inbound.port, inbound.protocol, inbound.listen, [holder]):
            dropped.append(inbound)
        else:
            kept.append(inbound)
    return kept, dropped

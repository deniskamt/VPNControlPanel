"""Что именно пользователь увидит в приложении.

Подписка собирается из трёх источников — сервер, подключение и (необязательно)
хост, — и по коду это разбросано. Администратору же нужен один список: какие
конфигурации получит человек, как они будут называться и куда пойдут. Здесь
тот же обход, что и в build_user_links, но с сохранением всех составляющих,
чтобы каждую строку можно было настроить.
"""

from dataclasses import dataclass
from typing import List, Optional

from app.models.enums import SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.models.user import User
from app.services.links import (
    DEFAULT_REMARK,
    _effective_security,
    _remark,
    build_link,
)


@dataclass
class Entry:
    """Одна строка в списке конфигураций у пользователя."""

    node: Node
    inbound: Inbound
    host: Optional[Host]
    remark: str
    address: str
    port: int
    network: str
    security: SecurityType
    link: Optional[str]

    @property
    def source(self) -> str:
        return "хост" if self.host else "по умолчанию"

    @property
    def key(self) -> str:
        """Устойчивый идентификатор строки для форм."""
        host_part = self.host.id if self.host else 0
        return f"{self.node.id}-{self.inbound.id}-{host_part}"


def _entry(user: User, inbound: Inbound, node: Node, host: Optional[Host]) -> Entry:
    options = inbound.settings or {}
    address = (host.address if host and host.address else None) or node.address
    port = (host.port if host and host.port else None) or inbound.port
    return Entry(
        node=node,
        inbound=inbound,
        host=host,
        remark=_remark(host.remark if host else DEFAULT_REMARK, node, user, inbound),
        address=address,
        port=port,
        network=inbound.network.value,
        security=_effective_security(inbound, host),
        link=build_link(user, inbound, node, host),
    )


def entries_for(user: User, nodes: List[Node]) -> List[Entry]:
    """Строки подписки конкретного пользователя, в порядке показа у клиента."""
    allowed_ids = {inbound.id for inbound in user.inbounds}
    entries: List[Entry] = []

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
            if not hosts:
                entries.append(_entry(user, inbound, node, None))
                continue
            for host in sorted(hosts, key=lambda item: (item.sort_order, item.id)):
                entries.append(_entry(user, inbound, node, host))

    return entries


def hidden_entries(user: User, nodes: List[Node]) -> List[dict]:
    """Почему часть подключений не попала в подписку.

    Пустая подписка выглядит одинаково при десятке разных причин, и каждый раз
    это выясняется перебором. Здесь причина названа сразу.
    """
    allowed_ids = {inbound.id for inbound in user.inbounds}
    reasons: List[dict] = []

    for node in sorted(nodes, key=lambda item: (item.sort_order, item.id)):
        if not node.is_enabled:
            reasons.append({"what": node.name, "why": "сервер выключен"})
            continue
        if not user.allowed_on(node.id):
            reasons.append(
                {"what": node.name, "why": "сервер закрыт для этого пользователя"}
            )
            continue

        if not node.inbounds:
            reasons.append(
                {"what": node.name, "why": "на сервере нет ни одного подключения"}
            )
            continue

        for inbound in sorted(node.inbounds, key=lambda item: item.id):
            label = f"{node.name} → {inbound.tag}"
            if not inbound.is_enabled:
                reasons.append({"what": label, "why": "подключение выключено"})
            elif inbound.id not in allowed_ids:
                reasons.append(
                    {"what": label, "why": "не отмечено у пользователя"}
                )
            elif user.proxy_settings(inbound.protocol) is None:
                reasons.append(
                    {
                        "what": label,
                        "why": f"у пользователя нет ключа {inbound.protocol.value}",
                    }
                )

    return reasons

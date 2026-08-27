"""Что именно пользователь увидит в приложении.

Подписка собирается из трёх источников — сервер, подключение и (необязательно)
хост, — и по коду это разбросано. Администратору же нужен один список: какие
конфигурации получит человек, как они будут называться и куда пойдут. Здесь
тот же перебор, что и в build_user_links, но с сохранением всех составляющих,
чтобы каждую строку можно было настроить.
"""

from dataclasses import dataclass
from typing import List, Optional

from app.models.enums import SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.models.user import User
from app.services.links import (
    _effective_security,
    build_link,
    user_remarks,
    user_rows,
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


def _entry(
    user: User, inbound: Inbound, node: Node, host: Optional[Host], remark: str
) -> Entry:
    address = (host.address if host and host.address else None) or node.address
    port = (host.port if host and host.port else None) or inbound.port
    return Entry(
        node=node,
        inbound=inbound,
        host=host,
        remark=remark,
        address=address,
        port=port,
        network=inbound.network.value,
        security=_effective_security(inbound, host),
        link=build_link(user, inbound, node, host, remark=remark),
    )


def entries_for(user: User, nodes: List[Node]) -> List[Entry]:
    """Строки подписки конкретного пользователя, в порядке показа у клиента.

    Названия берём те же, что уедут в ссылках, — вместе с разведением
    совпадений. Иначе администратор видел бы в панели одно, а человек в
    приложении другое.
    """
    rows = user_rows(user, nodes)
    return [
        _entry(user, inbound, node, host, remark)
        for (node, inbound, host), remark in zip(rows, user_remarks(user, rows))
    ]


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


def apply_order(rows: List[tuple]) -> None:
    """Записать сквозной порядок строк.

    У строки с хостом место своё. У строки по умолчанию отдельного места
    нет — она получает его от сервера, поэтому серверу достаётся номер его
    первой строки. Чтобы такую строку можно было двигать саму по себе, для
    неё заводится хост — этим занимается раздел «Подписка».
    """
    first_row: dict = {}
    for position, (node, _inbound, host) in enumerate(rows):
        if host is not None:
            host.sort_order = position
        else:
            first_row.setdefault(node.id, (node, position))

    for node, position in first_row.values():
        node.sort_order = position

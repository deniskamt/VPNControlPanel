"""Что требует внимания: поломки, которые панель видит сама.

Каждая из этих бед снаружи выглядит одинаково — «у людей не подключается»,
и выяснялась перебором команд на серверах. Большую часть панель может
заметить по своим же данным, раньше пользователей, — и сразу сказать, где
это чинится.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import NodeStatus, ProxyType, SecurityType
from app.models.inbound import Host, Inbound
from app.models.node import Node
from app.services import masking
from app.services.agent_source import bundled_version, is_outdated


@dataclass
class Issue:
    level: str  # err — у людей уже не работает; warn — сломается или вычислят
    title: str
    detail: str
    link: str
    action: str
    # Действие выполняется сразу (POST), а не ведёт на страницу.
    post: bool = False


def _names(nodes: List[Node]) -> str:
    return ", ".join(node.name for node in nodes)


def _transport(inbound: Inbound) -> str:
    """Hysteria2 слушает UDP, всё остальное — TCP: на одном порту они не мешают."""
    return "udp" if inbound.protocol == ProxyType.hysteria2 else "tcp"


async def collect(session: AsyncSession) -> List[Issue]:
    nodes = list((await session.execute(select(Node).order_by(Node.sort_order, Node.id))).scalars().all())
    inbounds = list((await session.execute(select(Inbound).order_by(Inbound.id))).scalars().all())
    hosts = list((await session.execute(select(Host))).scalars().all())
    enabled_nodes = [node for node in nodes if node.is_enabled]
    issues: List[Issue] = []

    # --- Серверы -------------------------------------------------------------
    broken = [node for node in enabled_nodes if node.status == NodeStatus.error]
    if broken:
        first = (broken[0].message or "").split(". ")[0][:160]
        issues.append(Issue(
            "err",
            f"Серверы с ошибкой: {_names(broken)}",
            f"На них сейчас никто не подключится. {broken[0].name}: {first}",
            "/nodes", "К серверам",
        ))

    version = bundled_version()
    outdated = [
        node for node in enabled_nodes
        if node.last_seen_at and is_outdated(node.agent_version, version)
    ]
    if outdated:
        issues.append(Issue(
            "warn",
            f"Устарел агент на {len(outdated)} серв.: {_names(outdated)}",
            f"В панели версия {version}. Без обновления не работают новые "
            "возможности — например, проверка маскировочных доменов.",
            "/nodes/update-agents", "Обновить все", post=True,
        ))

    empty = [node for node in enabled_nodes if not any(i.is_enabled for i in node.inbounds)]
    if empty:
        issues.append(Issue(
            "warn",
            f"Серверы без подключений: {_names(empty)}",
            "Сервер включён, но ни один протокол на нём не поднят — в подписке его нет.",
            "/subscription#node-protocols", "Протоколы на серверах",
        ))

    # --- Подключения ---------------------------------------------------------
    orphan = [i for i in inbounds if i.is_enabled and not any(n.is_enabled for n in i.nodes)]
    for inbound in orphan:
        issues.append(Issue(
            "warn",
            f"«{inbound.tag}» не поднято ни на одном сервере",
            "Подключение включено, но слушать его некому — у людей его нет.",
            "/subscription#node-protocols", "Протоколы на серверах",
        ))

    # Два подключения на одном порту одного сервера: Xray не примет конфиг
    # целиком, и падает весь сервер, а не одно подключение.
    for node in enabled_nodes:
        seen: Dict[Tuple[int, str], Inbound] = {}
        for inbound in sorted(node.inbounds, key=lambda i: i.id):
            if not inbound.is_enabled:
                continue
            key = (inbound.port, _transport(inbound))
            if key in seen:
                issues.append(Issue(
                    "err",
                    f"{node.name}: «{seen[key].tag}» и «{inbound.tag}» на одном порту {inbound.port}",
                    "Xray не поднимет конфиг с двумя подключениями на одном порту — "
                    "не работает весь сервер, а не одно подключение.",
                    "/inbounds", "К подключениям",
                ))
            else:
                seen[key] = inbound

    # --- Маскировка REALITY --------------------------------------------------
    node_names = {node.id: node.name for node in nodes}
    for inbound in inbounds:
        if inbound.security != SecurityType.reality or not inbound.is_enabled:
            continue
        on = [node for node in inbound.nodes if node.is_enabled]
        for domain, ids in masking.duplicates(inbound.settings, [n.id for n in on]).items():
            issues.append(Issue(
                "warn",
                f"«{inbound.tag}»: один домен {domain} на {len(ids)} серв.",
                f"{', '.join(node_names[i] for i in ids)}. Одинаковый домен — одна "
                "примета на все эти серверы, а за передним сервером nginx их не различит.",
                f"/masking#inbound-{inbound.id}", "Раздать разные",
            ))
        guide = sorted({masking.domain_for(inbound.settings, n.id) for n in on} & masking.DISCOURAGED)
        if guide:
            issues.append(Issue(
                "warn",
                f"«{inbound.tag}»: домен из популярных гайдов — {', '.join(guide)}",
                "Такие домены вычисляются в первую очередь, а www.cloudflare.com "
                "в России режется сам по себе.",
                f"/masking#inbound-{inbound.id}", "Подобрать другой",
            ))

    # Свой SNI у строки подписки, которого нет среди имён REALITY на сервере:
    # сервер такое рукопожатие не узнаёт, и строка молча не работает.
    by_id = {inbound.id: inbound for inbound in inbounds}
    for host in hosts:
        inbound: Optional[Inbound] = by_id.get(host.inbound_id)
        if (
            host.is_disabled or not host.sni or inbound is None
            or inbound.security != SecurityType.reality or not inbound.is_enabled
        ):
            continue
        targets = [n for n in inbound.nodes if n.is_enabled and host.node_id in (None, n.id)]
        bad = [n for n in targets if host.sni not in _server_names(inbound, n.id)]
        if bad:
            issues.append(Issue(
                "err",
                f"Строка «{host.remark}»: SNI {host.sni} не принимается сервером",
                f"«{inbound.tag}» на {_names(bad)} маскируется под другой домен — "
                "эта строка подписки не подключится. Очистите SNI в настройке строки.",
                "/subscription", "К подписке",
            ))

    issues.sort(key=lambda issue: issue.level != "err")
    return issues


def _server_names(inbound: Inbound, node_id: int) -> List[str]:
    """Имена, которые REALITY на этом сервере примет (как в конфиге ноды)."""
    names = list((inbound.settings or {}).get("serverNames") or [])
    own = masking.node_domains(inbound.settings).get(str(node_id))
    return ([own] if own else []) + names

"""Трафик серверов за сутки: всего, по пользователям и по протоколам.

Считается по часовым корзинам, поэтому «за 24 ч» — это последние 24–25 часов:
текущий неполный час входит целиком.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.inbound import Inbound
from app.models.usage import NodeUsage, NodeUserInboundUsage, NodeUserUsage

WINDOW = timedelta(hours=24)


def _since() -> datetime:
    return (datetime.utcnow() - WINDOW).replace(minute=0, second=0, microsecond=0)


async def day_stats(session: AsyncSession) -> Dict[str, Dict]:
    since = _since()

    node_total = {
        node_id: int(total or 0)
        for node_id, total in (
            await session.execute(
                select(NodeUsage.node_id, func.sum(NodeUsage.uplink + NodeUsage.downlink))
                .where(NodeUsage.created_at >= since)
                .group_by(NodeUsage.node_id)
            )
        ).all()
    }

    user_day = {
        (node_id, user_id): int(total or 0)
        for node_id, user_id, total in (
            await session.execute(
                select(NodeUserUsage.node_id, NodeUserUsage.user_id, func.sum(NodeUserUsage.used_traffic))
                .where(NodeUserUsage.created_at >= since)
                .group_by(NodeUserUsage.node_id, NodeUserUsage.user_id)
            )
        ).all()
    }

    inbounds = {
        inbound.id: inbound
        for inbound in (await session.execute(select(Inbound))).scalars().all()
    }
    user_protocols: Dict[Tuple[int, int], List[Tuple[Inbound, int]]] = {}
    node_protocols: Dict[int, Dict[int, int]] = {}
    for node_id, user_id, inbound_id, total in (
        await session.execute(
            select(
                NodeUserInboundUsage.node_id,
                NodeUserInboundUsage.user_id,
                NodeUserInboundUsage.inbound_id,
                func.sum(NodeUserInboundUsage.used_traffic),
            )
            .where(NodeUserInboundUsage.created_at >= since)
            .group_by(
                NodeUserInboundUsage.node_id,
                NodeUserInboundUsage.user_id,
                NodeUserInboundUsage.inbound_id,
            )
        )
    ).all():
        inbound = inbounds.get(inbound_id)
        if inbound is None or not total:
            continue
        user_protocols.setdefault((node_id, user_id), []).append((inbound, int(total)))
        per_node = node_protocols.setdefault(node_id, {})
        per_node[inbound_id] = per_node.get(inbound_id, 0) + int(total)

    for rows in user_protocols.values():
        rows.sort(key=lambda item: -item[1])

    return {
        "node_total": node_total,
        "user_day": user_day,
        "user_protocols": user_protocols,
        "node_protocols": {
            node_id: sorted(((inbounds[i], b) for i, b in per.items()), key=lambda item: -item[1])
            for node_id, per in node_protocols.items()
        },
    }

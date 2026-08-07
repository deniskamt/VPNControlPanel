"""Главная страница панели."""

from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.database import get_session
from app.models.admin import Admin
from app.models.audit import AuditLog
from app.models.enums import NodeStatus, UserStatus
from app.models.node import Node
from app.models.usage import NodeUsage, SystemUsage
from app.models.user import User
from app.web.templates import templates

router = APIRouter()


async def _collect_stats(session: AsyncSession) -> Dict[str, Any]:
    async def count_users(status: UserStatus) -> int:
        return (
            await session.scalar(
                select(func.count()).select_from(User).where(User.status == status)
            )
            or 0
        )

    total_users = await session.scalar(select(func.count()).select_from(User)) or 0
    usage = await session.get(SystemUsage, 1)

    day_ago = datetime.utcnow() - timedelta(hours=24)
    traffic_24h = (
        await session.scalar(
            select(func.coalesce(func.sum(NodeUsage.uplink + NodeUsage.downlink), 0))
            .where(NodeUsage.created_at >= day_ago)
        )
        or 0
    )
    online_users = (
        await session.scalar(
            select(func.count())
            .select_from(User)
            .where(User.online_at >= datetime.utcnow() - timedelta(minutes=5))
        )
        or 0
    )

    return {
        "total_users": total_users,
        "active_users": await count_users(UserStatus.active),
        "expired_users": await count_users(UserStatus.expired),
        "limited_users": await count_users(UserStatus.limited),
        "disabled_users": await count_users(UserStatus.disabled),
        "online_users": online_users,
        "total_traffic": (usage.uplink + usage.downlink) if usage else 0,
        "traffic_24h": traffic_24h,
    }


async def _traffic_series(session: AsyncSession, hours: int = 24) -> List[Dict[str, Any]]:
    """Почасовой трафик за последние сутки — для графика на дашборде."""
    since = (datetime.utcnow() - timedelta(hours=hours)).replace(
        minute=0, second=0, microsecond=0
    )
    result = await session.execute(
        select(
            NodeUsage.created_at,
            func.sum(NodeUsage.uplink + NodeUsage.downlink),
        )
        .where(NodeUsage.created_at >= since)
        .group_by(NodeUsage.created_at)
        .order_by(NodeUsage.created_at)
    )
    buckets = {row[0]: int(row[1] or 0) for row in result.all()}

    series: List[Dict[str, Any]] = []
    for offset in range(hours + 1):
        moment = since + timedelta(hours=offset)
        series.append({"hour": moment.strftime("%H:00"), "value": buckets.get(moment, 0)})
    return series


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    stats = await _collect_stats(session)
    series = await _traffic_series(session)
    peak = max((point["value"] for point in series), default=0) or 1

    nodes = list(
        (
            await session.execute(select(Node).order_by(Node.sort_order, Node.id))
        )
        .scalars()
        .all()
    )
    logs = list(
        (
            await session.execute(
                select(AuditLog).order_by(AuditLog.created_at.desc()).limit(10)
            )
        )
        .scalars()
        .all()
    )

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "admin": admin,
            "page": "dashboard",
            "stats": stats,
            "series": series,
            "peak": peak,
            "nodes": nodes,
            "logs": logs,
            "NodeStatus": NodeStatus,
        },
    )


@router.get("/partials/nodes-status", response_class=HTMLResponse)
async def nodes_status_partial(
    request: Request,
    session: AsyncSession = Depends(get_session),
    _: Admin = Depends(web_admin),
):
    """Кусок страницы, который HTMX сам перезапрашивает раз в 15 секунд."""
    nodes = list(
        (await session.execute(select(Node).order_by(Node.sort_order, Node.id)))
        .scalars()
        .all()
    )
    return templates.TemplateResponse(
        request, "partials/nodes_status.html", {"nodes": nodes}
    )

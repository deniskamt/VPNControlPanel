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
from app.models.inbound import Inbound
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


async def _setup_progress(session: AsyncSession) -> Dict[str, Any]:
    """Шаги, которые нужно пройти до первого работающего подключения.

    Пока они не пройдены, обычный дашборд бесполезен — на нём одни нули,
    и непонятно, что делать дальше.
    """
    nodes = await session.scalar(select(func.count()).select_from(Node)) or 0
    online = (
        await session.scalar(
            select(func.count()).select_from(Node).where(Node.status == NodeStatus.connected)
        )
        or 0
    )
    inbounds = await session.scalar(select(func.count()).select_from(Inbound)) or 0
    users = await session.scalar(select(func.count()).select_from(User)) or 0

    steps = [
        {
            "title": "Добавить сервер",
            "hint": "Укажите адрес и скопируйте команду установки агента",
            "done": nodes > 0,
            "link": "/nodes",
            "action": "К серверам",
        },
        {
            "title": "Дождаться агента",
            "hint": "Выполните команду на сервере — он станет зелёным",
            "done": online > 0,
            "link": "/nodes",
            "action": "Проверить",
        },
        {
            "title": "Создать подключение",
            "hint": "Шаблон VLESS + REALITY: ключи панель сгенерирует сама",
            "done": inbounds > 0,
            "link": "/inbounds",
            "action": "К подключениям",
        },
        {
            "title": "Выдать доступ",
            "hint": "Создайте пользователя и заберите ссылку или QR-код",
            "done": users > 0,
            "link": "/users",
            "action": "К пользователям",
        },
    ]

    return {
        "steps": steps,
        "done": sum(1 for step in steps if step["done"]),
        "total": len(steps),
        "complete": all(step["done"] for step in steps),
    }


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    setup = await _setup_progress(session)
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
            "setup": setup,
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

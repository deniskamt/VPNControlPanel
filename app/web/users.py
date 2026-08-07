"""Управление пользователями и подписками."""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import web_admin
from app.core.config import settings
from app.core.database import get_session
from app.models.access import UserNodeAccess
from app.models.admin import Admin
from app.models.enums import DataLimitResetStrategy, ProxyType, UserStatus
from app.models.inbound import Inbound
from app.models.node import Node
from app.models.user import User
from app.services import users as user_service
from app.services.audit import log_action
from app.services.qr import qr_svg
from app.services.worker import trigger_sync
from app.web.templates import templates

router = APIRouter(prefix="/users")

PAGE_SIZE = 25
GB = 1024**3


async def _get_user(session: AsyncSession, user_id: int) -> User:
    user = await session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")
    return user


def _redirect(query: str = "") -> RedirectResponse:
    return RedirectResponse(f"/users{query}", status_code=status.HTTP_303_SEE_OTHER)


def _expire_from_days(days: Optional[int]) -> Optional[int]:
    if not days or days <= 0:
        return None
    return int((datetime.utcnow() + timedelta(days=days)).timestamp())


@router.get("", response_class=HTMLResponse)
async def list_users(
    request: Request,
    search: str = Query(default=""),
    status_filter: str = Query(default="", alias="status"),
    page: int = Query(default=1, ge=1),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    query = select(User)
    if search:
        query = query.where(User.username.ilike(f"%{search.strip()}%"))
    if status_filter:
        try:
            query = query.where(User.status == UserStatus(status_filter))
        except ValueError:
            status_filter = ""

    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
    result = await session.execute(
        query.order_by(User.id.desc()).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)
    )
    users = list(result.scalars().all())

    rows: List[Dict[str, Any]] = []
    for user in users:
        rows.append(
            {
                "user": user,
                "subscription_url": settings.subscription_url(
                    user_service.subscription_token(user)
                ),
            }
        )

    inbounds = list(
        (
            await session.execute(
                select(Inbound).where(Inbound.is_enabled.is_(True)).order_by(Inbound.id)
            )
        )
        .scalars()
        .all()
    )

    return templates.TemplateResponse(
        request,
        "users.html",
        {
            "admin": admin,
            "page": "users",
            "rows": rows,
            "inbounds": inbounds,
            "protocols": [item.value for item in ProxyType],
            "statuses": [item.value for item in UserStatus],
            "search": search,
            "status_filter": status_filter,
            "page_number": page,
            "pages": max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE),
            "total": total,
            "GB": GB,
        },
    )


@router.get("/{user_id}", response_class=HTMLResponse)
async def user_detail(
    user_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    user = await _get_user(session, user_id)
    links = await user_service.user_links(session, user)
    inbounds = list(
        (
            await session.execute(
                select(Inbound).where(Inbound.is_enabled.is_(True)).order_by(Inbound.id)
            )
        )
        .scalars()
        .all()
    )
    subscription_url = settings.subscription_url(user_service.subscription_token(user))

    nodes = list(
        (await session.execute(select(Node).order_by(Node.sort_order, Node.id)))
        .scalars()
        .all()
    )
    access_by_node = {access.node_id: access for access in user.node_access}

    return templates.TemplateResponse(
        request,
        "user_detail.html",
        {
            "admin": admin,
            "page": "users",
            "user": user,
            "links": links,
            "inbounds": inbounds,
            "nodes": nodes,
            "access_by_node": access_by_node,
            "user_inbound_ids": {inbound.id for inbound in user.inbounds},
            "protocols": [item.value for item in ProxyType],
            "statuses": [item.value for item in UserStatus],
            "subscription_url": subscription_url,
            # QR удобнее ссылки: подписка забирается телефоном сразу.
            "subscription_qr": qr_svg(subscription_url, scale=5),
            "GB": GB,
        },
    )


@router.post("/create")
async def create_user(
    request: Request,
    username: str = Form(...),
    protocols: List[str] = Form(default=["vless"]),
    days: int = Form(default=30),
    data_limit_gb: float = Form(default=0),
    note: str = Form(default=""),
    telegram_id: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    username = username.strip()
    if await user_service.get_user(session, username) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Такой пользователь уже есть")

    user = await user_service.create_user(
        session,
        username,
        proxies={protocol: {} for protocol in protocols} or {"vless": {}},
        expire=_expire_from_days(days),
        data_limit=int(data_limit_gb * GB) if data_limit_gb else None,
        data_limit_reset_strategy=DataLimitResetStrategy.no_reset,
        note=note.strip() or None,
        telegram_id=int(telegram_id) if telegram_id.strip().isdigit() else None,
        admin_id=admin.id,
    )
    await log_action(
        session,
        action="user.create",
        actor=admin.username,
        target=user.username,
        target_type="user",
        ip=request.client.host if request.client else None,
    )
    await session.commit()

    trigger_sync()
    return _redirect()


@router.post("/{user_id}/update")
async def update_user(
    user_id: int,
    request: Request,
    days: int = Form(default=0),
    data_limit_gb: float = Form(default=0),
    device_limit: str = Form(default=""),
    user_status: str = Form(default="active"),
    note: str = Form(default=""),
    inbound_ids: List[int] = Form(default=[]),
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    user = await _get_user(session, user_id)
    user.device_limit = int(device_limit) if device_limit.strip().isdigit() else None
    if user.device_limit == 0:
        user.device_limit = None

    if days:
        # Продление считаем от текущей даты окончания, если она в будущем.
        now = int(datetime.utcnow().timestamp())
        base = user.expire if user.expire and user.expire > now else now
        user.expire = base + days * 86400
    user.data_limit = int(data_limit_gb * GB) if data_limit_gb else None
    user.note = note.strip() or None

    try:
        new_status = UserStatus(user_status)
    except ValueError:
        new_status = user.status
    if new_status != user.status:
        user.status = new_status
        user.last_status_change = datetime.utcnow()

    if inbound_ids:
        result = await session.execute(select(Inbound).where(Inbound.id.in_(inbound_ids)))
        user.inbounds = list(result.scalars().all())

    await log_action(
        session,
        action="user.update",
        actor=admin.username,
        target=user.username,
        target_type="user",
        details={"days": days, "data_limit_gb": data_limit_gb, "status": user_status},
        ip=request.client.host if request.client else None,
    )
    await session.commit()

    trigger_sync()
    return RedirectResponse(f"/users/{user_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/nodes")
async def update_node_access(
    user_id: int,
    request: Request,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Доступ к серверам и отдельные лимиты трафика на каждом из них.

    Поля приходят парами node_allowed_<id> / node_limit_<id>, поэтому разбираем
    форму вручную: список серверов заранее неизвестен.
    """
    user = await _get_user(session, user_id)
    form = await request.form()

    nodes = list(
        (await session.execute(select(Node).order_by(Node.sort_order, Node.id)))
        .scalars()
        .all()
    )
    existing = {access.node_id: access for access in user.node_access}
    changes: Dict[str, Any] = {}

    for node in nodes:
        allowed = f"node_allowed_{node.id}" in form
        raw_limit = str(form.get(f"node_limit_{node.id}", "") or "").strip()
        try:
            limit_gb = float(raw_limit) if raw_limit else 0.0
        except ValueError:
            limit_gb = 0.0
        limit = int(limit_gb * GB) if limit_gb > 0 else None

        access = existing.get(node.id)
        if access is None:
            # Строку заводим только если что-то отличается от умолчания:
            # «доступен, без отдельного лимита».
            if allowed and limit is None:
                continue
            access = UserNodeAccess(user_id=user.id, node_id=node.id)
            session.add(access)

        if access.is_allowed != allowed or access.data_limit != limit:
            changes[node.name] = {
                "allowed": allowed,
                "limit_gb": limit_gb if limit else None,
            }
        access.is_allowed = allowed
        access.data_limit = limit

    if changes:
        await log_action(
            session,
            action="user.node_access",
            actor=admin.username,
            target=user.username,
            target_type="user",
            details=changes,
            ip=request.client.host if request.client else None,
        )
    await session.commit()

    trigger_sync()
    return RedirectResponse(f"/users/{user_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/nodes/{node_id}/reset")
async def reset_node_traffic(
    user_id: int,
    node_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    """Обнулить трафик пользователя на одном сервере."""
    user = await _get_user(session, user_id)
    access = user.access_for(node_id)
    if access is not None:
        access.used_traffic = 0
        access.reset_at = datetime.utcnow()
        await log_action(
            session,
            action="user.node_reset",
            actor=admin.username,
            target=user.username,
            target_type="user",
            details={"node_id": node_id},
        )
        await session.commit()
        trigger_sync()
    return RedirectResponse(f"/users/{user_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/reset")
async def reset_traffic(
    user_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    user = await _get_user(session, user_id)
    user.used_traffic = 0
    if user.status == UserStatus.limited:
        user.status = UserStatus.active
    await log_action(
        session,
        action="user.reset",
        actor=admin.username,
        target=user.username,
        target_type="user",
    )
    await session.commit()

    trigger_sync()
    return RedirectResponse(f"/users/{user_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/revoke")
async def revoke_sub(
    user_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    user = await _get_user(session, user_id)
    await user_service.revoke_subscription(session, user)
    await log_action(
        session,
        action="user.revoke_sub",
        actor=admin.username,
        target=user.username,
        target_type="user",
        level="warning",
        message="выданы новые ключи, старая ссылка больше не работает",
    )
    await session.commit()

    trigger_sync()
    return RedirectResponse(f"/users/{user_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{user_id}/delete")
async def delete_user(
    user_id: int,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(web_admin),
):
    user = await _get_user(session, user_id)
    username = user.username
    await session.delete(user)
    await log_action(
        session,
        action="user.delete",
        actor=admin.username,
        target=username,
        target_type="user",
        level="warning",
    )
    await session.commit()

    trigger_sync()
    return _redirect()

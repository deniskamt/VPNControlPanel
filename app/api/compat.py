"""REST API, совместимый с Marzban.

Цель — чтобы NexloVPN, TGAdminBot и AppVPN продолжили работать без единой
правки: они ходят на /api/admin/token, /api/inbounds, /api/user*.
Формат ответов повторяет Marzban, включая имена полей.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import api_admin
from app.core.config import settings
from app.core.database import get_session
from app.core.security import create_admin_token, verify_password
from app.models.admin import Admin
from app.models.enums import DataLimitResetStrategy, ProxyType, UserStatus
from app.models.inbound import Inbound
from app.models.node import Node
from app.models.usage import SystemUsage
from app.models.user import User
from app.services import users as user_service
from app.services.audit import log_action
from app.services.worker import trigger_sync

router = APIRouter(prefix="/api", tags=["marzban-compat"])


# --- Схемы запросов --------------------------------------------------------


class UserCreateRequest(BaseModel):
    username: str
    proxies: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    inbounds: Dict[str, List[str]] = Field(default_factory=dict)
    expire: Optional[int] = None
    data_limit: Optional[int] = None
    data_limit_reset_strategy: Optional[str] = None
    status: Optional[str] = None
    note: Optional[str] = None
    telegram_id: Optional[int] = None


class UserModifyRequest(BaseModel):
    proxies: Optional[Dict[str, Dict[str, Any]]] = None
    inbounds: Optional[Dict[str, List[str]]] = None
    expire: Optional[int] = None
    data_limit: Optional[int] = None
    data_limit_reset_strategy: Optional[str] = None
    status: Optional[str] = None
    note: Optional[str] = None


# --- Сериализация ----------------------------------------------------------


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


async def serialize_user(session: AsyncSession, user: User) -> Dict[str, Any]:
    token = user_service.subscription_token(user)
    links = await user_service.user_links(session, user)

    proxies: Dict[str, Dict[str, Any]] = {}
    for proxy in user.proxies:
        proxies[proxy.protocol.value] = dict(proxy.settings or {})

    inbounds: Dict[str, List[str]] = {}
    for inbound in user.inbounds:
        inbounds.setdefault(inbound.protocol.value, []).append(inbound.tag)

    return {
        "username": user.username,
        "status": user.status.value,
        "used_traffic": user.used_traffic,
        "lifetime_used_traffic": user.lifetime_used_traffic,
        # В базе «без срока» и «без лимита» — это NULL, но Marzban отдавал
        # в API ноль, и клиенты считают эти поля числами: json null роняет
        # их на первой же арифметике (expire - now, used / data_limit).
        "data_limit": user.data_limit or 0,
        "data_limit_reset_strategy": user.data_limit_reset_strategy.value,
        "expire": user.expire or 0,
        "created_at": _iso(user.created_at),
        "note": user.note,
        "online_at": _iso(user.online_at),
        "sub_updated_at": _iso(user.sub_updated_at),
        "sub_last_user_agent": user.sub_last_user_agent,
        "subscription_url": settings.subscription_url(token),
        "links": links,
        "proxies": proxies,
        "inbounds": inbounds,
        "admin": None,
    }


def _parse_status(value: Optional[str], default: UserStatus) -> UserStatus:
    if not value:
        return default
    try:
        return UserStatus(value)
    except ValueError as exc:
        raise HTTPException(422, f"Неизвестный статус: {value}") from exc


def _parse_strategy(value: Optional[str]) -> DataLimitResetStrategy:
    if not value:
        return DataLimitResetStrategy.no_reset
    try:
        return DataLimitResetStrategy(value)
    except ValueError as exc:
        raise HTTPException(422, f"Неизвестная стратегия сброса: {value}") from exc


def _validate_protocols(proxies: Dict[str, Any]) -> None:
    for name in proxies:
        try:
            ProxyType(name)
        except ValueError as exc:
            raise HTTPException(422, f"Неизвестный протокол: {name}") from exc


# --- Авторизация -----------------------------------------------------------


@router.post("/admin/token")
async def admin_token(
    request: Request, session: AsyncSession = Depends(get_session)
) -> Dict[str, Any]:
    """Marzban принимает и form-data, и JSON — повторяем оба варианта."""
    username = password = ""
    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        payload = await request.json()
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
    else:
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))

    result = await session.execute(
        select(Admin).where(Admin.username == username, Admin.is_active.is_(True))
    )
    admin = result.scalar_one_or_none()
    if admin is None or not verify_password(password, admin.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")

    admin.last_login_at = datetime.utcnow()
    await session.commit()

    return {
        "access_token": create_admin_token(admin.username),
        "token_type": "bearer",
        "is_sudo": admin.is_sudo,
    }


@router.get("/admin")
async def current_admin(admin: Admin = Depends(api_admin)) -> Dict[str, Any]:
    return {
        "username": admin.username,
        "is_sudo": admin.is_sudo,
        "telegram_id": admin.telegram_id,
    }


# --- Inbounds --------------------------------------------------------------


@router.get("/inbounds")
async def list_inbounds(
    session: AsyncSession = Depends(get_session),
    _: Admin = Depends(api_admin),
) -> Dict[str, List[Dict[str, Any]]]:
    result = await session.execute(
        select(Inbound).where(Inbound.is_enabled.is_(True)).order_by(Inbound.id)
    )
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for inbound in result.scalars().all():
        grouped.setdefault(inbound.protocol.value, []).append(
            {
                "tag": inbound.tag,
                "protocol": inbound.protocol.value,
                "network": inbound.network.value,
                "tls": inbound.security.value,
                "port": inbound.port,
            }
        )
    return grouped


# --- Пользователи ----------------------------------------------------------


@router.post("/user", status_code=status.HTTP_200_OK)
async def create_user(
    payload: UserCreateRequest,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    existing = await user_service.get_user(session, payload.username)
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Пользователь уже существует")

    _validate_protocols(payload.proxies)
    user = await user_service.create_user(
        session,
        payload.username,
        proxies=payload.proxies or {"vless": {}},
        inbound_tags=payload.inbounds or None,
        expire=payload.expire,
        data_limit=payload.data_limit,
        data_limit_reset_strategy=_parse_strategy(payload.data_limit_reset_strategy),
        status=_parse_status(payload.status, UserStatus.active),
        note=payload.note,
        telegram_id=payload.telegram_id,
        admin_id=admin.id,
    )
    await log_action(
        session,
        action="user.create",
        actor=admin.username,
        target=user.username,
        target_type="user",
        message="через API",
    )
    await session.commit()
    await session.refresh(user)

    trigger_sync()
    return await serialize_user(session, user)


@router.get("/users")
async def list_users(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    username: Optional[str] = None,
    search: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    session: AsyncSession = Depends(get_session),
    _: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    query = select(User)
    if username:
        query = query.where(User.username == username)
    if search:
        query = query.where(User.username.ilike(f"%{search}%"))
    if status_filter:
        query = query.where(User.status == _parse_status(status_filter, UserStatus.active))

    total = await session.scalar(
        select(func.count()).select_from(query.subquery())
    )
    result = await session.execute(
        query.order_by(User.id.desc()).offset(offset).limit(limit)
    )

    items = [await serialize_user(session, user) for user in result.scalars().all()]
    return {"users": items, "total": total or 0}


@router.get("/user/{username}")
async def get_user(
    username: str,
    session: AsyncSession = Depends(get_session),
    _: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    user = await user_service.get_user(session, username)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")
    return await serialize_user(session, user)


@router.put("/user/{username}")
async def modify_user(
    username: str,
    payload: UserModifyRequest,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    user = await user_service.get_user(session, username)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")

    changes: Dict[str, Any] = {}

    if payload.expire is not None:
        user.expire = payload.expire or None
        changes["expire"] = payload.expire
    if payload.data_limit is not None:
        user.data_limit = payload.data_limit or None
        changes["data_limit"] = payload.data_limit
    if payload.data_limit_reset_strategy is not None:
        user.data_limit_reset_strategy = _parse_strategy(
            payload.data_limit_reset_strategy
        )
    if payload.note is not None:
        user.note = payload.note
    if payload.status is not None:
        user.status = _parse_status(payload.status, user.status)
        user.last_status_change = datetime.utcnow()
        changes["status"] = payload.status
    if payload.proxies:
        _validate_protocols(payload.proxies)
        await user_service.set_proxies(
            session, user, payload.proxies, payload.inbounds or None
        )
    elif payload.inbounds is not None:
        protocols = {proxy.protocol for proxy in user.proxies}
        user.inbounds = await user_service.resolve_inbounds(
            session, protocols, payload.inbounds
        )

    # Продление подписки должно возвращать пользователя в строй.
    if user.status in (UserStatus.expired, UserStatus.limited):
        expired = bool(user.expire) and user.expire <= int(datetime.utcnow().timestamp())
        limited = bool(user.data_limit) and user.used_traffic >= user.data_limit
        if not expired and not limited:
            user.status = UserStatus.active
            user.last_status_change = datetime.utcnow()

    await log_action(
        session,
        action="user.update",
        actor=admin.username,
        target=user.username,
        target_type="user",
        message="через API",
        details=changes or None,
    )
    await session.commit()
    await session.refresh(user)

    trigger_sync()
    return await serialize_user(session, user)


@router.delete("/user/{username}")
async def delete_user(
    username: str,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    user = await user_service.get_user(session, username)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")

    await session.delete(user)
    await log_action(
        session,
        action="user.delete",
        actor=admin.username,
        target=username,
        target_type="user",
        message="через API",
    )
    await session.commit()

    trigger_sync()
    return {"detail": "User successfully deleted"}


@router.post("/user/{username}/reset")
async def reset_user_traffic(
    username: str,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    user = await user_service.get_user(session, username)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")

    user.used_traffic = 0
    if user.status == UserStatus.limited:
        user.status = UserStatus.active
    await log_action(
        session,
        action="user.reset",
        actor=admin.username,
        target=username,
        target_type="user",
    )
    await session.commit()
    await session.refresh(user)

    trigger_sync()
    return await serialize_user(session, user)


@router.post("/user/{username}/revoke_sub")
async def revoke_subscription(
    username: str,
    session: AsyncSession = Depends(get_session),
    admin: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    user = await user_service.get_user(session, username)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")

    await user_service.revoke_subscription(session, user)
    await log_action(
        session,
        action="user.revoke_sub",
        actor=admin.username,
        target=username,
        target_type="user",
        level="warning",
    )
    await session.commit()
    await session.refresh(user)

    trigger_sync()
    return await serialize_user(session, user)


# --- Система ---------------------------------------------------------------


@router.get("/system")
async def system_stats(
    session: AsyncSession = Depends(get_session),
    _: Admin = Depends(api_admin),
) -> Dict[str, Any]:
    total_users = await session.scalar(select(func.count()).select_from(User)) or 0
    active_users = (
        await session.scalar(
            select(func.count()).select_from(User).where(User.status == UserStatus.active)
        )
        or 0
    )
    usage = await session.get(SystemUsage, 1)
    nodes_total = await session.scalar(select(func.count()).select_from(Node)) or 0

    return {
        "version": "1.0.0",
        "total_user": total_users,
        "users_active": active_users,
        "incoming_bandwidth": usage.uplink if usage else 0,
        "outgoing_bandwidth": usage.downlink if usage else 0,
        "nodes": nodes_total,
    }


@router.get("/sub")
async def subscription_by_token(
    token: str = Query(...),
    session: AsyncSession = Depends(get_session),
) -> Dict[str, Any]:
    """Отдаёт актуальный адрес подписки по её токену.

    Нужен мобильному приложению: оно так узнаёт новый URL, если сменился
    домен или подписку перевыпустили.
    """
    from app.services.subscription import get_subscription_payload

    payload = get_subscription_payload(token)
    if payload is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Недействительный токен")

    user = await user_service.get_user(session, payload["username"])
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Пользователь не найден")

    return {
        "subscription_url": settings.subscription_url(
            user_service.subscription_token(user)
        ),
        "username": user.username,
        "status": user.status.value,
        "expire": user.expire or 0,
    }
